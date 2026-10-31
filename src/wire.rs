//! SSH wire encoding (RFC 4251 §5, RFC 5656 §3.1) for the few structures se-agent emits.
//!
//! The ECDSA signature path is where Secretive 4.0.0 broke on CTK keys: it handed a DER
//! signature to a writer that expects raw r || s and split the DER in half. Here the only
//! accepted input is exactly 64 raw bytes; anything else is an error.

use anyhow::{Result, bail};

pub const KEY_TYPE: &str = "ecdsa-sha2-nistp256";
pub const CURVE: &str = "nistp256";

pub fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

pub fn put_string(buf: &mut Vec<u8>, data: &[u8]) {
    put_u32(buf, data.len() as u32);
    buf.extend_from_slice(data);
}

/// Encodes an unsigned big-endian integer as an SSH mpint: leading zero bytes stripped,
/// one 0x00 prepended when the top bit is set (mpints are two's complement), zero = empty.
pub fn put_mpint_unsigned(buf: &mut Vec<u8>, be: &[u8]) {
    let start = be.iter().position(|&b| b != 0).unwrap_or(be.len());
    let trimmed = &be[start..];
    if trimmed.first().is_some_and(|&b| b & 0x80 != 0) {
        put_u32(buf, trimmed.len() as u32 + 1);
        buf.push(0);
    } else {
        put_u32(buf, trimmed.len() as u32);
    }
    buf.extend_from_slice(trimmed);
}

/// Public key blob: string "ecdsa-sha2-nistp256", string "nistp256", string Q (65-byte SEC1 point).
pub fn public_key_blob(sec1_point: &[u8]) -> Result<Vec<u8>> {
    if sec1_point.len() != 65 || sec1_point[0] != 0x04 {
        bail!(
            "expected 65-byte uncompressed P-256 point, got {} bytes",
            sec1_point.len()
        );
    }
    let mut b = Vec::with_capacity(104);
    put_string(&mut b, KEY_TYPE.as_bytes());
    put_string(&mut b, CURVE.as_bytes());
    put_string(&mut b, sec1_point);
    Ok(b)
}

/// Signature blob for SSH_AGENT_SIGN_RESPONSE: string "ecdsa-sha2-nistp256", string (mpint r, mpint s).
/// `raw` must be CryptoKit's `rawRepresentation`: exactly 32-byte r followed by 32-byte s.
pub fn signature_blob(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() != 64 {
        bail!(
            "expected 64-byte raw r||s signature, got {} bytes (DER is not accepted)",
            raw.len()
        );
    }
    let mut inner = Vec::with_capacity(72);
    put_mpint_unsigned(&mut inner, &raw[..32]);
    put_mpint_unsigned(&mut inner, &raw[32..]);
    let mut b = Vec::with_capacity(inner.len() + 27);
    put_string(&mut b, KEY_TYPE.as_bytes());
    put_string(&mut b, &inner);
    Ok(b)
}

/// Cursor over an agent request body.
pub struct Reader<'a>(pub &'a [u8]);

impl<'a> Reader<'a> {
    pub fn u8(&mut self) -> Result<u8> {
        let Some((&b, rest)) = self.0.split_first() else {
            bail!("truncated message")
        };
        self.0 = rest;
        Ok(b)
    }

    pub fn u32(&mut self) -> Result<u32> {
        if self.0.len() < 4 {
            bail!("truncated message");
        }
        let (n, rest) = self.0.split_at(4);
        self.0 = rest;
        Ok(u32::from_be_bytes(n.try_into().unwrap()))
    }

    pub fn string(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        if self.0.len() < n {
            bail!("truncated string");
        }
        let (s, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{Signature as P256Sig, SigningKey, signature::Signer};
    use ssh_key::{PublicKey, Signature, public::KeyData};

    fn mpint(be: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        put_mpint_unsigned(&mut b, be);
        b
    }

    #[test]
    fn mpint_canonical_forms() {
        assert_eq!(mpint(&[0, 0]), vec![0, 0, 0, 0]);
        assert_eq!(mpint(&[0x7f]), vec![0, 0, 0, 1, 0x7f]);
        assert_eq!(mpint(&[0x80]), vec![0, 0, 0, 2, 0x00, 0x80]);
        assert_eq!(mpint(&[0, 0, 0x01, 0x02]), vec![0, 0, 0, 2, 0x01, 0x02]);
        assert_eq!(mpint(&[0, 0xff]), vec![0, 0, 0, 2, 0x00, 0xff]);
        // RFC 4251 §5 examples
        assert_eq!(
            mpint(&[0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]),
            vec![0, 0, 0, 8, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]
        );
    }

    #[test]
    fn rejects_der_and_wrong_lengths() {
        // A DER ECDSA signature starts 0x30 and is 70-72 bytes: must never be split as r||s.
        let der = [0x30u8; 71];
        assert!(signature_blob(&der).is_err());
        assert!(signature_blob(&[1u8; 63]).is_err());
        assert!(signature_blob(&[1u8; 65]).is_err());
        assert!(public_key_blob(&[4u8; 64]).is_err());
        assert!(public_key_blob(&[2u8; 65]).is_err());
    }

    /// Software P-256 key standing in for the Secure Enclave: raw r||s -> our blob ->
    /// verified by an independent implementation (ssh-key crate). Loops until r/s with a
    /// high top bit and with a leading zero byte have both been exercised.
    #[test]
    fn signature_blob_verifies_with_ssh_key() {
        let mut saw_high_bit = false;
        let mut saw_short = false;
        for i in 0..20_000u32 {
            if i >= 50 && saw_high_bit && saw_short {
                break;
            }
            let sk = SigningKey::random(&mut rand_core::OsRng);
            let point = sk.verifying_key().to_encoded_point(false);
            let blob = public_key_blob(point.as_bytes()).unwrap();
            let pk = PublicKey::from_bytes(&blob).unwrap();
            assert!(matches!(pk.key_data(), KeyData::Ecdsa(_)));

            let msg = format!("se-agent test message {i}");
            let sig: P256Sig = sk.sign(msg.as_bytes());
            let raw = sig.to_bytes();
            saw_high_bit |= raw[0] & 0x80 != 0 || raw[32] & 0x80 != 0;
            saw_short |= raw[0] == 0 || raw[32] == 0;

            let sblob = signature_blob(&raw).unwrap();
            let mut r = Reader(&sblob);
            assert_eq!(r.string().unwrap(), KEY_TYPE.as_bytes());
            let inner = r.string().unwrap();
            assert!(r.0.is_empty());
            let ssh_sig = Signature::new(
                ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP256,
                },
                inner.to_vec(),
            )
            .unwrap();
            use signature::Verifier;
            pk.key_data()
                .verify(msg.as_bytes(), &ssh_sig)
                .expect("verify");
            // A tampered message must fail.
            assert!(pk.key_data().verify(b"other", &ssh_sig).is_err());
        }
        assert!(
            saw_high_bit && saw_short,
            "test vectors did not cover both mpint edge cases"
        );
    }
}
