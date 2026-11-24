// C ABI shim between Rust and Apple frameworks (CryptoKit, Security, LocalAuthentication).
//
// Conventions:
// - Every function returns 0 on success, non-zero on error.
// - On error, *err_out is a malloc'd UTF-8 C string; the caller frees it with free().
// - Every output buffer is malloc'd; the caller frees it with free().
// - Private material never crosses this boundary: the key blob is the Secure Enclave-wrapped
//   `dataRepresentation`, which only this Mac's Secure Enclave can use.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

private func out(_ data: Data, _ ptr: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>, _ len: UnsafeMutablePointer<Int>) {
    let buf = malloc(max(data.count, 1))!.assumingMemoryBound(to: UInt8.self)
    data.copyBytes(to: buf, count: data.count)
    ptr.pointee = buf
    len.pointee = data.count
}

private func fail(_ message: String, _ err: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> Int32 {
    err.pointee = strdup(message)
    return -1
}

private func outString(_ s: String, _ ptr: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) {
    ptr.pointee = strdup(s)
}

@_cdecl("se_is_available")
public func se_is_available() -> Int32 {
    SecureEnclave.isAvailable ? 1 : 0
}

/// Creates a P-256 signing key inside the Secure Enclave.
/// Access control: `.privateKeyUsage` + `.userPresence` = Touch ID when available,
/// otherwise the Mac login password (e.g. lid closed). Not `.biometryAny`, which has no
/// password fallback.
@_cdecl("se_create")
public func se_create(
    blob_out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>, blob_len: UnsafeMutablePointer<Int>,
    pub_out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>, pub_len: UnsafeMutablePointer<Int>,
    err_out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    var cfErr: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .userPresence],
        &cfErr
    ) else {
        let msg = cfErr.map { CFErrorCopyDescription($0.takeRetainedValue()) as String } ?? "SecAccessControlCreateWithFlags failed"
        return fail(msg, err_out)
    }
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        out(key.dataRepresentation, blob_out, blob_len)
        out(key.publicKey.x963Representation, pub_out, pub_len)
        return 0
    } catch {
        return fail("\(error)", err_out)
    }
}

/// Recovers the uncompressed public point (65 bytes, 0x04 || X || Y) from a key blob. No prompt.
@_cdecl("se_public_key")
public func se_public_key(
    blob: UnsafePointer<UInt8>, blob_len: Int,
    pub_out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>, pub_len: UnsafeMutablePointer<Int>,
    err_out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: Data(bytes: blob, count: blob_len))
        out(key.publicKey.x963Representation, pub_out, pub_len)
        return 0
    } catch {
        return fail("\(error)", err_out)
    }
}

/// Creates an authentication context for `se_sign` and returns an owned (+1) handle.
/// `reason` is shown in the Touch ID / password dialog. Once a signature with this context has
/// been approved, further signatures with the same context do not prompt again, for as long as
/// the context lives: the reuse window is enforced by the caller, which frees the handle.
@_cdecl("se_context_new")
public func se_context_new(reason: UnsafePointer<CChar>) -> UnsafeMutableRawPointer {
    let context = LAContext()
    context.localizedReason = String(cString: reason)
    context.localizedCancelTitle = "Deny"
    return Unmanaged.passRetained(context).toOpaque()
}

/// Invalidates and releases a handle from `se_context_new`. Measured on macOS 27: `invalidate()`
/// alone does not stop an approved context from signing again, so releasing it is what counts.
@_cdecl("se_context_free")
public func se_context_free(ctx: UnsafeMutableRawPointer) {
    let context = Unmanaged<LAContext>.fromOpaque(ctx).takeRetainedValue()
    context.invalidate()
}

/// Signs `data` (the full message; CryptoKit hashes it with SHA-256, which is what
/// ecdsa-sha2-nistp256 requires, so the caller must NOT pre-hash).
/// Output is the 64-byte raw r || s (`rawRepresentation`), never DER.
/// `ctx` comes from `se_context_new`; it prompts unless it was already approved.
@_cdecl("se_sign")
public func se_sign(
    blob: UnsafePointer<UInt8>, blob_len: Int,
    data: UnsafePointer<UInt8>, data_len: Int,
    ctx: UnsafeMutableRawPointer,
    sig_out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>, sig_len: UnsafeMutablePointer<Int>,
    err_out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    do {
        let context = Unmanaged<LAContext>.fromOpaque(ctx).takeUnretainedValue()
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: Data(bytes: blob, count: blob_len),
            authenticationContext: context
        )
        let raw = try key.signature(for: Data(bytes: data, count: data_len)).rawRepresentation
        guard raw.count == 64 else {
            return fail("unexpected raw signature length \(raw.count), want 64", err_out)
        }
        out(raw, sig_out, sig_len)
        return 0
    } catch {
        return fail("\(error)", err_out)
    }
}

/// Resolves the code-signing identity of a socket peer from its audit token
/// (LOCAL_PEERTOKEN), which unlike a PID cannot be reused by another process.
/// flags_out bits: 1 = signature valid, 2 = satisfies "anchor apple" (Apple OS binary).
@_cdecl("se_peer_identity")
public func se_peer_identity(
    token: UnsafePointer<UInt8>, token_len: Int,
    path_out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>,
    signing_id_out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>,
    flags_out: UnsafeMutablePointer<UInt32>,
    err_out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    flags_out.pointee = 0
    let tokenData = Data(bytes: token, count: token_len) as CFData
    let attrs = [kSecGuestAttributeAudit: tokenData] as CFDictionary
    var code: SecCode?
    let st = SecCodeCopyGuestWithAttributes(nil, attrs, [], &code)
    guard st == errSecSuccess, let code else {
        return fail("SecCodeCopyGuestWithAttributes: OSStatus \(st)", err_out)
    }
    var flags: UInt32 = 0
    if SecCodeCheckValidity(code, [], nil) == errSecSuccess { flags |= 1 }
    var req: SecRequirement?
    if SecRequirementCreateWithString("anchor apple" as CFString, [], &req) == errSecSuccess, let req,
       SecCodeCheckValidity(code, [], req) == errSecSuccess {
        flags |= 2
    }
    var path = ""
    var signingID = ""
    var staticCode: SecStaticCode?
    if SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode {
        var info: CFDictionary?
        if SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
           let dict = info as? [String: Any] {
            signingID = dict[kSecCodeInfoIdentifier as String] as? String ?? ""
            path = (dict[kSecCodeInfoMainExecutable as String] as? URL)?.path ?? ""
        }
    }
    flags_out.pointee = flags
    outString(path, path_out)
    outString(signingID, signing_id_out)
    return 0
}

// --- age (age-plugin-se identities) ----------------------------------------------------------
//
// Mirrors age-plugin-se v0.2.1 (github.com/remko/age-plugin-se, Sources/Plugin.swift, HPKE.swift)
// byte for byte, with the same CryptoKit calls: stanza types `piv-p256` (age1se1 recipients) and
// `p256tag` (age1tag1). The identity's key blob is a SecureEnclave.P256.KeyAgreement key
// `dataRepresentation`; the ECDH runs in the Secure Enclave with the caller's LAContext.

private let ageKindPIV: Int32 = 0
private let ageKindTag: Int32 = 1

/// Compressed (33-byte) public key of an age-plugin-se identity key blob. No prompt.
@_cdecl("se_age_public")
public func se_age_public(
    blob: UnsafePointer<UInt8>, blob_len: Int,
    pub_out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>, pub_len: UnsafeMutablePointer<Int>,
    err_out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: Data(bytes: blob, count: blob_len))
        out(key.publicKey.compressedRepresentation, pub_out, pub_len)
        return 0
    } catch {
        return fail("\(error)", err_out)
    }
}

/// Recipient.sha256Tag: SHA-256(compressed public key)[0..4].
private func ageSHA256Tag(_ pub: Data) -> Data {
    Data(SHA256.hash(data: pub).prefix(4))
}

/// Recipient.p256HKDFTag: HKDF-Extract(salt "age-encryption.org/p256tag", enc || sha256Tag)[0..4].
private func ageP256Tag(_ pub: Data, _ enc: Data) -> Data {
    Data(
        HKDF<SHA256>.extract(
            inputKeyMaterial: SymmetricKey(data: enc + ageSHA256Tag(pub)),
            salt: Data("age-encryption.org/p256tag".utf8))
    ).prefix(4)
}

/// The 4-byte stanza tag this identity (compressed public key `pub`) answers to. No prompt.
@_cdecl("se_age_tag")
public func se_age_tag(
    pub: UnsafePointer<UInt8>, pub_len: Int, kind: Int32,
    share: UnsafePointer<UInt8>, share_len: Int,
    tag_out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>, tag_len: UnsafeMutablePointer<Int>,
    err_out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    let pub = Data(bytes: pub, count: pub_len)
    switch kind {
    case ageKindPIV: out(ageSHA256Tag(pub), tag_out, tag_len)
    case ageKindTag: out(ageP256Tag(pub, Data(bytes: share, count: share_len)), tag_out, tag_len)
    default: return fail("unknown stanza kind \(kind)", err_out)
    }
    return 0
}

// HPKE (RFC 9180) pieces used by age-plugin-se for p256tag: DHKEM(P-256), HKDF-SHA256, ChaCha20Poly1305.
private func hpkeSuiteID(kem: UInt16) -> Data {
    Data("HPKE".utf8) + Data([UInt8(kem >> 8), UInt8(kem & 0xff), 0x00, 0x01, 0x00, 0x03])
}

private func hpkeLabeledExtract(_ suiteID: Data, salt: Data?, label: String, ikm: Data) -> Data {
    let labeledIKM = Data("HPKE-v1".utf8) + suiteID + Data(label.utf8) + ikm
    return Data(HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: labeledIKM), salt: salt ?? Data()))
}

private func hpkeLabeledExpand(_ suiteID: Data, prk: Data, label: String, info: Data, length: Int) -> SymmetricKey {
    let labeledInfo = Data([UInt8((length >> 8) & 0xff), UInt8(length & 0xff)])
        + Data("HPKE-v1".utf8) + suiteID + Data(label.utf8) + info
    return HKDF<SHA256>.expand(pseudoRandomKey: SymmetricKey(data: prk), info: labeledInfo, outputByteCount: length)
}

private func symmetricData(_ k: SymmetricKey) -> Data { k.withUnsafeBytes { Data($0) } }

/// Unwraps one recipient stanza: `share` is the ephemeral public key (33 bytes compressed for
/// piv-p256, 65 bytes uncompressed for p256tag), `body` the 32-byte sealed file key. Prompts
/// unless `ctx` (from se_context_new) was already approved. Returns the 16-byte file key.
@_cdecl("se_age_unwrap")
public func se_age_unwrap(
    blob: UnsafePointer<UInt8>, blob_len: Int, kind: Int32,
    share: UnsafePointer<UInt8>, share_len: Int,
    body: UnsafePointer<UInt8>, body_len: Int,
    ctx: UnsafeMutableRawPointer,
    key_out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>, key_len: UnsafeMutablePointer<Int>,
    err_out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    do {
        let context = Unmanaged<LAContext>.fromOpaque(ctx).takeUnretainedValue()
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: Data(bytes: blob, count: blob_len),
            authenticationContext: context
        )
        let shareData = Data(bytes: share, count: share_len)
        let wrapKey: SymmetricKey
        let nonce: ChaChaPoly.Nonce
        switch kind {
        case ageKindPIV:
            let shareKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: shareData)
            let shared = try key.sharedSecretFromKeyAgreement(with: shareKey)
            wrapKey = shared.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: shareData + key.publicKey.compressedRepresentation,
                sharedInfo: Data("piv-p256".utf8),
                outputByteCount: 32
            )
            nonce = try ChaChaPoly.Nonce(data: Data(count: 12))
        case ageKindTag:
            // HPKE.dhkemDecap
            let shareKey = try P256.KeyAgreement.PublicKey(x963Representation: shareData)
            let dh = try key.sharedSecretFromKeyAgreement(with: shareKey).withUnsafeBytes { Data($0) }
            let kemSuite = Data("KEM".utf8) + Data([0x00, 0x10])
            let eaePRK = hpkeLabeledExtract(kemSuite, salt: nil, label: "eae_prk", ikm: dh)
            let sharedSecret = hpkeLabeledExpand(
                kemSuite, prk: eaePRK, label: "shared_secret",
                info: shareData + key.publicKey.x963Representation, length: 32)
            // HPKE.context(kem: .dhkemP256, info: "age-encryption.org/p256tag")
            let suite = hpkeSuiteID(kem: 0x0010)
            let pskIDHash = hpkeLabeledExtract(suite, salt: nil, label: "psk_id_hash", ikm: Data())
            let infoHash = hpkeLabeledExtract(
                suite, salt: nil, label: "info_hash", ikm: Data("age-encryption.org/p256tag".utf8))
            let ksContext = Data([0x00]) + pskIDHash + infoHash
            let secret = hpkeLabeledExtract(suite, salt: symmetricData(sharedSecret), label: "secret", ikm: Data())
            wrapKey = hpkeLabeledExpand(suite, prk: secret, label: "key", info: ksContext, length: 32)
            nonce = try ChaChaPoly.Nonce(
                data: symmetricData(hpkeLabeledExpand(suite, prk: secret, label: "base_nonce", info: ksContext, length: 12)))
        default:
            return fail("unknown stanza kind \(kind)", err_out)
        }
        let fileKey = try ChaChaPoly.open(
            ChaChaPoly.SealedBox(combined: Data(nonce) + Data(bytes: body, count: body_len)),
            using: wrapKey)
        out(fileKey, key_out, key_len)
        return 0
    } catch {
        return fail("\(error)", err_out)
    }
}
