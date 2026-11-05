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
