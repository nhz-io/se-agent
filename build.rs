// Compiles swift/SEShim.swift into a static library with swiftc (Command Line Tools are enough)
// and links it, plus the Swift runtime and Apple frameworks it needs.
use std::{env, path::PathBuf, process::Command};

fn main() {
    let src = "swift/SEShim.swift";
    println!("cargo:rerun-if-changed={src}");

    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "aarch64" => "arm64",
        other => panic!("unsupported arch {other}: se-agent needs Apple Silicon"),
    };
    let lib = out.join("libseshim.a");
    let status = Command::new("swiftc")
        .args(["-O", "-whole-module-optimization", "-parse-as-library"])
        .args(["-emit-library", "-static", "-module-name", "SEShim"])
        .args(["-target", &format!("{arch}-apple-macos14")])
        .arg("-o")
        .arg(&lib)
        .arg(src)
        .status()
        .expect("run swiftc (install Command Line Tools: xcode-select --install)");
    assert!(status.success(), "swiftc failed");

    let sdk = Command::new("xcrun")
        .args(["--show-sdk-path"])
        .output()
        .expect("xcrun");
    let sdk = String::from_utf8(sdk.stdout).unwrap();
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=seshim");
    // Swift runtime ships in the OS (/usr/lib/swift); the SDK has the .tbd stubs to link against.
    println!(
        "cargo:rustc-link-search=native={}/usr/lib/swift",
        sdk.trim()
    );
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
    for fw in ["Foundation", "CryptoKit", "Security", "LocalAuthentication"] {
        println!("cargo:rustc-link-lib=framework={fw}");
    }
}
