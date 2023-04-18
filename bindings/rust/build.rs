extern crate bindgen;

use bindgen::CargoCallbacks;
use std::env;
use std::path::PathBuf;

fn main() {
    // This is the directory where the library is located.
    let libdir_path = PathBuf::from("../../lib/")
        // Canonicalize the path as `rustc-link-search` requires an absolute
        // path.
        .canonicalize()
        .expect("cannot canonicalize path");

    // This is the path to the `c` headers file.
    let headers_path = libdir_path.join("../include/constantine_ethereum_bls_signatures.h");
    let headers_path_str = headers_path.to_str().expect("Path is not a valid string");

    // Tell cargo to look for shared libraries in the specified directory
    println!(
        "cargo:rustc-link-search=native={}",
        libdir_path.to_str().unwrap()
    );

    // Tell cargo to tell rustc to link our library. Cargo will
    // automatically know it must look for a `lib<blah>.a` file.
    println!(
        "cargo:rustc-link-lib=static:-bundle,+whole-archive=constantine_ethereum_bls_signatures"
    );
    println!(
        "cargo:rerun-if-changed={}/libconstantine_ethereum_bls_signatures.a",
        libdir_path.to_str().unwrap()
    );

    // Tell cargo to invalidate the built crate whenever the header changes.
    println!("cargo:rerun-if-changed={}", headers_path_str);

    println!("cargo:include={}", headers_path_str);

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header(headers_path_str)
        .clang_args([format!("-I{headers_path_str}")])
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(CargoCallbacks))
        .derive_debug(true)
        .derive_eq(true)
        .rustified_enum("ctt_eth_bls_status")
        .use_core()
        .merge_extern_blocks(true)
        .layout_tests(false)
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs");
    bindings
        .write_to_file(out_path)
        .expect("Couldn't write bindings!");
}
