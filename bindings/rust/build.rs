extern crate bindgen;

use bindgen::CargoCallbacks;
use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

fn release_build_options(c: &mut Command) -> &mut Command {
    c.arg("-d:danger")
        .arg("--opt:size")
        .arg("--panics:on")
        .arg("-d:noSignalHandler")
        .arg("--verbosity:0")
        .arg("--hints:off")
        .arg("--warnings:off")
        .arg("--passC:-fno-semantic-interposition")
        .arg("--passC:-falign-functions=64")
        .arg("-d:useMalloc")
}

fn nim_compile<'a>(target_os: &'a str, _target_arch: &'a str) -> Command {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let mut output = Command::new("nim");
    output
        .arg("c")
        .arg("--nomain")
        .arg("--app:staticLib")
        // .arg("--noLinking") // we'll see about that...
        // .arg("--genScript:on") // we'll see about that...
        .arg("-d:release") // added that myself
        .arg("--nimMainPrefix:ctt_eth_bls_init_") // make this paramterized
        .arg("--nimcache:nimcache/constantine_ethereum_bls_signatures"); // i think this is right...

    if target_os.ne("none") {
        let lib_path = out_path.join("libconstantine_ethereum_bls_signatures.a");
        if target_os.eq("linux") {
            output.arg(format!(
                "--out:{}",
                lib_path.to_str().expect("lib_path err")
            ));
        } else {
            let _ = writeln!(
                io::stderr(),
                "\nerror occurred: target_os: {} currently not supported\n",
                target_os
            );
            std::process::exit(1);
        }
    } else {
        let lib_path = out_path.join("libconstantine_ethereum_bls_signatures.a");
        output
            .arg("--os:any") // assumes any os, but also works for bare metal, i believe
            .arg("-d:posix") // needed this to build for --os:any
            .arg("--cpu:mips") // TODO: Make this generic for other cpus
            .arg(format!(
                "--out:{}",
                lib_path.to_str().expect("lib_path err")
            ))
            .arg("-d:CttASM=false") // TODO: apparently this isnt needed, but will leave her efor now
            .arg("-d:Constantine32") // TODO: also not needed, but will leave in
            .arg("-d:useMalloc")
            .arg("--passC:-I /usr/mips-linux-gnu/include")
            .arg("--passC:--verbose")
            .arg("--threads=off")
            .arg("--mm:none")
            .arg("--gc:none")
            .arg("--passC:--target=mips-none-gnu")
            .arg("--cc:clang"); // apparently this is faster, but need to investigate if we can have gcc for rust and clang for nim
    }
    release_build_options(&mut output).arg("../../constantine/ethereum_bls_signatures.nim");
    output
}
fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    // This is the directory where the library is located.
    let libdir_path = PathBuf::from("../../lib/")
        // Canonicalize the path as `rustc-link-search` requires an absolute
        // path.
        .canonicalize()
        .expect("cannot canonicalize path");

    // This is the path to the `c` headers file.
    let headers_path = libdir_path.join("../include/constantine_ethereum_bls_signatures.h");
    let headers_path_str = headers_path.to_str().expect("Path is not a valid string");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    eprintln!("Target OS: {}, Target Arch: {}", target_os, target_arch);
    let mut compile_cmd: Command = nim_compile(&target_os, &target_arch);
    eprintln!("Executing Nim Compile: {:?}", compile_cmd);

    let output = compile_cmd
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .expect("Failed to execute Nim command");

    if !output.status.success() {
        let msg = String::from_utf8_lossy(output.stderr.as_slice());
        let _ = writeln!(io::stderr(), "\nerror occurred: {}\n", msg);
        std::process::exit(1);
    }

    // Tell cargo to look for shared libraries in the specified directory
    println!(
        "cargo:rustc-link-search=native={}",
        out_path.to_str().unwrap()
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
