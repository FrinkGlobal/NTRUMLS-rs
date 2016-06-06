extern crate gcc;

fn main() {
    let mut build_script = gcc::Config::new();
        build_script.opt_level(2)
        .file("src/c/src/crypto_hash_sha512.c")
        .file("src/c/src/crypto_stream.c")
        .file("src/c/src/fastrandombytes.c")
        .file("src/c/src/shred.c")
        .file("src/c/src/convert.c")
        .file("src/c/src/pack.c")
        .file("src/c/src/pol.c")
        .file("src/c/src/params.c")
        .file("src/c/src/pqntrusign.c");
    if cfg!(target_os = "windows") {
        build_script.file("src/c/src/randombytes-vs.c")
    } else {
        build_script.file("src/c/src/randombytes.c")
    }
    .include("src/c/src")
    .compile("libntrumls.a");
}
