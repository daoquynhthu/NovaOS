use std::env;
use std::path::Path;

fn main() {
    let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let linker_script = Path::new(&dir).join("linker.lds");
    println!("cargo:rustc-link-arg=-T{}", linker_script.display());
    println!("cargo:rustc-link-arg=-no-pie");
    println!("cargo:rerun-if-changed=linker.lds");
}
