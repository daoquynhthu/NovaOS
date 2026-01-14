use std::env;
use std::path::PathBuf;

fn main() {
    let target = env::var("TARGET").unwrap();
    // 这里需要根据 CMake 构建过程中的 seL4 头文件路径进行动态配置
    // 目前仅为占位符
    println!("cargo:rerun-if-changed=build.rs");
}
