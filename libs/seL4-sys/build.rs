use std::env;
use std::path::PathBuf;

fn main() {
    let target = env::var("TARGET").unwrap();
    
    // 1. 获取从 CMake 传递过来的 seL4 内核构建目录
    // CMakeLists.txt 中需要通过 set(ENV{SEL4_OUT_DIR} ...) 传递此变量
    let sel4_out_dir = env::var("SEL4_OUT_DIR").expect("SEL4_OUT_DIR not set. Are you building via CMake?");
    let sel4_out_path = PathBuf::from(&sel4_out_dir);

    let sel4_kernel_dir = env::var("SEL4_KERNEL_DIR").expect("SEL4_KERNEL_DIR not set");
    let sel4_kernel_path = PathBuf::from(&sel4_kernel_dir);

    // 2. 确定头文件搜索路径
    // seL4 构建系统通常将生成的头文件放在以下位置：
    let include_dirs = vec![
        sel4_out_path.join("libsel4/include"),
        sel4_out_path.join("gen_config"),
        sel4_out_path.join("libsel4/autoconf"),
        sel4_out_path.join("libsel4/gen_config"),
        sel4_out_path.join("libsel4/arch_include/x86"), // TODO: 动态架构支持
        sel4_out_path.join("libsel4/sel4_arch_include/x86_64"), // Generated headers for x86_64
        sel4_out_path.join("libsel4/sel4_plat_include/pc99"), // TODO: 动态平台支持
        // Source paths
        sel4_kernel_path.join("libsel4/include"),
        sel4_kernel_path.join("libsel4/arch_include/x86"),
        sel4_kernel_path.join("libsel4/sel4_arch_include/x86_64"),
        sel4_kernel_path.join("libsel4/sel4_plat_include/pc99"),
        sel4_kernel_path.join("libsel4/mode_include/64"),
    ];

    // 3. 配置 bindgen
    let mut builder = bindgen::Builder::default()
        .header("src/wrapper.h") // 我们需要创建一个 wrapper.h 来包含 sel4.h
        .use_core()
        .ctypes_prefix("cty")
        .derive_default(true)
        .derive_debug(true)
        .rustified_enum("seL4_Error")
        // 显式指定目标架构，防止 bindgen 默认使用宿主机架构
        .clang_arg(format!("--target={}", target));

    // Fix for Windows host compiling for x86_64: force 64-bit enums
    if target.contains("x86_64") && cfg!(windows) {
        builder = builder.clang_arg("-D_WIN32");
    }

    for dir in include_dirs {
        builder = builder.clang_arg(format!("-I{}", dir.display()));
    }

    // 4. 生成绑定
    let bindings = builder.generate().expect("Unable to generate bindings");

    // 5. 写入输出文件
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/wrapper.h");
}
