cmake_minimum_required(VERSION 3.18)

project(NovaOS C ASM)

# Use lld linker from Rust toolchain if available
add_link_options("-fuse-ld=lld")

# 1. 基础配置
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# 2. seL4 内核配置
set(KERNEL_PATH "${CMAKE_CURRENT_SOURCE_DIR}/kernel/seL4")

# 默认目标架构：x86_64
if (NOT DEFINED KernelSel4Arch)
    set(KernelSel4Arch "x86_64")
endif()

# 默认平台：PC99 (QEMU)
if (NOT DEFINED KernelPlatform)
    set(KernelPlatform "pc99")
endif()

# 显式设置 PLATFORM 变量，确保 seL4 能够识别
set(PLATFORM ${KernelPlatform} CACHE STRING "Platform")

# 引入 seL4 构建系统
add_subdirectory(${KERNEL_PATH} kernel)

# 3. Rust 构建集成
# 确保 Cargo 输出目录在 CMake 构建目录下
set(CARGO_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/cargo")
set(ENV{CARGO_TARGET_DIR} "${CARGO_TARGET_DIR}")

# [关键] 导出 seL4 构建产物目录给 Rust build.rs
# seL4 的构建系统将头文件生成在 ${CMAKE_CURRENT_BINARY_DIR}/kernel
set(SEL4_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/kernel")
set(ENV{SEL4_OUT_DIR} "${SEL4_OUT_DIR}")

# RootServer 路径
set(ROOTSERVER_SRC "${CMAKE_CURRENT_SOURCE_DIR}/services/rootserver")
set(ROOTSERVER_BIN "${CARGO_TARGET_DIR}/${KernelSel4Arch}-unknown-none/release/rootserver")

# 自定义命令构建 Rust RootServer
add_custom_command(
    OUTPUT ${ROOTSERVER_BIN}
    COMMAND ${CMAKE_COMMAND} -E env "SEL4_OUT_DIR=${SEL4_OUT_DIR}" "SEL4_KERNEL_DIR=${KERNEL_PATH}" "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}" cargo build --release --manifest-path ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml -p rootserver --target ${KernelSel4Arch}-unknown-none
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/kernel/libsel4/include/sel4/invocation.h
    COMMENT "Compiling NovaOS RootServer (Rust)..."
)

# Convert kernel.elf to 32-bit ELF for QEMU compatibility
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/kernel/kernel32.elf
    COMMAND "C:/Program Files/LLVM/bin/llvm-objcopy.exe" -I elf64-x86-64 -O elf32-i386 ${CMAKE_CURRENT_BINARY_DIR}/kernel/kernel.elf ${CMAKE_CURRENT_BINARY_DIR}/kernel/kernel32.elf
    DEPENDS kernel.elf
    COMMENT "Converting kernel.elf to 32-bit for QEMU..."
)

add_custom_target(nova_rootserver ALL DEPENDS ${ROOTSERVER_BIN} ${CMAKE_CURRENT_BINARY_DIR}/kernel/kernel32.elf)
add_dependencies(nova_rootserver sel4)
# Ensure kernel is built
if(TARGET kernel.elf)
    add_dependencies(nova_rootserver kernel.elf)
endif()

# 4. 生成可引导镜像
# 需要使用 seL4_tools 中的 elfloader
# 暂时仅打印信息，待工具链完善
message(STATUS "NovaOS Configuration:")
message(STATUS "  Arch: ${KernelSel4Arch}")
message(STATUS "  Platform: ${KernelPlatform}")
message(STATUS "  RootServer: ${ROOTSERVER_BIN}")
