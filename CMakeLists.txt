cmake_minimum_required(VERSION 3.18)

project(NovaOS C ASM)

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

# 引入 seL4 构建系统
add_subdirectory(${KERNEL_PATH} kernel)

# 3. Rust 构建集成
# 确保 Cargo 输出目录在 CMake 构建目录下
set(CARGO_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/cargo")
set(ENV{CARGO_TARGET_DIR} "${CARGO_TARGET_DIR}")

# RootServer 路径
set(ROOTSERVER_SRC "${CMAKE_CURRENT_SOURCE_DIR}/services/rootserver")
set(ROOTSERVER_BIN "${CARGO_TARGET_DIR}/${KernelSel4Arch}-unknown-none/release/rootserver")

# 自定义命令构建 Rust RootServer
add_custom_command(
    OUTPUT ${ROOTSERVER_BIN}
    COMMAND cargo build --release --manifest-path ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml -p rootserver --target ${KernelSel4Arch}-unknown-none
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Compiling NovaOS RootServer (Rust)..."
)

add_custom_target(nova_rootserver ALL DEPENDS ${ROOTSERVER_BIN})

# 4. 生成可引导镜像
# 需要使用 seL4_tools 中的 elfloader
# 暂时仅打印信息，待工具链完善
message(STATUS "NovaOS Configuration:")
message(STATUS "  Arch: ${KernelSel4Arch}")
message(STATUS "  Platform: ${KernelPlatform}")
message(STATUS "  RootServer: ${ROOTSERVER_BIN}")
