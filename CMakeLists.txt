cmake_minimum_required(VERSION 3.10)
project(ncm-c C)

set(CMAKE_C_STANDARD 11)

# 可自定义输出二进制名
set(BINARY_NAME "ncm")

# 根据平台设置编译选项
if(WIN32)
    set(PLATFORM_SOURCES "backend/scanner_win.c")
    # Windows 原生系统库，无需安装任何包
    set(PLATFORM_LIBS iphlpapi psapi ws2_32)
else()
    set(PLATFORM_SOURCES "backend/scanner_lin.c")
    # Linux 零外部依赖，仅使用标准 C 库
    set(PLATFORM_LIBS m)
endif()

# 源文件
set(SOURCES
    main.c
    backend/scanner.h
    backend/kernel_probe.c
    backend/nl_listener.c
    lib/logic.c
    export_html.c
    ${PLATFORM_SOURCES}
)

add_executable(${BINARY_NAME} ${SOURCES})

# 包含目录
target_include_directories(${BINARY_NAME} PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/lib
    ${CMAKE_CURRENT_SOURCE_DIR}/backend
)

# 链接库
target_link_libraries(${BINARY_NAME} PRIVATE ${PLATFORM_LIBS})

# 编译优化：极致裁剪体积
if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    if(MSVC)
        target_compile_options(${BINARY_NAME} PRIVATE /Os /GL)
        target_link_options(${BINARY_NAME} PRIVATE /LTCG /OPT:REF /OPT:ICF)
    else()
        target_compile_options(${BINARY_NAME} PRIVATE -Os -fdata-sections -ffunction-sections)
        target_link_options(${BINARY_NAME} PRIVATE -Wl,--gc-sections -s)
        # 强制静态链接以达到零依赖（可选，某些系统 link glibc 有困难）
        # target_link_options(${BINARY_NAME} PRIVATE -static)
    endif()
endif()
