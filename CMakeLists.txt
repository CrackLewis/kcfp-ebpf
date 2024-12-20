cmake_minimum_required(VERSION 3.11)

set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)

set(CMAKE_BUILD_TYPE Debug)

project(kcfp-ebpf VERSION 0.1.0)

aux_source_directory(src/common COMMON_SRC)
aux_source_directory(src/wcfi WCFI_SRC)
aux_source_directory(src/psd PSD_SRC)

add_executable(kcfp_ebpf src/main.cc ${COMMON_SRC} ${WCFI_SRC} ${PSD_SRC})

target_include_directories(kcfp_ebpf PRIVATE src)
target_include_directories(kcfp_ebpf PRIVATE /usr/include/bcc)

target_link_libraries(kcfp_ebpf PRIVATE bcc)

