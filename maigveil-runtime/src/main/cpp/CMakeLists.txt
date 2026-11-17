cmake_minimum_required(VERSION 3.22.1)
project(maigveil LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(
    maigveil
    SHARED
    crypto_engine.cpp
    apk_sig_verifier.cpp
    anti_tamper.cpp
    vm_engine.cpp
    jni_bridge.cpp
)

target_compile_options(maigveil PRIVATE
    -std=c++20
    -fvisibility=hidden
    -fvisibility-inlines-hidden
    -ffunction-sections
    -fdata-sections
    -fno-rtti
    -Wall
    -Wextra
    -Wno-unused-parameter
)

target_link_options(maigveil PRIVATE
    -Wl,--gc-sections
    -Wl,--exclude-libs,ALL
    -Wl,-z,relro,-z,now
)

find_library(log-lib log)
find_library(android-lib android)

target_link_libraries(maigveil
    ${android-lib}
    ${log-lib}
    dl
)
