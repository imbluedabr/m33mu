# cmake/RustPlugin.cmake
#
# Provides mm_rust_plugins_build() — registers a single custom command that
# builds the wolfssl-simulators Cargo workspace and imports the resulting
# static libraries as CMake IMPORTED targets.
#
# Usage (in CMakeLists.txt):
#
#   include(cmake/RustPlugin.cmake)
#   mm_rust_plugins_build()
#   target_link_libraries(m33mu_lib PUBLIC
#       atecc608_sim se050_sim stsafe_a120_sim tropic01_sim)
#
# Each IMPORTED target exposes its .a file; the caller must still add the
# Rust runtime link flags (-lpthread -ldl -lm) to the final executable or
# library target.

set(_MM_RUST_WORKSPACE
    "${CMAKE_SOURCE_DIR}/third_party/wolfssl-simulators"
    CACHE INTERNAL "Rust simulator workspace directory")

set(_MM_RUST_TARGET_DIR
    "${_MM_RUST_WORKSPACE}/target/release"
    CACHE INTERNAL "Rust simulator cargo target/release directory")

set(_MM_ATECC608_LIB  "${_MM_RUST_TARGET_DIR}/libatecc608_sim.a")
set(_MM_SE050_LIB     "${_MM_RUST_TARGET_DIR}/libse050_sim.a")
set(_MM_STSAFE_LIB    "${_MM_RUST_TARGET_DIR}/libstsafe_a120_sim.a")
set(_MM_TROPIC01_LIB  "${_MM_RUST_TARGET_DIR}/libtropic01_sim.a")

# Collect all Rust source files so CMake knows when to re-run cargo.
file(GLOB_RECURSE _MM_RUST_SOURCES
    "${_MM_RUST_WORKSPACE}/atecc608-sim/src/*.rs"
    "${_MM_RUST_WORKSPACE}/se050-sim/src/*.rs"
    "${_MM_RUST_WORKSPACE}/stsafe-a120-sim/src/*.rs"
    "${_MM_RUST_WORKSPACE}/tropic01-sim/src/*.rs"
    "${_MM_RUST_WORKSPACE}/atecc608-sim/Cargo.toml"
    "${_MM_RUST_WORKSPACE}/se050-sim/Cargo.toml"
    "${_MM_RUST_WORKSPACE}/stsafe-a120-sim/Cargo.toml"
    "${_MM_RUST_WORKSPACE}/tropic01-sim/Cargo.toml"
    "${_MM_RUST_WORKSPACE}/Cargo.toml"
)

macro(mm_rust_plugins_build)
    # One custom command builds the entire workspace; all .a files are
    # outputs so CMake tracks them correctly.
    add_custom_command(
        OUTPUT
            "${_MM_ATECC608_LIB}"
            "${_MM_SE050_LIB}"
            "${_MM_STSAFE_LIB}"
            "${_MM_TROPIC01_LIB}"
        COMMAND
            "${CARGO_EXECUTABLE}" build --release
        WORKING_DIRECTORY "${_MM_RUST_WORKSPACE}"
        DEPENDS ${_MM_RUST_SOURCES}
        COMMENT "Building wolfSSL simulator Rust plugins (cargo build --release)"
        VERBATIM
    )

    add_custom_target(rust_plugins_build
        DEPENDS
            "${_MM_ATECC608_LIB}"
            "${_MM_SE050_LIB}"
            "${_MM_STSAFE_LIB}"
            "${_MM_TROPIC01_LIB}"
    )

    add_library(atecc608_sim STATIC IMPORTED GLOBAL)
    set_target_properties(atecc608_sim PROPERTIES
        IMPORTED_LOCATION "${_MM_ATECC608_LIB}"
    )
    add_dependencies(atecc608_sim rust_plugins_build)

    add_library(se050_sim STATIC IMPORTED GLOBAL)
    set_target_properties(se050_sim PROPERTIES
        IMPORTED_LOCATION "${_MM_SE050_LIB}"
    )
    add_dependencies(se050_sim rust_plugins_build)

    add_library(stsafe_a120_sim STATIC IMPORTED GLOBAL)
    set_target_properties(stsafe_a120_sim PROPERTIES
        IMPORTED_LOCATION "${_MM_STSAFE_LIB}"
    )
    add_dependencies(stsafe_a120_sim rust_plugins_build)

    add_library(tropic01_sim STATIC IMPORTED GLOBAL)
    set_target_properties(tropic01_sim PROPERTIES
        IMPORTED_LOCATION "${_MM_TROPIC01_LIB}"
    )
    add_dependencies(tropic01_sim rust_plugins_build)
endmacro()
