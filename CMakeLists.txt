cmake_minimum_required(VERSION 3.16)
project(dilithium_library C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(MSVC)
  add_compile_options(/W3)
else()
  add_compile_options(-Wall -Wextra)
endif()

set(DILITHIUM_SOURCES
  src/fips202.c
  src/symmetric.c
  src/randombytes.c
  src/verify.c
  src/utils.c
  src/reduce.c
  src/ntt.c
  src/rounding.c
  src/poly.c
  src/polyvec.c
  src/packing.c
  src/sign.c
)

add_library(dilithium STATIC ${DILITHIUM_SOURCES})
target_include_directories(dilithium PUBLIC
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
)

if(WIN32)
  target_link_libraries(dilithium PUBLIC bcrypt)
endif()

function(dilithium_add_test name source)
  add_executable(${name} ${source})
  target_link_libraries(${name} PRIVATE dilithium)
endfunction()

dilithium_add_test(test_keygen tests/test_keygen.c)
dilithium_add_test(test_sign tests/test_sign.c)
dilithium_add_test(test_verify tests/test_verify.c)
dilithium_add_test(benchmark tests/benchmark.c)

add_executable(basic_signature_example examples/basic_signature_example.c)
target_link_libraries(basic_signature_example PRIVATE dilithium)

add_executable(randomized_signature_example examples/randomized_signature_example.c)
target_link_libraries(randomized_signature_example PRIVATE dilithium)

add_executable(dilithium_sig examples/dilithium_sig.c)
target_link_libraries(dilithium_sig PRIVATE dilithium)


enable_testing()
add_test(NAME keygen COMMAND test_keygen)
add_test(NAME sign COMMAND test_sign)
add_test(NAME verify COMMAND test_verify)
