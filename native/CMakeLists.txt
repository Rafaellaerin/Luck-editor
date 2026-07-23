cmake_minimum_required(VERSION 3.20)
project(luck_native VERSION 5.0.0 LANGUAGES C CXX)

option(LUCK_ENABLE_SANITIZERS "Enable address and undefined-behavior sanitizers" OFF)
option(LUCK_BUILD_TESTS "Build native tests" ON)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

function(luck_c_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes -Wformat=2 -Wundef -Werror)
  endif()
endfunction()

function(luck_cpp_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX /permissive-)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2 -Wundef -Werror)
  endif()
endfunction()

function(luck_sanitizers target)
  if(LUCK_ENABLE_SANITIZERS AND NOT MSVC)
    target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(${target} PRIVATE -fsanitize=address,undefined)
  endif()
endfunction()

add_library(luck_c STATIC
  c/src/buffer.c c/src/cookie.c c/src/hash.c c/src/parser.c c/src/redact.c
  c/src/serialize.c c/src/status.c c/src/string.c c/src/validate.c)
target_include_directories(luck_c PUBLIC c/include)
if(NOT MSVC)
  target_link_libraries(luck_c PUBLIC m)
endif()
luck_c_warnings(luck_c)
luck_sanitizers(luck_c)

add_library(luck_cpp STATIC
  cpp/src/archive.cpp cpp/src/diff.cpp cpp/src/domain_index.cpp cpp/src/policy.cpp
  cpp/src/query.cpp cpp/src/snapshot.cpp cpp/src/statistics.cpp cpp/src/store.cpp)
target_include_directories(luck_cpp PUBLIC cpp/include c/include)
target_link_libraries(luck_cpp PUBLIC luck_c)
luck_cpp_warnings(luck_cpp)
luck_sanitizers(luck_cpp)

add_executable(luck-native tools/luck_native.cpp)
target_link_libraries(luck-native PRIVATE luck_cpp)
luck_cpp_warnings(luck-native)
luck_sanitizers(luck-native)

if(LUCK_BUILD_TESTS)
  enable_testing()
  add_executable(luck_c_tests c/tests/test_main.c)
  target_link_libraries(luck_c_tests PRIVATE luck_c)
  luck_c_warnings(luck_c_tests)
  luck_sanitizers(luck_c_tests)
  add_test(NAME luck_c_tests COMMAND luck_c_tests)

  add_executable(luck_cpp_tests cpp/tests/test_main.cpp)
  target_link_libraries(luck_cpp_tests PRIVATE luck_cpp)
  luck_cpp_warnings(luck_cpp_tests)
  luck_sanitizers(luck_cpp_tests)
  add_test(NAME luck_cpp_tests COMMAND luck_cpp_tests)
endif()
