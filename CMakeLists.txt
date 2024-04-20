cmake_minimum_required(VERSION 3.10)
project(nostr-cxx-bot)
include(ExternalProject)
include(CheckLibraryExists)

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

set(CMAKE_CXX_FLAGS_RELEASE "-O3 -std=c++20 -Wextra ${CMAKE_C_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG "-g -std=c++20 -Wall -Wextra ${CMAKE_C_FLAGS}")

#--------------------------------------------------
# libsecp256k1
set(LIBSECP256K1_LIBRARIES ${CMAKE_CURRENT_SOURCE_DIR}/deps/bitcoin-core-libsecp256k1/build/src/libsecp256k1.a)
add_custom_target(libsecp256k1 DEPENDS ${LIBSECP256K1_LIBRARIES})
add_custom_command(
    OUTPUT ${LIBSECP256K1_LIBRARIES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/deps/bitcoin-core-libsecp256k1
    COMMAND sh
    ARGS -c 'cmake -B build -D CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -D BUILD_SHARED_LIBS=off && cmake --build build -t secp256k1'
)
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/deps/bitcoin-core-libsecp256k1/build/src)

#--------------------------------------------------
# libspdlog
if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    set(LIBSPDLOG_LIBRARIES ${CMAKE_CURRENT_SOURCE_DIR}/deps/gabime-spdlog/build/libspdlogd.a)
else()
    set(LIBSPDLOG_LIBRARIES ${CMAKE_CURRENT_SOURCE_DIR}/deps/gabime-spdlog/build/libspdlog.a)
endif()
add_custom_target(libspdlog DEPENDS ${LIBSPDLOG_LIBRARIES})
add_custom_command(
    OUTPUT ${LIBSPDLOG_LIBRARIES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/deps/gabime-spdlog
    COMMAND sh
    ARGS -c 'cmake -B build -D CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -D BUILD_SHARED_LIBS=off && cmake --build build -t spdlog'
)
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/deps/gabime-spdlog/build)

#--------------------------------------------------
# libbech32
set(LIBBECH32_LIBRARIES ${CMAKE_CURRENT_SOURCE_DIR}/deps/dcdpr-libbech32/build/libbech32/libbech32.a)
add_custom_target(libbech32 DEPENDS ${LIBBECH32_LIBRARIES})
add_custom_command(
    OUTPUT ${LIBBECH32_LIBRARIES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/deps/dcdpr-libbech32
    COMMAND sh
    ARGS -c 'cmake -B build -D CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -D BUILD_SHARED_LIBS=off && cmake --build build -t bech32'
)
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/deps/dcdpr-libbech32/build)

#--------------------------------------------------
# libcpprest
if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    set(LIBCPPREST_LIBRARIES ${CMAKE_CURRENT_SOURCE_DIR}/deps/microsoft-cpprestsdk/build/Debug/Binaries/libcpprest.a)
else()
    set(LIBCPPREST_LIBRARIES ${CMAKE_CURRENT_SOURCE_DIR}/deps/microsoft-cpprestsdk/build/Release/Binaries/libcpprest.a)
endif()
add_custom_target(libcpprest DEPENDS ${LIBCPPREST_LIBRARIES})
add_custom_command(
    OUTPUT ${LIBCPPREST_LIBRARIES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/deps/microsoft-cpprestsdk
    COMMAND sh
    ARGS -c 'cmake -B build -D CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -D CMAKE_CXX_FLAGS="-Wno-format-truncation" -D BUILD_SHARED_LIBS=off && cmake --build build -t cpprest'
)
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/deps/microsoft-cpprestsdk/build)

#--------------------------------------------------
# nostr-cxx-bot-core
set (t_ nostr-cxx-bot-core)

include_directories(
    ${t_}
    ${PROJECT_SOURCE_DIR}/deps/dcdpr-libbech32/include
    ${PROJECT_SOURCE_DIR}/deps/nlohmann-json/include
    ${PROJECT_SOURCE_DIR}/deps/bitcoin-core-libsecp256k1/include
    ${PROJECT_SOURCE_DIR}/deps/gabime-spdlog/include
    ${PROJECT_SOURCE_DIR}/deps/microsoft-cpprestsdk/include
    ${PROJECT_SOURCE_DIR}/deps/p-ranav-argparse/include
)
add_library (${t_} INTERFACE)
add_dependencies(${t_} libsecp256k1)
add_dependencies(${t_} libbech32)
add_dependencies(${t_} libspdlog)
add_dependencies(${t_} libcpprest)
target_link_libraries(${t_} INTERFACE crypto)
target_link_libraries(${t_} INTERFACE fmt)
target_link_libraries(${t_} INTERFACE ${LIBSECP256K1_LIBRARIES})
target_link_libraries(${t_} INTERFACE ${LIBBECH32_LIBRARIES})
target_link_libraries(${t_} INTERFACE ${LIBSPDLOG_LIBRARIES})
target_link_libraries(${t_} INTERFACE ${LIBCPPREST_LIBRARIES})
target_link_libraries(${t_} INTERFACE z)
target_link_libraries(${t_} INTERFACE ssl)

#--------------------------------------------------
# nostr-cxx-bot
set (t_ nostr-cxx-bot)
add_executable(${t_} main.cxx)
target_link_libraries(${t_} PRIVATE nostr-cxx-bot-core)

enable_testing()
add_test(test nostr-cxx-bot-test)
