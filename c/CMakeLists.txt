cmake_minimum_required(VERSION 3.20)
project(trakshya-systemd LANGUAGES C VERSION 1.0.0)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBMICROHTTPD REQUIRED libmicrohttpd)
pkg_check_modules(LIBCURL REQUIRED libcurl)
pkg_check_modules(OPENSSL REQUIRED openssl)

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${LIBMICROHTTPD_INCLUDE_DIRS}
    ${LIBCURL_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
)

link_directories(
    ${LIBMICROHTTPD_LIBRARY_DIRS}
    ${LIBCURL_LIBRARY_DIRS}
    ${OPENSSL_LIBRARY_DIRS}
)

set(SOURCES
    src/main.c
    src/hids/engine.c
    src/hids/parser.c
    src/fim/engine.c
    src/fim/hasher.c
    src/sca/engine.c
    src/sca/checks.c
    src/vuln/engine.c
    src/vuln/cve_db.c
    src/active_response/engine.c
    src/active_response/iptables.c
    src/active_response/process.c
    src/active_response/posture.c
    src/utils.c
)

add_executable(trakshya-systemd ${SOURCES})

target_link_libraries(trakshya-systemd
    ${LIBMICROHTTPD_LIBRARIES}
    ${LIBCURL_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    m
    pthread
)

install(TARGETS trakshya-systemd DESTINATION /usr/local/bin)

enable_testing()
add_subdirectory(tests)
