cmake_minimum_required(VERSION 3.15)
project(hydra7)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Помощь CMake в поиске Homebrew на macOS
if(APPLE)
    list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew;/usr/local")
endif()

# --- Поиск OpenSSL ---
find_package(OpenSSL REQUIRED)

# --- Поиск Asio ---
# 1. Пробуем найти через конфиг (для vcpkg на Windows)
find_package(asio CONFIG QUIET)
if(NOT asio_FOUND)
    # 2. Если нет конфига, ищем просто заголовочные файлы (для Linux/macOS)
    find_path(ASIO_INCLUDE_DIR asio.hpp)
    if(ASIO_INCLUDE_DIR)
        add_library(asio::asio INTERFACE IMPORTED)
        set_target_properties(asio::asio PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${ASIO_INCLUDE_DIR}")
        set(asio_FOUND TRUE)
    else()
        message(FATAL_ERROR "Asio headers not found! Install libasio-dev (Ubuntu) or asio (macOS).")
    endif()
endif()

# --- Поиск nlohmann_json ---
find_package(nlohmann_json CONFIG QUIET)
if(NOT nlohmann_json_FOUND)
    find_path(JSON_INCLUDE_DIR nlohmann/json.hpp)
    if(JSON_INCLUDE_DIR)
        add_library(nlohmann_json::nlohmann_json INTERFACE IMPORTED)
        set_target_properties(nlohmann_json::nlohmann_json PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${JSON_INCLUDE_DIR}")
    else()
        message(FATAL_ERROR "nlohmann_json not found!")
    endif()
endif()

add_executable(hydra7 main.cpp)

target_link_libraries(hydra7 PRIVATE 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    asio::asio
    nlohmann_json::nlohmann_json
)

if(WIN32)
    target_link_libraries(hydra7 PRIVATE ws2_32 crypt32)
    set_target_properties(hydra7 PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
    target_link_libraries(hydra7 PRIVATE pthread dl)
endif()
