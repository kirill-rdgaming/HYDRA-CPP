cmake_minimum_required(VERSION 3.15)
project(hydra7 VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Поиск OpenSSL
find_package(OpenSSL REQUIRED)

# Поиск Asio и nlohmann_json (предполагаем наличие в системе или через пакетный менеджер)
# Если библиотек нет в системе, GitHub Actions скачает их через менеджер пакетов

add_executable(hydra7 main.cpp)

target_include_directories(hydra7 PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(hydra7 PRIVATE OpenSSL::SSL OpenSSL::Crypto)

if(THREADS_PREFER_PTHREAD_FLAG)
    target_link_libraries(hydra7 PRIVATE Threads::Threads)
endif()

if(WIN32)
    target_link_libraries(hydra7 PRIVATE ws2_32 crypt32)
    # Статическая линковка Runtime для Windows (чтобы не требовал MSVCP140.dll)
    set_target_properties(hydra7 PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()