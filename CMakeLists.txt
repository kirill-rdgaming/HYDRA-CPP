cmake_minimum_required(VERSION 3.15)
project(hydra7)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(asio CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

add_executable(hydra7 main.cpp)

target_link_libraries(hydra7 PRIVATE 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    asio::asio
    nlohmann_json::nlohmann_json
)

if(WIN32)
    target_link_libraries(hydra7 PRIVATE ws2_32 crypt32)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
    target_link_libraries(hydra7 PRIVATE pthread dl)
endif()
