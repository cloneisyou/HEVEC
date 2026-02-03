cmake_minimum_required(VERSION 3.14)

project(
  HEVEC
  VERSION 1.0
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(BUILD_HEXL "Build HEXL from source" ON)
option(BUILD_PYTHON "Build Python bindings" OFF)
option(BUILD_TCP_BACKEND "Build legacy TCP client/server classes" OFF)

set(HEVEC_SOURCES
  src/Client.cpp
  src/HEVECClient.cpp
  src/HEVECServer.cpp
  src/HEval.cpp
  src/PIRServer.cpp
  src/Random.cpp
  src/Server.cpp
  src/SecretKey.cpp)

if(BUILD_TCP_BACKEND)
  list(APPEND HEVEC_SOURCES
    src/HEVECClientTCP.cpp
    src/HEVECServerTCP.cpp)
  set(HEVEC_ENABLE_TCP_DEF HEVEC_ENABLE_TCP)
endif()

add_library(HEVEC ${HEVEC_SOURCES})

if(HEVEC_ENABLE_TCP_DEF)
  target_compile_definitions(HEVEC PUBLIC ${HEVEC_ENABLE_TCP_DEF})
endif()

target_include_directories(
  HEVEC PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)

include(FetchContent)

# ---------- HEXL ----------
if(BUILD_HEXL)
  FetchContent_Declare(
    hexl
    GIT_REPOSITORY https://github.com/intel/hexl.git
    GIT_TAG v1.2.5)
  set(HEXL_BENCHMARK OFF)
  set(HEXL_TESTING OFF)
  FetchContent_MakeAvailable(hexl)
else()
  find_package(hexl REQUIRED)
endif()

# ---------- OpenSSL / OpenMP / Threads ----------
find_package(OpenSSL REQUIRED)
find_package(OpenMP)
find_package(Threads REQUIRED)

# ---------- Boost (Beast는 헤더 전용) ----------
find_package(Boost 1.75 REQUIRED)

if(Boost_FOUND)
  target_include_directories(HEVEC PUBLIC ${Boost_INCLUDE_DIRS})
endif()

# ---------- 링크 ----------
target_include_directories(HEVEC PUBLIC ${hexl_INCLUDE_DIRS})
target_link_libraries(HEVEC
  PUBLIC
    hexl
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

if(OpenMP_CXX_FOUND)
  target_link_libraries(HEVEC PUBLIC OpenMP::OpenMP_CXX)
else()
  target_compile_definitions(HEVEC PUBLIC HEVEC_DISABLE_OPENMP)
  message(STATUS "OpenMP not found. Building HEVEC without OpenMP support; performance may be reduced.")
endif()

# (선택) Windows에서 정적 링크 시 소켓 라이브러리 필요할 수 있음
if(WIN32)
  target_link_libraries(HEVEC PUBLIC ws2_32 mswsock)
endif()

# ---------- Python Binding ----------
if(BUILD_PYTHON)
  find_package(Python3 COMPONENTS Interpreter Development REQUIRED)
  FetchContent_Declare(
    pybind11
    GIT_REPOSITORY https://github.com/pybind/pybind11.git
    GIT_TAG v2.11.1)
  FetchContent_MakeAvailable(pybind11)

  pybind11_add_module(hevec_py python/bindings.cpp)
  target_link_libraries(hevec_py PRIVATE HEVEC)
  target_include_directories(hevec_py PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
  set_target_properties(hevec_py PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}"
    PREFIX "")
endif()

# ---------- Install ----------
include(GNUInstallDirs)
install(
  TARGETS HEVEC
  EXPORT HEVECTargets
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(
  EXPORT HEVECTargets
  FILE HEVECConfig.cmake
  NAMESPACE HEVEC::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/HEVEC)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/HEVECConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY AnyNewerVersion)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/HEVECConfigVersion.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/HEVEC)
