cmake_minimum_required(VERSION 3.16)

# Read version from version.h
file(READ "${CMAKE_SOURCE_DIR}/src/version.h" VERSION_HEADER)
string(REGEX MATCH "PEHINT_VERSION_MAJOR ([0-9]+)" _ "${VERSION_HEADER}")
set(PEHINT_VERSION_MAJOR ${CMAKE_MATCH_1})
string(REGEX MATCH "PEHINT_VERSION_MINOR ([0-9]+)" _ "${VERSION_HEADER}")
set(PEHINT_VERSION_MINOR ${CMAKE_MATCH_1})
string(REGEX MATCH "PEHINT_VERSION_PATCH ([0-9]+)" _ "${VERSION_HEADER}")
set(PEHINT_VERSION_PATCH ${CMAKE_MATCH_1})

project(PEHint VERSION ${PEHINT_VERSION_MAJOR}.${PEHINT_VERSION_MINOR}.${PEHINT_VERSION_PATCH} LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Enable Qt features
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

# Set Qt prefix path if not already set
if(NOT DEFINED CMAKE_PREFIX_PATH)
    if(DEFINED ENV{QTDIR})
        set(CMAKE_PREFIX_PATH $ENV{QTDIR})
        message(STATUS "Setting CMAKE_PREFIX_PATH to: $ENV{QTDIR}")
    else()
        message(WARNING "QTDIR environment variable not set. Qt6 may not be found.")
    endif()
endif()

# Find Qt6 with specific version requirement
find_package(Qt6 6.8.0 REQUIRED COMPONENTS Core Widgets Concurrent)

# Alternative approach if the above fails
if(NOT Qt6_FOUND)
    message(STATUS "Trying alternative Qt6 finding method...")
    find_package(Qt6 REQUIRED COMPONENTS Core)
    if(Qt6_FOUND)
        find_package(Qt6 REQUIRED COMPONENTS Widgets Concurrent)
    endif()
endif()

if(NOT Qt6_FOUND)
    message(FATAL_ERROR "Qt6 not found. Please ensure Qt 6.8.0 is installed and QTDIR is set correctly.")
endif()

# Set Qt6 specific options for Visual Studio
if(WIN32)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
    
    # Check if we're using MSVC or GCC/MinGW
    if(MSVC)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /bigobj")
        
        # Set build-specific flags for MSVC
        if(CMAKE_BUILD_TYPE STREQUAL "Release")
            set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /DNDEBUG")
            set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG")
        elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
            set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Zi /Od /RTC1")
        endif()
    else()
        # GCC/MinGW specific flags
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
        
        # Set build-specific flags for GCC
        if(CMAKE_BUILD_TYPE STREQUAL "Release")
            set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DNDEBUG")
        endif()
    endif()
endif()

# Source files
set(PROJECT_SOURCES
    src/main.cpp
    src/mainwindow.cpp
    src/mainwindow.h
    src/hexviewer.cpp
    src/hexviewer.h
    src/pe_structures.h
    src/pe_utils.cpp
    src/pe_utils.h
    src/pe_data_model.cpp
    src/pe_data_model.h
    src/pe_data_directory_parser.cpp
    src/pe_data_directory_parser.h
    src/pe_import_export_parser.cpp
    src/pe_import_export_parser.h
    src/pe_parser_new.cpp
    src/pe_parser_new.h
    src/pe_security_analyzer.cpp
    src/pe_security_analyzer.h
    src/pe_ui_presenter.h
    src/pe_ui_manager.cpp
    src/pe_ui_manager.h
    src/security_config_manager.cpp
    src/security_config_manager.h
    src/language_manager.h
    src/language_manager.cpp
    resources/resource.qrc
)

# Configure the resource file with version information
# Set the icon path relative to the build directory
set(ICON_PATH "${CMAKE_SOURCE_DIR}/resources/imgs/PEHint-ico.ico")

configure_file(
    "${CMAKE_SOURCE_DIR}/resources/app.rc"
    "${CMAKE_BINARY_DIR}/app.rc"
    @ONLY
)

# Add the configured resource file to sources
list(APPEND PROJECT_SOURCES "${CMAKE_BINARY_DIR}/app.rc")

# Create executable
add_executable(PEHint ${PROJECT_SOURCES})

# Link Qt6 libraries
target_link_libraries(PEHint PRIVATE
    Qt6::Core 
    Qt6::Widgets 
    Qt6::Concurrent
)

# Include directories
target_include_directories(PEHint PRIVATE src)

# Set properties for Visual Studio
set_target_properties(PEHint PROPERTIES
    WIN32_EXECUTABLE TRUE
    VS_DEBUGGER_ENVIRONMENT "PATH=${CMAKE_BINARY_DIR}/bin"
)

# Use Qt's built-in deployment tool for plugins
if(Qt6_VERSION VERSION_GREATER_EQUAL 6.2.0)
    qt_finalize_executable(PEHint)
endif()
