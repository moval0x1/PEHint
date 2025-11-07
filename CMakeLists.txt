cmake_minimum_required(VERSION 3.16)

# Set C++ compiler before project() if not found
# This is especially important for Ninja generator
if(NOT DEFINED CMAKE_CXX_COMPILER)
    if(WIN32)
        # For Ninja generator with MSVC, we need to find the compiler
        # Try common Visual Studio installation paths
        set(MSVC_PATHS
            "C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC"
            "C:/Program Files/Microsoft Visual Studio/2022/Professional/VC/Tools/MSVC"
            "C:/Program Files/Microsoft Visual Studio/2022/Enterprise/VC/Tools/MSVC"
            "C:/Program Files (x86)/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC"
            "C:/Program Files (x86)/Microsoft Visual Studio/2022/Professional/VC/Tools/MSVC"
            "C:/Program Files (x86)/Microsoft Visual Studio/2022/Enterprise/VC/Tools/MSVC"
        )
        
        # Find the latest MSVC version
        file(GLOB MSVC_VERSIONS ${MSVC_PATHS}/*)
        list(SORT MSVC_VERSIONS)
        list(REVERSE MSVC_VERSIONS)
        
        foreach(MSVC_PATH ${MSVC_VERSIONS})
            set(CL_PATH "${MSVC_PATH}/bin/Hostx64/x64/cl.exe")
            if(EXISTS "${CL_PATH}")
                set(CMAKE_CXX_COMPILER "${CL_PATH}")
                message(STATUS "Found MSVC compiler: ${CMAKE_CXX_COMPILER}")
                break()
            endif()
        endforeach()
        
        # If still not found, try environment variable
        if(NOT CMAKE_CXX_COMPILER)
            if(DEFINED ENV{VCINSTALLDIR})
                set(VCINSTALLDIR $ENV{VCINSTALLDIR})
                set(CL_PATH "${VCINSTALLDIR}/bin/Hostx64/x64/cl.exe")
                if(EXISTS "${CL_PATH}")
                    set(CMAKE_CXX_COMPILER "${CL_PATH}")
                    message(STATUS "Found MSVC compiler from VCINSTALLDIR: ${CMAKE_CXX_COMPILER}")
                endif()
            endif()
        endif()
    endif()
endif()

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

# Set output directories - handle both single-config and multi-config generators
if(CMAKE_GENERATOR MATCHES "Visual Studio")
    # For Visual Studio generator, use configuration-specific paths
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin/Debug)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin/Release)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/lib/Debug)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/lib/Release)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/lib/Debug)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/lib/Release)
else()
    # For single-config generators, use the standard paths
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
endif()

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
    else()
        # GCC/MinGW specific flags
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
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
    src/crash_handler.h
    src/crash_handler.cpp
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

# Link Windows-specific libraries
if(WIN32)
    target_link_libraries(PEHint PRIVATE dbghelp)
endif()

# Include directories
target_include_directories(PEHint PRIVATE src)

# Set properties for Visual Studio
set_target_properties(PEHint PROPERTIES
    WIN32_EXECUTABLE TRUE
    VS_DEBUGGER_ENVIRONMENT "PATH=${CMAKE_BINARY_DIR}/bin"
    VS_DEBUGGER_WORKING_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG}"
)

# Use Qt's built-in deployment tool for plugins
if(Qt6_VERSION VERSION_GREATER_EQUAL 6.2.0)
    qt_finalize_executable(PEHint)
endif()

# Copy config directory to output directory for debugging
# This ensures config files are available when running from Visual Studio
if(EXISTS "${CMAKE_SOURCE_DIR}/config")
    # Function to copy config directory
    function(copy_config_directory target output_dir)
        # Copy entire config directory
        add_custom_command(TARGET ${target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory "${output_dir}/config"
            COMMAND ${CMAKE_COMMAND} -E copy_directory 
                "${CMAKE_SOURCE_DIR}/config" 
                "${output_dir}/config"
            COMMENT "Copying config directory to ${output_dir}/config"
        )
    endfunction()
    
    # Copy config files for Debug and Release builds
    if(CMAKE_GENERATOR MATCHES "Visual Studio")
        # Multi-config generator (Visual Studio)
        copy_config_directory(PEHint "${CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG}")
        copy_config_directory(PEHint "${CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE}")
    else()
        # Single-config generator (Ninja, etc.)
        copy_config_directory(PEHint "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
    endif()
    
    message(STATUS "Config directory will be copied to output directory for debugging")
else()
    message(WARNING "Config directory not found at ${CMAKE_SOURCE_DIR}/config")
endif()

# Enable testing
enable_testing()

# Add tests subdirectory if it exists
if(EXISTS "${CMAKE_SOURCE_DIR}/tests/CMakeLists.txt")
    add_subdirectory(tests)
endif()