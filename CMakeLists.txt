cmake_minimum_required(VERSION 3.16)

project(PEHint VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

# Specify where to look for .ui files
set(CMAKE_AUTOUIC_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/ui)

# Add include directories for headers
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/headers)

# Add include directories for src
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

# Source files
set(SRC_FILES
    src/main.cpp
    src/mainwindow.cpp
    src/orderedmap.cpp
    src/PEFILE.cpp
    src/PE32FILE.cpp
    src/PE64FILE.cpp
)

# Header files
set(HEADER_FILES
    headers/mainwindow.h
    headers/winntdef.h
    headers/orderedmap.h
    headers/PEFILE_CUSTOM_STRUCTS.h
    headers/PE64FILE.h
    headers/PEFILE.h
    headers/PE32FILE.h
)

# UI files
set(UI_FILES
    ui/mainwindow.ui
    ui/resource.qrc
)

# Combine all sources
set(PROJECT_SOURCES
    ${SRC_FILES}
    ${HEADER_FILES}
    ${UI_FILES}
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(PEHint
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
    )

    target_link_libraries(PEHint PRIVATE Qt${QT_VERSION_MAJOR}::Widgets)

    include(GNUInstallDirs)
    install(TARGETS PEHint
        BUNDLE DESTINATION .
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )

    if(QT_VERSION_MAJOR EQUAL 6)
        qt_finalize_executable(PEHint)
    endif()
else()
    message(FATAL_ERROR "This project requires Qt version 6 or higher.")
endif()
