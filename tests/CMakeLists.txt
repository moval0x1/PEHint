# Unit Testing Framework for PEHint

# Find Qt6 Test component
find_package(Qt6 6.10.2 REQUIRED COMPONENTS Test)

# Test executable
# Use CMAKE_CURRENT_SOURCE_DIR since this CMakeLists.txt is in tests/ subdirectory
add_executable(PEHintTests
    unit/pe_parser_test.cpp
    unit/pe_data_model_test.cpp
    unit/pe_utils_test.cpp
    unit/pe_dependency_analyzer_test.cpp
    unit/pe_string_extractor_test.cpp
    unit/test_main.cpp
)

# Link Qt6 Test library
target_link_libraries(PEHintTests PRIVATE
    Qt6::Core
    Qt6::Test
    Qt6::Concurrent
    Qt6::Widgets
)

# Include directories
target_include_directories(PEHintTests PRIVATE 
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}
)

# Link against PEHint source files (for testing internal functions)
target_sources(PEHintTests PRIVATE
    ${CMAKE_SOURCE_DIR}/src/pe_parser_new.cpp
    ${CMAKE_SOURCE_DIR}/src/pe_data_model.cpp
    ${CMAKE_SOURCE_DIR}/src/pe_data_directory_parser.cpp
    ${CMAKE_SOURCE_DIR}/src/pe_import_export_parser.cpp
    ${CMAKE_SOURCE_DIR}/src/pe_utils.cpp
    ${CMAKE_SOURCE_DIR}/src/language_manager.cpp
    ${CMAKE_SOURCE_DIR}/src/pe_error_handler.cpp
    ${CMAKE_SOURCE_DIR}/src/pe_dependency_analyzer.cpp
    ${CMAKE_SOURCE_DIR}/src/pe_string_extractor.cpp
)

# One POST_BUILD block: multiple TARGET POST_BUILD commands can overwrite each other on some generators.
if(WIN32)
    get_target_property(_pehint_qmake Qt6::qmake IMPORTED_LOCATION)
    if(_pehint_qmake)
        get_filename_component(_pehint_qt_bin "${_pehint_qmake}" DIRECTORY)
        set(_pehint_qt_root "${_pehint_qt_bin}/..")
        if(EXISTS "${CMAKE_SOURCE_DIR}/config")
            add_custom_command(TARGET PEHintTests POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:PEHintTests>/config"
                COMMAND ${CMAKE_COMMAND} -E copy_directory
                    "${CMAKE_SOURCE_DIR}/config"
                    "$<TARGET_FILE_DIR:PEHintTests>/config"
                COMMAND "${_pehint_qt_bin}/windeployqt.exe"
                    "$<TARGET_FILE:PEHintTests>"
                    --no-translations
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${_pehint_qt_bin}/Qt6Gui.dll"
                    "$<TARGET_FILE_DIR:PEHintTests>/"
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${_pehint_qt_bin}/Qt6Widgets.dll"
                    "$<TARGET_FILE_DIR:PEHintTests>/"
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${_pehint_qt_bin}/Qt6Concurrent.dll"
                    "$<TARGET_FILE_DIR:PEHintTests>/"
                COMMAND ${CMAKE_COMMAND} -E make_directory
                    "$<TARGET_FILE_DIR:PEHintTests>/platforms"
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${_pehint_qt_root}/plugins/platforms/qwindows.dll"
                    "$<TARGET_FILE_DIR:PEHintTests>/platforms/"
                COMMENT "Copy config + deploy Qt for PEHintTests (ctest)"
            )
        else()
            add_custom_command(TARGET PEHintTests POST_BUILD
                COMMAND "${_pehint_qt_bin}/windeployqt.exe"
                    "$<TARGET_FILE:PEHintTests>"
                    --no-translations
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${_pehint_qt_bin}/Qt6Gui.dll"
                    "$<TARGET_FILE_DIR:PEHintTests>/"
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${_pehint_qt_bin}/Qt6Widgets.dll"
                    "$<TARGET_FILE_DIR:PEHintTests>/"
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${_pehint_qt_bin}/Qt6Concurrent.dll"
                    "$<TARGET_FILE_DIR:PEHintTests>/"
                COMMAND ${CMAKE_COMMAND} -E make_directory
                    "$<TARGET_FILE_DIR:PEHintTests>/platforms"
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${_pehint_qt_root}/plugins/platforms/qwindows.dll"
                    "$<TARGET_FILE_DIR:PEHintTests>/platforms/"
                COMMENT "Deploy Qt for PEHintTests (ctest)"
            )
        endif()
    elseif(EXISTS "${CMAKE_SOURCE_DIR}/config")
        add_custom_command(TARGET PEHintTests POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:PEHintTests>/config"
            COMMAND ${CMAKE_COMMAND} -E copy_directory
                "${CMAKE_SOURCE_DIR}/config"
                "$<TARGET_FILE_DIR:PEHintTests>/config"
            COMMENT "Copy config for PEHintTests"
        )
    endif()
elseif(EXISTS "${CMAKE_SOURCE_DIR}/config")
    add_custom_command(TARGET PEHintTests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:PEHintTests>/config"
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_SOURCE_DIR}/config"
            "$<TARGET_FILE_DIR:PEHintTests>/config"
        COMMENT "Copy config for PEHintTests"
    )
endif()

# Run from exe directory so config/ and deployed Qt DLLs match runtime layout
add_test(
    NAME PEHintUnitTests
    COMMAND ${CMAKE_COMMAND} -E chdir "$<TARGET_FILE_DIR:PEHintTests>" "$<TARGET_FILE:PEHintTests>"
)
