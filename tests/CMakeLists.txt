# Unit Testing Framework for PEHint

# Find Qt6 Test component
find_package(Qt6 6.8.0 REQUIRED COMPONENTS Test)

# Test executable
# Use CMAKE_CURRENT_SOURCE_DIR since this CMakeLists.txt is in tests/ subdirectory
add_executable(PEHintTests
    unit/pe_parser_test.cpp
    unit/pe_data_model_test.cpp
    unit/pe_security_analyzer_test.cpp
    unit/pe_utils_test.cpp
    unit/test_main.cpp
)

# Link Qt6 Test library
target_link_libraries(PEHintTests PRIVATE
    Qt6::Core
    Qt6::Test
    Qt6::Concurrent
)

# Include directories
target_include_directories(PEHintTests PRIVATE 
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}
)

# Link against PEHint source files (for testing internal functions)
# Note: In production, you might want to create a library target
target_sources(PEHintTests PRIVATE
    ${CMAKE_SOURCE_DIR}/src/pe_parser_new.cpp
    ${CMAKE_SOURCE_DIR}/src/pe_data_model.cpp
    ${CMAKE_SOURCE_DIR}/src/pe_security_analyzer.cpp
    ${CMAKE_SOURCE_DIR}/src/pe_utils.cpp
    ${CMAKE_SOURCE_DIR}/src/language_manager.cpp
    ${CMAKE_SOURCE_DIR}/src/security_config_manager.cpp
    ${CMAKE_SOURCE_DIR}/src/pe_error_handler.cpp
)

# Add test to CTest
add_test(NAME PEHintUnitTests COMMAND PEHintTests)

