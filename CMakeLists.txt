cmake_minimum_required(VERSION 3.15)
project(
  fstrace
  LANGUAGES C CXX
)
set(CMAKE_CXX_STANDARD 17)
set(ARCH "linux-x64-glibc")
set(CMAKE_BUILD_TYPE Release)
# set_target_properties(fstrace_addon PROPERTIES
#     ADDITIONAL_CLEAN_FILES "node/@fstrace/${ARCH}/${PROJECT_NAME}.${ARCH}.node;node/@fstrace/${ARCH}/${PROJECT_NAME}.${ARCH}"
# )

# Build fstrace
add_executable(fstrace src/fstrace.cc)
target_include_directories(fstrace PUBLIC "${PROJECT_BINARY_DIR}")
target_compile_features(fstrace PUBLIC cxx_std_20)

# Install
install(TARGETS fstrace DESTINATION bin)

# Tests
include(CTest)

# add_executable(test_fstrace tests/test_fstrace.cc)
# add_test(NAME TestFsTrace COMMAND test_fstrace)

# Build addon
execute_process(
    COMMAND node -p "require('path').resolve(process.execPath, '../../include/node')"
    OUTPUT_VARIABLE NODE_INC
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
# echo NODE_INC for debugging
message(NODE_INC="${NODE_INC}")

include_directories(${NODE_INC})
add_library(addon SHARED src/fstrace_addon.cc)
set_target_properties(addon PROPERTIES PREFIX "" SUFFIX ".${ARCH}.node")

# Copy addon files to node package
add_custom_command(
    TARGET addon POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:addon>
        ${PROJECT_SOURCE_DIR}/node/@fstrace/${ARCH}/${PROJECT_NAME}.${ARCH}.node
)
add_custom_command(
    TARGET addon POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:fstrace>
        ${PROJECT_SOURCE_DIR}/node/@fstrace/${ARCH}/${PROJECT_NAME}.${ARCH}
)
