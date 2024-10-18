cmake_minimum_required(VERSION 3.15)
project(
  fstrace
  LANGUAGES C CXX
)
set(CMAKE_CXX_STANDARD 20)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
  message(STATUS "Building in debug mode")
  set(CMAKE_BUILD_TYPE Debug)
  add_compile_options(-Og)
else()
  message(STATUS "Building in release mode")
  set(CMAKE_BUILD_TYPE Release)
  add_compile_options(-Ofast)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

# Build fstrace
add_executable(fstrace src/fstrace.cc)
target_include_directories(fstrace PUBLIC "${PROJECT_BINARY_DIR}")
target_compile_features(fstrace PUBLIC cxx_std_20)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  message(STATUS "Setting DEBUG flag. FD4 will have debug log. and FD3 will have comments with syscall info.")
  target_compile_definitions(fstrace PRIVATE DEBUG)
endif()

set_target_properties(fstrace PROPERTIES
    ADDITIONAL_CLEAN_FILES "${PROJECT_SOURCE_DIR}/node/fstrace/${PROJECT_NAME}"
)
add_custom_command(
    TARGET fstrace POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:fstrace>
        ${PROJECT_SOURCE_DIR}/node/fstrace/${PROJECT_NAME}
)

# # Install
# install(TARGETS fstrace DESTINATION bin)

# # Tests
# include(CTest)

# add_executable(test_fstrace tests/test_fstrace.cc)
# add_test(NAME TestFsTrace COMMAND test_fstrace)
# target_include_directories(test_fstrace PUBLIC "${PROJECT_SOURCE_DIR}")

# # Build addon
# execute_process(
#     COMMAND node -p "require('path').resolve(process.execPath, '../../include/node')"
#     OUTPUT_VARIABLE NODE_INC
#     OUTPUT_STRIP_TRAILING_WHITESPACE
# )

# include_directories(${NODE_INC})
# add_library(addon SHARED src/fstrace_addon.cc)
# set_target_properties(addon PROPERTIES PREFIX "" SUFFIX ".${ARCH}.node")

# # Copy addon files to node package
# add_custom_command(
#     TARGET addon POST_BUILD
#     COMMAND ${CMAKE_COMMAND} -E copy
#         $<TARGET_FILE:addon>
#         ${PROJECT_SOURCE_DIR}/node/@fstrace/${ARCH}/${PROJECT_NAME}.${ARCH}.node
# )
# add_custom_command(
#     TARGET addon POST_BUILD
#     COMMAND ${CMAKE_COMMAND} -E copy
#         $<TARGET_FILE:fstrace>
#         ${PROJECT_SOURCE_DIR}/node/@fstrace/${ARCH}/${PROJECT_NAME}.${ARCH}
# )
