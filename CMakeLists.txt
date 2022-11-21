cmake_minimum_required(VERSION 3.5)

project("formatPE" 
    LANGUAGES "C" "CXX"
    DESCRIPTION "header-only library provides a convinient way to represent a PE-file as an enumerable object."
    HOMEPAGE_URL "https://github.com/HoShiMin/formatPE"
    )

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 17)

if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "4")
    set(PlatformDir "x86")
else()
    set(PlatformDir "x64")
endif()


# for formatPE::Pe header only
add_library("${PROJECT_NAME}_Pe" INTERFACE)
target_include_directories("${PROJECT_NAME}_Pe" INTERFACE
"${CMAKE_CURRENT_LIST_DIR}/formatPE/"
)
add_library("${PROJECT_NAME}::Pe" ALIAS "${PROJECT_NAME}_Pe")

# for formatPE::Pdb library
add_library("${PROJECT_NAME}_Pdb"
"./formatPE/Pdb/Pdb.h"
"./formatPE/Pdb/Pdb.cpp"
)
target_include_directories("${PROJECT_NAME}_Pdb" PUBLIC
"${CMAKE_CURRENT_LIST_DIR}/formatPE/"
)
add_library("${PROJECT_NAME}::Pdb" ALIAS "${PROJECT_NAME}_Pdb")

# for formatPE::SymLoader library
add_library("${PROJECT_NAME}_SymLoader"
"./formatPE/Pdb/SymLoader.h"
"./formatPE/Pdb/SymLoader.cpp"
)
target_include_directories("${PROJECT_NAME}_SymLoader" PUBLIC
"${CMAKE_CURRENT_LIST_DIR}/formatPE/"
)
add_library("${PROJECT_NAME}::SymLoader" ALIAS "${PROJECT_NAME}_SymLoader")
target_link_libraries("${PROJECT_NAME}_SymLoader" PUBLIC
formatPE::Pe
formatPE::Pdb
)

# test
add_executable("PeTests"
"./PeTests/PeTests.cpp"
)
target_link_libraries("PeTests" PUBLIC
formatPE::Pe
formatPE::Pdb
formatPE::SymLoader
)
enable_testing()
add_test(
"PeTests"
"${CMAKE_BINARY_DIR}/${PlatformDir}/bin/PeTests.exe"
)

set_target_properties("${PROJECT_NAME}_Pe" "${PROJECT_NAME}_Pdb" "${PROJECT_NAME}_SymLoader" "PeTests"
PROPERTIES 
ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${PlatformDir}/lib"
LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${PlatformDir}/lib"
RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${PlatformDir}/bin"
)