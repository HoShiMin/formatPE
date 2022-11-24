
if(NOT DEFINED formatPE_Name)
    set(formatPE_Name "formatPE")
endif()

if(NOT DEFINED PlatformDir)
    if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "4")
        set(PlatformDir "x86")
    else()
        set(PlatformDir "x64")
    endif()
endif()

# for formatPE::Pe header only
add_library("${formatPE_Name}_Pe" INTERFACE)
target_include_directories("${formatPE_Name}_Pe" INTERFACE
"${CMAKE_CURRENT_LIST_DIR}/formatPE/"
)
add_library("${formatPE_Name}::Pe" ALIAS "${formatPE_Name}_Pe")

# for formatPE::Pdb library
add_library("${formatPE_Name}_Pdb"
"${CMAKE_CURRENT_LIST_DIR}/formatPE/Pdb/Pdb.h"
"${CMAKE_CURRENT_LIST_DIR}/formatPE/Pdb/Pdb.cpp"
)
target_include_directories("${formatPE_Name}_Pdb" PUBLIC
"${CMAKE_CURRENT_LIST_DIR}/formatPE/"
)
add_library("${formatPE_Name}::Pdb" ALIAS "${formatPE_Name}_Pdb")

# for formatPE::SymLoader library
add_library("${formatPE_Name}_SymLoader"
"${CMAKE_CURRENT_LIST_DIR}/formatPE/Pdb/SymLoader.h"
"${CMAKE_CURRENT_LIST_DIR}/formatPE/Pdb/SymLoader.cpp"
)
target_include_directories("${formatPE_Name}_SymLoader" PUBLIC
"${CMAKE_CURRENT_LIST_DIR}/formatPE/"
)
add_library("${formatPE_Name}::SymLoader" ALIAS "${formatPE_Name}_SymLoader")
target_link_libraries("${formatPE_Name}_SymLoader" PUBLIC
formatPE::Pe
formatPE::Pdb
)

# test
add_executable("PeTests"
"${CMAKE_CURRENT_LIST_DIR}/PeTests/PeTests.cpp"
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

set_target_properties("${formatPE_Name}_Pe" "${formatPE_Name}_Pdb" "${formatPE_Name}_SymLoader" "PeTests"
PROPERTIES 
ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${PlatformDir}/lib"
LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${PlatformDir}/lib"
RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${PlatformDir}/bin"
)