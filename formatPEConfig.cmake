if(NOT DEFINED formatPE_NAME)
    set(formatPE_NAME "formatPE")
endif()

if(NOT DEFINED PLATFORM_DIR)
    if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "4")
        set(PLATFORM_DIR "x86")
    else()
        set(PLATFORM_DIR "x64")
    endif()
endif()



# formatPE::Pe is header-only:
add_library("${formatPE_NAME}_Pe" INTERFACE)

target_include_directories("${formatPE_NAME}_Pe" INTERFACE
    "${CMAKE_CURRENT_LIST_DIR}/formatPE/"
)

add_library("${formatPE_NAME}::Pe" ALIAS "${formatPE_NAME}_Pe")



# formatPE::Pdb library:
add_library("${formatPE_NAME}_Pdb"
    "${CMAKE_CURRENT_LIST_DIR}/formatPE/Pdb/Pdb.h"
    "${CMAKE_CURRENT_LIST_DIR}/formatPE/Pdb/Pdb.cpp"
)

target_include_directories("${formatPE_NAME}_Pdb" PUBLIC
    "${CMAKE_CURRENT_LIST_DIR}/formatPE/"
)

add_library("${formatPE_NAME}::Pdb" ALIAS "${formatPE_NAME}_Pdb")



# formatPE::SymLoader library:
add_library("${formatPE_NAME}_SymLoader"
    "${CMAKE_CURRENT_LIST_DIR}/formatPE/Pdb/SymLoader.h"
    "${CMAKE_CURRENT_LIST_DIR}/formatPE/Pdb/SymLoader.cpp"
)

target_include_directories("${formatPE_NAME}_SymLoader" PUBLIC
    "${CMAKE_CURRENT_LIST_DIR}/formatPE/"
)

target_link_libraries("${formatPE_NAME}_SymLoader" PUBLIC
    formatPE::Pe
    formatPE::Pdb
)

add_library("${formatPE_NAME}::SymLoader" ALIAS "${formatPE_NAME}_SymLoader")



# Tests:
add_executable("PeTests" "${CMAKE_CURRENT_LIST_DIR}/PeTests/PeTests.cpp")
target_link_libraries("PeTests" PUBLIC
    formatPE::Pe
    formatPE::Pdb
    formatPE::SymLoader
)

enable_testing()
add_test("PeTests" "${CMAKE_BINARY_DIR}/${PLATFORM_DIR}/bin/PeTests.exe")



set_target_properties(
    "${formatPE_NAME}_Pe"
    "${formatPE_NAME}_Pdb"
    "${formatPE_NAME}_SymLoader"
    "PeTests"
    PROPERTIES 
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${PLATFORM_DIR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${PLATFORM_DIR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${PLATFORM_DIR}/bin"
)