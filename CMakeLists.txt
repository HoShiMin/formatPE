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

set(formatPE_Name ${PROJECT_NAME})

include("${CMAKE_CURRENT_LIST_DIR}/formatPEConfig.cmake")