cmake_minimum_required(VERSION 3.2 FATAL_ERROR)
include(ExternalProject)
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-rtti")

option(HUNTER_ENABLED "Enable hunter package pulling" OFF)
include("cmake/HunterGate.cmake")

HunterGate(
    URL "https://github.com/ruslo/hunter/archive/v0.18.64.tar.gz"
    SHA1 "baf9c8cc4f65306f0e442b5419967b4c4c04589a"
)

project(pam-ipmi CXX C)

hunter_add_package(Boost)

option(YOCTO "Enable Building In Yocto" OFF)
if(NOT YOCTO)

    #### headers that can't be built without yocto
    include_directories(non-yocto)
    ####

endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

###############
# import OpenSSL (crypto)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
find_package(PAM REQUIRED)
include_directories(${PAM_INCLUDE_DIR})

add_library(pam_ipmicheck SHARED src/pam_ipmicheck/pam_ipmicheck.c)
set_target_properties(pam_ipmicheck PROPERTIES PREFIX "")
target_link_libraries(pam_ipmicheck ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(pam_ipmicheck ${PAM_LIBRARY})

add_library(pam_ipmisave SHARED src/pam_ipmisave/pam_ipmisave.c)
set_target_properties(pam_ipmisave PROPERTIES PREFIX "")
target_link_libraries(pam_ipmisave ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(pam_ipmisave ${PAM_LIBRARY})

install (TARGETS pam_ipmicheck pam_ipmisave LIBRARY DESTINATION /lib/security)

