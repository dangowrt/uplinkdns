cmake_minimum_required(VERSION 3.13)
project(uplinkdns VERSION 0.1.0 LANGUAGES C)

include(GNUInstallDirs)
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
pkg_check_modules(CARES REQUIRED IMPORTED_TARGET libcares>=1.34)

add_library(uplinkdns SHARED
	src/interpose.c
	src/real.c
	src/resolver.c
	src/synth.c
	src/uplink.c)

set_target_properties(uplinkdns PROPERTIES
	C_STANDARD 99
	C_VISIBILITY_PRESET hidden
	VERSION ${PROJECT_VERSION}
	SOVERSION ${PROJECT_VERSION_MAJOR}
	PUBLIC_HEADER include/uplinkdns.h)
target_compile_options(uplinkdns PRIVATE -Wall -Wextra)
target_include_directories(uplinkdns PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
	$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_link_libraries(uplinkdns PRIVATE PkgConfig::CARES Threads::Threads
	${CMAKE_DL_LIBS})

configure_file(uplinkdns.pc.in uplinkdns.pc @ONLY)

install(TARGETS uplinkdns
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/uplinkdns.pc
	DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
