CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(wfd-manager C)

#SET(PREFIX $(CMAKE_INSTALL_PREFIX))
SET(prefix "/usr")
SET(EXEC_PREFIX "\${prefix}")
SET(LIBDIR "\${prefix}/lib")
SET(INCLUDEDIR "\${prefix}/include")

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED wifi-direct glib-2.0 gobject-2.0 dlog capi-appfw-application vconf)
FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include
					${CMAKE_SOURCE_DIR}/oem
					)

SET(CMAKE_C_FLAGS "${CMAKE_CFLAGS} ${EXTRA_CFLAGS} -g")
SET(CMAKE_C_FLAGS_DEBUG "O0 -g")
SET(CMAKE_C_FLAGS_RELEASE "O2")

ADD_DEFINITIONS("-DPREFIX=\"${CMAKE_INSTALL_PREFIX}\"")
ADD_DEFINITIONS("-DUSE_DLOG")

SET(SRCS
	${CMAKE_SOURCE_DIR}/src/wifi-direct-manager.c
	${CMAKE_SOURCE_DIR}/src/wifi-direct-state.c
	${CMAKE_SOURCE_DIR}/src/wifi-direct-client.c
	${CMAKE_SOURCE_DIR}/src/wifi-direct-peer.c
	${CMAKE_SOURCE_DIR}/src/wifi-direct-group.c
	${CMAKE_SOURCE_DIR}/src/wifi-direct-session.c
	${CMAKE_SOURCE_DIR}/src/wifi-direct-event.c
	${CMAKE_SOURCE_DIR}/src/wifi-direct-util.c
	${CMAKE_SOURCE_DIR}/oem/wifi-direct-oem.c
	)

ADD_EXECUTABLE(${PROJECT_NAME} ${SRCS})
TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${pkgs_LDFLAGS} -ldl)

INSTALL(TARGETS ${PROJECT_NAME} DESTINATION bin)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/dhcpd.p2p.conf DESTINATION etc/wifi-direct)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/udhcp_script.non-autoip DESTINATION etc/wifi-direct)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/dhcpd-notify.sh DESTINATION bin)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/wifi-direct-server.sh DESTINATION bin)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/wifi-direct-dhcp.sh DESTINATION bin)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/p2p_supp.sh DESTINATION sbin)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/p2p_supp.conf DESTINATION etc/wifi-direct)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/access_list DESTINATION etc/wifi-direct)

ADD_SUBDIRECTORY(plugin/wpasupplicant)
