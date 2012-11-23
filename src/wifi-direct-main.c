/*
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd All Rights Reserved 
 *
 * This file is part of <Wi-Fi Direct>
 * Written by Sungsik Jang<sngsik.jang@samsung.com>, Dongwook Lee<dwmax.lee@samsung.com>
 *
 * PROPRIETARY/CONFIDENTIAL
 *
 * This software is the confidential and proprietary information of SAMSUNG ELECTRONICS ("Confidential Information").
 * You shall not disclose such Confidential Information and shall use it only in accordance
 * with the terms of the license agreement you entered into with SAMSUNG ELECTRONICS.
 * SAMSUNG make no representations or warranties about the suitability of the software,
 * either express or implied, including but not limited to the implied warranties of merchantability,
 * fitness for a particular purpose, or non-infringement.
 * SAMSUNG shall not be liable for any damages suffered by licensee as a result of using,
 * modifying or distributing this software or its derivatives.
 *
 */


/*****************************************************************************
 * 	Standard headers
 *****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <stdbool.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <linux/unistd.h>
#include <glib.h>
#include <glib-object.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <sys/utsname.h>

/*****************************************************************************
 * 	Platform headers
 *****************************************************************************/
#include "vconf-keys.h"

/*****************************************************************************
 * 	Wi-Fi Direct Server headers
 *****************************************************************************/
#include "wifi-direct.h"
#include "wifi-direct-stub.h"
#include "wifi-direct-service.h"
#include "wifi-direct-utils.h"
#include "wifi-direct-event-handler.h"
#include "wifi-direct-oem.h"

/*****************************************************************************
 * 	Wi-Fi Macros
 *****************************************************************************/


/*****************************************************************************
 * 	Wi-Fi Global variables
 *****************************************************************************/
wfd_server_control_t g_wfd_server;


void wfd_server_process_event(wfd_event_t event);


char *wfd_server_print_cmd(wifi_direct_cmd_e cmd)
{
	switch (cmd)
	{
	case WIFI_DIRECT_CMD_REGISTER:
		return "WIFI_DIRECT_CMD_REGISTER";
	case WIFI_DIRECT_CMD_INIT_ASYNC_SOCKET:
		return "WIFI_DIRECT_CMD_INIT_ASYNC_SOCKET";
	case WIFI_DIRECT_CMD_DEREGISTER:
		return "WIFI_DIRECT_CMD_DEREGISTER";
	case WIFI_DIRECT_CMD_ACTIVATE:
		return "WIFI_DIRECT_CMD_ACTIVATE";
	case WIFI_DIRECT_CMD_DEACTIVATE:
		return "WIFI_DIRECT_CMD_DEACTIVATE";
	case WIFI_DIRECT_CMD_START_DISCOVERY:
		return "WIFI_DIRECT_CMD_START_DISCOVERY";
	case WIFI_DIRECT_CMD_CANCEL_DISCOVERY:
		return "WIFI_DIRECT_CMD_CANCEL_DISCOVERY";
	case WIFI_DIRECT_CMD_GET_DISCOVERY_RESULT:
		return "WIFI_DIRECT_CMD_GET_DISCOVERY_RESULT";
	case WIFI_DIRECT_CMD_SEND_PROVISION_DISCOVERY_REQ:
		return "WIFI_DIRECT_CMD_SEND_PROVISION_DISCOVERY_REQ";
	case WIFI_DIRECT_CMD_GET_LINK_STATUS:
		return "WIFI_DIRECT_CMD_GET_LINK_STATUS";
	case WIFI_DIRECT_CMD_CONNECT:
		return "WIFI_DIRECT_CMD_CONNECT";
	case WIFI_DIRECT_CMD_DISCONNECT_ALL:
		return "WIFI_DIRECT_CMD_DISCONNECT_ALL";
	case WIFI_DIRECT_CMD_CREATE_GROUP:
		return "WIFI_DIRECT_CMD_CREATE_GROUP";
	case WIFI_DIRECT_CMD_ACTIVATE_PUSHBUTTON:
		return "WIFI_DIRECT_CMD_ACTIVATE_PUSHBUTTON";
	case WIFI_DIRECT_CMD_IS_GROUPOWNER:
		return "WIFI_DIRECT_CMD_IS_GROUPOWNER";
	case WIFI_DIRECT_CMD_GET_SSID:
		return "WIFI_DIRECT_CMD_GET_SSID";
	case WIFI_DIRECT_CMD_SET_SSID:
		return "WIFI_DIRECT_CMD_SET_SSID";
	case WIFI_DIRECT_CMD_GET_IP_ADDR:
		return "WIFI_DIRECT_CMD_GET_IP_ADDR";
	case WIFI_DIRECT_CMD_GET_CONFIG:
		return "WIFI_DIRECT_CMD_GET_CONFIG";
	case WIFI_DIRECT_CMD_SET_WPS_PIN:
		return "WIFI_DIRECT_CMD_SET_WPS_PIN";
	case WIFI_DIRECT_CMD_GET_WPS_PIN:
		return "WIFI_DIRECT_CMD_GET_WPS_PIN";
	case WIFI_DIRECT_CMD_GET_INCOMMING_PEER_INFO:
		return "WIFI_DIRECT_CMD_GET_INCOMMING_PEER_INFO";
	case WIFI_DIRECT_CMD_SET_WPA:
		return "WIFI_DIRECT_CMD_SET_WPA";
	case WIFI_DIRECT_CMD_GET_SUPPORTED_WPS_MODE:
		return "WIFI_DIRECT_CMD_GET_SUPPORTED_WPS_MODE";
	case WIFI_DIRECT_CMD_SET_CURRENT_WPS_MODE:
		return "WIFI_DIRECT_CMD_SET_CURRENT_WPS_MODE";
	case WIFI_DIRECT_CMD_GET_CONNECTED_PEERS_INFO:
		return "WIFI_DIRECT_CMD_GET_CONNECTED_PEERS_INFO";
	case WIFI_DIRECT_CMD_CANCEL_GROUP:
		return "WIFI_DIRECT_CMD_CANCEL_GROUP";
	case WIFI_DIRECT_CMD_DISCONNECT:
		return "WIFI_DIRECT_CMD_DISCONNECT";
	case WIFI_DIRECT_CMD_GET_GO_INTENT:
		return "WIFI_DIRECT_CMD_GET_GO_INTENT";
	case WIFI_DIRECT_CMD_SET_GO_INTENT:
		return "WIFI_DIRECT_CMD_SET_GO_INTENT";
	case WIFI_DIRECT_CMD_IS_DISCOVERABLE:
		return "WIFI_DIRECT_CMD_IS_DISCOVERABLE";
	case WIFI_DIRECT_CMD_GET_OWN_GROUP_CHANNEL:
		return "WIFI_DIRECT_CMD_GET_OWN_GROUP_CHANNEL";
	default:
		return "WIFI_DIRECT_CMD_INVALID";

	}
}

wfd_server_control_t *wfd_server_get_control()
{
	return &g_wfd_server;
}

static gboolean wfd_server_accept_client_socket(GIOChannel* source, GIOCondition condition, gpointer data)
{
	int clientfd = -1;
	socklen_t clientlen = 0;
	wfd_server_control_t *wfd_server = wfd_server_get_control();
	int servfd = wfd_server->async_sockfd;

	__WFD_SERVER_FUNC_ENTER__;

	if (servfd < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "Error!!! Invalid sockfd argument = [%d] \n", servfd);
		__WFD_SERVER_FUNC_EXIT__;
		return FALSE;
	}

	errno = 0;
	clientfd = accept(servfd, NULL, &clientlen);
	if (clientfd == -1)
	{
		WFD_SERVER_LOG(WFD_LOG_ASSERT,
					   "Error!!! Accepting the client socket. Error = [%s]. Server socket = [%d] \n",
					   strerror(errno), servfd);

		int ret = 0;
		char req[10] = "";
		int reqlen = 10;

		errno = 0;
		ret = read(servfd, req, reqlen);
		if (ret == 0)
		{
			WFD_SERVER_LOG(WFD_LOG_LOW, "Server Socket got closed\n");
		}
		else if (ret < 0)
		{
			WFD_SERVER_LOG( WFD_LOG_ERROR, "Error!!! reading server socket. Error = [%s]\n", strerror(errno));
		}
		else
			WFD_SERVER_LOG(WFD_LOG_LOW, "Read [%d] data\n", ret);

		__WFD_SERVER_FUNC_EXIT__;
		return -1;
	}

	WFD_SERVER_LOG(WFD_LOG_LOW, "Accepted the client: [%d]\n", clientfd);

	if (!(wfd_server_register_client(clientfd)))
	{
		WFD_SERVER_LOG(WFD_LOG_ERROR, "Error!!! adding new client\n");
		close(clientfd);
	}
	__WFD_SERVER_FUNC_EXIT__;
	return true;
}

static int wfd_server_create_socket(void)
{
	int len = 0;
	int sockfd = -1;
	struct sockaddr_un servAddr;
	mode_t sock_mode;			// socket file permission
	wfd_server_control_t *wfd_server = wfd_server_get_control();

	__WFD_SERVER_FUNC_ENTER__;

	/** It is safe to Unlink the path.*/
	unlink(WFD_SERVER_SOCKET_PATH);
	errno = 0;
	if ((sockfd = socket(PF_LOCAL, SOCK_STREAM, 0)) == -1)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "Error!!! creating UNIX socket. Error = [%s]\n", strerror(errno));
		__WFD_SERVER_FUNC_EXIT__;
		return -1;
	}

	memset(&servAddr, 0, sizeof(servAddr));
	servAddr.sun_family = AF_UNIX;
	strcpy(servAddr.sun_path, WFD_SERVER_SOCKET_PATH);
	len = sizeof(servAddr.sun_family) + strlen(WFD_SERVER_SOCKET_PATH);

	errno = 0;

	sock_mode = (S_IRWXU | S_IRWXG | S_IRWXO);

	if (bind(sockfd, (struct sockaddr *) &servAddr, len) == -1)
	{
		WFD_SERVER_LOG( WFD_LOG_LOW, "Error!!! binding to the socket address. Error = [%s]\n", strerror(errno));
		__WFD_SERVER_FUNC_EXIT__;
		return -1;
	}

	WFD_SERVER_LOG(WFD_LOG_LOW, "Binded to the server socket.\n");

	if (chmod(WFD_SERVER_SOCKET_PATH, sock_mode) < 0)
	{
		WFD_SERVER_LOG(WFD_LOG_LOW, "[server] chmod() error\n");
		return -1;
	}

	errno = 0;
	if (listen(sockfd, WFD_MAX_CLIENTS) == -1)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "Error!!! while listening to the socket. Error = [%s]\n", strerror(errno));
		__WFD_SERVER_FUNC_EXIT__;
		return -1;
	}

	wfd_server->async_sockfd = sockfd;

	WFD_SERVER_LOG( WFD_LOG_LOW, "Successfully created the server socket [%d]\n", sockfd);
	__WFD_SERVER_FUNC_EXIT__;
	return 1;
}

void wfd_load_plugin()
{
	void *handle;
	char *filename;
	struct utsname kernel_info;
	int res;    

	res = uname(&kernel_info);
	if(res != 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "Failed to detect target type\n");
	}
	else
	{
		WFD_SERVER_LOG( WFD_LOG_LOW, "Node name of this device [%s]\n", kernel_info.nodename);
		WFD_SERVER_LOG( WFD_LOG_LOW, "HW ID of this device [%s]\n", kernel_info.machine);

		
		if((strcmp(kernel_info.nodename, "U1SLP") == 0)
			|| (strcmp(kernel_info.nodename, "U1HD") == 0) 
			/*|| (strcmp(kernel_info.nodename, "TRATS") == 0)*/)
			filename = "/usr/lib/wifi-direct-plugin-broadcom.so";		
		else
			filename = "/usr/lib/wifi-direct-plugin-wpasupplicant.so";
	}

	handle = dlopen(filename, RTLD_NOW);
	if (!handle) {
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "Error for dlopen\n");
		fputs(dlerror(), stderr);
		return;
	}

	int (*plugin_load)(struct wfd_oem_operations **ops) = NULL;
	plugin_load = (int (*)(struct wfd_oem_operations **ops))dlsym(handle, "wfd_plugin_load");

	if (!plugin_load) {
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "Error for dlsym[%s]\n", strerror(errno));
		return ;
	}

	struct wfd_oem_operations *temp_ops;
	(*plugin_load)(&temp_ops);
	g_ops = temp_ops;

	return;
}


/*****************************************************************************
 * 	Wi-Fi Global Function Definition
 *****************************************************************************/

static int wfd_server_init(void)
{
	int i = -1;
	unsigned char NULL_MAC[6] = { 0, 0, 0, 0, 0, 0 };

	__WFD_SERVER_FUNC_ENTER__;

	memset(&g_wfd_server, 0, sizeof(wfd_server_control_t));
	g_wfd_server.active_clients = 0;
	g_wfd_server.async_sockfd = -1;
	g_wfd_server.sync_sockfd = -1;

	// ToDo: Read them from repository.
	g_wfd_server.config_data.channel = 11;
	g_wfd_server.config_data.wps_config = WIFI_DIRECT_WPS_TYPE_PBC;
	g_wfd_server.config_data.auto_connection = false;
	g_wfd_server.config_data.want_persistent_group = false;
	g_wfd_server.config_data.max_clients = WFD_MAC_ASSOC_STA;
	g_wfd_server.config_data.hide_SSID = false;
	g_wfd_server.config_data.group_owner_intent = 8;
	g_wfd_server.config_data.primary_dev_type = WIFI_DIRECT_PRIMARY_DEVICE_TYPE_TELEPHONE;	// Telephone
	g_wfd_server.config_data.secondary_dev_type = WIFI_DIRECT_SECONDARY_DEVICE_TYPE_PHONE_SM_DUAL;	// smart phone dual mode (wifi and cellular)

	//g_wfd_server.config_data.primary_dev_type = WFD_DEVICE_TYPE_CAT_TELEPHONE;
	//g_wfd_server.config_data.secondary_dev_type = WFD_DEVICE_TYPE_SUB_CAT_PHONE_WM;


	for (i = 0; i < WFD_MAX_CLIENTS; i++)
	{
		memset(&g_wfd_server.client[i], 0, sizeof(wfd_server_client_t));
	}

	for (i = 0; i < 8; i++)
	{
		memset(&g_wfd_server.connected_peers[i], 0, sizeof(wfd_local_connected_peer_info_t));
		g_wfd_server.connected_peers[i].isUsed = 0;

	}
	g_wfd_server.connected_peer_count = 0;
	memcpy(g_wfd_server.current_peer.mac_address, NULL_MAC, 6);

	g_wfd_server.autonomous_group_owner = false;

	wfd_load_plugin();

	wfd_oem_init(wfd_server_process_event);

	wfd_set_device_name_as_ssid();

	wfd_set_DHCP_event_handler();

	if (wfd_set_wifi_direct_state(WIFI_DIRECT_STATE_DEACTIVATED) < 0)
		WFD_SERVER_LOG(WFD_LOG_ASSERT, "wfd_set_wifi_direct_state() failed\n");


	__WFD_SERVER_FUNC_EXIT__;
	return 0;
}

static int wfd_server_destroy()
{
	__WFD_SERVER_FUNC_ENTER__;

	if (g_wfd_server.async_sockfd>0)
		close(g_wfd_server.async_sockfd);
	unlink(WFD_SERVER_SOCKET_PATH);

	memset(&g_wfd_server, 0, sizeof(wfd_server_control_t));

	wfd_oem_destroy();

	__WFD_SERVER_FUNC_EXIT__;
	return 0;
}

static gboolean wfd_connection_timeout_cb(void *user_data)
{
	__WFD_SERVER_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();
	wifi_direct_client_noti_s noti;

	g_source_remove(wfd_server->connection_timer);
	wfd_server->connection_timer = 0;


	if (wfd_oem_is_groupowner())
	{
		wfd_server_set_state(WIFI_DIRECT_STATE_GROUP_OWNER);
	}
	else
	{
		wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATED);
	}

#if 0
	// disconnect the peer to reset state.
	if (wfd_oem_is_groupowner() == TRUE)
	{
		WFD_SERVER_LOG(WFD_LOG_LOW, "Peer's Intf MAC is " MACSTR "\n", MAC2STR(wfd_server->current_peer.intf_mac_address));
		if ( NULL == wfd_server->current_peer.intf_mac_address )
			WFD_SERVER_LOG( WFD_LOG_ASSERT, "[wfd_server->current_peer.intf_mac_address] is Null!\n");

		if (wfd_oem_disconnect_sta(wfd_server->current_peer.intf_mac_address) == FALSE)
			WFD_SERVER_LOG( WFD_LOG_ASSERT, "Error... wfd_oem_disconnect_sta() failed\n");
	}
	else
	{
		wfd_server_set_state(WIFI_DIRECT_STATE_DISCONNECTING);

		if (wfd_oem_disconnect() == TRUE)
		{
			wfd_server->config_data.wps_config = WIFI_DIRECT_WPS_TYPE_PBC;	// set wps_config to default
		}
		else
		{
			wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATED);
			WFD_SERVER_LOG( WFD_LOG_ASSERT, "Error... wfd_oem_disconnect() failed\n");
		}
	}
#endif

	memset(&noti, 0, sizeof(wifi_direct_client_noti_s));


	snprintf(noti.param1, sizeof(noti.param1),MACSTR, MAC2STR(wfd_server->current_peer.mac_address));

	noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP;
	noti.error = WIFI_DIRECT_ERROR_CONNECTION_TIME_OUT;

	wfd_server_reset_connecting_peer();
	wfd_server_clear_connected_peer();

	__wfd_server_send_client_event(&noti);

	__WFD_SERVER_FUNC_EXIT__;

	return FALSE;
}

void wfd_timer_connection_start()
{
	__WFD_SERVER_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();

	if (wfd_server->connection_timer > 0)
		g_source_remove(wfd_server->connection_timer);

	wfd_server->connection_timer = 0;

	wfd_server->connection_timer = g_timeout_add(120000 /* 120 seconds*/, (GSourceFunc)wfd_connection_timeout_cb , NULL);

	__WFD_SERVER_FUNC_EXIT__;
}

void wfd_timer_connection_cancel()
{
	__WFD_SERVER_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();

	if (wfd_server->connection_timer > 0)
		g_source_remove(wfd_server->connection_timer);

	wfd_server->connection_timer = 0;

	__WFD_SERVER_FUNC_EXIT__;
}


static gboolean wfd_termination_timeout_cb(void *user_data)
{
	__WFD_SERVER_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();

	if (wfd_server->active_clients > 0)
	{
		WFD_SERVER_LOG(WFD_LOG_LOW, "There is an active clients(Num=[%d]). Run timer again..\n", wfd_server->active_clients);
		// Restart timer by returning true.
		return TRUE;
	}

	int state = wfd_server_get_state();

	if (state != WIFI_DIRECT_STATE_DEACTIVATED)
	{
		WFD_SERVER_LOG(WFD_LOG_LOW, "State is not 'deactivated' ( state=[%d] ).  Cancel timer.\n", state);
		// Cancel timer by returning false.
		return FALSE;
	}

	if (wfd_server->async_sockfd > 0)
		close(wfd_server->async_sockfd);

	g_main_quit(wfd_server->mainloop);

	WFD_SERVER_LOG(WFD_LOG_LOW, "g_main_quit()..\n");
	__WFD_SERVER_FUNC_EXIT__;

	// Cancel timer by returning false.
	return FALSE;
}


void wfd_termination_timer_start()
{
	__WFD_SERVER_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();

	if (wfd_server->termination_timer > 0)
	{
		g_source_remove(wfd_server->termination_timer);
		WFD_SERVER_LOG(WFD_LOG_LOW, "Termination timer is restarted..\n");
	}
	else
	{
		WFD_SERVER_LOG(WFD_LOG_LOW, "Termination timer is started..\n");
	}

	wfd_server->termination_timer = 0;

	wfd_server->termination_timer = g_timeout_add(120000 /* 120 seconds*/, (GSourceFunc)wfd_termination_timeout_cb , NULL);


	__WFD_SERVER_FUNC_EXIT__;
}


void wfd_termination_timer_cancel()
{
	__WFD_SERVER_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();

	if (wfd_server->termination_timer > 0)
		g_source_remove(wfd_server->termination_timer);

	wfd_server->termination_timer = 0;
	WFD_SERVER_LOG(WFD_LOG_LOW, "Termination timer is canceled..\n");

	__WFD_SERVER_FUNC_EXIT__;
}

static gboolean wfd_discovery_timeout_cb(void *user_data)
{
	__WFD_SERVER_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();
	wifi_direct_client_noti_s noti;
	int ret;

	g_source_remove(wfd_server->discovery_timer);
	wfd_server->discovery_timer = 0;

	if (wfd_oem_is_groupowner())
	{
		wfd_server_set_state(WIFI_DIRECT_STATE_GROUP_OWNER);
	}
	else
	{
		wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATED);
	}

	ret = wfd_oem_cancel_discovery();
	if (ret == false)
	{
		WFD_SERVER_LOG( WFD_LOG_ERROR, "Error!! wfd_oem_cancel_discovery() failed..\n");
	}

#if 0
	memset(&noti, 0, sizeof(wifi_direct_client_noti_s));

	noti.event = WIFI_DIRECT_CLI_EVENT_DISCOVER_END;
	noti.error = WIFI_DIRECT_ERROR_NONE;

	__wfd_server_send_client_event(&noti);
#endif

	__WFD_SERVER_FUNC_EXIT__;

	return FALSE;
}

void wfd_timer_discovery_start(int seconds)
{
	__WFD_SERVER_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();

	if (wfd_server->discovery_timer> 0)
		g_source_remove(wfd_server->discovery_timer);

	wfd_server->discovery_timer = 0;

	wfd_server->discovery_timer = g_timeout_add((seconds*1000), (GSourceFunc)wfd_discovery_timeout_cb , NULL);

	__WFD_SERVER_FUNC_EXIT__;
}

void wfd_timer_discovery_cancel()
{
	__WFD_SERVER_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();

	if (wfd_server->discovery_timer > 0)
		g_source_remove(wfd_server->discovery_timer);

	wfd_server->discovery_timer = 0;

	__WFD_SERVER_FUNC_EXIT__;
}

int main(gint argc, gchar * argv[])
{
	GMainLoop *mainloop = NULL;
	wfd_server_control_t *wfd_server = wfd_server_get_control();
	int i = -1;

	__WFD_SERVER_FUNC_ENTER__;

	WFD_SERVER_LOG( WFD_LOG_LOW,"========================================\n");
	WFD_SERVER_LOG( WFD_LOG_LOW,"=                                      		=\n");
	WFD_SERVER_LOG( WFD_LOG_LOW,"=         WiFi Direct Server          	=\n");
	WFD_SERVER_LOG( WFD_LOG_LOW,"=                                      		=\n");
	WFD_SERVER_LOG( WFD_LOG_LOW,"========================================\n");

	for (i = 0; i < argc; i++)
	{
		WFD_SERVER_LOG(WFD_LOG_LOW, "arg[%d]= %s\n", i, argv[i]);
	}

	if (!g_thread_supported())
	{
		g_thread_init(NULL);
	}

	g_type_init();

	mainloop = g_main_loop_new(NULL, FALSE);

	WFD_SERVER_LOG(WFD_LOG_LOW, "gmainloop is initialized\n");


	WFD_SERVER_LOG(WFD_LOG_LOW, "Entering g_main_loop()...\n");

	wfd_server_init();

	if (wfd_server_create_socket() == -1)
	{
		__WFD_SERVER_FUNC_EXIT__;
		return -1;
	}

	GIOChannel* gio2 = g_io_channel_unix_new(wfd_server->async_sockfd);
	g_io_add_watch(gio2, G_IO_IN, (GIOFunc)wfd_server_accept_client_socket, NULL);
	g_io_channel_unref(gio2);


	wfd_server->mainloop = mainloop;
	wfd_termination_timer_start();

	//////////////////////////////////
	// Start g_main_loop
	//
	g_main_loop_run(mainloop);

	WFD_SERVER_LOG(WFD_LOG_LOW, "Leave g_main_loop_run()...\n");

	wfd_server_destroy();

	WFD_SERVER_LOG(WFD_LOG_LOW, "WLAN engine is destroyed...\n");

	WFD_SERVER_LOG(WFD_LOG_LOW, "=================================\n");
	WFD_SERVER_LOG(WFD_LOG_LOW, "     Quit WiFi Direct Manager main()\n");
	WFD_SERVER_LOG(WFD_LOG_LOW, "=================================\n");
	WFD_SERVER_LOG(WFD_LOG_LOW, "Bye...\n");

	__WFD_SERVER_FUNC_EXIT__;

	return 0;
}
