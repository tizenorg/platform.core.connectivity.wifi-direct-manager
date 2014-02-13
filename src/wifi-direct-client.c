/*
 * Network Configuration Module
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/**
 * This file implements wifi direct client functions.
 *
 * @file		wifi-direct-client.c
 * @author	Gibyoung Kim (lastkgb.kim@samsung.com)
 * @version	0.7
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>

#include <glib.h>
#include <vconf.h>

#include <wifi-direct.h>
#include <wifi-direct-internal.h>

#include "wifi-direct-manager.h"
#include "wifi-direct-oem.h"
#include "wifi-direct-session.h"
#include "wifi-direct-group.h"
#include "wifi-direct-client.h"
#include "wifi-direct-util.h"
#include "wifi-direct-state.h"
#include "wifi-direct-peer.h"


static int _wfd_deregister_client(void *data, int client_id);
static gboolean wfd_client_process_request(GIOChannel *source,
									GIOCondition condition,
									gpointer user_data);


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
	case WIFI_DIRECT_CMD_GET_LINK_STATUS:
		return "WIFI_DIRECT_CMD_GET_LINK_STATUS";
	case WIFI_DIRECT_CMD_CONNECT:
		return "WIFI_DIRECT_CMD_CONNECT";
	case WIFI_DIRECT_CMD_CANCEL_CONNECTION:
		return "WIFI_DIRECT_CMD_CANCEL_CONNECTION";
	case WIFI_DIRECT_CMD_REJECT_CONNECTION:
		return "WIFI_DIRECT_CMD_REJECT_CONNECTION";

	case WIFI_DIRECT_CMD_DISCONNECT_ALL:
		return "WIFI_DIRECT_CMD_DISCONNECT_ALL";
	case WIFI_DIRECT_CMD_CREATE_GROUP:
		return "WIFI_DIRECT_CMD_CREATE_GROUP";
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
	case WIFI_DIRECT_CMD_SET_CONFIG:
		return "WIFI_DIRECT_CMD_SET_CONFIG";
	case WIFI_DIRECT_CMD_SEND_CONNECT_REQ:
		return "WIFI_DIRECT_CMD_SEND_CONNECT_REQ";

	case WIFI_DIRECT_CMD_ACTIVATE_PUSHBUTTON:
		return "WIFI_DIRECT_CMD_ACTIVATE_PUSHBUTTON";
	case WIFI_DIRECT_CMD_SET_WPS_PIN:
		return "WIFI_DIRECT_CMD_SET_WPS_PIN";
	case WIFI_DIRECT_CMD_GET_WPS_PIN:
		return "WIFI_DIRECT_CMD_GET_WPS_PIN";
	case WIFI_DIRECT_CMD_GENERATE_WPS_PIN:
		return "WIFI_DIRECT_CMD_GENERATE_WPS_PIN";
	case WIFI_DIRECT_CMD_GET_INCOMMING_PEER_INFO:
		return "WIFI_DIRECT_CMD_GET_INCOMMING_PEER_INFO";
	case WIFI_DIRECT_CMD_GET_PASSPHRASE:
		return "WIFI_DIRECT_CMD_GET_PASSPHRASE";
	case WIFI_DIRECT_CMD_SET_WPA:
		return "WIFI_DIRECT_CMD_SET_WPA";
	case WIFI_DIRECT_CMD_GET_SUPPORTED_WPS_MODE:
		return "WIFI_DIRECT_CMD_GET_SUPPORTED_WPS_MODE";
	case WIFI_DIRECT_CMD_GET_LOCAL_WPS_MODE:
		return "WIFI_DIRECT_CMD_GET_LOCAL_WPS_MODE";
	case WIFI_DIRECT_CMD_GET_REQ_WPS_MODE:
		return "WIFI_DIRECT_CMD_GET_REQ_WPS_MODE";
	case WIFI_DIRECT_CMD_SET_REQ_WPS_MODE:
		return "WIFI_DIRECT_CMD_SET_REQ_WPS_MODE";
	case WIFI_DIRECT_CMD_GET_CONNECTED_PEERS_INFO:
		return "WIFI_DIRECT_CMD_GET_CONNECTED_PEERS_INFO";
	case WIFI_DIRECT_CMD_DESTROY_GROUP:
		return "WIFI_DIRECT_CMD_DESTROY_GROUP";

	case WIFI_DIRECT_CMD_DISCONNECT:
		return "WIFI_DIRECT_CMD_DISCONNECT";
	case WIFI_DIRECT_CMD_SET_GO_INTENT:
		return "WIFI_DIRECT_CMD_SET_GO_INTENT";
	case WIFI_DIRECT_CMD_GET_GO_INTENT:
		return "WIFI_DIRECT_CMD_GET_GO_INTENT";
	case WIFI_DIRECT_CMD_GET_DEVICE_MAC:
		return "WIFI_DIRECT_CMD_GET_DEVICE_MAC";
	case WIFI_DIRECT_CMD_IS_AUTONOMOUS_GROUP:
		return "WIFI_DIRECT_CMD_IS_AUTONOMOUS_GROUP";
	case WIFI_DIRECT_CMD_SET_MAX_CLIENT:
		return "WIFI_DIRECT_CMD_SET_MAX_CLIENT";
	case WIFI_DIRECT_CMD_GET_MAX_CLIENT:
		return "WIFI_DIRECT_CMD_GET_MAX_CLIENT";
	case WIFI_DIRECT_CMD_SET_AUTOCONNECTION_MODE:
		return "WIFI_DIRECT_CMD_SET_AUTOCONNECTION_MODE";

	case WIFI_DIRECT_CMD_IS_AUTOCONNECTION_MODE:
		return "WIFI_DIRECT_CMD_IS_AUTOCONNECTION_MODE";
	case WIFI_DIRECT_CMD_IS_DISCOVERABLE:
		return "WIFI_DIRECT_CMD_IS_DISCOVERABLE";
	case WIFI_DIRECT_CMD_IS_LISTENING_ONLY:
		return "WIFI_DIRECT_CMD_IS_LISTENING_ONLY";
	case WIFI_DIRECT_CMD_GET_OPERATING_CHANNEL:
		return "WIFI_DIRECT_CMD_GET_OPERATING_CHANNEL";
	case WIFI_DIRECT_CMD_ACTIVATE_PERSISTENT_GROUP:
		return "WIFI_DIRECT_CMD_ACTIVATE_PERSISTENT_GROUP";
	case WIFI_DIRECT_CMD_DEACTIVATE_PERSISTENT_GROUP:
		return "WIFI_DIRECT_CMD_DEACTIVATE_PERSISTENT_GROUP";
	case WIFI_DIRECT_CMD_IS_PERSISTENT_GROUP:
		return "WIFI_DIRECT_CMD_IS_PERSISTENT_GROUP";
	case WIFI_DIRECT_CMD_GET_PERSISTENT_GROUP_INFO:
		return "WIFI_DIRECT_CMD_GET_PERSISTENT_GROUP_INFO";
	case WIFI_DIRECT_CMD_REMOVE_PERSISTENT_GROUP:
		return "WIFI_DIRECT_CMD_REMOVE_PERSISTENT_GROUP";
	case WIFI_DIRECT_CMD_GET_DEVICE_NAME:
		return "WIFI_DIRECT_CMD_GET_DEVICE_NAME";

	case WIFI_DIRECT_CMD_SET_DEVICE_NAME:
		return "WIFI_DIRECT_CMD_SET_DEVICE_NAME";
	case WIFI_DIRECT_CMD_SET_OEM_LOGLEVEL:
		return "WIFI_DIRECT_CMD_SET_OEM_LOGLEVEL";
	case WIFI_DIRECT_CMD_SERVICE_ADD:
		return "WIFI_DIRECT_CMD_SERVICE_ADD";
	case WIFI_DIRECT_CMD_SERVICE_DEL:
		return "WIFI_DIRECT_CMD_SERVICE_DEL";
	case WIFI_DIRECT_CMD_SERV_DISC_REQ:
		return "WIFI_DIRECT_CMD_SERV_DISC_REQ";
	case WIFI_DIRECT_CMD_SERV_DISC_CANCEL:
		return "WIFI_DIRECT_CMD_SERV_DISC_CANCEL";
	case WIFI_DIRECT_CMD_INIT_WIFI_DISPLAY:
		return "WIFI_DIRECT_CMD_INIT_WIFI_DISPLAY";
	case WIFI_DIRECT_CMD_DEINIT_WIFI_DISPLAY:
		return "WIFI_DIRECT_CMD_DEINIT_WIFI_DISPLAY";
	case WIFI_DIRECT_CMD_GET_DISPLAY_PORT:
		return "WIFI_DIRECT_CMD_GET_DISPLAY_PORT";
	case WIFI_DIRECT_CMD_GET_DISPLAY_TYPE:
		return "WIFI_DIRECT_CMD_GET_DISPLAY_TYPE";
	default:
		return "WIFI_DIRECT_CMD_INVALID";

	}
}

static wfd_client_s *_wfd_client_find_by_id(GList *clients, int client_id)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_client_s *client = NULL;
	GList *temp = NULL;

	if (!clients || client_id < 0) {
		WDS_LOGE("Invalid parameter(client_id:%d)", client_id);
		return NULL;
	}

	temp = g_list_first(clients);
	while (temp) {
		client = (wfd_client_s*) temp->data;
		if (client->client_id == client_id) {
			WDS_LOGD("Client found. [%d]", client_id);
			break;
		}
		temp = g_list_next(temp);
		client = NULL;
	}

	__WDS_LOG_FUNC_EXIT__;
	return client;
}

static int _wfd_client_check_socket(int sock)
{
	struct pollfd p_fd;
	int res = 0;

	p_fd.fd = sock;
	p_fd.events = POLLIN | POLLOUT | POLLERR | POLLHUP | POLLNVAL;
	res = poll((struct pollfd *) &p_fd, 1, 1);

	if (res < 0) {
		WDS_LOGE("Polling error from socket[%d]. [%s]", sock, strerror(errno));
		return -1;
	} else if (res == 0) {
		WDS_LOGD( "poll timeout. socket is busy\n");
		return 1;
	} else {

		if (p_fd.revents & POLLERR) {
			WDS_LOGE("Error! POLLERR from socket[%d]", sock);
			return -1;
		} else if (p_fd.revents & POLLHUP) {
			WDS_LOGE("Error! POLLHUP from socket[%d]", sock);
			return -1;
		} else if (p_fd.revents & POLLNVAL) {
			WDS_LOGE("Error! POLLNVAL from socket[%d]", sock);
			return -1;
		} else if (p_fd.revents & POLLIN) {
			WDS_LOGD("POLLIN from socket [%d]", sock);
			return 0;
		} else if (p_fd.revents & POLLOUT) {
			WDS_LOGD("POLLOUT from socket [%d]", sock);
			return 0;
		}
	}

	WDS_LOGD("Unknown poll event [%d]", p_fd.revents);
	return -1;
}

static int _wfd_send_to_client(int sock, char *data, int data_len)
{
	__WDS_LOG_FUNC_ENTER__;
	int wbytes = 0;
	int left_len = data_len;
	char *ptr = data;
	int res = 0;

	if (sock < SOCK_FD_MIN || !data || data_len < 0) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	res = _wfd_client_check_socket(sock);
	if (res < 0) {
		WDS_LOGE("Socket error");
		return -1;
	} else if (res > 0) {
		WDS_LOGE("Socket is busy");
		return -2;
	}

	errno = 0;
	while (left_len) {
		wbytes = write(sock, ptr, left_len);
		if (wbytes <= 0) {
			WDS_LOGE("Failed to write data into socket[%d]. [error=%s]", sock, strerror(errno));
			break;
		}else if (wbytes < left_len) {
			WDS_LOGD("%d bytes left. Continue sending...", left_len - wbytes);
			left_len -= wbytes;
			ptr += wbytes;
		} else if (wbytes == left_len) {
			WDS_LOGD("Succeeded to write data[%d bytes] into socket [%d]", wbytes, sock);
			left_len = 0;
		} else {
			WDS_LOGE("Unknown error occurred. [%s]", strerror(errno));
			break;
		}
	}

	__WDS_LOG_FUNC_EXIT__;
	if (left_len)
		return -1;
	else
		return 0;
}

static int _wfd_read_from_client(int sock, char *data, int data_len)
{
	__WDS_LOG_FUNC_ENTER__;
	int rbytes = 0;
	int total_rbytes = 0;
	int res = 0;

	if(sock < SOCK_FD_MIN || !data || data_len <= 0) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	res = _wfd_client_check_socket(sock);
	if (res < 0) {
		WDS_LOGE("Socket error");
		return -1;
	} else if (res > 0) {
		WDS_LOGE("Socket is busy");
		return -2;
	}

	while(data_len) {
		errno = 0;
		rbytes = read(sock, data, data_len);
		if (rbytes <= 0) {
			WDS_LOGE("Failed to read data from socket[%d]", sock);
			return -1;
		}
		total_rbytes += rbytes;
		data += rbytes;
		data_len -= rbytes;
	}

	__WDS_LOG_FUNC_EXIT__;
	return total_rbytes;
}

int wfd_client_send_event(wfd_manager_s *manager, wifi_direct_client_noti_s *noti)
{
	__WDS_LOG_FUNC_ENTER__;
	int cnt = 0;
	int res = 0;
	wfd_client_s *client = NULL;
	GList *temp = NULL;

	if (!manager || !noti) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	temp = g_list_first(manager->clients);
	while (temp) {
		client = temp->data;
		res = _wfd_send_to_client(client->asock, (char*) noti, sizeof(wifi_direct_client_noti_s));
		if (res < 0) {
			WDS_LOGE("Failed to send Notification[%d] to client [%d]", noti->event, client->client_id);
			temp = g_list_next(temp);
			_wfd_deregister_client(manager, client->client_id);
		} else {
			WDS_LOGD("Succeeded to send Notification [%d:%d] to client [%d]", noti->event,
									noti->error, client->client_id);
			temp = g_list_next(temp);
			cnt++;
		}
		client = NULL;
	}
	WDS_LOGD("Notification[%d:%d] sent to %d clients, Not Sent [%d]",
					noti->event, noti->error, cnt, manager->client_count - cnt);


	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

static int _wfd_register_client(void *data, int sock)
{
	__WDS_LOG_FUNC_ENTER__;
	int rbytes = 0;
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	wfd_manager_s *manager = (wfd_manager_s*) data;
	wfd_client_s *client = NULL;
	int res = 0;

	if (sock < SOCK_FD_MIN) {
		WDS_LOGE("Invalid argument");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	errno = 0;
	rbytes = read(sock, (char*) &req, sizeof(wifi_direct_client_request_s));
	if (rbytes <= 0) {
		WDS_LOGE("Failed to read socket data from client. [%s]", strerror(errno));
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	if (req.cmd == WIFI_DIRECT_CMD_REGISTER) {
		// TODO: check validity of command
		client = _wfd_client_find_by_id(manager->clients, req.client_id);
		if (client) {
			WDS_LOGE("Client already exist. client_id [%d]", sock);
			res = WIFI_DIRECT_ERROR_NOT_PERMITTED; // WIFI_DIRECT_ERROR_ALREADY_EXIST
			goto send_response;
		}

		client = (wfd_client_s*) calloc(1, sizeof(wfd_client_s));
		client->client_id = sock;
		client->ssock = sock;

		GIOChannel *gio = NULL;
		gio = g_io_channel_unix_new(sock);
		client->gsource_id = g_io_add_watch(gio, G_IO_IN | G_IO_ERR | G_IO_HUP,
							(GIOFunc) wfd_client_process_request, (gpointer) sock);
		g_io_channel_unref(gio);

		manager->clients = g_list_prepend(manager->clients, (gpointer) client);
		manager->client_count++;
		WDS_LOGD("Client [%d] is added. %d client alive", client->client_id, manager->client_count);

		res = WIFI_DIRECT_ERROR_NONE;
		WDS_LOGD("New client[%d] added. Total count [%d]", client->client_id, manager->client_count);
	} else if (req.cmd == WIFI_DIRECT_CMD_INIT_ASYNC_SOCKET) {
		client = _wfd_client_find_by_id(manager->clients, req.client_id);
		if (!client) {
			WDS_LOGE("Client not found. client_id[%d]", req.client_id);
			res = WIFI_DIRECT_ERROR_NOT_PERMITTED; // WIFI_DIRECT_ERROR_UNKNOWN_CLIENT
			goto done;
		}

		client->asock = sock;
		WDS_LOGD("Async socket[%d] for New client[%d] added.", sock, client->client_id);
		goto done;
	} else {
		WDS_LOGE("Unknown command from client. [%d]", req.cmd);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

send_response:
	rsp.cmd = req.cmd;
	rsp.client_id = client->client_id;
	rsp.result = res;
	res = _wfd_send_to_client(sock, (char*) &rsp, sizeof(wifi_direct_client_response_s));
	if (res < 0) {
		WDS_LOGE("Failed to send response to client");
		_wfd_deregister_client(manager, req.client_id);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}
done:
	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

static gboolean _wfd_remove_event_source(gpointer data)
{
	__WDS_LOG_FUNC_ENTER__;
	int source_id = (int) data;
	int res = 0;

	if (source_id < 0) {
		WDS_LOGE("Invalid source ID [%d]", source_id);
		return FALSE;
	}

	res = g_source_remove(source_id);
	if (!res) {
		WDS_LOGE("Failed to remove GSource");
		return FALSE;
	}
	WDS_LOGD("Succeeded to remove GSource");

	__WDS_LOG_FUNC_EXIT__;
	return FALSE;
}

static int _wfd_deregister_client(void *data, int client_id)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_client_s *client = NULL;
	wfd_manager_s *manager = (wfd_manager_s*) data;

	client =  _wfd_client_find_by_id(manager->clients, client_id);
	if (!client) {
		WDS_LOGE("Failed to find client[%d]", client_id);
		return -1;
	}
	manager->clients = g_list_remove(manager->clients, client);
	manager->client_count--;
	WDS_LOGD("Client [%d] is removed. %d client left", client->client_id, manager->client_count);

	if (client->asock >= SOCK_FD_MIN)
		close(client->asock);
	client->asock = -1;
	if (client->ssock >= SOCK_FD_MIN)
		close(client->ssock);
	client->ssock = -1;
	g_idle_add((GSourceFunc) _wfd_remove_event_source, (gpointer) client->gsource_id);
	client->gsource_id = 0;

	if (client)
		free(client);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

static int _wfd_create_server_socket(wfd_manager_s *manager)
{
	__WDS_LOG_FUNC_ENTER__;
	int sock;
	struct sockaddr_un saddr;
	int sock_opt = 1;
	int res = 0;

	if (!manager) {
		WDS_LOGE("Invalid parameter(NULL)");
		return -1;
	}

	/* Server socket initialization */
	unlink(WFD_SERVER_SOCK_PATH);

	errno = 0;
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < SOCK_FD_MIN) {
		WDS_LOGE("Failed to create server socket. [%s]", strerror(errno));
		if (sock >= 0)
			close(sock);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	errno = 0;
	res = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &sock_opt, sizeof(sock_opt));
	if (res == -1) {
		WDS_LOGE("Failed to set socket option. [%s]", strerror(errno));
		close(sock);
		return -1;
	}

	memset(&saddr, 0x00, sizeof(saddr));
	saddr.sun_family = AF_UNIX;
	snprintf(saddr.sun_path, sizeof(saddr.sun_path), WFD_SERVER_SOCK_PATH);

	errno = 0;
	res = bind(sock, (struct sockaddr*) &saddr, sizeof(saddr));
	if (res == -1) {
		WDS_LOGE("Failed to bind server socket. [%s]", strerror(errno));
		close(sock);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	errno = 0;
	res = chmod(WFD_SERVER_SOCK_PATH, WFD_SERVER_SOCK_MODE);
	if (res == -1) {
		WDS_LOGE("Failed to change mode of server socket file. [%s]", strerror(errno));
		close(sock);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	errno = 0;
	res = listen(sock, WFD_MAX_CLIENT);
	if (res == -1) {
		WDS_LOGE("Failed to listen server socket. [%s]", strerror(errno));
		close(sock);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	manager->serv_sock = sock;
	WDS_LOGD("Succeeded to create server socket. [%d]", sock);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

static gboolean _wfd_accept_client(GIOChannel *source,
									GIOCondition condition,
									gpointer user_data)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = (wfd_manager_s*) user_data;
	int cli_sock = -1;
	socklen_t cli_len = 0;
	int res = 0;

	if (!manager || manager->serv_sock < 0) {
		WDS_LOGE("Invalid parameter");
		return FALSE;
	}

	errno = 0;
	cli_sock = accept(manager->serv_sock, NULL, &cli_len);
	if (cli_sock == -1) {
		WDS_LOGE("Failed to accept client. [%s]", strerror(errno));
		return FALSE;
	}

	res = _wfd_register_client(manager, cli_sock);
	if (res < 0) {
		WDS_LOGE("Failed to register client.");
		close(cli_sock);
		return TRUE;
	}

	__WDS_LOG_FUNC_EXIT__;
	return TRUE;
}

int wfd_client_handler_init(wfd_manager_s *manager)
{
	__WDS_LOG_FUNC_ENTER__;
	GList *clients = manager->clients;
	int res = 0;

	if (clients) {
		g_list_free(clients);
		clients = NULL;
	}

	res = _wfd_create_server_socket(manager);
	if (res < 0) {
		WDS_LOGE("Failed to create server socket");
		return -1;
	}

	GIOChannel *gio = g_io_channel_unix_new(manager->serv_sock);
	manager->client_handle = g_io_add_watch(gio, G_IO_IN,
							(GIOFunc) _wfd_accept_client, manager);
	g_io_channel_unref(gio);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_client_handler_deinit(wfd_manager_s *manager)
{
	__WDS_LOG_FUNC_ENTER__;
	GList *temp = NULL;
	wfd_client_s *client = NULL;

	// TODO: remove event source watching GIOChannel
	if (manager->serv_sock >= SOCK_FD_MIN)
		close(manager->serv_sock);
	manager->serv_sock = -1;
	g_source_remove(manager->client_handle);
	manager->client_handle = 0;

	temp = g_list_first(manager->clients);
	while(temp) {
		client = temp->data;
		if (client->ssock >= SOCK_FD_MIN)
			close(client->ssock);
		client->ssock = -1;
		if (client->asock >= SOCK_FD_MIN)
			close(client->asock);
		client->asock = -1;
		g_source_remove(client->gsource_id);
		client->gsource_id = 0;
		free(client);
		temp = g_list_next(temp);
	}
	g_list_free(manager->clients);

	manager->client_count = 0;
	manager->clients = NULL;
	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

static gboolean wfd_client_process_request(GIOChannel *source,
									GIOCondition condition,
									gpointer user_data)
{
	__WDS_LOG_FUNC_ENTER__;
	int sock = (int) user_data;
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	char *extra_rsp = NULL;
	wifi_direct_client_noti_s *noti = NULL;
	wfd_manager_s *manager = wfd_get_manager();
	int res = 0;

	if (sock < SOCK_FD_MIN) {
		WDS_LOGE("Invalid argument");
		__WDS_LOG_FUNC_EXIT__;
		return FALSE;
	}

	memset(&req, 0x0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0x0, sizeof(wifi_direct_client_response_s));

	res = _wfd_read_from_client(sock, (char*) &req, sizeof(req));
	if (res < 0) {
		WDS_LOGE("Client socket Hanged up");
		_wfd_deregister_client(manager, req.client_id);
		__WDS_LOG_FUNC_EXIT__;
		return FALSE;
	} else if (res == 0) {
		WDS_LOGE("Client socket busy");
		return TRUE;
	}
	WDS_LOGD("Client request [%d:%s], %d bytes read from socket[%d]", req.cmd, wfd_server_print_cmd(req.cmd), res, sock);

	rsp.cmd = req.cmd;
	rsp.client_id = req.client_id;
	rsp.result = WIFI_DIRECT_ERROR_NONE;

	switch (req.cmd) {
	case WIFI_DIRECT_CMD_DEREGISTER:	// manager
		_wfd_send_to_client(sock, (char*) &rsp, sizeof(rsp));

		res = _wfd_deregister_client(manager, req.client_id);
		if (res < 0) {
			WDS_LOGE("Failed to deregister client[%d]", sock);
		}

		goto done;
		break;
	case WIFI_DIRECT_CMD_ACTIVATE:	// manager (event)
		if (manager->state > WIFI_DIRECT_STATE_DEACTIVATED) {
			rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			break;
		}
		rsp.result = wfd_util_wifi_direct_activatable();
		if (rsp.result < 0)
			break;

		res = _wfd_send_to_client(sock, (char*) &rsp, sizeof(rsp));
		if (res < 0) {
			WDS_LOGE("Failed to send response to client");
			_wfd_deregister_client(manager, req.client_id);
			__WDS_LOG_FUNC_EXIT__;
			return FALSE;
		}

		noti = (wifi_direct_client_noti_s*) calloc(1, sizeof(wifi_direct_client_noti_s));
		noti->event = WIFI_DIRECT_CLI_EVENT_ACTIVATION;
		noti->error = wfd_manager_activate(manager);
		res = wfd_client_send_event(manager, noti);
		if (res < 0) {
			WDS_LOGE("Failed to send Notification to client");
			free(noti);
			__WDS_LOG_FUNC_EXIT__;
			return FALSE;
		}
		WDS_LOGD("Succeeded to send Notification[%d] to client", noti->event);

		if (noti->error == WIFI_DIRECT_ERROR_NONE) {
			wfd_manager_local_config_set(manager);
			wfd_util_start_wifi_direct_popup();
		}
		free(noti);

		goto done;
		break;
	case WIFI_DIRECT_CMD_DEACTIVATE:	// manager (event)
		if (manager->state < WIFI_DIRECT_STATE_ACTIVATED) {
			rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			break;
		}
		res = _wfd_send_to_client(sock, (char*) &rsp, sizeof(rsp));
		if (res < 0) {
			WDS_LOGE("Failed to send response to client");
			_wfd_deregister_client(manager, req.client_id);
			__WDS_LOG_FUNC_EXIT__;
			return FALSE;
		}

		noti = (wifi_direct_client_noti_s*) calloc(1, sizeof(wifi_direct_client_noti_s));
		noti->event = WIFI_DIRECT_CLI_EVENT_DEACTIVATION;
		noti->error = wfd_manager_deactivate(manager);
		res = wfd_client_send_event(manager, noti);
		if (res < 0) {
			WDS_LOGE("Failed to send Notification to client");
			free(noti);
			__WDS_LOG_FUNC_EXIT__;
			return FALSE;
		}
		WDS_LOGD("Succeeded to send Notification[%d] to client", noti->event);
		free(noti);
		wfd_state_set(manager, WIFI_DIRECT_STATE_DEACTIVATED);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_DEACTIVATED);

		wfd_destroy_group(manager, GROUP_IFNAME);
		wfd_destroy_session(manager);
		wfd_manager_init_service(manager->local);
		wfd_manager_init_query(manager);
		if(manager->local->wifi_display)
		{
			free(manager->local->wifi_display);
			manager->local->wifi_display = NULL;
		}
		wfd_peer_clear_all(manager);
		WDS_LOGD("peer count[%d], peers[%d]", manager->peer_count, manager->peers);
		wfd_local_reset_data(manager);
		goto done;
		break;
	case WIFI_DIRECT_CMD_GET_LINK_STATUS:
		rsp.param1 = manager->state;
		break;
	case WIFI_DIRECT_CMD_START_DISCOVERY:
		{
			if (manager->state != WIFI_DIRECT_STATE_ACTIVATED &&
					manager->state != WIFI_DIRECT_STATE_DISCOVERING &&
					manager->state != WIFI_DIRECT_STATE_GROUP_OWNER) {
				WDS_LOGE("Wi-Fi Direct is not available status for scanning.");
				rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
				break;
			}

			wfd_oem_scan_param_s param;
			memset(&param, 0x0, sizeof(wfd_oem_scan_param_s));
			if (req.data.int1)	// listen_only
				param.scan_mode = WFD_OEM_SCAN_MODE_PASSIVE;
			else
				param.scan_mode = WFD_OEM_SCAN_MODE_ACTIVE;
			param.scan_time = req.data.int2;	// timeout
			if (manager->local->dev_role == WFD_DEV_ROLE_GO)
				param.scan_type = WFD_OEM_SCAN_TYPE_SOCIAL;

			res = wfd_oem_start_scan(manager->oem_ops, &param);
			if (res < 0) {
				WDS_LOGE("Failed to start scan");
				rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
				break;
			}
			WDS_LOGE("Succeeded to start scan");
			wfd_state_set(manager, WIFI_DIRECT_STATE_DISCOVERING);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_DISCOVERING);

			noti = (wifi_direct_client_noti_s*) calloc(1, sizeof(wifi_direct_client_noti_s));
			if (req.data.int1) {
				noti->event = WIFI_DIRECT_CLI_EVENT_DISCOVER_START_LISTEN_ONLY;
				manager->scan_mode = WFD_SCAN_MODE_PASSIVE;
			} else {
				noti->event = WIFI_DIRECT_CLI_EVENT_DISCOVER_START;
				manager->scan_mode = WFD_SCAN_MODE_ACTIVE;
			}
			noti->error = WIFI_DIRECT_ERROR_NONE;
		}
		break;
	case WIFI_DIRECT_CMD_CANCEL_DISCOVERY:
		if (manager->state != WIFI_DIRECT_STATE_ACTIVATED &&
				manager->state != WIFI_DIRECT_STATE_DISCOVERING) {
			rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			break;
		}

		res = wfd_oem_stop_scan(manager->oem_ops);
		if (res < 0) {
			WDS_LOGE("Failed to stop scan");
			rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			break;
		}
		WDS_LOGE("Succeeded to stop scan");

		noti = (wifi_direct_client_noti_s*) calloc(1, sizeof(wifi_direct_client_noti_s));
		noti->event = WIFI_DIRECT_CLI_EVENT_DISCOVER_END;
		noti->error = WIFI_DIRECT_ERROR_NONE;
		if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
			wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
		} else {
			wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
		}

		break;
	case WIFI_DIRECT_CMD_IS_LISTENING_ONLY:
		rsp.param1 = manager->scan_mode == WFD_SCAN_MODE_PASSIVE;
		break;
	case WIFI_DIRECT_CMD_GET_DISCOVERY_RESULT:
		{
			wfd_discovery_entry_s *peers = NULL;
			int peer_cnt = 0;
			peer_cnt = wfd_manager_get_peers(manager, &peers);
			WDS_LOGD("Peer count [%d], Peer list [%x]", peer_cnt, peers);
			if (peer_cnt < 0) {
				WDS_LOGE("Failed to get scan result");
				rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
				break;
			}
			rsp.param1 = peer_cnt;
			rsp.result = WIFI_DIRECT_ERROR_NONE;

			rsp.data_length = peer_cnt * sizeof(wfd_discovery_entry_s);
			extra_rsp = (char*) peers;
			WDS_LOGD("extra_rsp length [%d], extra_rsp [%x]", rsp.data_length, extra_rsp);
		}
		break;
	case WIFI_DIRECT_CMD_CONNECT: //session (event)
		{
			if (manager->state != WIFI_DIRECT_STATE_ACTIVATED &&
					manager->state != WIFI_DIRECT_STATE_DISCOVERING &&
					manager->state != WIFI_DIRECT_STATE_GROUP_OWNER) {
				rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
				break;
			}

			wfd_group_s *group = (wfd_group_s*) manager->group;
			if (group && group->member_count >= manager->max_station) {
				rsp.result = WIFI_DIRECT_ERROR_TOO_MANY_CLIENT;
				break;
			}

			res = _wfd_send_to_client(sock, (char*) &rsp, sizeof(rsp));
			if (res < 0) {
				WDS_LOGE("Failed to send response to client");
				_wfd_deregister_client(manager, req.client_id);
				__WDS_LOG_FUNC_EXIT__;
				return FALSE;
			}

			noti = (wifi_direct_client_noti_s*) calloc(1, sizeof(wifi_direct_client_noti_s));
			res = wfd_manager_connect(manager, req.data.mac_addr);
			if (res < 0) {
				WDS_LOGE("Failed to connet with peer " MACSTR, MAC2STR(req.data.mac_addr));
				noti->event = WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP;
				noti->error = WIFI_DIRECT_ERROR_OPERATION_FAILED;
				snprintf(noti->param1, MACSTR_LEN, MACSTR, MAC2STR(req.data.mac_addr));
			} else {
				noti->event = WIFI_DIRECT_CLI_EVENT_CONNECTION_START;
				noti->error = WIFI_DIRECT_ERROR_NONE;
				snprintf(noti->param1, MACSTR_LEN, MACSTR, MAC2STR(req.data.mac_addr));
			}
			goto send_notification;
		}
		break;
	case WIFI_DIRECT_CMD_SEND_CONNECT_REQ:
		{
			// TODO: check state
			wfd_group_s *group = (wfd_group_s*) manager->group;
			if (group && group->member_count >= manager->max_station) {
				rsp.result = WIFI_DIRECT_ERROR_TOO_MANY_CLIENT;
				goto send_response;
			}

			res = _wfd_send_to_client(sock, (char*) &rsp, sizeof(rsp));
			if (res < 0) {
				WDS_LOGE("Failed to send response to client");
				_wfd_deregister_client(manager, req.client_id);
				__WDS_LOG_FUNC_EXIT__;
				return FALSE;
			}

			noti = (wifi_direct_client_noti_s*) calloc(1, sizeof(wifi_direct_client_noti_s));
			res = wfd_manager_accept_connection(manager, req.data.mac_addr);
			if (res < 0) {
				WDS_LOGE("Failed to connet with peer " MACSTR, MAC2STR(req.data.mac_addr));
				noti->event = WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP;
				noti->error = WIFI_DIRECT_ERROR_OPERATION_FAILED;
				snprintf(noti->param1, MACSTR_LEN, MACSTR, MAC2STR(req.data.mac_addr));
			} else {
				noti->event = WIFI_DIRECT_CLI_EVENT_CONNECTION_START;
				noti->error = WIFI_DIRECT_ERROR_NONE;
				snprintf(noti->param1, MACSTR_LEN, MACSTR, MAC2STR(req.data.mac_addr));
			}
			goto send_notification;
		}
		break;
	case WIFI_DIRECT_CMD_CANCEL_CONNECTION:
		{
			if (!manager->session || manager->state != WIFI_DIRECT_STATE_CONNECTING) {
				WDS_LOGE("It's not CONNECTING state");
				rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
				break;
			}

			res = _wfd_send_to_client(sock, (char*) &rsp, sizeof(rsp));
			if (res < 0) {
				WDS_LOGE("Failed to send response to client");
				_wfd_deregister_client(manager, req.client_id);
				__WDS_LOG_FUNC_EXIT__;
				return FALSE;
			}

			res = wfd_manager_cancel_connection(manager, req.data.mac_addr);
			if (res < 0)
				WDS_LOGE("Failed to cancel connection");

			noti = (wifi_direct_client_noti_s*) calloc(1, sizeof(wifi_direct_client_noti_s));
			noti->event = WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP;
			noti->error = WIFI_DIRECT_ERROR_CONNECTION_CANCELED;
			snprintf(noti->param1, MACSTR_LEN, MACSTR, MAC2STR(req.data.mac_addr));
			goto send_notification;
		}
		break;
	case WIFI_DIRECT_CMD_REJECT_CONNECTION:
		{
			wfd_session_s *session = (wfd_session_s*) manager->session;

			if (!session || manager->state != WIFI_DIRECT_STATE_CONNECTING) {
				WDS_LOGE("It's not permitted with this state [%d]", manager->state);
				rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
				break;
			}

			if (session->direction != SESSION_DIRECTION_INCOMING) {
				WDS_LOGE("Only incomming session can be rejected");
				rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
				break;
			}

			res = _wfd_send_to_client(sock, (char*) &rsp, sizeof(rsp));
			if (res < 0) {
				WDS_LOGE("Failed to send response to client");
				_wfd_deregister_client(manager, req.client_id);
				__WDS_LOG_FUNC_EXIT__;
				return FALSE;
			}

			res = wfd_manager_reject_connection(manager, req.data.mac_addr);
			if (res < 0) {
				WDS_LOGE("Failed to reject connection");
				// TODO: check whether set state and break
			}

			noti = (wifi_direct_client_noti_s*) calloc(1, sizeof(wifi_direct_client_noti_s));
			noti->event = WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP;
			noti->error = WIFI_DIRECT_ERROR_CONNECTION_CANCELED;
			snprintf(noti->param1, MACSTR_LEN, MACSTR, MAC2STR(req.data.mac_addr));
			goto send_notification;
		}
		break;
	case WIFI_DIRECT_CMD_DISCONNECT:	// group, session
		{
			if (!manager->group || manager->state < WIFI_DIRECT_STATE_CONNECTED) {
				WDS_LOGE("It's not permitted with this state [%d]", manager->state);
				rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
				break;
			}

			res = _wfd_send_to_client(sock, (char*) &rsp, sizeof(rsp));
			if (res < 0) {
				WDS_LOGE("Failed to send response to client");
				_wfd_deregister_client(manager, req.client_id);
				__WDS_LOG_FUNC_EXIT__;
				return FALSE;
			}

			noti = (wifi_direct_client_noti_s*) calloc(1, sizeof(wifi_direct_client_noti_s));
			noti->event = WIFI_DIRECT_CLI_EVENT_DISCONNECTION_RSP;
			noti->error = wfd_manager_disconnect(manager, req.data.mac_addr);
			snprintf(noti->param1, MACSTR_LEN, MACSTR, MAC2STR(req.data.mac_addr));
			goto send_notification;
		}
		break;
	case WIFI_DIRECT_CMD_DISCONNECT_ALL:
		{
			if (!manager->group || manager->state < WIFI_DIRECT_STATE_CONNECTED) {
				WDS_LOGD("It's not connected state [%d]", manager->state);
				rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
				break;
			}

			res = _wfd_send_to_client(sock, (char*) &rsp, sizeof(rsp));
			if (res < 0) {
				WDS_LOGE("Failed to send response to client");
				_wfd_deregister_client(manager, req.client_id);
				__WDS_LOG_FUNC_EXIT__;
				return FALSE;
			}

			noti = (wifi_direct_client_noti_s*) calloc(1, sizeof(wifi_direct_client_noti_s));
			noti->event = WIFI_DIRECT_CLI_EVENT_DISCONNECTION_RSP;
			noti->error = wfd_manager_disconnect_all(manager);
			goto send_notification;
		}
		break;
	case WIFI_DIRECT_CMD_GET_CONNECTED_PEERS_INFO:
		{
			// even though status is not CONNECTED, this command can be excuted only when group exist
			if (!manager->group && manager->state < WIFI_DIRECT_STATE_CONNECTED) {
				WDS_LOGD("It's not connected state [%d]", manager->state);
				rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
				break;
			}

			wfd_connected_peer_info_s *peers = NULL;
			int peer_cnt = 0;
			peer_cnt = wfd_manager_get_connected_peers(manager, &peers);
			WDS_LOGD("Peer count [%d], Peer list [%x]", peer_cnt, peers);
			if (peer_cnt < 0) {
				WDS_LOGE("Failed to get scan result");
				rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
				break;
			}
			rsp.param1 = peer_cnt;
			rsp.result = WIFI_DIRECT_ERROR_NONE;

			rsp.data_length = peer_cnt * sizeof(wfd_connected_peer_info_s);
			extra_rsp = (char*) peers;
			WDS_LOGD("extra_rsp length [%d], extra_rsp [%x]", rsp.data_length, extra_rsp);
		}
		break;
	case WIFI_DIRECT_CMD_GET_IP_ADDR:	// group
		res = wfd_local_get_ip_addr(rsp.param2);
		if (res < 0) {
			WDS_LOGE("Failed to get local IP address");
			rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
		break;
	case WIFI_DIRECT_CMD_CREATE_GROUP:	// group
		{
			wfd_group_s *group = manager->group;
			if (group || manager->state < WIFI_DIRECT_STATE_ACTIVATED) {
				WDS_LOGE("Group already exist");
				rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
				break;
			}

			group = wfd_create_pending_group(manager, manager->local->intf_addr);
			if (!group) {
				WDS_LOGE("Failed to create pending group");
				rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
				break;
			}
			group->flags |= WFD_GROUP_FLAG_AUTONOMOUS;
			manager->group = group;
			WDS_LOGD("Succeeded to create pending group");

			res = wfd_oem_create_group(manager->oem_ops, 0, 0);
			if (res < 0) {
				WDS_LOGE("Failed to create group");
				wfd_destroy_group(manager, GROUP_IFNAME);
				rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			}
		}
		break;
	case WIFI_DIRECT_CMD_DESTROY_GROUP:
		{
			wfd_group_s *group = manager->group;
			if (!group && manager->state < WIFI_DIRECT_STATE_CONNECTED) {
				WDS_LOGE("Group not exist");
				rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
				break;
			}

			res = wfd_oem_destroy_group(manager->oem_ops, group->ifname);
			if (res < 0) {
				WDS_LOGE("Failed to destroy group");
				rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
				break;
			}

			res = wfd_destroy_group(manager, group->ifname);
			if (res < 0)
				WDS_LOGE("Failed to destroy group");

			wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);

			noti = (wifi_direct_client_noti_s*) calloc(1, sizeof(wifi_direct_client_noti_s));
			noti->event = WIFI_DIRECT_CLI_EVENT_GROUP_DESTROY_RSP;
			noti->error = WIFI_DIRECT_ERROR_NONE;
		}
		break;
	case WIFI_DIRECT_CMD_IS_GROUPOWNER:
		{
			wfd_device_s *local = manager->local;
			rsp.param1 = local->dev_role == WFD_DEV_ROLE_GO;
		}
		break;
	case WIFI_DIRECT_CMD_IS_AUTONOMOUS_GROUP:
		{
			wfd_group_s *group = manager->group;
			if (!group) {
				WDS_LOGE("Group not exist");
				rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
				break;
			}
			rsp.param1 = group->flags & WFD_GROUP_FLAG_AUTONOMOUS;
		}
		break;
	case WIFI_DIRECT_CMD_IS_PERSISTENT_GROUP:
		{
			wfd_group_s *group = manager->group;
			if (!group) {
				WDS_LOGE("Group not exist");
				rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
				break;
			}
			rsp.param1 = group->flags & WFD_GROUP_FLAG_PERSISTENT;
		}
		break;
	case WIFI_DIRECT_CMD_GET_OPERATING_CHANNEL:
		{
			wfd_group_s *group = manager->group;
			if (!group) {
				WDS_LOGE("Group not exist");
				rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
				break;
			}
			rsp.param1 = wfd_util_freq_to_channel(group->freq);
			// TODO: check channel value
		}
		break;
	case WIFI_DIRECT_CMD_GET_PERSISTENT_GROUP_INFO:	// group
		{
			if (manager->state < WIFI_DIRECT_STATE_ACTIVATED) {
				WDS_LOGE("Wi-Fi Direct is not activated.");
				rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
				break;
			}

			int persistent_group_count = 0;
			wfd_persistent_group_info_s *plist;

			res = wfd_oem_get_persistent_groups(manager->oem_ops, &plist, &persistent_group_count);
			if (res < 0) {
				WDS_LOGE("Error!! wfd_oem_get_persistent_group_info() failed..");
				rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
				break;
			}

			rsp.param1 = persistent_group_count;
			rsp.result = WIFI_DIRECT_ERROR_NONE;
			rsp.data_length = persistent_group_count * sizeof(wfd_persistent_group_info_s);
			extra_rsp = (char*) plist;
			WDS_LOGD("extra_rsp length [%d], extra_rsp [%x]", rsp.data_length, extra_rsp);
		}
		break;
	case WIFI_DIRECT_CMD_ACTIVATE_PERSISTENT_GROUP:
		if (manager->state < WIFI_DIRECT_STATE_ACTIVATED) {
			WDS_LOGE("Wi-Fi Direct is not activated.");
			rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			break;
		}

		res = wfd_oem_set_persistent_reconnect(manager->oem_ops, NULL, TRUE);
		if (res < 0) {
			WDS_LOGE("Failed to activate persistent group");
			rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
		break;
	case WIFI_DIRECT_CMD_DEACTIVATE_PERSISTENT_GROUP:
		if (manager->state < WIFI_DIRECT_STATE_ACTIVATED) {
			WDS_LOGE("Wi-Fi Direct is not activated.");
			rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			break;
		}

		res = wfd_oem_set_persistent_reconnect(manager->oem_ops, NULL, FALSE);
		if (res < 0) {
			WDS_LOGE("Failed to activate persistent group");
			rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
		break;
	case WIFI_DIRECT_CMD_REMOVE_PERSISTENT_GROUP:	// group
		{
			wfd_persistent_group_info_s persistent_group;

			if (manager->state < WIFI_DIRECT_STATE_ACTIVATED) {
				WDS_LOGE("Wi-Fi Direct is not activated.");
				rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
				_wfd_read_from_client(sock, (char*) &persistent_group, sizeof(wfd_persistent_group_info_s));
				break;
			}

			res = _wfd_read_from_client(sock, (char*) &persistent_group, sizeof(wfd_persistent_group_info_s));
			if (res == -2) {
				WDS_LOGE("Client socket Hanged up");
				_wfd_deregister_client(manager, sock);
				return FALSE;
			} else if (res == -1) {
				WDS_LOGE("Failed to read socket [%d]", sock);
				return TRUE;
			}
			WDS_LOGD("Remove persistent group [%s]", persistent_group.ssid);

			res = wfd_oem_remove_persistent_group(manager->oem_ops,
									persistent_group.ssid, persistent_group.go_mac_address);
			if (res < 0) {
				WDS_LOGE("Failed to remove persistent group");
				rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			}
		}
		break;
	case WIFI_DIRECT_CMD_GET_SSID:
	case WIFI_DIRECT_CMD_GET_DEVICE_NAME:	// manager (sync)
		res = wfd_local_get_dev_name(rsp.param2);
		if (res < 0) {
			WDS_LOGE("Failed to get device name");
			rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
		break;
	case WIFI_DIRECT_CMD_SET_SSID:
	case WIFI_DIRECT_CMD_SET_DEVICE_NAME:	// manager (sync)
		{
			char dev_name[WIFI_DIRECT_MAX_DEVICE_NAME_LEN] = {0, };
			res = _wfd_read_from_client(sock, dev_name, WIFI_DIRECT_MAX_DEVICE_NAME_LEN);
			if (res < 0) {
				WDS_LOGE("Failed to set device name");
				rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
				break;
			}

			res = wfd_local_set_dev_name(dev_name);
			if (res < 0) {
				WDS_LOGE("Failed to set device name");
				rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			}
		}
		break;
	case WIFI_DIRECT_CMD_GET_DEVICE_MAC:	// manager (sync)
		{
			unsigned char mac[MACADDR_LEN] = {0, };
			res = wfd_local_get_dev_mac(mac);
			if (res < 0) {
				WDS_LOGE("Failed to get device mac");
				rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
				break;
			}
			memcpy(rsp.param2, mac, sizeof(mac));
		}
		break;
	case WIFI_DIRECT_CMD_GET_GO_INTENT:	// manager (sync)
		res = wfd_manager_get_go_intent(&rsp.param1);
		if (res < 0) {
			WDS_LOGE("Failed to get GO intent");
			rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
		break;
	case WIFI_DIRECT_CMD_SET_GO_INTENT:	// manager (sync)
		res = wfd_manager_set_go_intent(req.data.int1);
		if (res < 0) {
			WDS_LOGE("Failed to set GO intent");
			rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
		break;
	case WIFI_DIRECT_CMD_GET_MAX_CLIENT:
		res = wfd_manager_get_max_station(&rsp.param1);
		if (res < 0) {
			WDS_LOGE("Failed to get max station");
			rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
		break;
	case WIFI_DIRECT_CMD_SET_MAX_CLIENT:
		res = wfd_manager_set_max_station(req.data.int1);
		if (res < 0) {
			WDS_LOGE("Failed to set max station");
			rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
		break;
	case WIFI_DIRECT_CMD_IS_AUTOCONNECTION_MODE:
		res = wfd_manager_get_autoconnection(&rsp.param1);
		if (res < 0) {
			WDS_LOGE("Failed to get autoconnection");
			rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
		break;
	case WIFI_DIRECT_CMD_SET_AUTOCONNECTION_MODE:	// manager (sync)
		res = wfd_manager_set_autoconnection(req.data.int1);
		if (res < 0) {
			WDS_LOGE("Failed to set autoconnection");
			rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
		break;
	case WIFI_DIRECT_CMD_IS_DISCOVERABLE:
		if (manager->state == WIFI_DIRECT_STATE_DISCOVERING
				|| wfd_group_is_autonomous(manager->group) == 1)
			rsp.param1 = TRUE;
		else
			rsp.param1 = FALSE;
		break;
	case WIFI_DIRECT_CMD_GET_SUPPORTED_WPS_MODE:	// manager (sync)
		res = wfd_local_get_supported_wps_mode(&rsp.param1);
		if (res < 0) {
			WDS_LOGE("Failed to get supported wps mode");
			rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
		break;
	case WIFI_DIRECT_CMD_GET_LOCAL_WPS_MODE:
		res = wfd_local_get_wps_mode(&rsp.param1);
		if (res < 0) {
			WDS_LOGE("Failed to get wps mode");
			rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
		break;
	case WIFI_DIRECT_CMD_GET_REQ_WPS_MODE:
		res = wfd_manager_get_req_wps_mode(&rsp.param1);
		if (res < 0) {
			WDS_LOGE("Failed to get request wps mode");
			rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
		break;
	case WIFI_DIRECT_CMD_SET_REQ_WPS_MODE:
		res = wfd_manager_set_req_wps_mode(req.data.int1);
		if (res < 0) {
			WDS_LOGE("Failed to set request wps mode");
			rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
		break;
	case WIFI_DIRECT_CMD_ACTIVATE_PUSHBUTTON:
		if (manager->local->dev_role != WFD_DEV_ROLE_GO) {
			WDS_LOGE("Wi-Fi Direct is not Group Owner.");
			rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			break;
		}

		res = wfd_oem_wps_start(manager->oem_ops, NULL, WFD_WPS_MODE_PBC, NULL);
		if (res < 0) {
			WDS_LOGE("Failed to start wps");
			rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
		break;
	case WIFI_DIRECT_CMD_GET_PASSPHRASE:
		{
			wfd_group_s *group = manager->group;
			if (!group) {
				WDS_LOGE("Group not exist");
				rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
				break;
			}
			if (group->role == WFD_DEV_ROLE_GC) {
				WDS_LOGE("Device is not GO");
				rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
				break;
			}
			snprintf(rsp.param2, PASSPHRASE_LEN, "%s", group->pass);
		}
		break;
	case WIFI_DIRECT_CMD_GET_WPS_PIN:	// session
		{
			wfd_session_s *session = (wfd_session_s*) manager->session;
			if (!session) {
				WDS_LOGE("Session not exist");
				rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
				break;
			}

			if (session->wps_pin[0] == '\0') {
				WDS_LOGE("WPS PIN is not set");
				rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
				break;
			}
			snprintf(rsp.param2, sizeof(rsp.param2), "%s", session->wps_pin);
		}
		break;
	case WIFI_DIRECT_CMD_SET_WPS_PIN:	// session
		{
			char pin[PINSTR_LEN+1] = {0, };
			wfd_session_s *session = (wfd_session_s*) manager->session;
			if (!session) {
				WDS_LOGE("Session not exist");
				rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
				_wfd_read_from_client(sock, pin, PINSTR_LEN);
				break;
			}

			res = _wfd_read_from_client(sock, session->wps_pin, PINSTR_LEN);
			if (res == -2) {
				WDS_LOGE("Client socket Hanged up");
				_wfd_deregister_client(manager, sock);
				return FALSE;
			} else if (res == -1) {
				WDS_LOGE("Failed to read socket [%d]", sock);
				return TRUE;
			}
			session->wps_pin[PINSTR_LEN] = '\0';
			WDS_LOGD("PIN string [%s]", session->wps_pin);
		}
		break;
	case WIFI_DIRECT_CMD_GENERATE_WPS_PIN:	// manager
		// TODO: implement in plugin
		break;
	case WIFI_DIRECT_CMD_SERVICE_ADD:
		{
			char *buff = NULL;

			buff = (char *)calloc(sizeof(char), req.cmd_data_len);
			res = _wfd_read_from_client(sock, buff, req.cmd_data_len);
			if (res < 0) {
				WDS_LOGE("Failed to get service data");
				rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
				free(buff);
				break;
			}

			res = wfd_manager_service_add(manager, req.data.int1, buff);
			if (res < 0) {
				WDS_LOGE("Failed to add service");
				rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			}

			free(buff);
		}
		break;
	case WIFI_DIRECT_CMD_SERVICE_DEL:
		{
			char *buff = NULL;

			buff = (char *)calloc(sizeof(char),req.cmd_data_len);
			res = _wfd_read_from_client(sock, buff, req.cmd_data_len);
			if (res < 0) {
				WDS_LOGE("Failed to get service data");
				rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
				free(buff);
				break;
			}

			res = wfd_manager_service_del(manager, req.data.int1, buff);
			if (res < 0) {
				WDS_LOGE("Failed to delete service");
				rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			}

			free(buff);
		}
		break;
	case WIFI_DIRECT_CMD_SERV_DISC_REQ:
		{
			char *buff = NULL;

			if(req.cmd_data_len != 0)
			{
				buff = (char*)calloc(sizeof(char),req.cmd_data_len);
				res = _wfd_read_from_client(sock, buff, req.cmd_data_len);
				if (res < 0) {
					WDS_LOGE("Failed to get service data");
					rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
					free(buff);
					break;
				}
			}

			res = wfd_manager_serv_disc_req(manager,req.data.mac_addr, req.data.int1, buff);
			if (res < 0) {
				WDS_LOGE("Failed to requset service discovery");
				rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			}
			rsp.param1 = res;

			if(buff != NULL)
				free(buff);
		}
		break;
	case WIFI_DIRECT_CMD_SERV_DISC_CANCEL:
		{
			res = wfd_manager_serv_disc_cancel(manager, req.data.int1);
			if (res < 0) {
				WDS_LOGE("Failed to delete service cancel");
				rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			}
		}
		break;
	case WIFI_DIRECT_CMD_INIT_WIFI_DISPLAY:
		{
			int hdcp;

			res = _wfd_read_from_client(sock, (char *)&hdcp, req.cmd_data_len);
			if (res < 0) {
				WDS_LOGE("Failed to get hdcp data");
				rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
				break;
			}
			res = wfd_manager_init_wifi_display(req.data.int1, req.data.int2, hdcp);
			if (res < 0) {
				WDS_LOGE("Failed to initialize wifi display");
				rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			}
		}
		break;
	case WIFI_DIRECT_CMD_DEINIT_WIFI_DISPLAY:
		{
			res = wfd_manager_deinit_wifi_display();
			if (res < 0) {
				WDS_LOGE("Failed to deinitialize wifi display");
				rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			}
		}
		break;
	case WIFI_DIRECT_CMD_GET_DISPLAY_PORT:
		{
			res = wfd_local_get_display_port(&rsp.param1);
			if (res < 0) {
				WDS_LOGE("Failed to get local wifi display port");
				rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			}
		}
		break;
	case WIFI_DIRECT_CMD_GET_DISPLAY_TYPE:
		{
			res = wfd_local_get_display_type(&rsp.param1);
			if (res < 0) {
				WDS_LOGE("Failed to get local wifi display type");
				rsp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			}
		}
		break;
	default:
		WDS_LOGE("Unknown command[%d]", req.cmd);
		rsp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
		break;
	}

send_response:
	res = _wfd_send_to_client(sock, (char*) &rsp, sizeof(rsp));
	if (res < 0) {
		WDS_LOGE("Failed to send response to client");
		if (noti)
			free(noti);
		_wfd_deregister_client(manager, req.client_id);
		__WDS_LOG_FUNC_EXIT__;
		return FALSE;
	}

	if (rsp.data_length > 0) {
		res = _wfd_send_to_client(sock, (char*) extra_rsp, rsp.data_length);
		if (res < 0) {
			WDS_LOGE("Failed to send extra response data to client");
			free(extra_rsp);
			if (noti)
				free(noti);
			_wfd_deregister_client(manager, req.client_id);
			__WDS_LOG_FUNC_EXIT__;
			return FALSE;
		}
		if (extra_rsp)
			free(extra_rsp);
	}

send_notification:
	if (noti) {
		res = wfd_client_send_event(manager, noti);
		if (res < 0) {
			WDS_LOGE("Failed to send Notification to client");
			free(noti);
			__WDS_LOG_FUNC_EXIT__;
			return FALSE;
		}
		WDS_LOGD("Succeeded to send Notification[%d] to client", noti->event);
		free(noti);
	}

done:

	__WDS_LOG_FUNC_EXIT__;
	return TRUE;
}

