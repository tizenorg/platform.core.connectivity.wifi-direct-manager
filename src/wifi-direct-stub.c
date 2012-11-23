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
 
#include <glib.h>
#include <sys/poll.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/poll.h>

#include "wifi-direct-client-handler.h"
#include "wifi-direct-service.h"
#include "wifi-direct-internal.h"
#include "wifi-direct-stub.h"

bool wfd_server_client_request_callback(GIOChannel* source, GIOCondition condition, gpointer data);


int wfd_server_is_fd_writable(int fd)
{
	struct pollfd pevent;
	int retval = 0;

	pevent.fd = fd;
	pevent.events = POLLERR | POLLHUP | POLLNVAL | POLLOUT;
	retval = poll((struct pollfd *) &pevent, 1, 1);

	if (retval < 0)
	{
		WFD_SERVER_LOG(WFD_LOG_LOW, "fd [%d]: poll error ret=[%d] !!\n", fd, retval);
		return -1;
	}
	else if (retval == 0)
	{
		// fd might be busy.
		WFD_SERVER_LOG(WFD_LOG_LOW, "poll timeout. fd is busy\n");
		return 0;
	}

	if (pevent.revents & POLLERR)
	{
		WFD_SERVER_LOG(WFD_LOG_LOW, "fd [%d]: POLLERR !!\n", fd);
		return -1;
	}
	else if (pevent.revents & POLLHUP)
	{
		WFD_SERVER_LOG(WFD_LOG_LOW, "fd [%d]: POLLHUP !!\n", fd);
		return -1;
	}
	else if (pevent.revents & POLLNVAL)
	{
		WFD_SERVER_LOG(WFD_LOG_LOW, "fd [%d]: POLLNVAL !!\n", fd);
		return -1;
	}
	else if (pevent.revents & POLLOUT)
	{
		// fd is writable..
		// WFD_SERVER_LOG(WFD_LOG_LOW, "fd [%d]: POLLOUT !!\n", fd);
		return 1;
	}

	return -1;
}


int wfd_server_read_socket_event(int sockfd, char *dataptr, int datalen)
{
	int pollret = 0;
	struct pollfd pollfd;
	int timeout = 1000;			/* For 1 sec */
	int retval = 0;
	int total_data_recd = 0;

	__WFD_SERVER_FUNC_ENTER__;

	if (sockfd < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "Error!!! Invalid socket FD [%d]\n", sockfd);
		__WFD_SERVER_FUNC_EXIT__;
		return -1;
	}

	pollfd.fd = sockfd;
	pollfd.events = POLLIN | POLLERR | POLLHUP;
	pollret = poll(&pollfd, 1, timeout);

	WFD_SERVER_LOG(WFD_LOG_LOW, "POLL ret = %d\n", pollret);

	if (pollret > 0)
	{
		if (pollfd.revents == POLLIN)
		{
			WFD_SERVER_LOG(WFD_LOG_LOW, "POLLIN \n");

			while (datalen)
			{
				errno = 0;
				retval = read(sockfd, (char*)dataptr, datalen);
				WFD_SERVER_LOG( WFD_LOG_LOW, "sockfd %d retval %d\n",sockfd,retval);
				if (retval <= 0)
				{
					WFD_SERVER_LOG( WFD_LOG_ERROR, "Error!!! reading data, error [%s]\n", strerror(errno));
					__WFD_SERVER_FUNC_EXIT__;
					return retval;
				}
				total_data_recd += retval;
				dataptr += retval;
				datalen -= retval;
			}
			__WFD_SERVER_FUNC_EXIT__;
			return total_data_recd;
		}
		else if (pollfd.revents & POLLHUP)
		{
			WFD_SERVER_LOG( WFD_LOG_ERROR, "Error!!! POLLHUP: connection disconnected fd=[%d]\n", sockfd);
			__WFD_SERVER_FUNC_EXIT__;
			return -1;
		}
		else if (pollfd.revents & POLLERR)
		{
			WFD_SERVER_LOG( WFD_LOG_ERROR, "Error!!! POLLERR: error happens at the socket. fd=[%d]\n", sockfd);
			__WFD_SERVER_FUNC_EXIT__;
			return -1;
		}
	}
	else if (pollret == 0)
	{
		WFD_SERVER_LOG(WFD_LOG_LOW, "POLLing timeout fd=[%d]\n", sockfd);
		__WFD_SERVER_FUNC_EXIT__;
		return -1;
	}
	else
	{
		WFD_SERVER_LOG( WFD_LOG_ERROR, "Error!!! Polling unknown error fd=[%d]\n", sockfd);
		__WFD_SERVER_FUNC_EXIT__;
		return -1;
	}

	__WFD_SERVER_FUNC_EXIT__;
	return 0;
}

void wfd_server_reset_client(int sync_sockfd)
{
	wfd_server_control_t *wfd_server = wfd_server_get_control();
	int index = 0;

	__WFD_SERVER_FUNC_ENTER__;

	for (index = 0; index < WFD_MAX_CLIENTS; index++)
	{
		if ((wfd_server->client[index].isUsed == TRUE) &&
			(wfd_server->client[index].sync_sockfd == sync_sockfd))
		{
			WFD_SERVER_LOG( WFD_LOG_HIGH,
					"Reset client[%d]: ClientID=%d, socketfd=(%d,%d), handle=[%d] total active clients = [%d]\n",
					index,
					wfd_server->client[index].client_id,
					wfd_server->client[index].sync_sockfd,
					wfd_server->client[index].async_sockfd,
					wfd_server->client[index].dev_handle,
					wfd_server->active_clients-1);

			g_source_remove(wfd_server->client[index].g_source_id);

			// Protect standard input / output / error
			if (wfd_server->client[index].async_sockfd > 2)
				close(wfd_server->client[index].async_sockfd);

			if (wfd_server->client[index].sync_sockfd > 2)
				close(wfd_server->client[index].sync_sockfd);

			/* Reset Entity */
			wfd_server->client[index].isUsed = FALSE;
			wfd_server->client[index].client_id = -1;
			wfd_server->client[index].sync_sockfd = -1;
			wfd_server->client[index].async_sockfd = -1;
			wfd_server->client[index].g_source_id = -1;
			wfd_server->client[index].dev_handle = -1;

			wfd_server->active_clients--;

			wfd_termination_timer_start();

			wfd_server_print_client();

			__WFD_SERVER_FUNC_EXIT__;
			return;
		}
	}

	WFD_SERVER_LOG( WFD_LOG_EXCEPTION,
			"Error!!! Reset client fail: socketfd=%d is not found\n", sync_sockfd);
	__WFD_SERVER_FUNC_EXIT__;
	return;
}

void wfd_server_print_client()
{
	__WFD_SERVER_FUNC_ENTER__;
	
	wfd_server_control_t *wfd_server = wfd_server_get_control();
	int index = 0;

	WFD_SERVER_LOG( WFD_LOG_HIGH, "--------------------\n", wfd_server->active_clients-1);
	for (index = 0; index < WFD_MAX_CLIENTS; index++)
	{
		if (wfd_server->client[index].isUsed == TRUE)
		{
			WFD_SERVER_LOG(WFD_LOG_HIGH,
					"+ CLIENT[%d]: ClientID=%d, sktfd=(%d,%d), g_src_id= [%d]\n",
					index,
					wfd_server->client[index].client_id,
					wfd_server->client[index].sync_sockfd,
					wfd_server->client[index].async_sockfd,
					wfd_server->client[index].g_source_id
					);
		}
	}
	WFD_SERVER_LOG( WFD_LOG_HIGH, "Total active client=[%d]\n", wfd_server->active_clients);
	WFD_SERVER_LOG( WFD_LOG_HIGH, "--------------------\n");

	__WFD_SERVER_FUNC_EXIT__;
	return;
}



bool wfd_server_client_request_callback(GIOChannel* source, GIOCondition condition, gpointer data)
{
	int sockfd = (int) data;
	wifi_direct_client_request_s client_req;
	int req_len = sizeof(wifi_direct_client_request_s);

	__WFD_SERVER_FUNC_ENTER__;

	memset(&client_req, 0, req_len);

	if (wfd_server_read_socket_event(sockfd, (char *) &client_req, req_len) < 0)
	{
		wfd_server_reset_client(sockfd);
		__WFD_SERVER_FUNC_EXIT__;
		return FALSE;
	}

	wfd_server_process_client_request(&client_req);

	__WFD_SERVER_FUNC_EXIT__;
	return TRUE;
}


/* Function to connect client with wfd_server */
bool wfd_server_register_client(int sockfd)
{
	int index = 0;
	int status = 0;
	wifi_direct_client_request_s register_req;
	wifi_direct_client_response_s register_rsp;
	wfd_server_control_t *wfd_server = wfd_server_get_control();

	__WFD_SERVER_FUNC_ENTER__;

	if (sockfd <= 0)
	{
		// invalid socket fd should not be closed!!
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "Error!!! Invalid sockfd argument = [%d] \n", sockfd);
		__WFD_SERVER_FUNC_EXIT__;
		return TRUE;
	}

	/** Read the Register socket type*/
	errno = 0;
	status = read(sockfd, (char*)&register_req, sizeof(wifi_direct_client_request_s));
	if(status <= 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ERROR, "Error!!! reading data, error [%s]\n", strerror(errno));
		__WFD_SERVER_FUNC_EXIT__;
		return FALSE;
	}

	if (register_req.cmd == WIFI_DIRECT_CMD_REGISTER)
	{
		WFD_SERVER_LOG( WFD_LOG_LOW, "Client socket for sync data transfer, from client [%d] \n", register_req.client_id);

		for (index = 0; index < WFD_MAX_CLIENTS; index++)
		{
			if (wfd_server->client[index].isUsed == FALSE)
			{
				/*Send Client id to the application */
				int datasent = 0;

				memset(&register_rsp, 0, sizeof(wifi_direct_client_response_s));
				register_rsp.cmd = WIFI_DIRECT_CMD_REGISTER;
				register_rsp.client_id = sockfd;
				register_rsp.result = WIFI_DIRECT_ERROR_NONE;
				errno = 0;
				datasent = write(sockfd, (char*)&register_rsp, sizeof(wifi_direct_client_response_s));

				WFD_SERVER_LOG( WFD_LOG_LOW,
						"Written RSP of [%d] data into client socket [%d], errinfo [%s] \n",
						datasent, sockfd, strerror(errno));

				/** register socket watcher to g_main_loop */
				GIOChannel* gio;
				gio = g_io_channel_unix_new(sockfd);
				int source_id = g_io_add_watch(gio, G_IO_IN | G_IO_ERR | G_IO_HUP,
						(GIOFunc)wfd_server_client_request_callback, (gpointer)sockfd);

				/** Found Free Entity */
				wfd_server->client[index].isUsed = TRUE;
				wfd_server->client[index].client_id = sockfd;
				wfd_server->client[index].sync_sockfd = sockfd;
				wfd_server->client[index].g_source_id = source_id;

				wfd_server->active_clients++;

				WFD_SERVER_LOG( WFD_LOG_LOW, "Client stored in index [%d], total active clients = [%d]\n", index, wfd_server->active_clients);
				__WFD_SERVER_FUNC_EXIT__;
				return TRUE;
			}
		}

		if (index == WFD_MAX_CLIENTS)
		{
			int datasent = 0;
			memset(&register_rsp, 0, sizeof(wifi_direct_client_response_s));
			register_rsp.cmd = WIFI_DIRECT_CMD_REGISTER;
			register_rsp.client_id = sockfd;
			register_rsp.result = WIFI_DIRECT_ERROR_RESOURCE_BUSY;
			errno = 0;
			datasent = write(sockfd, (char*)&register_rsp, sizeof(wifi_direct_client_response_s));

			WFD_SERVER_LOG(WFD_LOG_ERROR, "Error!!! Too Many Client\n");
			__WFD_SERVER_FUNC_EXIT__;
			return FALSE;
		}
	}
	else if (register_req.cmd == WIFI_DIRECT_CMD_INIT_ASYNC_SOCKET)
	{
		WFD_SERVER_LOG( WFD_LOG_LOW, "Client socket for Async Event notification from client [%d]\n", register_req.client_id);

		for (index = 0; index < WFD_MAX_CLIENTS; index++)
		{
			if ((wfd_server->client[index].isUsed == TRUE)
				&& (wfd_server->client[index].client_id ==
					register_req.client_id))
			{
				wfd_server->client[index].async_sockfd = sockfd;

				WFD_SERVER_LOG( WFD_LOG_LOW, "Client stored in index [%d], total active clients = [%d]\n", index, wfd_server->active_clients);

				wfd_server_print_client();

				__WFD_SERVER_FUNC_EXIT__;
				return TRUE;
			}
		}

		if (index == WFD_MAX_CLIENTS)
		{
			WFD_SERVER_LOG(WFD_LOG_ERROR, "Error!!! Client not found \n");
			__WFD_SERVER_FUNC_EXIT__;
			return FALSE;
		}
	}
	else
	{
		WFD_SERVER_LOG( WFD_LOG_ERROR, "Error!!! Received unknown command [%d] \n", register_req.cmd);
		__WFD_SERVER_FUNC_EXIT__;
		return FALSE;
	}

	WFD_SERVER_LOG(WFD_LOG_ERROR, "Error!!! Unknown...\n");
	__WFD_SERVER_FUNC_EXIT__;
	return FALSE;
}
