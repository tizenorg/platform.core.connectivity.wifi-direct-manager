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
 
#ifndef __WIFI_DIRECT_STUB_H_
#define __WIFI_DIRECT_STUB_H_

#include "wifi-direct-internal.h"
#include "wifi-direct-utils.h"

int wfd_server_is_fd_writable(int fd);
bool wfd_server_register_client(int sockfd);
void wfd_server_process_client_request(wifi_direct_client_request_s * client_req);
void wfd_server_reset_client(int sync_sockfd);
void wfd_server_print_client();
int wfd_server_read_socket_event(int sockfd, char* dataptr, int datalen);

#endif		//__WIFI_DIRECT_STUB_H_

