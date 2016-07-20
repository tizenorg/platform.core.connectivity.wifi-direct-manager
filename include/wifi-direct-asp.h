/*
 * Network Configuration Module
 *
 * Copyright (c) 2016 Samsung Electronics Co., Ltd. All rights reserved.
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
 * This file declares wifi direct Application Service Platfrom(ASP) utility functions.
 *
 * @file        wifi-direct-asp.h
 * @author      Jiung Yu (jiung.yu@samsung.com)
 * @version     0.1
 */

#ifndef __WIFI_DIRECT_ASP_H__
#define __WIFI_DIRECT_ASP_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	ASP_CONNECT_STATUS_ROLE_REJECTED = -2,  /**< network role rejected */
	ASP_CONNECT_STATUS_NOMORE_CONNECT = -1,  /**< no more connect */
	ASP_CONNECT_STATUS_REQUEST_SENT = 0x01,  /**< session request sent */
	ASP_CONNECT_STATUS_REQUEST_RECEIVED = 0x02,  /**< session request received */
	ASP_CONNECT_STATUS_REQUEST_DEFERRED = 0x04,  /**< session request deferred */
	ASP_CONNECT_STATUS_REQUEST_ACCEPTED = 0x08,  /**< session request accepted */
	ASP_CONNECT_STATUS_REQUEST_FAILED = 0x10,  /**< session request failed */
	ASP_CONNECT_STATUS_GROUP_FORMATION_STARTED = 0x20,  /**< group formation started */
	ASP_CONNECT_STATUS_GROUP_FORMATION_COMPLETED = 0x40,  /**< group formation completed */
	ASP_CONNECT_STATUS_GROUP_FORMATION_FAILED = 0x80,  /**< group formation failed*/
} asp_connect_status_e;

void wfd_asp_session_request(wfd_oem_asp_prov_s *prov_param);
void wfd_asp_session_config_request(unsigned int session_id, int get_pin, char *pin);
void wfd_asp_connect_status(unsigned char *session_mac,
		unsigned int session_id, int status, char *deferred);

#ifdef __cplusplus
}
#endif

#endif /* __WIFI_DIRECT_ASP_H__ */
