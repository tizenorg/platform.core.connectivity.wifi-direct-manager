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
 * This file implements wifi direct manager functions.
 *
 * @file		wifi-direct-manager.c
 * @author	Gibyoung Kim (lastkgb.kim@samsung.com)
 * @version	0.7
 */

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/utsname.h>
#include <time.h>
#include <errno.h>

#include <glib.h>
#include <glib-object.h>

#include <wifi-direct.h>
#include <wifi-direct-internal.h>

#include "wifi-direct-manager.h"
#include "wifi-direct-oem.h"
#include "wifi-direct-session.h"
#include "wifi-direct-group.h"
#include "wifi-direct-peer.h"
#include "wifi-direct-state.h"
#include "wifi-direct-client.h"
#include "wifi-direct-event.h"
#include "wifi-direct-util.h"

wfd_manager_s *g_manager;

wfd_manager_s *wfd_get_manager()
{
	return g_manager;
}

static gboolean _wfd_exit_timeout_cb(void *user_data)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = (wfd_manager_s*) user_data;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		return TRUE;
	}

	if (manager->client_count > 0) {
		WDS_LOGD("Client count [%d]", manager->client_count);
		return TRUE;
	}

	if (manager->state == WIFI_DIRECT_STATE_DEACTIVATED) {
		WDS_LOGD("Terminate Wi-Fi Direct Manager");
		g_main_quit(manager->main_loop);
	}
	manager->exit_timer = 0;
	WDS_LOGD( "Stop exit timer. State [%d]", manager->state);

	__WDS_LOG_FUNC_EXIT__;
	return FALSE;
}

static int _wfd_local_init_device(wfd_manager_s *manager)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = NULL;
	int res = 0;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	errno = 0;
	local = (wfd_device_s*) calloc(1, sizeof(wfd_device_s));
	if (!local) {
		WDS_LOGE("Failed to allocate memory for local device [%s]", strerror(errno));
		return -1;
	}

	res = wfd_util_get_phone_name(local->dev_name);
	if (res < 0) {
		WDS_LOGE("Failed to get phone name of local device. Use default device name");
		strncpy(local->dev_name, DEFAULT_DEVICE_NAME, DEV_NAME_LEN);
		local->dev_name[DEV_NAME_LEN] = '\0';
	}
	WDS_LOGD("Local Device name [%s]", local->dev_name);
	wfd_util_set_dev_name_notification();

	res = wfd_util_get_local_dev_mac(local->dev_addr);
	if (res < 0) {
		WDS_LOGE("Failed to get local device MAC address");
	}

	memcpy(local->intf_addr, local->dev_addr, MACADDR_LEN);
	local->intf_addr[4] ^= 0x80;
	WDS_LOGD("Local Interface MAC address [" MACSTR "]", MAC2STR(local->intf_addr));

	local->config_methods = WFD_WPS_MODE_PBC | WFD_WPS_MODE_DISPLAY | WFD_WPS_MODE_KEYPAD;
	local->wps_mode = WFD_WPS_MODE_PBC;
	// TODO: initialize other local device datas
	manager->local = local;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

static int _wfd_local_deinit_device(wfd_manager_s *manager)
{
	__WDS_LOG_FUNC_ENTER__;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	wfd_util_unset_dev_name_notification();

	if (manager->local)
		free(manager->local);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_local_reset_data(wfd_manager_s *manager)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = manager->local;

	/* init local device data */
	local->dev_role = WFD_DEV_ROLE_NONE;
	local->wps_mode = WFD_WPS_MODE_PBC;
	memset(local->go_dev_addr, 0x0, MACADDR_LEN);
	memset(local->ip_addr, 0x0, IPADDR_LEN);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_local_get_dev_name(char *dev_name)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = g_manager->local;

	if (!dev_name) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	strncpy(dev_name, local->dev_name, DEV_NAME_LEN);
	dev_name[DEV_NAME_LEN-1] = '\0';
	WDS_LOGD("Local device name [%s]", dev_name);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_local_set_dev_name(char *dev_name)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = g_manager->local;

	if (!dev_name) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	strncpy(local->dev_name, dev_name, DEV_NAME_LEN);
	local->dev_name[DEV_NAME_LEN-1] = '\0';

	if (g_manager->state >= WIFI_DIRECT_STATE_ACTIVATED) {
		wfd_oem_set_dev_name(g_manager->oem_ops, dev_name);

		wfd_oem_scan_param_s param;
		param.scan_mode = WFD_OEM_SCAN_MODE_ACTIVE;
		param.scan_type = WFD_OEM_SCAN_TYPE_FULL;
		param.scan_time = 5;
		param.refresh = TRUE;
		wfd_oem_start_scan(g_manager->oem_ops, &param);
		g_manager->scan_mode = WFD_SCAN_MODE_ACTIVE;
		WDS_LOGD("Device name changed. Active scan started");
	}

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_local_get_dev_mac(unsigned char *dev_mac)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = g_manager->local;

	if (!dev_mac) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	memcpy(dev_mac, local->dev_addr, MACADDR_LEN);
	WDS_LOGD("Local device MAC address [" MACSTR "]", MAC2STR(dev_mac));

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_local_get_intf_mac(unsigned char *intf_mac)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = g_manager->local;

	if (!intf_mac) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	memcpy(intf_mac, local->intf_addr, MACADDR_LEN);
	WDS_LOGD("Local interface MAC address [" MACSTR "]", MAC2STR(intf_mac));

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_local_get_ip_addr(char *ip_str)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = g_manager->local;

	if (!ip_str) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	snprintf(ip_str, IPSTR_LEN, IPSTR, IP2STR(local->ip_addr));
	WDS_LOGD("Local IP address [" IPSTR "]", IP2STR(local->ip_addr));

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_local_get_supported_wps_mode(int *config_methods)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = g_manager->local;

	if (!config_methods) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	*config_methods = local->config_methods;
	WDS_LOGD("Local config method [0x%x]", *config_methods);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_local_get_wps_mode(int *wps_mode)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = g_manager->local;

	if (!wps_mode) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	*wps_mode = local->wps_mode;
	WDS_LOGD("Local wps mode [0x%x]", *wps_mode);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_local_set_wps_mode(int wps_mode)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = g_manager->local;

	if (!wps_mode) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	local->wps_mode = wps_mode;
	WDS_LOGD("Local wps mode [0x%x]", wps_mode);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_manager_get_go_intent(int *go_intent)
{
	__WDS_LOG_FUNC_ENTER__;
	if (!go_intent) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	*go_intent = g_manager->go_intent;
	WDS_LOGD("Local GO intent [%d]", *go_intent);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_manager_set_go_intent(int go_intent)
{
	__WDS_LOG_FUNC_ENTER__;

	if (go_intent < 0 || go_intent > 15) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	g_manager->go_intent = go_intent;
	if (g_manager->state >= WIFI_DIRECT_STATE_ACTIVATED)
		wfd_oem_set_go_intent(g_manager->oem_ops, go_intent);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_manager_get_max_station(int *max_station)
{
	__WDS_LOG_FUNC_ENTER__;

	if (!max_station) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	*max_station = g_manager->max_station;
	WDS_LOGD("Local max station[%d]", *max_station);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_manager_set_max_station(int max_station)
{
	__WDS_LOG_FUNC_ENTER__;

	if (max_station < 1) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	g_manager->max_station = max_station;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_manager_get_autoconnection(int *autoconnection)
{
	__WDS_LOG_FUNC_ENTER__;
	if (!autoconnection) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	*autoconnection = g_manager->autoconnection;
	WDS_LOGD("Local autoconnection [%s]", *autoconnection ? "TRUE":"FALSE");

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_manager_set_autoconnection(int autoconnection)
{
	__WDS_LOG_FUNC_ENTER__;
	if (autoconnection < 0) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	g_manager->autoconnection = autoconnection;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_manager_get_req_wps_mode(int *req_wps_mode)
{
	__WDS_LOG_FUNC_ENTER__;

	if (!req_wps_mode) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	*req_wps_mode = g_manager->req_wps_mode;
	WDS_LOGD("Requested wps mode [0x%x]", *req_wps_mode);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_manager_set_req_wps_mode(int req_wps_mode)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = g_manager->local;

	if (req_wps_mode != WIFI_DIRECT_WPS_TYPE_PBC &&
			req_wps_mode != WIFI_DIRECT_WPS_TYPE_PIN_DISPLAY &&
			req_wps_mode != WIFI_DIRECT_WPS_TYPE_PIN_KEYPAD) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	g_manager->req_wps_mode = req_wps_mode;
	WDS_LOGD("Requested wps mode [0x%x]", req_wps_mode);
	if (req_wps_mode == WFD_WPS_MODE_DISPLAY)
		local->wps_mode = WFD_WPS_MODE_KEYPAD;
	else if (req_wps_mode == WFD_WPS_MODE_KEYPAD)
		local->wps_mode = WFD_WPS_MODE_DISPLAY;
	else
		local->wps_mode = req_wps_mode;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_manager_local_config_set(wfd_manager_s *manager)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = NULL;
	int res = 0;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	local = manager->local;

	local->wps_mode = WFD_WPS_MODE_PBC;
	WDS_LOGD("Device name set as %s", local->dev_name);
	wfd_oem_set_dev_type(manager->oem_ops, local->pri_dev_type, local->sec_dev_type);
	wfd_oem_set_go_intent(manager->oem_ops, manager->go_intent);
	wfd_oem_set_dev_name(manager->oem_ops, local->dev_name);

	return WIFI_DIRECT_ERROR_NONE;
}

int wfd_local_get_display_port(int *port)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = g_manager->local;

	if (!port) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	if (!local->wifi_display) {
		WDS_LOGE("wifi display is not registered");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	*port = local->wifi_display->ctrl_port;
	WDS_LOGD("Local display port [%d]", *port);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_local_get_display_type(wifi_direct_display_type_e *type)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = g_manager->local;

	if (!type) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	if (!local->wifi_display) {
		WDS_LOGE("wifi display is not registered");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	*type = local->wifi_display->type;
	WDS_LOGD("Local display type [%d]", *type);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_manager_activate(wfd_manager_s *manager)
{
	__WDS_LOG_FUNC_ENTER__;
	int res = 0;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	if (manager->state > WIFI_DIRECT_STATE_ACTIVATING) {
		WDS_LOGE("Already activated");
		return 1;
	}

	wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATING);

	res = wfd_oem_activate(manager->oem_ops);
	if (res < 0) {
		WDS_LOGE("Failed to activate");
		wfd_state_set(manager, WIFI_DIRECT_STATE_DEACTIVATED);
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}
	WDS_LOGE("Succeeded to activate");

	wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
	wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);

	__WDS_LOG_FUNC_EXIT__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wfd_manager_deactivate(wfd_manager_s *manager)
{
	__WDS_LOG_FUNC_ENTER__;
	int res = 0;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	if (manager->state < WIFI_DIRECT_STATE_ACTIVATING) {
		WDS_LOGE("Already deactivated");
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}

	wfd_state_set(manager, WIFI_DIRECT_STATE_DEACTIVATING);

	res = wfd_oem_deactivate(manager->oem_ops);
	if (res < 0) {
		WDS_LOGE("Failed to deactivate");
		// TODO: check state setting is correct
		wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}
	WDS_LOGE("Succeeded to deactivate");

	wfd_state_set(manager, WIFI_DIRECT_STATE_DEACTIVATED);
	wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_DEACTIVATED);

	manager->req_wps_mode = WFD_WPS_MODE_PBC;

	__WDS_LOG_FUNC_EXIT__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wfd_manager_connect(wfd_manager_s *manager, unsigned char *peer_addr)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_session_s *session = NULL;
	int res = 0;

	if (!manager || !peer_addr) {
		WDS_LOGE("Invalid parameter");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	session = (wfd_session_s*) manager->session;
	if (session && session->type != SESSION_TYPE_INVITE) {
		WDS_LOGE("Session already exist or not an invitaion session");
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}

	if (!session) {
		session = wfd_create_session(manager, peer_addr,
					manager->req_wps_mode, SESSION_DIRECTION_OUTGOING);
		if (!session) {
			WDS_LOGE("Failed to create new session");
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	if (manager->local->dev_role == WFD_DEV_ROLE_GO && session->type != SESSION_TYPE_INVITE) {
		session->type = SESSION_TYPE_INVITE;
		res = wfd_session_invite(session);
	} else {
		/* joining to group or starting connection with PD */
		/* In case of invitation session PD should be started
		 * peer->dev_role == WFD_DEV_ROLE_GO
		 * session->direction == SESSION_DIRECTION_INCOMING
		 * session->invitation == TRUE;
		 */
		res = wfd_session_start(session);
	}
	if (res < 0) {
		WDS_LOGE("Failed to start session");
		wfd_destroy_session(manager);
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}
	wfd_state_set(manager, WIFI_DIRECT_STATE_CONNECTING);

	__WDS_LOG_FUNC_EXIT__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wfd_manager_accept_connection(wfd_manager_s *manager, unsigned char *peer_addr)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_session_s *session = NULL;
	wfd_device_s *peer = NULL;
	int res = 0;

	if (!manager || !peer_addr) {
		WDS_LOGE("Invalid parameter");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	session = (wfd_session_s*) manager->session;
	if (!session) {
		WDS_LOGE("Session not found");
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}

	peer = wfd_peer_find_by_dev_addr(manager, peer_addr);
	if (!peer) {
		WDS_LOGE("Peer is NULL");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	// TODO: check peer_addr with session's peer_addr

	if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
		/* Peer want to join my group(Peer sent PD) */
		WDS_LOGD("My device is GO and peer want to join my group, so WPS will be started");
		res = wfd_session_wps(session);
	} else if (peer->dev_role == WFD_DEV_ROLE_GO) {
		/* FIX ME: When Enter PIN or Display event comes up from supplicant
		 * manager send Connection WPS Req event to client.
		 * So, application use accept_connection API.
		 * This is odd situation. We need new client event such as WPS_KEYPAD/WPS_DISPLAY for application.
		 * We can correct alien code below with new client event */
		if (session->direction == SESSION_DIRECTION_OUTGOING) {
			WDS_LOGD("Peer device is GO, WPS_Enrollee will be started");
			wfd_session_wps(manager->session);
		} else {
			WDS_LOGD("Peer device is GO, so Prov_Disc will be started");
			wfd_session_start(session);
		}
	} else {
		/* Prov_disc_req received. GO Negotiation will be started */
		WDS_LOGD("My device is Device, so Negotiation will be started");
		res = wfd_session_connect(session);
	}
	if (res < 0) {
		WDS_LOGE("Failed to start session");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}
	wfd_state_set(manager, WIFI_DIRECT_STATE_CONNECTING);

	__WDS_LOG_FUNC_EXIT__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wfd_manager_cancel_connection(wfd_manager_s *manager, unsigned char *peer_addr)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_session_s *session = NULL;
	wfd_group_s *group = NULL;
	int res = 0;

	if (!manager || !peer_addr) {
		WDS_LOGE("Invalid parameter");
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	res = wfd_session_cancel(manager->session, peer_addr);
	if (res < 0) {
		WDS_LOGE("Failed to cancel session");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	if (manager->local->dev_role != WFD_DEV_ROLE_GO)
		wfd_oem_destroy_group(manager->oem_ops, GROUP_IFNAME);

	group = (wfd_group_s*) manager->group;
	if (group) {
		wfd_group_remove_member(group, peer_addr);
		if (!group->member_count) {
			wfd_oem_destroy_group(manager->oem_ops, group->ifname);
			wfd_destroy_group(manager, group->ifname);
		} else {
			wfd_oem_disconnect(manager->oem_ops, peer_addr);
		}
	}

	if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
		wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
	} else {
		wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
	}

	__WDS_LOG_FUNC_EXIT__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wfd_manager_reject_connection(wfd_manager_s *manager, unsigned char *peer_addr)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_session_s *session = NULL;
	int res = 0;

	if (!manager || !peer_addr) {
		WDS_LOGE("Invalid parameter");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	session = (wfd_session_s*) manager->session;
	if (!session) {
		WDS_LOGE("Session not found");
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}

	if (manager->local->dev_role == WFD_DEV_ROLE_NONE) {
		res = wfd_oem_reject_connection(manager->oem_ops, peer_addr);
		if (res < 0) {
			WDS_LOGE("Failed to reject connection");
			// TODO: check whether set state and break
		}
	}
	wfd_destroy_session(manager);

	if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
		wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
	} else {
		wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
	}

	__WDS_LOG_FUNC_EXIT__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wfd_manager_disconnect(wfd_manager_s *manager, unsigned char *peer_addr)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_group_s *group = NULL;
	wfd_device_s *peer = NULL;
	int res = 0;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	if (!peer_addr) {
		WDS_LOGE("Invalid parameter");
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	group = (wfd_group_s*) manager->group;
	if (!group) {
		WDS_LOGE("Group not found");
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}

	peer = wfd_group_find_member_by_addr(group, peer_addr);
	if (!peer) {
		WDS_LOGE("Connected peer not found");
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	wfd_state_set(manager, WIFI_DIRECT_STATE_DISCONNECTING);

	if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
		res = wfd_oem_disconnect(manager->oem_ops, peer->intf_addr);
	} else {
		res = wfd_oem_destroy_group(manager->oem_ops, group->ifname);
	}
	if (res < 0) {
		WDS_LOGE("Failed to disconnect peer");
		res = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		goto failed;
	}
	WDS_LOGE("Succeeded to disconnect peer");

	wfd_group_remove_member(group, peer_addr);
	if (!group->member_count) {
		wfd_oem_destroy_group(manager->oem_ops, group->ifname);
		wfd_destroy_group(manager, group->ifname);
	}

	if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
		wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
	} else {
		wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
	}

	__WDS_LOG_FUNC_EXIT__;
	return WIFI_DIRECT_ERROR_NONE;

failed:
	if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
		wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
	} else {
		wfd_state_set(manager, WIFI_DIRECT_STATE_CONNECTED);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_CONNECTED);
	}

	__WDS_LOG_FUNC_EXIT__;
	return res;
}

int wfd_manager_disconnect_all(wfd_manager_s *manager)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_group_s *group = NULL;
	int res = 0;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	group = (wfd_group_s*) manager->group;
	if (!group) {
		WDS_LOGE("Group not found");
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}

	wfd_state_set(manager, WIFI_DIRECT_STATE_DISCONNECTING);

	res = wfd_oem_destroy_group(manager->oem_ops, group->ifname);
	if (res < 0) {
		WDS_LOGE("Failed to destroy group");
		res = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		goto failed;
	}
	WDS_LOGE("Succeeded to disconnect all peer");

	wfd_destroy_group(manager, group->ifname);

	wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
	wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);

	__WDS_LOG_FUNC_EXIT__;
	return WIFI_DIRECT_ERROR_NONE;

failed:
	if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
		wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
	} else {
		wfd_state_set(manager, WIFI_DIRECT_STATE_CONNECTED);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_CONNECTED);
	}

	__WDS_LOG_FUNC_EXIT__;
	return res;
}

static int _wfd_manager_service_copy(char* dst, GList* services, int dst_length)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_service_s *service = NULL;
	GList *temp = NULL;
	char* ptr = dst;
	int length = dst_length;
	int res = 0;

	temp = g_list_first(services);
	while (temp) {

		service = temp->data;
		if(length < service->service_str_length + 4)
		{
			WDS_LOGD("There is not enough space to reserve service list");
			break;
		}

		memcpy(ptr, service->service_string, service->service_str_length);
		ptr+=service->service_str_length;
		strncpy(ptr," ,\n",3);
		ptr+=3;
		length = length - service->service_str_length - 3;

		temp = g_list_next(temp);
	}
	*ptr='\0';
	__WDS_LOG_FUNC_EXIT__;
	return res;
}

int wfd_manager_get_peers(wfd_manager_s *manager, wfd_discovery_entry_s **peers_data)
{
	__WDS_LOG_FUNC_ENTER__;
	GList *temp = NULL;
	wfd_device_s *peer = NULL;
	wfd_discovery_entry_s *peers = NULL;
	int peer_count = 0;
	int count = 0;
	int res = 0;

	if (!manager || !peers_data) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	unsigned long time = 0;
	struct timeval tval;
	gettimeofday(&tval, NULL);
	time = tval.tv_sec;
	WDS_LOGI("Current time [%ld]", time);

	peer_count = manager->peer_count;
	if (peer_count < 0)
		return -1;
	else if (peer_count == 0)
		return 0;

	errno = 0;
	peers = (wfd_discovery_entry_s*) calloc(peer_count, sizeof(wfd_discovery_entry_s));
	if (!peers) {
		WDS_LOGF("Failed to allocate memory for peer data. [%s]", strerror(errno));
		return -1;
	}

	temp = g_list_first(manager->peers);
	while (temp && count < peer_count) {
		peer = temp->data;
		if (!peer)
			goto next;
		if (peer->time + 4 < time) {
			WDS_LOGD("Device data is too old to report to application [%s]", peer->dev_name);
			res = wfd_update_peer(manager, peer);
			if (res < 0) {
				WDS_LOGE("This device is disappeared [%s]", peer->dev_name);
				temp = g_list_next(temp);
				manager->peers = g_list_remove(manager->peers, peer);
				manager->peer_count--;
				wfd_manager_init_service(peer);
				if(peer->wifi_display)
					free(peer->wifi_display);
				free(peer);
				peer = NULL;
				continue;
			}
		}

		strncpy(peers[count].device_name, peer->dev_name, DEV_NAME_LEN);
		peers[count].device_name[DEV_NAME_LEN] = '\0';
		memcpy(peers[count].mac_address, peer->dev_addr, MACADDR_LEN);
		memcpy(peers[count].intf_address, peer->intf_addr, MACADDR_LEN);
		peers[count].channel = peer->channel;
		peers[count].is_group_owner = peer->dev_role == WFD_DEV_ROLE_GO;
		peers[count].is_persistent_go = peer->group_flags & WFD_OEM_GROUP_FLAG_PERSISTENT_GROUP;
		peers[count].is_connected = peer->dev_role == WFD_DEV_ROLE_GC;
		peers[count].wps_device_pwd_id = 0;
		peers[count].wps_cfg_methods = peer->config_methods;
		peers[count].category = peer->pri_dev_type;
		peers[count].subcategory = peer->sec_dev_type;
		_wfd_manager_service_copy(peers[count].services, peer->services, 1024);
		if(peer->wifi_display)
			peers[count].is_wfd_device = peer->wifi_display->availability;

		count++;
		WDS_LOGD("%dth peer [%s]", count, peer->dev_name);
next:
		temp = g_list_next(temp);
		peer = NULL;
	}
	WDS_LOGD("%d peers converted", count);
	WDS_LOGD("Final peer count is %d", manager->peer_count);

	*peers_data = peers;

	__WDS_LOG_FUNC_EXIT__;
	return count;
}

int wfd_manager_get_connected_peers(wfd_manager_s *manager, wfd_connected_peer_info_s **peers_data)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_connected_peer_info_s *peers = NULL;
	wfd_group_s *group = NULL;
	wfd_device_s *peer = NULL;
	GList *temp = NULL;
	int peer_count = 0;
	int count = 0;

	if (!manager || !peers_data) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	group = manager->group;
	if (!group) {
		WDS_LOGE("Group not exist");
		return -1;
	}

	peer_count = group->member_count;
	if (peer_count == 0) {
		WDS_LOGD("Member not exist");
		return 0;
	}

	errno = 0;
	peers = (wfd_connected_peer_info_s*) calloc(peer_count, sizeof(wfd_connected_peer_info_s));
	if (!peers) {
		WDS_LOGE("Failed to allocate memory for connected peer data. [%s]", strerror(errno));
		return -1;
	}

	temp = g_list_first(group->members);
	while (temp && count < group->member_count) {
		peer = temp->data;
		{
			strncpy(peers[count].device_name, peer->dev_name, DEV_NAME_LEN);
			peers[count].device_name[DEV_NAME_LEN] = '\0';
			memcpy(peers[count].mac_address, peer->dev_addr, MACADDR_LEN);
			memcpy(peers[count].intf_address, peer->intf_addr, MACADDR_LEN);
			memcpy(peers[count].ip_address, peer->ip_addr, IPADDR_LEN);
			peers[count].category = peer->pri_dev_type;
			peers[count].subcategory = peer->sec_dev_type;
			peers[count].channel = peer->channel;
			peers[count].is_p2p = 1;
			_wfd_manager_service_copy(peers[count].services, peer->services, 1024);
			WDS_LOGD("%dth member converted[%s]", count, peers[count].device_name);
			count++;
		}
		temp = g_list_next(temp);
		peer = NULL;
	}
	WDS_LOGD("%d members converted", count);

	*peers_data = peers;

	__WDS_LOG_FUNC_EXIT__;
	return count;
}

wfd_device_s *wfd_manager_find_connected_peer(wfd_manager_s *manager, unsigned char *peer_addr)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *peer = NULL;

	if (!manager || !peer_addr) {
		WDS_LOGE("Invalid parameter");
		return NULL;
	}

	peer = wfd_group_find_member_by_addr(manager->group, peer_addr);

	__WDS_LOG_FUNC_EXIT__;
	return peer;
}

wfd_device_s *wfd_manager_get_current_peer(wfd_manager_s *manager)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_session_s *session = NULL;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return NULL;
	}

	session = manager->session;
	if (session && session->peer) {
		__WDS_LOG_FUNC_EXIT__;
		return session->peer;
	}

	__WDS_LOG_FUNC_EXIT__;
	return NULL;
}

int wfd_manager_get_goup_ifname(char **ifname)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_group_s *group = g_manager->group;

	if (!ifname) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	if (!group) {
		WDS_LOGE("Group not exist");
		return -1;
	}

	*ifname = group->ifname;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

static wfd_service_s *_wfd_service_find(wfd_device_s *device, wifi_direct_service_type_e type, char *data)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_service_s *result = NULL;
	GList *temp = NULL;
	int cmp_result = 0;

	temp = g_list_first(device->services);
	while (temp) {
		result = temp->data;

		if(result->service_type == WIFI_DIRECT_SERVICE_BONJOUR)
			cmp_result = strncmp(data, result->service_string, strlen(data));
		else
			cmp_result = strcmp(data, result->service_string);

		if(type == result->service_type && !cmp_result)
		{
			WDS_LOGD("Service found");
			break;
		}
		temp = g_list_next(temp);
		result = NULL;
	}
	__WDS_LOG_FUNC_EXIT__;
	return result;
}

static wfd_query_s *_wfd_query_find(wfd_manager_s *manager, unsigned char* mac_addr, wifi_direct_service_type_e  type, char *data)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_query_s *query = NULL;
	GList *temp = NULL;
	int data_len = 0;

	if(data != NULL)
		data_len = strlen(data);

	temp = g_list_first(manager->query_handles);
	while (temp) {
		query = temp->data;

		if(!memcmp(query->mac_addr, mac_addr, MACADDR_LEN) &&
				type == query->service_type)
		{
			if(data_len)
			{
				if(!strcmp(data, query->query_string))
				{
					WDS_LOGD("Query found");
					break;
				}
			}else{
				WDS_LOGD("Query found");
				break;
			}
		}
		temp = g_list_next(temp);
		query = NULL;
	}
	__WDS_LOG_FUNC_EXIT__;
	return query;
}

int wfd_manager_service_add(wfd_manager_s *manager, wifi_direct_service_type_e  type, char *data)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s * device = manager->local;
	wfd_service_s * service;
	int res = 0;

	if (!device || !data) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	service = _wfd_service_find(device, type, data);
	if (service) {
		WDS_LOGE("service already exist");
		service->ref_counter++;
		__WDS_LOG_FUNC_EXIT__;
		return 0;
	}

	res = wfd_oem_service_add(manager->oem_ops, type, data);
	if (res < 0) {
		WDS_LOGE("Failed to add service");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	service = (wfd_service_s*) calloc(1, sizeof(wfd_service_s));
	service->service_string = strndup(data, strlen(data));
	service->service_str_length = strlen(data);
	service->service_type = type;
	service->ref_counter=1;
	device->services = g_list_prepend(device->services, service);
	__WDS_LOG_FUNC_EXIT__;
	return res;
}

int wfd_manager_service_del(wfd_manager_s *manager, wifi_direct_service_type_e  type, char *data)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s * device = manager->local;
	wfd_service_s* service;
	int res = 0;

	if (!device || !data) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}
	service = _wfd_service_find(device, type, data);
	if (!service) {
		WDS_LOGE("Failed to find service");
		res = -1;

	}else if(service->ref_counter ==1)
	{
		res = wfd_oem_service_del(manager->oem_ops, type, data);
		if (res < 0) {
			WDS_LOGE("Failed to delete service");
			__WDS_LOG_FUNC_EXIT__;
			return -1;
		}
		device->services = g_list_remove(device->services, service);
		free(service->service_string);
		free(service);

	}else{
		service->ref_counter--;
	}
	__WDS_LOG_FUNC_EXIT__;
	return res;
}

int wfd_manager_serv_disc_req(wfd_manager_s *manager, unsigned char* mad_addr, wifi_direct_service_type_e  type, char *data)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_query_s* query;
	int res = 0;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}
	query = _wfd_query_find(manager, mad_addr, type, data);
	if (query) {
		WDS_LOGE("Query already exist");
		query->ref_counter++;
		__WDS_LOG_FUNC_EXIT__;
		return 0;
	}

	res = wfd_oem_serv_disc_req(manager->oem_ops, mad_addr, type, data);
	if (res < 0) {
		WDS_LOGE("Failed to request service discovery");
		return res;
	}
	query = (wfd_query_s*) calloc(1, sizeof(wfd_query_s));
	query->handle = res;
	query->ref_counter=1;
	memcpy(query->mac_addr, mad_addr, MACADDR_LEN);

	if(data && strlen(data))
		query->query_string = strndup(data, strlen(data));
	query->service_type = type;
	manager->query_handles = g_list_prepend(manager->query_handles, query);
	__WDS_LOG_FUNC_EXIT__;
	return res;
}

int wfd_manager_serv_disc_cancel(wfd_manager_s *manager,  int handle)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_query_s *query = NULL;
	GList *temp = NULL;
	int res = 0;

	temp = g_list_first(manager->query_handles);
	while (temp) {
		query = temp->data;

		//TODO : compare the services
		if(query->handle == handle)
		{
			WDS_LOGD("Query handle found");
			break;
		}
		temp = g_list_next(temp);
		query = NULL;
	}

	if(query == NULL) {
		WDS_LOGE("handle does not exist");
		return -1;
	}else if(query->ref_counter ==1) {

		res = wfd_oem_serv_disc_cancel(manager->oem_ops, query->handle);
		if (res < 0) {
			WDS_LOGE("Failed to cancel service discovery or already canceled");
		}
		manager->query_handles = g_list_remove(manager->query_handles, query);
		if(query->query_string)
			free(query->query_string);
		free(query);
	}else
		query->ref_counter--;

	__WDS_LOG_FUNC_EXIT__;
	return res;
}

int wfd_manager_init_service(wfd_device_s *device)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_service_s* service = NULL;
	GList *temp = NULL;
	int res = 0;

	if (!device) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	if(device->services)
	{
		temp = g_list_first(device->services);
		while (temp) {
			service = temp->data;
			free(service->service_string);
			free(service);
			temp = g_list_next(temp);
		}
		g_list_free(device->services);
	}
	__WDS_LOG_FUNC_EXIT__;
	return res;
}

int wfd_manager_init_query(wfd_manager_s *manager)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_query_s *query = NULL;
	GList *temp = NULL;
	int res = 0;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	if(manager->query_handles)
	{
		temp = g_list_first(manager->query_handles);
		while (temp) {
			query = temp->data;

			free(query->query_string);
			free(query);
			temp = g_list_next(temp);
		}
		g_list_free(manager->query_handles);
	}

	__WDS_LOG_FUNC_EXIT__;
	return res;
}

int wfd_manager_init_wifi_display(wifi_direct_display_type_e type, int port, int hdcp)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s * device = g_manager->local;
	wfd_display_info_s * display;
	int res = 0;

	if (type < 0 || port < 0 || hdcp < 0) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	res = wfd_oem_init_wifi_display(g_manager->oem_ops, type, port, hdcp);
	if (res < 0) {
		WDS_LOGE("Failed to initialize wifi display");
		return -1;
	}

	if(!device->wifi_display)
		device->wifi_display = calloc(1, sizeof(wfd_display_info_s));

	device->wifi_display->type = type;
	device->wifi_display->hdcp_support = hdcp;
	device->wifi_display->ctrl_port = port;

	__WDS_LOG_FUNC_EXIT__;
	return res;
}

int wfd_manager_deinit_wifi_display()
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s * device = g_manager->local;
	wfd_display_info_s * display;
	int res = 0;

	res = wfd_oem_deinit_wifi_display(g_manager->oem_ops);
	if (res < 0) {
		WDS_LOGE("Failed to deinitialize wifi display");
		return -1;
	}

	if(device->wifi_display)
	{
		free(device->wifi_display);
		device->wifi_display = NULL;
	}
	__WDS_LOG_FUNC_EXIT__;
	return res;
}

static wfd_manager_s *wfd_manager_init()
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = NULL;
	int res = 0;

	manager = (wfd_manager_s*) calloc(1, sizeof(wfd_manager_s));
	if (!manager) {
		WDS_LOGE("Failed to allocate memory for wfd_manager structure");
		return NULL;
	}

	manager->go_intent = 7;
	manager->req_wps_mode = WFD_WPS_MODE_PBC;
	manager->max_station = 8;

	res = _wfd_local_init_device(manager);
	if (res < 0) {
		WDS_LOGE("Failed to initialize local device");
		free(manager);
		return NULL;		// really stop manager?
	}
	WDS_LOGD("Succeeded to initialize local device");

	manager->exit_timer = g_timeout_add(120000,
						(GSourceFunc) _wfd_exit_timeout_cb, manager);
	WDS_LOGD("Exit timer started");

	__WDS_LOG_FUNC_EXIT__;
	return manager;
}

int wfd_manager_deinit(wfd_manager_s *manager)
{
	__WDS_LOG_FUNC_ENTER__;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	if (manager->exit_timer > 0)
		g_source_remove(manager->exit_timer);
	manager->exit_timer = 0;

	_wfd_local_deinit_device(manager);

	if (manager)
		free(manager);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

static void *wfd_plugin_init(wfd_manager_s *manager)
{
	__WDS_LOG_FUNC_ENTER__;
	void *handle;
	struct utsname kernel_info;
	int res;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return NULL;
	}

	res = uname(&kernel_info);
	if (res) {
		WDS_LOGE("Failed to detect target type");
		__WDS_LOG_FUNC_EXIT__;
		return NULL;
	}
	WDS_LOGD("Node name [%s], HW ID [%s]", kernel_info.nodename, kernel_info.machine);

	errno = 0;
	handle = dlopen(SUPPL_PLUGIN_PATH, RTLD_NOW);
	if (!handle) {
		WDS_LOGE("Failed to open shared object. [%s]", dlerror());
		__WDS_LOG_FUNC_EXIT__;
		return NULL;
	}

	errno = 0;
	int (*plugin_load)(wfd_oem_ops_s **ops) = NULL;
	plugin_load = (int (*)(wfd_oem_ops_s **ops)) dlsym(handle, "wfd_plugin_load");
	if (!plugin_load) {
		WDS_LOGE( "Failed to load symbol. Error = [%s]", strerror(errno));
		dlclose(handle);
		__WDS_LOG_FUNC_EXIT__;
		return NULL;
	}

	wfd_oem_ops_s *temp_ops;
	(*plugin_load)(&temp_ops);
	manager->oem_ops = temp_ops;

	res = wfd_oem_init(temp_ops, (wfd_oem_event_cb) wfd_process_event, manager);
	if (res < 0) {
		WDS_LOGE("Failed to initialize OEM");
		dlclose(handle);
		__WDS_LOG_FUNC_EXIT__;
		return NULL;
	}
	WDS_LOGD("Succeeded to initialize OEM");

	__WDS_LOG_FUNC_EXIT__;
	return handle;
}

static int wfd_plugin_deinit(wfd_manager_s *manager)
{
	__WDS_LOG_FUNC_ENTER__;

	if (!manager || !manager->plugin_handle) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	dlclose(manager->plugin_handle);
	manager->plugin_handle = NULL;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int main(int argc, char *argv[])
{
	__WDS_LOG_FUNC_ENTER__;
	GMainLoop *main_loop = NULL;
	int res = 0;

	if (!g_thread_supported())
		g_thread_init(NULL);

	g_type_init();

	// TODO: Parsing argument
	/* Wi-Fi direct connection for S-Beam can be optimized using argument */

	g_manager = wfd_manager_init();
	if (!g_manager) {
		WDS_LOGE("Failed to initialize wifi-direct manager");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}
	WDS_LOGD("Succeeded to initialize manager");

	g_manager->plugin_handle = wfd_plugin_init(g_manager);
	if (!g_manager->plugin_handle) {
		WDS_LOGE("Failed to initialize plugin");
		wfd_manager_deinit(g_manager);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}
	WDS_LOGD("Succeeded to load plugin");

	res = wfd_client_handler_init(g_manager);
	if (res < 0) {
		WDS_LOGE("Failed to initialize client handler");
		wfd_plugin_deinit(g_manager);
		wfd_manager_deinit(g_manager);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}
	WDS_LOGD("Succeeded to initialize client handler");

	main_loop = g_main_loop_new(NULL, FALSE);
	if (main_loop == NULL) {
		WDS_LOGE("Failed to create GMainLoop structure");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}
	g_manager->main_loop = main_loop;

	g_main_loop_run(main_loop);

	wfd_client_handler_deinit(g_manager);
	wfd_plugin_deinit(g_manager);
	wfd_manager_deinit(g_manager);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}
