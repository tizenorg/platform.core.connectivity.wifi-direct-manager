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
 * This file implements wifi direct event functions.
 *
 * @file		wifi-direct-event.c
 * @author	Gibyoung Kim (lastkgb.kim@samsung.com)
 * @version	0.7
 */

#include <stdio.h>
#include <stdlib.h>
#include <poll.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include <glib.h>

#include <wifi-direct.h>

#include "wifi-direct-ipc.h"
#include "wifi-direct-manager.h"
#include "wifi-direct-oem.h"
#include "wifi-direct-peer.h"
#include "wifi-direct-group.h"
#include "wifi-direct-session.h"
#include "wifi-direct-event.h"
#include "wifi-direct-state.h"
#include "wifi-direct-util.h"
#include "wifi-direct-error.h"
#include "wifi-direct-log.h"
#include "wifi-direct-dbus.h"


static int _wfd_event_update_peer(wfd_manager_s *manager, wfd_oem_dev_data_s *data)
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_device_s *peer = NULL;

	if (!manager || !data) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	peer = wfd_peer_find_by_dev_addr(manager, data->p2p_dev_addr);
	if (!peer) {
		peer = wfd_add_peer(manager, data->p2p_dev_addr, data->name);
		if (!peer) {
			WDS_LOGE("Failed to add peer");
			__WDS_LOG_FUNC_EXIT__;
			return -1;
		}
	} else {
		if (strcmp(peer->dev_name, data->name)) {
			g_strlcpy(peer->dev_name, data->name, DEV_NAME_LEN + 1);
			WDS_LOGD("Device name is changed [" MACSECSTR ": %s]",
					MAC2SECSTR(peer->dev_addr), peer->dev_name);
		}
	}
#ifndef CTRL_IFACE_DBUS
	memcpy(peer->intf_addr, data->p2p_intf_addr, MACADDR_LEN);
#endif /* CTRL_IFACE_DBUS */
	peer->pri_dev_type = data->pri_dev_type;
	peer->sec_dev_type = data->sec_dev_type;
	peer->config_methods = data->config_methods;
	peer->dev_flags = data->dev_flags;
	peer->group_flags = data->group_flags;
	peer->dev_role = data->dev_role;
#ifdef TIZEN_FEATURE_WIFI_DISPLAY
	memcpy(&(peer->display), &(data->display), sizeof(wfd_display_s));
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

#if !(__GNUC__ <= 4 && __GNUC_MINOR__ < 8)
	wfd_util_get_current_time(&peer->time);
#else
	struct timeval tval;
	gettimeofday(&tval, NULL);
	peer->time = tval.tv_sec;
#endif
	WDS_LOGI("Update time [%s - %ld]", peer->dev_name, peer->time);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

 gboolean _wfd_connection_retry(gpointer *data)
{
	wfd_session_s *session = (wfd_session_s*) data;
	if (!session) {
		WDS_LOGE("Session is NULL");
		__WDS_LOG_FUNC_EXIT__;
		return G_SOURCE_REMOVE;
	}

	switch (session->state) {
		case SESSION_STATE_STARTED:
			WDS_LOGD("PD again");
			wfd_session_start(session);
			break;
		case SESSION_STATE_GO_NEG:
			WDS_LOGD("Negotiation again");
			wfd_session_connect(session);
			break;
		case SESSION_STATE_WPS:
			WDS_LOGD("WPS again");
			wfd_session_wps(session);
			break;
		default:
			WDS_LOGE("Invalid session state [%d]", session->state);
			break;
	}
	__WDS_LOG_FUNC_EXIT__;
	return G_SOURCE_REMOVE;
}

static void __wfd_process_deactivated(wfd_manager_s *manager, wfd_oem_event_s *event)
{
 	__WDS_LOG_FUNC_ENTER__;

	wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
				     "Deactivation",
				     g_variant_new("(i)", WIFI_DIRECT_ERROR_NONE));

	wfd_destroy_group(manager, GROUP_IFNAME);
	wfd_destroy_session(manager);
	wfd_peer_clear_all(manager);
	wfd_local_reset_data(manager);

	wfd_state_set(manager, WIFI_DIRECT_STATE_DEACTIVATED);
	wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_DEACTIVATED);
	manager->req_wps_mode = WFD_WPS_MODE_PBC;

#ifdef TIZEN_FEATURE_DEFAULT_CONNECTION_AGENT
	wfd_util_stop_wifi_direct_popup();
#endif /* TIZEN_FEATURE_DEFAULT_CONNECTION_AGENT */
	__WDS_LOG_FUNC_EXIT__;
	return;
}

static void __wfd_process_peer_found(wfd_manager_s *manager, wfd_oem_event_s *event)
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_oem_dev_data_s *edata = NULL;
	char peer_mac_address[MACSTR_LEN+1] = {0, };
	int res = 0;

	edata = (wfd_oem_dev_data_s*) event->edata;
	if (!edata || event->edata_type != WFD_OEM_EDATA_TYPE_DEVICE) {
		WDS_LOGE("Invalid event data");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	res = _wfd_event_update_peer(manager, edata);
	if (res < 0) {
		WDS_LOGE("Failed to update peer data");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	if (manager->state > WIFI_DIRECT_STATE_ACTIVATING &&
			manager->state != WIFI_DIRECT_STATE_CONNECTING &&
			manager->state != WIFI_DIRECT_STATE_DISCONNECTING) {
		snprintf(peer_mac_address, MACSTR_LEN, MACSTR, MAC2STR(edata->p2p_dev_addr));
		wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
					     "PeerFound",
					     g_variant_new("(s)", peer_mac_address));
	}

#if defined(TIZEN_FEATURE_ASP)

	GList *list;
	GVariantBuilder *builder = NULL;
	GVariant *params = NULL;
	wfd_oem_advertise_service_s *service;

	for(list = (GList *)event->asp_services; list != NULL; list = list->next) {
		service = (wfd_oem_advertise_service_s *)list->data;

		builder = g_variant_builder_new(G_VARIANT_TYPE ("a{sv}"));
		g_variant_builder_add(builder, "{sv}", "search_id", g_variant_new("t", service->search_id));
		g_variant_builder_add(builder, "{sv}", "service_mac", g_variant_new("s", peer_mac_address));
		g_variant_builder_add(builder, "{sv}", "device_name", g_variant_new("s", edata->name));
		g_variant_builder_add(builder, "{sv}", "advertisement_id", g_variant_new("u", service->adv_id));
		g_variant_builder_add(builder, "{sv}", "config_method", g_variant_new("u", service->config_method));
		if(service->service_type)
			g_variant_builder_add(builder, "{sv}", "service_type", g_variant_new("s", service->service_type));
		params = g_variant_new("(a{sv})", builder);
		g_variant_builder_unref(builder);

		wfd_manager_dbus_emit_signal(WFD_MANAGER_ASP_INTERFACE,
					     "SearchResult",
					     params);
	}
#endif
 	__WDS_LOG_FUNC_EXIT__;
	return;
}

static void __wfd_process_peer_disappeared(wfd_manager_s *manager, wfd_oem_event_s *event)
{
 	__WDS_LOG_FUNC_ENTER__;

	wfd_session_s *session = NULL;
	wfd_device_s *peer = NULL;
	char peer_mac_address[MACSTR_LEN+1] = {0, };

	session = manager->session;
	if(session != NULL && session->peer != NULL) {
		peer = session->peer;
		WDS_LOGD("session peer [" MACSTR "] lost peer ["  MACSTR "]", MAC2STR(peer->dev_addr),
						MAC2STR(event->dev_addr));
		if(memcmp(peer->dev_addr, event->dev_addr, MACADDR_LEN) == 0) {
			WDS_LOGD("peer already in connection");
			return;
		}
	}

	wfd_remove_peer(manager, event->dev_addr);

	snprintf(peer_mac_address, MACSTR_LEN, MACSTR, MAC2STR(event->dev_addr));
	wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
				     "PeerLost",
				     g_variant_new("(s)", peer_mac_address));

 	__WDS_LOG_FUNC_EXIT__;
 	return;
}

static void __wfd_process_discovery_finished(wfd_manager_s *manager, wfd_oem_event_s *event)
{
 	__WDS_LOG_FUNC_ENTER__;

	if (manager->state != WIFI_DIRECT_STATE_DISCOVERING &&
			manager->state != WIFI_DIRECT_STATE_ACTIVATED) {
		WDS_LOGE("Notify finding stopped when discovering or activated. [%d]", manager->state);
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	if (manager->scan_mode == WFD_SCAN_MODE_PASSIVE) {
		WDS_LOGE("During passive scan, Discover Finished event will not notified");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
		wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
	} else {
		wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
	}
	manager->scan_mode = WFD_SCAN_MODE_NONE;

	wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
				     "DiscoveryFinished",
				     NULL);

	__WDS_LOG_FUNC_EXIT__;
	return;
}

static void __wfd_process_prov_disc_req(wfd_manager_s *manager, wfd_oem_event_s *event)
{
 	__WDS_LOG_FUNC_ENTER__;

	wfd_device_s *peer = NULL;
 	int res = 0;
	wfd_group_s *group = (wfd_group_s*) manager->group;

	if (group && group->role == WFD_DEV_ROLE_GC) {
		WDS_LOGD("Device has GC role - ignore this provision request");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

#ifdef CTRL_IFACE_DBUS
	wfd_oem_dev_data_s *edata = NULL;

	edata = (wfd_oem_dev_data_s*) event->edata;
	if (!edata || event->edata_type != WFD_OEM_EDATA_TYPE_DEVICE) {
		WDS_LOGE("Invalid event data");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	res = _wfd_event_update_peer(manager, edata);
	peer = wfd_peer_find_by_dev_addr(manager, event->dev_addr);
#else /* CTRL_IFACE_DBUS */
	peer = wfd_peer_find_by_dev_addr(manager, event->dev_addr);
	if (!peer) {
		WDS_LOGD("Prov_disc from unknown peer. Add new peer");
		peer = wfd_add_peer(manager, event->dev_addr, "DIRECT-");
		if (!peer) {
			WDS_LOGE("Failed to add peer for invitation");
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
		wfd_update_peer(manager, peer);
	}
	wfd_update_peer_time(manager, event->dev_addr);
#endif /* CTRL_IFACE_DBUS */

	if (WFD_DEV_ROLE_GO != manager->local->dev_role) {
		WDS_LOGI("TV is not GO, updated peer data only.");

		manager->local->wps_mode = event->wps_mode;
		if (event->wps_mode == WFD_WPS_MODE_PBC ||
				event->wps_mode == WFD_WPS_MODE_KEYPAD) {
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}

	if (peer) {
		if (WFD_PEER_STATE_DISCOVERED < peer->state)
		{
			WDS_LOGD("Peer already connected/connecting, ignore this provision request");
			__WDS_LOG_FUNC_EXIT__;
			return;
		}

		peer->state = WFD_PEER_STATE_CONNECTING;
	}

	res = wfd_session_process_event(manager, event);
	if (res < 0)
		WDS_LOGE("Failed to process event of session");

	__WDS_LOG_FUNC_EXIT__;
	return;
}

static void __wfd_process_prov_disc_resp(wfd_manager_s *manager, wfd_oem_event_s *event)
{
 	__WDS_LOG_FUNC_ENTER__;

	wfd_device_s *peer = NULL;
	int res = 0;

#ifdef CTRL_IFACE_DBUS
	wfd_oem_dev_data_s *edata = NULL;

	edata = (wfd_oem_dev_data_s*) event->edata;
	if (!edata || event->edata_type != WFD_OEM_EDATA_TYPE_DEVICE) {
		WDS_LOGE("Invalid event data");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	res = _wfd_event_update_peer(manager, edata);
	peer = wfd_peer_find_by_dev_addr(manager, event->dev_addr);
	if (peer)
		peer->state = WFD_PEER_STATE_CONNECTING;
#else /* CTRL_IFACE_DBUS */
	peer = wfd_peer_find_by_dev_addr(manager, event->dev_addr);
	if (!peer) {
		WDS_LOGD("Prov_disc from unknown peer. Add new peer");
		peer = wfd_add_peer(manager, event->dev_addr, "DIRECT-");
		if (!peer) {
			WDS_LOGE("Failed to add peer for invitation");
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
		peer->state = WFD_PEER_STATE_CONNECTING;
		wfd_update_peer(manager, peer);
	}
	wfd_update_peer_time(manager, event->dev_addr);
#endif /* CTRL_IFACE_DBUS */

	res = wfd_session_process_event(manager, event);
	if (res < 0)
		WDS_LOGE("Failed to process event of session");

	__WDS_LOG_FUNC_EXIT__;
	return;
}

static void __wfd_process_prov_disc_fail(wfd_manager_s *manager, wfd_oem_event_s *event)
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_session_s *session = NULL;
	unsigned char *peer_addr = NULL;
	char peer_mac_address[MACSTR_LEN+1] = {0, };

	session = (wfd_session_s*) manager->session;
	if (!session) {
		WDS_LOGE("Unexpected event. Session not exist");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	peer_addr = wfd_session_get_peer_addr(session);
	if (!peer_addr) {
		WDS_LOGE("Session do not have peer");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	snprintf(peer_mac_address, MACSTR_LEN, MACSTR, MAC2STR(peer_addr));
	wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
				     "Connection",
				     g_variant_new("(iis)", WIFI_DIRECT_ERROR_CONNECTION_FAILED,
							    WFD_EVENT_CONNECTION_RSP,
							    peer_mac_address));

	if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
		wfd_group_s *group = (wfd_group_s*) manager->group;
		if (group && !group->member_count && (wfd_group_is_autonomous(group) == FALSE)) {
			wfd_destroy_group(manager, GROUP_IFNAME);

			wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
		} else {
			wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
		}
	} else {
		wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
	}

	wfd_destroy_session(manager);

	wfd_oem_refresh(manager->oem_ops);
#if 0
	/* After connection failed, scan again */
	wfd_oem_scan_param_s param;
	memset(&param, 0x0, sizeof(wfd_oem_scan_param_s));
	param.scan_mode = WFD_OEM_SCAN_MODE_ACTIVE;
	param.scan_time = 2;
	param.scan_type = WFD_OEM_SCAN_TYPE_SOCIAL;
	wfd_oem_start_scan(manager->oem_ops, &param);
	manager->scan_mode = WFD_SCAN_MODE_ACTIVE;
#endif
	__WDS_LOG_FUNC_EXIT__;
	return;
}

static void __wfd_process_go_neg_req(wfd_manager_s *manager, wfd_oem_event_s *event)
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_group_s *group = (wfd_group_s*) manager->group;
	if (group && group->role == WFD_DEV_ROLE_GC) {
		WDS_LOGD("Device has GC role - ignore this go neg request");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

#ifdef CTRL_IFACE_DBUS
	wfd_oem_dev_data_s *edata = NULL;
	int res = 0;

	edata = (wfd_oem_dev_data_s*) event->edata;
	if (!edata || event->edata_type != WFD_OEM_EDATA_TYPE_DEVICE) {
		WDS_LOGE("Invalid event data");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	res = _wfd_event_update_peer(manager, edata);
	if (res < 0) {
		WDS_LOGE("Failed to update peer data");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}
#else /* CTRL_IFACE_DBUS */
	wfd_oem_conn_data_s *edata = NULL;
	wfd_device_s *peer = NULL;

	edata = (wfd_oem_conn_data_s*) event->edata;
	if (!edata || event->edata_type != WFD_OEM_EDATA_TYPE_CONN) {
		WDS_LOGE("Invalid connection event data");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	peer = wfd_peer_find_by_dev_addr(manager, event->dev_addr);
	if (!peer) {
		WDS_LOGD("Invitation from unknown peer. Add new peer");
		peer = wfd_add_peer(manager, event->dev_addr, "DIRECT-");
		if (!peer) {
			WDS_LOGE("Failed to add peer for invitation");
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}

	if (edata->wps_mode == 0)
		edata->wps_mode = 1;

	event->wps_mode = edata->wps_mode;
#endif /* CTRL_IFACE_DBUS */

	wfd_session_process_event(manager, event);
	__WDS_LOG_FUNC_EXIT__;
	return;
}

 static void __wfd_process_go_neg_fail(wfd_manager_s *manager, wfd_oem_event_s *event)
 {
	__WDS_LOG_FUNC_ENTER__;

	wfd_session_s *session = NULL;
	wfd_oem_conn_data_s *edata = NULL;
	unsigned char *peer_addr = NULL;
	char peer_mac_address[MACSTR_LEN] = {0, };

	session = (wfd_session_s*) manager->session;
	if (!session) {
		WDS_LOGE("Unexpected event. Session not exist");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	peer_addr = wfd_session_get_peer_addr(session);
	if (!peer_addr) {
		WDS_LOGE("Session do not have peer");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	edata = (wfd_oem_conn_data_s*) event->edata;
	if (!edata) {
		WDS_LOGE("Invalid p2p connection data");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	if (edata->status < 0 && session->connecting_120) {
		if (session->retry_gsrc) {
			g_source_remove(session->retry_gsrc);
			session->retry_gsrc = 0;
		}
		session->retry_gsrc = g_idle_add((GSourceFunc) _wfd_connection_retry, session);
		WDS_LOGD("Connection will be retried");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	snprintf(peer_mac_address, MACSTR_LEN, MACSTR, MAC2STR(peer_addr));
	wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
				     "Connection",
				     g_variant_new("(iis)", WIFI_DIRECT_ERROR_CONNECTION_FAILED,
							    WFD_EVENT_CONNECTION_RSP,
							    peer_mac_address));

	wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
	wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);

	wfd_destroy_group(manager, GROUP_IFNAME);
	wfd_destroy_session(manager);
	manager->local->dev_role = WFD_DEV_ROLE_NONE;
	__WDS_LOG_FUNC_EXIT__;
	return;
}

static void __wfd_process_go_neg_done(wfd_manager_s *manager, wfd_oem_event_s *event)
{
	__WDS_LOG_FUNC_ENTER__;

#ifdef CTRL_IFACE_DBUS
	wfd_session_s *session = NULL;
	wfd_oem_conn_data_s *edata = NULL;
	wfd_device_s *peer = NULL;

	edata = (wfd_oem_conn_data_s*) event->edata;
	if (edata == NULL) {
		WDS_LOGE("Invalid event data");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	session = (wfd_session_s*) manager->session;
	if(session && session->peer) {
		peer = session->peer;
		memcpy(peer->intf_addr, edata->peer_intf_addr, MACADDR_LEN);
	}

	wfd_session_process_event(manager, event);
#endif /* CTRL_IFACE_DBUS */
	__WDS_LOG_FUNC_EXIT__;
	return;
}

static void __wfd_process_wps_fail(wfd_manager_s *manager, wfd_oem_event_s *event)
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_session_s *session = NULL;
	unsigned char *peer_addr = NULL;

	session = (wfd_session_s*) manager->session;
	if (!session) {
		WDS_LOGE("Unexpected event. Session not exist");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	peer_addr = wfd_session_get_peer_addr(session);
	if (!peer_addr) {
		WDS_LOGE("Session do not have peer");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	char peer_mac_address[MACSTR_LEN+1] = {0, };
	g_snprintf(peer_mac_address, MACSTR_LEN, MACSTR, MAC2STR(peer_addr));
	wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
				     "Connection",
				     g_variant_new("(iis)", WIFI_DIRECT_ERROR_CONNECTION_FAILED,
							    WFD_EVENT_CONNECTION_RSP,
							    peer_mac_address));

	if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
		wfd_group_s *group = (wfd_group_s*) manager->group;
		if (group && !group->member_count && (wfd_group_is_autonomous(group) == FALSE)) {
			wfd_destroy_group(manager, GROUP_IFNAME);

			wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
		} else {
			wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
		}
	} else {
		wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
	}

	wfd_destroy_session(manager);

	wfd_oem_refresh(manager->oem_ops);
#if 0
	/* After connection failed, scan again */
	wfd_oem_scan_param_s param;
	memset(&param, 0x0, sizeof(wfd_oem_scan_param_s));
	param.scan_mode = WFD_OEM_SCAN_MODE_ACTIVE;
	param.scan_time = 2;
	param.scan_type = WFD_OEM_SCAN_TYPE_SOCIAL;
	wfd_oem_start_scan(manager->oem_ops, &param);
	manager->scan_mode = WFD_SCAN_MODE_ACTIVE;
#endif
	__WDS_LOG_FUNC_EXIT__;
	return;
}

static void __wfd_process_wps_done(wfd_manager_s *manager, wfd_oem_event_s *event)
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_session_process_event(manager, event);

	__WDS_LOG_FUNC_EXIT__;
	return;
}

static void __wfd_process_key_neg_fail(wfd_manager_s *manager, wfd_oem_event_s *event)
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_session_s *session = NULL;
	unsigned char *peer_addr = NULL;
	char peer_mac_address[MACSTR_LEN+1] = {0, };

	session = (wfd_session_s*) manager->session;
	if (!session) {
		WDS_LOGE("Unexpected event. Session not exist");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	peer_addr = wfd_session_get_peer_addr(session);
	if (!peer_addr) {
		WDS_LOGE("Session do not has peer");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	g_snprintf(peer_mac_address, MACSTR_LEN, MACSTR, MAC2STR(peer_addr));
	wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
				     "Connection",
				     g_variant_new("(iis)", WIFI_DIRECT_ERROR_CONNECTION_FAILED,
							    WFD_EVENT_CONNECTION_RSP,
							    peer_mac_address));

	if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
		wfd_group_s *group = (wfd_group_s*) manager->group;
		if (group && !group->member_count && (wfd_group_is_autonomous(group) == FALSE)) {
			wfd_destroy_group(manager, GROUP_IFNAME);

			wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
		} else {
			wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
		}
	} else {
		wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
	}

	wfd_destroy_session(manager);

	wfd_oem_refresh(manager->oem_ops);
#if 0
	/* After connection failed, scan again */
	wfd_oem_scan_param_s param;
	memset(&param, 0x0, sizeof(wfd_oem_scan_param_s));
	param.scan_mode = WFD_OEM_SCAN_MODE_ACTIVE;
	param.scan_time = 2;
	param.scan_type = WFD_OEM_SCAN_TYPE_SOCIAL;
	wfd_oem_start_scan(manager->oem_ops, &param);
	manager->scan_mode = WFD_SCAN_MODE_ACTIVE;
#endif
	__WDS_LOG_FUNC_EXIT__;
	return;
}

static void __wfd_process_key_neg_done(wfd_manager_s *manager, wfd_oem_event_s *event)
{
	__WDS_LOG_FUNC_ENTER__;

	__WDS_LOG_FUNC_EXIT__;
	return;
}

static void __wfd_process_conn_fail(wfd_manager_s *manager, wfd_oem_event_s *event)
{
	__WDS_LOG_FUNC_ENTER__;

	__WDS_LOG_FUNC_EXIT__;
	return;
}

static void __wfd_process_conn_done(wfd_manager_s *manager, wfd_oem_event_s *event)
{
	__WDS_LOG_FUNC_ENTER__;

	__WDS_LOG_FUNC_EXIT__;
	return;
}

static void __wfd_process_group_created(wfd_manager_s *manager, wfd_oem_event_s *event)
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_group_s *group = (wfd_group_s*) manager->group;
	wfd_session_s *session = (wfd_session_s*) manager->session;

	if (!group) {
		group = wfd_create_pending_group(manager, event->intf_addr);
		if (!group) {
			WDS_LOGE("Failed to create pending group");
			__WDS_LOG_FUNC_EXIT__;
			return;
		}

		manager->group = group;
	}

	wfd_group_complete(manager, event);

	if (group->role == WFD_DEV_ROLE_GC && session) {
#ifdef TIZEN_FEATURE_IP_OVER_EAPOL
		wfd_device_s *peer = session->peer;
		if(peer == NULL) {
			WDS_LOGE("Unexpected event. Peer doesn't exist");
			return;
		}

		wfd_update_peer(manager, peer);

		if(peer->ip_type == WFD_IP_TYPE_OVER_EAPOL) {
			char peer_mac_address[MACSTR_LEN+1] = {0, };

			wfd_util_ip_over_eap_assign(peer, event->ifname);

			g_snprintf(peer_mac_address, MACSTR_LEN, MACSTR, MAC2STR(peer->dev_addr));
			wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
						     "Connection",
						     g_variant_new("(iis)", WIFI_DIRECT_ERROR_NONE,
									    WFD_EVENT_CONNECTION_RSP,
									    peer_mac_address));

			wfd_state_set(manager, WIFI_DIRECT_STATE_CONNECTED);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_CONNECTED);

			wfd_destroy_session(manager);
		}
#endif /* TIZEN_FEATURE_IP_OVER_EAPOL */
		wfd_peer_clear_all(manager);
	} else {
		if (group->flags & WFD_GROUP_FLAG_AUTONOMOUS) {
			wfd_manager_dbus_emit_signal(WFD_MANAGER_GROUP_INTERFACE,
						     "Created", NULL);
			wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
		}
	}
	__WDS_LOG_FUNC_EXIT__;
	return;
}

static void __wfd_process_group_destroyed(wfd_manager_s *manager, wfd_oem_event_s *event)
{
	__WDS_LOG_FUNC_ENTER__;

	char peer_mac_address[MACSTR_LEN+1] = {0, };
	unsigned char *peer_addr = wfd_session_get_peer_addr(manager->session);

	if (peer_addr != NULL)
		g_snprintf(peer_mac_address, MACSTR_LEN, MACSTR, MAC2STR(peer_addr));
	else
		g_snprintf(peer_mac_address, MACSTR_LEN, "%s", "");

	if (manager->state == WIFI_DIRECT_STATE_DISCONNECTING) {
		wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
					     "Disconnection",
					     g_variant_new("(iis)", WIFI_DIRECT_ERROR_NONE,
								    WFD_EVENT_DISCONNECTION_RSP,
								    peer_mac_address));

	} else if (manager->state == WIFI_DIRECT_STATE_CONNECTING && manager->session){
		wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
					     "Connection",
					     g_variant_new("(iis)", WIFI_DIRECT_ERROR_CONNECTION_FAILED,
								    WFD_EVENT_CONNECTION_RSP,
								    peer_mac_address));

	} else if (manager->state >= WIFI_DIRECT_STATE_CONNECTED) {
		if (manager->local->dev_role != WFD_DEV_ROLE_GO) {
			wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
						     "Disconnection",
						     g_variant_new("(iis)", WIFI_DIRECT_ERROR_NONE,
									    WFD_EVENT_DISCONNECTION_RSP,
									    peer_mac_address));
		} else {
			wfd_manager_dbus_emit_signal(WFD_MANAGER_GROUP_INTERFACE,
						     "Destroyed", NULL);
		}
	} else {
		WDS_LOGD("Unexpected event(GROUP_DESTROYED). Ignore it");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
	wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
	wfd_destroy_group(manager, event->ifname);
	wfd_destroy_session(manager);
	manager->local->dev_role = WFD_DEV_ROLE_NONE;

	__WDS_LOG_FUNC_EXIT__;
	return;
}

static void __wfd_process_invitation_req(wfd_manager_s *manager, wfd_oem_event_s *event)
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_device_s *peer = NULL;
	wfd_session_s *session = NULL;
	wfd_oem_invite_data_s *edata = NULL;
	int res = 0;
	char peer_mac_address[MACSTR_LEN+1] = {0, };

	peer = wfd_peer_find_by_dev_addr(manager, event->dev_addr);
	if (!peer) {
		WDS_LOGD("Invitation from unknown peer. Add new peer");
		peer = wfd_add_peer(manager, event->dev_addr, "DIRECT-");
		if (!peer) {
			WDS_LOGE("Failed to add peer for invitation");
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	peer->dev_role = WFD_DEV_ROLE_GO;

	edata = (wfd_oem_invite_data_s*) event->edata;
	memcpy(peer->intf_addr, edata->bssid, MACADDR_LEN);
	wfd_update_peer_time(manager, event->dev_addr);

	session = wfd_create_session(manager, event->dev_addr,
					manager->req_wps_mode, SESSION_DIRECTION_INCOMING);
	if (!session) {
		WDS_LOGE("Failed to create session");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}
	session->type = SESSION_TYPE_INVITE;
	wfd_session_timer(session, 1);

	wfd_state_set(manager, WIFI_DIRECT_STATE_CONNECTING);

	res = wfd_session_start(session);
	if (res < 0) {
		WDS_LOGE("Failed to start session");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	g_snprintf(peer_mac_address, MACSTR_LEN, MACSTR, MAC2STR(event->dev_addr));
	wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
				     "Connection",
				     g_variant_new("(iis)", WIFI_DIRECT_ERROR_NONE,
							    WFD_EVENT_CONNECTION_REQ,
							    peer_mac_address));

	__WDS_LOG_FUNC_EXIT__;
	return;
}

static void __wfd_process_invitation_res(wfd_manager_s *manager, wfd_oem_event_s *event)
{
	__WDS_LOG_FUNC_ENTER__;

 	__WDS_LOG_FUNC_EXIT__;
	return;
}

static void __wfd_process_sta_connected(wfd_manager_s *manager, wfd_oem_event_s *event)
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_session_s *session = (wfd_session_s*) manager->session;
	wfd_group_s *group = (wfd_group_s*) manager->group;
	wfd_device_s *peer = NULL;
	char peer_mac_address[MACSTR_LEN+1] = {0, };

	// FIXME: Move this code to plugin
	if (!memcmp(event->intf_addr, manager->local->intf_addr, MACADDR_LEN)) {
		WDS_LOGD("Ignore this event");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	if (ISZEROMACADDR(event->dev_addr)) {
		WDS_LOGD("Legacy Peer Connected [Peer: " MACSTR "]", MAC2STR(event->intf_addr));

		peer = wfd_peer_find_by_dev_addr(manager, event->intf_addr);
		if (!peer) {
			WDS_LOGI("Add legacy peer");
			peer = wfd_add_peer(manager, event->intf_addr, "LEGACY-PEER");
			if (!peer) {
				WDS_LOGE("Failed to add Legacy peer.");
				__WDS_LOG_FUNC_EXIT__;
				return;
			}
		}

		memcpy(peer->intf_addr, event->intf_addr, MACADDR_LEN);
		peer->state = WFD_PEER_STATE_CONNECTED;
		wfd_group_add_member(group, peer->dev_addr);

		g_snprintf(peer_mac_address, MACSTR_LEN, MACSTR, MAC2STR(peer->dev_addr));
		wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
					     "Connection",
					     g_variant_new("(iis)", WIFI_DIRECT_ERROR_NONE,
								    WFD_EVENT_CONNECTION_RSP,
								    peer_mac_address));

		wfd_util_dhcps_wait_ip_leased(peer);
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	session = (wfd_session_s*) manager->session;
	if (!session) {
		WDS_LOGD("Unexpected event. Session is NULL [peer: " MACSECSTR "]",
									MAC2SECSTR(event->dev_addr));
		wfd_oem_destroy_group(manager->oem_ops, GROUP_IFNAME);
		wfd_destroy_group(manager, GROUP_IFNAME);
		wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	peer = wfd_session_get_peer(session);
	if (!peer) {
		WDS_LOGE("Peer not found");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	group = (wfd_group_s*) manager->group;
	if (!group) {
		group = wfd_create_pending_group(manager, event->intf_addr);
		if (!group) {
			WDS_LOGE("Failed to create pending group");
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
		manager->group = group;
	}
	wfd_group_add_member(group, peer->dev_addr);

	session->state = SESSION_STATE_COMPLETED;
#ifndef CTRL_IFACE_DBUS
	memcpy(peer->intf_addr, event->intf_addr, MACADDR_LEN);
#endif /* CTRL_IFACE_DBUS */
	peer->state = WFD_PEER_STATE_CONNECTED;

	wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
	wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);

	g_snprintf(peer_mac_address, MACSTR_LEN, MACSTR, MAC2STR(peer->dev_addr));
	wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
				     "Connection",
				     g_variant_new("(iis)", WIFI_DIRECT_ERROR_NONE,
							    WFD_EVENT_CONNECTION_RSP,
							    peer_mac_address));

#ifdef CTRL_IFACE_DBUS
	wfd_update_peer(manager, peer);
#endif /* CTRL_IFACE_DBUS */
#ifdef TIZEN_FEATURE_IP_OVER_EAPOL
	if (event->ip_addr_peer[3]) {
		peer->ip_type = WFD_IP_TYPE_OVER_EAPOL;
		memcpy(peer->client_ip_addr, event->ip_addr_peer, IPADDR_LEN);
		WDS_LOGE("Peer's client IP [" IPSTR "]", IP2STR((char*) &peer->client_ip_addr));
		memcpy(peer->go_ip_addr, manager->local->ip_addr, IPADDR_LEN);
		WDS_LOGE("Peer's GO IP [" IPSTR "]", IP2STR((char*) &peer->go_ip_addr));
	}
	if(peer->ip_type == WFD_IP_TYPE_OVER_EAPOL) {
		char peer_mac_address[MACSTR_LEN+1] = {0,};
		char assigned_ip_address[IPSTR_LEN+1] = {0,};

		memcpy(peer->ip_addr, peer->client_ip_addr, IPADDR_LEN);

		g_snprintf(peer_mac_address, MACSTR_LEN, MACSTR, MAC2STR(peer->dev_addr));
		g_snprintf(assigned_ip_address, IPSTR_LEN, IPSTR, IP2STR(peer->ip_addr));
		wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
				     "PeerIPAssigned",
				     g_variant_new("(ss)", peer_mac_address,
							   assigned_ip_address));
	} else
#endif /* TIZEN_FEATURE_IP_OVER_EAPOL */
	wfd_util_dhcps_wait_ip_leased(peer);
	wfd_destroy_session(manager);

	__WDS_LOG_FUNC_EXIT__;
	return;
}

static void __wfd_process_sta_disconnected(wfd_manager_s *manager, wfd_oem_event_s *event)
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_group_s *group = NULL;
	wfd_device_s *peer = NULL;
	unsigned char peer_addr[MACADDR_LEN] = {0, };
	char peer_mac_address[MACSTR_LEN+1] = {0, };

	group = (wfd_group_s*) manager->group;
	if (!group) {
		WDS_LOGE("Group not found");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	if (ISZEROMACADDR(event->dev_addr)) {
		WDS_LOGD("Legacy Peer Disconnected [Peer: " MACSTR "]", MAC2STR(event->intf_addr));
		g_snprintf(peer_mac_address, MACSTR_LEN, MACSTR, MAC2STR(event->intf_addr));
		wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
					     "Disconnection",
					     g_variant_new("(iis)", WIFI_DIRECT_ERROR_NONE,
								    WFD_EVENT_DISCONNECTION_IND,
								    peer_mac_address));

		wfd_group_remove_member(group, event->intf_addr);

		if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
			wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
		} else {
			wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
		}
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

#ifdef CTRL_IFACE_DBUS
	peer = wfd_group_find_member_by_addr(group, event->dev_addr);
#else /* CTRL_IFACE_DBUS */
	peer = wfd_group_find_member_by_addr(group, event->intf_addr);
#endif /* DBUS_IFACE */
	if (!peer) {
		WDS_LOGE("Failed to find connected peer");
		peer = wfd_session_get_peer(manager->session);
		if (!peer) {
			WDS_LOGE("Failed to find connecting peer");
			__WDS_LOG_FUNC_EXIT__;
			return;
		}

#ifdef CTRL_IFACE_DBUS
		/**
		 * If no peer connected and
		 * disconnected event is not for connecting peer
		 * then event should be ignored.
		 * This situation can arrise when TV is GO and
		 * some connected peer sent disassociation.
		 */
		if (memcmp(peer_addr, event->dev_addr, MACADDR_LEN)) {
			WDS_LOGE("Unexpected event, Ignore it...");
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
#endif /* CTRL_DBUS_IFACE */
	}
	memcpy(peer_addr, peer->dev_addr, MACADDR_LEN);

	/**
	 * If state is not DISCONNECTING, connection is finished by peer.
	 *  Required the check also, when Device is Group Owner and state is DISCOVERING.
	 */
	if (manager->state >= WIFI_DIRECT_STATE_CONNECTED ||
				(manager->state == WIFI_DIRECT_STATE_DISCOVERING &&
				 manager->local->dev_role == WFD_DEV_ROLE_GO)) {
		wfd_group_remove_member(group, peer_addr);
		g_snprintf(peer_mac_address, MACSTR_LEN, MACSTR, MAC2STR(peer_addr));
		if (group->member_count) {
			wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
						     "Disconnection",
						     g_variant_new("(iis)", WIFI_DIRECT_ERROR_NONE,
									    WFD_EVENT_DISASSOCIATION_IND,
									    peer_mac_address));
		} else {
			wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
						     "Disconnection",
						     g_variant_new("(iis)", WIFI_DIRECT_ERROR_NONE,
									    WFD_EVENT_DISCONNECTION_IND,
									    peer_mac_address));
		}

	} else if (manager->state == WIFI_DIRECT_STATE_DISCONNECTING) {
		g_snprintf(peer_mac_address, MACSTR_LEN, MACSTR, MAC2STR(peer_addr));
		wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
					     "Disconnection",
					     g_variant_new("(iis)", WIFI_DIRECT_ERROR_NONE,
								    WFD_EVENT_DISCONNECTION_RSP,
								    peer_mac_address));

	} else if (manager->state == WIFI_DIRECT_STATE_CONNECTING &&
			/* Some devices(GO) send disconnection message before connection completed.
			 * This message should be ignored when device is not GO */
			manager->local->dev_role == WFD_DEV_ROLE_GO) {
		if (WFD_PEER_STATE_CONNECTED == peer->state) {
			WDS_LOGD("Peer is already Connected !!!");
			wfd_group_remove_member(group, peer_addr);
			g_snprintf(peer_mac_address, MACSTR_LEN, MACSTR, MAC2STR(peer_addr));
			wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
						     "Disconnection",
						     g_variant_new("(iis)", WIFI_DIRECT_ERROR_NONE,
									    WFD_EVENT_DISASSOCIATION_IND,
									    peer_mac_address));

		} else if (WFD_PEER_STATE_CONNECTING == peer->state) {
			WDS_LOGD("Peer is Connecting...");
			g_snprintf(peer_mac_address, MACSTR_LEN, MACSTR, MAC2STR(peer_addr));
			wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
						     "Connection",
						     g_variant_new("(iis)", WIFI_DIRECT_ERROR_CONNECTION_FAILED,
									    WFD_EVENT_CONNECTION_RSP,
									    peer_mac_address));
		} else {
			WDS_LOGE("Unexpected Peer State. Ignore it");
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	} else {
		WDS_LOGE("Unexpected event. Ignore it");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
		wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
	} else {
		wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
	}

	/* If there is no member, GO should be destroyed */
	if (!group->member_count) {
		wfd_oem_destroy_group(manager->oem_ops, group->ifname);
		wfd_destroy_group(manager, group->ifname);
		wfd_peer_clear_all(manager);
	}

	wfd_destroy_session(manager);

	__WDS_LOG_FUNC_EXIT__;
	return;
}

static void __wfd_process_terminating(wfd_manager_s *manager, wfd_oem_event_s *event)
{
	__WDS_LOG_FUNC_ENTER__;

	__WDS_LOG_FUNC_EXIT__;
	return;
}

static void __wfd_process_group_formation_failure(wfd_manager_s *manager, wfd_oem_event_s *event)
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_session_s *session = (wfd_session_s*) manager->session;
	if (!session) {
		WDS_LOGE("Unexpected event. Session not exist");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	unsigned char *peer_addr = wfd_session_get_peer_addr(session);
	if (!peer_addr) {
		WDS_LOGE("Session do not has peer");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	char peer_mac_address[MACSTR_LEN+1] = {0, };
	g_snprintf(peer_mac_address, MACSTR_LEN, MACSTR, MAC2STR(peer_addr));
	wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
				     "Connection",
				     g_variant_new("(iis)", WIFI_DIRECT_ERROR_CONNECTION_FAILED,
							    WFD_EVENT_CONNECTION_RSP,
							    peer_mac_address));

	wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
	wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
	wfd_destroy_session(manager);
	manager->local->dev_role = WFD_DEV_ROLE_NONE;

	wfd_oem_refresh(manager->oem_ops);

	__WDS_LOG_FUNC_EXIT__;
	return;
}

/**
 * This event is generated by supplicant when persitent invite is auto accepted
 * so that wfd-manager can get indication that a peer will be connected in near future.
 * session is started for that peer, so that it is not ignored when connected.
 */
static void __wfd_process_invitation_accepted(wfd_manager_s *manager, wfd_oem_event_s *event)
{

	__WDS_LOG_FUNC_ENTER__;

	wfd_session_s *session = (wfd_session_s*) manager->session;
	wfd_device_s *peer = NULL;
	char peer_mac_address[MACSTR_LEN+1] = {0, };

	peer = wfd_peer_find_by_dev_addr(manager, event->dev_addr);
	if (!peer) {
		WDS_LOGI("Invitation from unknown peer. Add new peer");
		peer = wfd_add_peer(manager, event->dev_addr, "DIRECT-");
		if (!peer) {
			WDS_LOGE("Failed to add peer for invitation");
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	/**By default, peer device information is complete but there's some exception
	* if DEV-FOUND event was not preceding before connection start event.
	*/
	wfd_update_peer(manager, peer);
	peer->dev_role = WFD_DEV_ROLE_GO;

	if (!session) {
		session = wfd_create_session(manager, event->dev_addr,
					event->wps_mode, SESSION_DIRECTION_INCOMING);
		if (!session) {
			WDS_LOGE("Failed to create session with peer [" MACSTR "]",
							MAC2STR(event->dev_addr));
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}

	session->state = SESSION_STATE_WPS;
	wfd_session_timer(session, 1);

	g_snprintf(peer_mac_address, MACSTR_LEN, MACSTR, MAC2STR(event->dev_addr));
	wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
					 "Connection",
					 g_variant_new("(iis)", WIFI_DIRECT_ERROR_NONE,
								WFD_EVENT_CONNECTION_IN_PROGRESS,
								peer_mac_address));

	wfd_state_set(manager, WIFI_DIRECT_STATE_CONNECTING);
	wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_CONNECTING);

	__WDS_LOG_FUNC_EXIT__;
}

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
static void __wfd_process_serv_disc_resp(wfd_manager_s *manager, wfd_oem_event_s *event)
{
	__WDS_LOG_FUNC_ENTER__;
	int service_type;
	char response_data[256] = {0, };
	char peer_mac_address[MACSTR_LEN+1] = {0, };

	wfd_update_peer_time(manager, event->dev_addr);

	if (event->edata_type == WFD_OEM_EDATA_TYPE_NEW_SERVICE) {
		wfd_oem_new_service_s *service = NULL;;
		GList *temp = NULL;
		GList *services = (GList*) event->edata;
		int count = 0;

		WDS_LOGD("%d service data found", event->dev_role);

		temp = g_list_first(services);
		while(temp && count < event->dev_role) {
			service = (wfd_oem_new_service_s*) temp->data;
			service_type = service->protocol;
			if (service->protocol == WFD_OEM_SERVICE_TYPE_BONJOUR) {
				g_snprintf(peer_mac_address, MACSTR_LEN, MACSTR, MAC2STR(event->dev_addr));
				g_snprintf(response_data, 256, "%s|%s", service->data.bonjour.query, service->data.bonjour.rdata);
				WDS_LOGD("Found service: [%d: %s] - [" MACSECSTR "]", service->protocol,
							service->data.bonjour.query, MAC2SECSTR(event->dev_addr));
			} else {
				WDS_LOGD("Found service is not supported");
				goto next;
			}

			wfd_manager_dbus_emit_signal(WFD_MANAGER_SERVICE_INTERFACE,
						     "DiscoveryFound",
						     g_variant_new("(iss)", service_type,
									    response_data,
									    peer_mac_address));
next:
			temp = g_list_next(temp);
			service = NULL;
			count++;
		}
	} else if (event->edata_type == WFD_OEM_EDATA_TYPE_SERVICE) {
		wfd_oem_service_data_s *edata = (wfd_oem_service_data_s*) event->edata;

		if(!edata) {
			service_type = -1;
		} else {
			service_type = edata->type;
			g_snprintf(peer_mac_address, MACSTR_LEN, MACSTR, MAC2STR(event->dev_addr));
			switch(edata->type) {
				WDS_LOGE("Unknown type [type ID: %d]", edata->type);
			}
		}

		wfd_manager_dbus_emit_signal(WFD_MANAGER_SERVICE_INTERFACE,
					     "DiscoveryFound",
					     g_variant_new("(iss)", service_type,
								    response_data,
								    peer_mac_address));
	}

	__WDS_LOG_FUNC_EXIT__;
	return;
}

static void __wfd_process_serv_disc_started(wfd_manager_s *manager, wfd_oem_event_s *event)
{
	__WDS_LOG_FUNC_ENTER__;

	__WDS_LOG_FUNC_EXIT__;
	return;
}
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */


#if defined(TIZEN_FEATURE_ASP)
static void __wfd_process_asp_serv_resp(wfd_manager_s *manager, wfd_oem_event_s *event)
 {
	__WDS_LOG_FUNC_ENTER__;

	wfd_oem_asp_service_s *service = NULL;
	GVariantBuilder *builder = NULL;
	GVariant *params = NULL;

	service = (wfd_oem_asp_service_s *)event->edata;
	if(service == NULL) {
		WDS_LOGE("P2P service found event has NULL information");
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	builder = g_variant_builder_new(G_VARIANT_TYPE ("a{sv}"));
	g_variant_builder_add(builder, "{sv}", "search_id", g_variant_new("u", service->search_id));
	g_variant_builder_add(builder, "{sv}", "service_mac", g_variant_new("s", event->dev_addr));
	g_variant_builder_add(builder, "{sv}", "advertisement_id", g_variant_new("u", service->adv_id));
	g_variant_builder_add(builder, "{sv}", "config_method", g_variant_new("u", service->config_method));
	if(service->service_type)
		g_variant_builder_add(builder, "{sv}", "service_type", g_variant_new("s", service->service_type));
	if(service->service_info)
		g_variant_builder_add(builder, "{sv}", "service_info", g_variant_new("s", service->service_info));
	g_variant_builder_add(builder, "{sv}", "status", g_variant_new("y", service->status));
	params = g_variant_new("(a{sv})", builder);
	g_variant_builder_unref(builder);

	wfd_manager_dbus_emit_signal(WFD_MANAGER_ASP_INTERFACE,
				     "SearchResult",
				     params);

	__WDS_LOG_FUNC_EXIT__;
	return;
 }
#endif /* TIZEN_FEATURE_ASP */

static struct {
 const int event_id;
 void (*function) (wfd_manager_s *manager, wfd_oem_event_s *event);
} wfd_oem_event_map[] = {
	{
		WFD_OEM_EVENT_NONE,
		NULL
	},
	{
		WFD_OEM_EVENT_DEACTIVATED,
		__wfd_process_deactivated
	},
	{
		WFD_OEM_EVENT_PEER_FOUND,
		__wfd_process_peer_found
	},
	{
		WFD_OEM_EVENT_PEER_DISAPPEARED,
		__wfd_process_peer_disappeared
	},
	{
		WFD_OEM_EVENT_DISCOVERY_FINISHED,
		__wfd_process_discovery_finished
	},
	{
		WFD_OEM_EVENT_PROV_DISC_REQ,
		__wfd_process_prov_disc_req
	},
	{
		WFD_OEM_EVENT_PROV_DISC_RESP,
		__wfd_process_prov_disc_resp
	},
	{
		WFD_OEM_EVENT_PROV_DISC_FAIL,
		__wfd_process_prov_disc_fail
	},
	{
		WFD_OEM_EVENT_GO_NEG_REQ,
		__wfd_process_go_neg_req
	},
	{
		WFD_OEM_EVENT_GO_NEG_FAIL,
		__wfd_process_go_neg_fail
	},
	{
		WFD_OEM_EVENT_GO_NEG_DONE,
		__wfd_process_go_neg_done
	},
	{
		WFD_OEM_EVENT_WPS_FAIL,
		__wfd_process_wps_fail
	},
	{
		WFD_OEM_EVENT_WPS_DONE,
		__wfd_process_wps_done
	},
	{
		WFD_OEM_EVENT_KEY_NEG_FAIL,
		__wfd_process_key_neg_fail
	},
	{
		WFD_OEM_EVENT_KEY_NEG_DONE,
		__wfd_process_key_neg_done
	},
	{
		WFD_OEM_EVENT_CONN_FAIL,
		__wfd_process_conn_fail
	},
	{
		WFD_OEM_EVENT_CONN_DONE,
		__wfd_process_conn_done
	},
	{
		WFD_OEM_EVENT_GROUP_CREATED,
		__wfd_process_group_created
	},
	{
		WFD_OEM_EVENT_GROUP_DESTROYED,
		__wfd_process_group_destroyed
	},
	{
		WFD_OEM_EVENT_INVITATION_REQ,
		__wfd_process_invitation_req
	},
	{
		WFD_OEM_EVENT_INVITATION_RES,
		__wfd_process_invitation_res
	},
	{
		WFD_OEM_EVENT_STA_CONNECTED,
		__wfd_process_sta_connected
	},
	{
		WFD_OEM_EVENT_STA_DISCONNECTED,
		__wfd_process_sta_disconnected
	},
	{
		WFD_OEM_EVENT_TERMINATING,
		__wfd_process_terminating
	},

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
	{
		WFD_OEM_EVENT_SERV_DISC_RESP,
		__wfd_process_serv_disc_resp
	},
	{
		WFD_OEM_EVENT_SERV_DISC_STARTED,
		__wfd_process_serv_disc_started
	},
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */
	{
		WFD_OEM_EVENT_GROUP_FORMATION_FAILURE,
		__wfd_process_group_formation_failure
	},
	{
		WFD_OEM_EVENT_INVITATION_ACCEPTED,
		__wfd_process_invitation_accepted
	},
#if defined(TIZEN_FEATURE_ASP)
	{
		WFD_OEM_EVENT_ASP_SERV_RESP,
		__wfd_process_asp_serv_resp,
	},
#endif /* TIZEN_FEATURE_ASP */
	{
		WFD_OEM_EVENT_MAX,
		NULL
	}
 };

 int wfd_process_event(void *user_data, void *data)
 {
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = NULL;
	wfd_oem_event_s *event = NULL;

	manager = (wfd_manager_s*) user_data;
	event = (wfd_oem_event_s*) data;
	if (!manager || !event) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	WDS_LOGD("Event[%d] from " MACSECSTR, event->event_id,
						MAC2SECSTR(event->dev_addr));

	if(event->event_id > WFD_OEM_EVENT_NONE &&
			event->event_id < WFD_OEM_EVENT_MAX)
		 wfd_oem_event_map[event->event_id].function(manager, event);
	else
		WDS_LOGE("Invalid event ID");

	__WDS_LOG_FUNC_EXIT__;
	return 0;
 }
