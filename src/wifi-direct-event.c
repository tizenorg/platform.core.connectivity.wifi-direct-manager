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
#include "wifi-direct-client.h"
#include "wifi-direct-state.h"
#include "wifi-direct-util.h"


static int _wfd_event_update_peer(wfd_manager_s *manager, wfd_oem_dev_data_s *data)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *peer = NULL;

	if (!manager || !data) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	peer = wfd_peer_find_by_dev_addr(manager, data->p2p_dev_addr);
	if (!peer) {
		peer = wfd_add_peer(manager, data->p2p_dev_addr, data->name);
		if (!peer) {
			WDS_LOGE("Failed to add peer");
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

	return G_SOURCE_REMOVE;
}

int wfd_process_event(void *user_data, void *data)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = (wfd_manager_s*) user_data;
	wfd_oem_event_s *event = (wfd_oem_event_s*) data;
	int res = 0;

	if (!manager || !event) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	WDS_LOGD("Event[%d] from " MACSECSTR, event->event_id, MAC2SECSTR(event->dev_addr));

	switch (event->event_id) {
	case WFD_OEM_EVENT_DEACTIVATED:
	{
		// TODO: notify app
		wifi_direct_client_noti_s noti;
		memset(&noti, 0x0, sizeof(wifi_direct_client_noti_s));
		noti.event = WIFI_DIRECT_CLI_EVENT_DEACTIVATION;
		noti.error = WIFI_DIRECT_ERROR_NONE;
		wfd_client_send_event(manager, &noti);

		// TODO: remove group, session, all peers
		wfd_destroy_group(manager, GROUP_IFNAME);
		wfd_destroy_session(manager);
		wfd_peer_clear_all(manager);
		wfd_local_reset_data(manager);

		wfd_state_set(manager, WIFI_DIRECT_STATE_DEACTIVATED);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_DEACTIVATED);
		manager->req_wps_mode = WFD_WPS_MODE_PBC;
	}
	break;
	case WFD_OEM_EVENT_PEER_FOUND:
	{
		wfd_oem_dev_data_s *edata = (wfd_oem_dev_data_s*) event->edata;
		if (!edata || event->edata_type != WFD_OEM_EDATA_TYPE_DEVICE) {
			WDS_LOGE("Invalid event data");
			break;
		}

		res = _wfd_event_update_peer(manager, edata);
		if (res < 0) {
			WDS_LOGE("Failed to update peer data");
			break;
		}

		if (manager->state > WIFI_DIRECT_STATE_ACTIVATING &&
				manager->state != WIFI_DIRECT_STATE_CONNECTING &&
				manager->state != WIFI_DIRECT_STATE_DISCONNECTING) {
			wifi_direct_client_noti_s noti;
			memset(&noti, 0x0, sizeof(wifi_direct_client_noti_s));
			snprintf(noti.param1, MACSTR_LEN, MACSTR, MAC2STR(edata->p2p_dev_addr));
			noti.event = WIFI_DIRECT_CLI_EVENT_DISCOVER_FOUND_PEERS;
			noti.error = WIFI_DIRECT_ERROR_NONE;
			wfd_client_send_event(manager, &noti);
		}
	}
	break;
	case WFD_OEM_EVENT_PROV_DISC_REQ:
	case WFD_OEM_EVENT_PROV_DISC_RESP:
	{
		wfd_device_s *peer = NULL;
#ifdef CTRL_IFACE_DBUS
		wfd_oem_dev_data_s *edata = (wfd_oem_dev_data_s*) event->edata;
		if (!edata || event->edata_type != WFD_OEM_EDATA_TYPE_DEVICE) {
			WDS_LOGE("Invalid event data");
			break;
		}

		res = _wfd_event_update_peer(manager, edata);
		peer = wfd_peer_find_by_dev_addr(manager, event->dev_addr);
		peer->state = WFD_PEER_STATE_CONNECTING;
#else /* CTRL_IFACE_DBUS */
		peer = wfd_peer_find_by_dev_addr(manager, event->dev_addr);
		if (!peer) {
			WDS_LOGD("Porv_disc from unknown peer. Add new peer");
			peer = wfd_add_peer(manager, event->dev_addr, "DIRECT-");
			if (!peer) {
				WDS_LOGE("Failed to add peer for invitation");
				return -1;
			}
			peer->state = WFD_PEER_STATE_CONNECTING;
			wfd_update_peer(manager, peer);
		}
		wfd_update_peer_time(manager, event->dev_addr);
#endif /* CTRL_IFACE_DBUS */
		res = wfd_session_process_event(manager, event);
		if (res < 0) {
			WDS_LOGE("Failed to process event of session");
			break;
		}
	}
	break;
	case WFD_OEM_EVENT_PEER_DISAPPEARED:
	{
		wfd_remove_peer(manager, event->dev_addr);
		wifi_direct_client_noti_s noti;
		memset(&noti, 0x0, sizeof(wifi_direct_client_noti_s));
		noti.event = WIFI_DIRECT_CLI_EVENT_DISCOVER_FOUND_PEERS;
		noti.error = WIFI_DIRECT_ERROR_NONE;
		wfd_client_send_event(manager, &noti);
	}
	break;
	case WFD_OEM_EVENT_DISCOVERY_FINISHED:
	{
		if (manager->state != WIFI_DIRECT_STATE_DISCOVERING &&
				manager->state != WIFI_DIRECT_STATE_ACTIVATED) {
			WDS_LOGE("Notify finding stoped when discovering or activated. [%d]", manager->state);
			break;
		}

		if (manager->scan_mode == WFD_SCAN_MODE_PASSIVE) {
			WDS_LOGE("During passive scan, Discover Finished event will not notified");
			break;
		}

		if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
			wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
		} else {
			wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
		}
		manager->scan_mode = WFD_SCAN_MODE_NONE;

		wifi_direct_client_noti_s noti;
		memset(&noti, 0x0, sizeof(wifi_direct_client_noti_s));
		noti.event = WIFI_DIRECT_CLI_EVENT_DISCOVER_END;
		noti.error = WIFI_DIRECT_ERROR_NONE;
		wfd_client_send_event(manager, &noti);
	}
	break;
	case WFD_OEM_EVENT_INVITATION_REQ:
	{
		wfd_device_s *peer = NULL;
		wfd_session_s *session = NULL;
		wfd_oem_invite_data_s *edata = (wfd_oem_invite_data_s*) event->edata;

		peer = wfd_peer_find_by_dev_addr(manager, event->dev_addr);
		if (!peer) {
			WDS_LOGD("Invitation from unknown peer. Add new peer");
			peer = wfd_add_peer(manager, event->dev_addr, "DIRECT-");
			if (!peer) {
				WDS_LOGE("Failed to add peer for invitation");
				return -1;
			}
		}
		peer->dev_role = WFD_DEV_ROLE_GO;
		memcpy(peer->intf_addr, edata->bssid, MACADDR_LEN);
		wfd_update_peer_time(manager, event->dev_addr);

		session = wfd_create_session(manager, event->dev_addr,
						manager->req_wps_mode, SESSION_DIRECTION_INCOMING);
		if (!session) {
			WDS_LOGE("Failed to create session");
			return -1;
		}
		session->type = SESSION_TYPE_INVITE;
		wfd_session_timer(session, 1);

		wfd_state_set(manager, WIFI_DIRECT_STATE_CONNECTING);

		wifi_direct_client_noti_s noti;
		memset(&noti, 0x0, sizeof(wifi_direct_client_noti_s));
		noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_REQ;
		noti.error = WIFI_DIRECT_ERROR_NONE;
		snprintf(noti.param1, sizeof(noti.param1), MACSTR, MAC2STR(event->dev_addr));
		wfd_client_send_event(manager, &noti);
	}
	break;
	case WFD_OEM_EVENT_GO_NEG_REQ:
	{
		wfd_session_s *session = (wfd_session_s*) manager->session;
#ifdef CTRL_IFACE_DBUS
		wfd_oem_dev_data_s *edata = (wfd_oem_dev_data_s*) event->edata;
		if (!edata || event->edata_type != WFD_OEM_EDATA_TYPE_DEVICE) {
			WDS_LOGE("Invalid event data");
			break;
		}

		res = _wfd_event_update_peer(manager, edata);
		if (res < 0) {
			WDS_LOGE("Failed to update peer data");
			break;
		}
#else /* CTRL_IFACE_DBUS */
		wfd_device_s *peer = NULL;
		wfd_oem_conn_data_s *edata = (wfd_oem_conn_data_s*) event->edata;

		if (!edata || event->edata_type != WFD_OEM_EDATA_TYPE_CONN) {
			WDS_LOGE("Invalid connection event data");
			break;
		}

		peer = wfd_peer_find_by_dev_addr(manager, event->dev_addr);
		if (!peer) {
			WDS_LOGD("Invitation from unknown peer. Add new peer");
			peer = wfd_add_peer(manager, event->dev_addr, "DIRECT-");
			if (!peer) {
				WDS_LOGE("Failed to add peer for invitation");
				break;
			}
		}

		if (edata->wps_mode == 0)
			edata->wps_mode = 1;
#endif /* CTRL_IFACE_DBUS */
		if (!session) {
			session = wfd_create_session(manager, event->dev_addr,
#ifdef CTRL_IFACE_DBUS
							event->wps_mode, SESSION_DIRECTION_INCOMING);
#else /* CTRL_IFACE_DBUS */
							edata->wps_mode, SESSION_DIRECTION_INCOMING);
#endif /* CTRL_IFACE_DBUS */
			if (!session) {
				WDS_LOGE("Failed to create session");
				return -1;
			}
			session->type = SESSION_TYPE_NORMAL;
			session->state = SESSION_STATE_GO_NEG;
			wfd_session_timer(session, 1);
			wfd_state_set(manager, WIFI_DIRECT_STATE_CONNECTING);

			wifi_direct_client_noti_s noti;
			memset(&noti, 0x0, sizeof(wifi_direct_client_noti_s));
			noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_REQ;
			noti.error = WIFI_DIRECT_ERROR_NONE;
			g_snprintf(noti.param1, sizeof(noti.param1), MACSTR, MAC2STR(event->dev_addr));
			wfd_client_send_event(manager, &noti);
		} else {
			wfd_session_process_event(manager, event);
		}
	}
	break;
	case WFD_OEM_EVENT_GO_NEG_DONE:
#ifdef CTRL_IFACE_DBUS
	{
		wfd_session_s *session = (wfd_session_s*) manager->session;
		wfd_oem_conn_data_s *edata = (wfd_oem_conn_data_s*) event->edata;
		wfd_device_s *peer = NULL;

		if (event == NULL || edata == NULL) {
			WDS_LOGE("Invalid event data");
			break;
		}

		if(session && session->peer) {
			peer = session->peer;
			memcpy(peer->intf_addr, edata->peer_intf_addr, MACADDR_LEN);
		}
		manager->local->dev_role = event->dev_role;
		wfd_session_process_event(manager, event);
	}
	break;
#endif /* CTRL_IFACE_DBUS */
	case WFD_OEM_EVENT_WPS_DONE:
		wfd_session_process_event(manager, event);
	break;
	case WFD_OEM_EVENT_CONNECTED:
	case WFD_OEM_EVENT_STA_CONNECTED:
	{
		// FIXME: Move this code to plugin
		if (!memcmp(event->intf_addr, manager->local->intf_addr, MACADDR_LEN)) {
			WDS_LOGD("Ignore this event");
			break;
		}

		wfd_session_s *session = (wfd_session_s*) manager->session;
		if (!session) {
			WDS_LOGD("Unexpected event. Session is NULL [peer: " MACSECSTR "]",
										MAC2SECSTR(event->dev_addr));
			wfd_oem_destroy_group(manager->oem_ops, GROUP_IFNAME);
			wfd_destroy_group(manager, GROUP_IFNAME);
			wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
			break;
		}

		wfd_device_s *peer = wfd_session_get_peer(session);
		if (!peer) {
			WDS_LOGE("Peer not found");
			break;
		}

		wfd_group_s *group = (wfd_group_s*) manager->group;
		if (!group) {
			group = wfd_create_pending_group(manager, event->intf_addr);
			if (!group) {
				WDS_LOGE("Failed to create pending group");
				break;
			}
			manager->group = group;
		}
		wfd_group_add_member(group, peer->dev_addr);

		session->state = SESSION_STATE_COMPLETED;
#ifndef CTRL_IFACE_DBUS
		memcpy(peer->intf_addr, event->intf_addr, MACADDR_LEN);
#endif /* CTRL_IFACE_DBUS */
		peer->state = WFD_PEER_STATE_CONNECTED;

		if (event->event_id == WFD_OEM_EVENT_STA_CONNECTED) {	// GO
			wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);

			wifi_direct_client_noti_s noti;
			memset(&noti, 0x0, sizeof(wifi_direct_client_noti_s));
			noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP;
			noti.error = WIFI_DIRECT_ERROR_NONE;
			snprintf(noti.param1, MACSTR_LEN, MACSTR, MAC2STR(peer->dev_addr));
			wfd_client_send_event(manager, &noti);
#ifdef CTRL_IFACE_DBUS
			wfd_update_peer(manager, peer);
#endif /* CTRL_IFACE_DBUS */

			wfd_util_dhcps_wait_ip_leased(peer);
			wfd_destroy_session(manager);
		}
	}
	break;
	case WFD_OEM_EVENT_DISCONNECTED:
	case WFD_OEM_EVENT_STA_DISCONNECTED:
	{
		wfd_group_s *group = (wfd_group_s*) manager->group;
		wfd_session_s *session = (wfd_session_s*) manager->session;
		wfd_device_s *peer = NULL;
		unsigned char peer_addr[MACADDR_LEN] = {0, };
		wifi_direct_client_noti_s noti;
		memset(&noti, 0x0, sizeof(wifi_direct_client_noti_s));

		if (!group) {
			WDS_LOGE("Group not found");
			break;
		}

#ifdef CTRL_IFACE_DBUS
		peer = wfd_group_find_member_by_addr(group, event->dev_addr);
#else /* CTRL_IFACE_DBUS */
		peer = wfd_group_find_member_by_addr(group, event->intf_addr);
#endif /* DBUS_IFACE */
		if (!peer) {
			WDS_LOGE("Failed to find connected peer");
			peer = wfd_session_get_peer(session);
			if (!peer) {
				WDS_LOGE("Failed to find connecting peer");
				break;
			}
		}
		memcpy(peer_addr, peer->dev_addr, MACADDR_LEN);

		/* If state is not DISCONNECTING, connection is finished by peer */
		if (manager->state >= WIFI_DIRECT_STATE_CONNECTED) {
			wfd_group_remove_member(group, peer_addr);
			if (group->member_count)
				noti.event = WIFI_DIRECT_CLI_EVENT_DISASSOCIATION_IND;
			else
				noti.event = WIFI_DIRECT_CLI_EVENT_DISCONNECTION_IND;
			noti.error = WIFI_DIRECT_ERROR_NONE;
			g_snprintf(noti.param1, MACSTR_LEN, MACSTR, MAC2STR(peer_addr));
			/* If there is no member and GO is not Auto GO,
			 * then GO should be destroyed */
			if (!group->member_count && (wfd_group_is_autonomous(group) == FALSE)) {
				wfd_oem_destroy_group(manager->oem_ops, group->ifname);
				wfd_destroy_group(manager, group->ifname);
			}
		} else if (manager->state == WIFI_DIRECT_STATE_DISCONNECTING) {
			noti.event = WIFI_DIRECT_CLI_EVENT_DISCONNECTION_RSP;
			noti.error = WIFI_DIRECT_ERROR_NONE;
			g_snprintf(noti.param1, MACSTR_LEN, MACSTR, MAC2STR(peer_addr));
		} else if (manager->state == WIFI_DIRECT_STATE_CONNECTING &&
				/* Some devices(GO) send disconnection message before connection completed.
				 * This message should be ignored when device is not GO */
				manager->local->dev_role == WFD_DEV_ROLE_GO) {
			if (WFD_PEER_STATE_CONNECTED == peer->state) {
				WDS_LOGD("Peer is already Connected !!!");
				noti.event = WIFI_DIRECT_CLI_EVENT_DISASSOCIATION_IND;
				noti.error = WIFI_DIRECT_ERROR_NONE;
			} else if (WFD_PEER_STATE_CONNECTING == peer->state) {
				WDS_LOGD("Peer is Connecting...");
				noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP;
				noti.error = WIFI_DIRECT_ERROR_CONNECTION_FAILED;
			} else {
				WDS_LOGE("Unexpected Peer State. Ignore it");
				break;
			}
			g_snprintf(noti.param1, MACSTR_LEN, MACSTR, MAC2STR(peer_addr));
		} else {
			WDS_LOGE("Unexpected event. Ignore it");
			break;
		}
		wfd_client_send_event(manager, &noti);

		if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
			wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
		} else {
			wfd_destroy_group(manager, GROUP_IFNAME);
			wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
		}
		wfd_destroy_session(manager);
	}
	break;
	case WFD_OEM_EVENT_GROUP_CREATED:
	{
		wfd_group_s *group = (wfd_group_s*) manager->group;
#ifdef CTRL_IFACE_DBUS
		if(event->dev_role == WFD_DEV_ROLE_GC && !group) {

			group = wfd_create_pending_group(manager, event->intf_addr);
			if (!group) {
				WDS_LOGE("Failed to create pending group");
				break;
			}
			manager->group = group;
		}
#endif /* CTRL_IFACE_DBUS */

		if (!group) {
			if (!manager->session) {
				WDS_LOGE("Unexpected Event. Group should be removed(Client)");
				wfd_oem_destroy_group(manager->oem_ops, event->ifname);
				break;
			}

			group = wfd_create_group(manager, event);
			if (!group) {
				WDS_LOGE("Failed to create group");
				break;
			}
		} else {
			if (!manager->session && !(group->flags & WFD_GROUP_FLAG_AUTONOMOUS)) {
				WDS_LOGE("Unexpected Event. Group should be removed(Owner)");
				wfd_oem_destroy_group(manager->oem_ops, group->ifname);
				break;
			}

			if (group->pending) {
				wfd_group_complete(manager, event);
			} else {
				WDS_LOGE("Unexpected event. Group already exist");
				break;
			}
		}

		wifi_direct_client_noti_s noti;
		memset(&noti, 0x0, sizeof(wifi_direct_client_noti_s));
		if (group->role == WFD_DEV_ROLE_GC) {
#ifndef CTRL_IFACE_DBUS
			wfd_destroy_session(manager);
#endif /* CTRL_IFACE_DBUS */
			wfd_peer_clear_all(manager);
		} else {
			if (group->flags & WFD_GROUP_FLAG_AUTONOMOUS) {
				noti.event = WIFI_DIRECT_CLI_EVENT_GROUP_CREATE_RSP;
				wfd_client_send_event(manager, &noti);
				wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
				wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
			}
		}
	}
	break;
	case WFD_OEM_EVENT_GROUP_DESTROYED:
	{
		wifi_direct_client_noti_s noti;
		memset(&noti, 0x0, sizeof(wifi_direct_client_noti_s));
		if (manager->state == WIFI_DIRECT_STATE_DISCONNECTING) {
			noti.event = WIFI_DIRECT_CLI_EVENT_DISCONNECTION_RSP;
			noti.error = WIFI_DIRECT_ERROR_NONE;
		} else if (manager->state == WIFI_DIRECT_STATE_CONNECTING && manager->session){
			noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP;
			noti.error = WIFI_DIRECT_ERROR_CONNECTION_FAILED;
			unsigned char *peer_addr = wfd_session_get_peer_addr(manager->session);
			if(peer_addr != NULL)
				g_snprintf(noti.param1, MACSTR_LEN, MACSTR, MAC2STR(peer_addr));
		} else if (manager->state >= WIFI_DIRECT_STATE_CONNECTED) {
			noti.event = WIFI_DIRECT_CLI_EVENT_GROUP_DESTROY_RSP;
			noti.error = WIFI_DIRECT_ERROR_NONE;
		} else {
			WDS_LOGD("Unexpected event(GROUP_DESTROYED). Ignore it");
			break;
		}
		wfd_client_send_event(manager, &noti);

		wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
		wfd_destroy_group(manager, event->ifname);
		wfd_destroy_session(manager);
		manager->local->dev_role = WFD_DEV_ROLE_NONE;
	}
	break;
	case WFD_OEM_EVENT_GO_NEG_FAIL:
	{
		wfd_session_s *session = (wfd_session_s*) manager->session;
		if (!session) {
			WDS_LOGE("Unexpected event. Session not exist");
			break;
		}

		unsigned char *peer_addr = wfd_session_get_peer_addr(session);
		if (!peer_addr) {
			WDS_LOGE("Session do not has peer");
			break;
		}

		if (event->event_id == WFD_OEM_EVENT_GO_NEG_FAIL) {
			wfd_oem_conn_data_s *edata = (wfd_oem_conn_data_s*) event->edata;
			if (edata && edata->status < 0 && session->connecting_120) {
				if (session->retry_gsrc) {
					g_source_remove(session->retry_gsrc);
					session->retry_gsrc = 0;
				}
				session->retry_gsrc = g_idle_add((GSourceFunc) _wfd_connection_retry, session);
				WDS_LOGD("Connection will be retried");
				break;
			}
		}

		wifi_direct_client_noti_s noti;
		memset(&noti, 0x0, sizeof(wifi_direct_client_noti_s));
		noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP;
		noti.error = WIFI_DIRECT_ERROR_CONNECTION_FAILED;
		snprintf(noti.param1, MACSTR_LEN, MACSTR, MAC2STR(peer_addr));
		wfd_client_send_event(manager, &noti);

		if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
			wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
		} else {
			wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
		}

		wfd_destroy_session(manager);
	}
	break;
	case WFD_OEM_EVENT_PROV_DISC_FAIL:
	case WFD_OEM_EVENT_WPS_FAIL:
	case WFD_OEM_EVENT_KEY_NEG_FAIL:
	{
		wfd_session_s *session = (wfd_session_s*) manager->session;
		if (!session) {
			WDS_LOGE("Unexpected event. Session not exist");
			break;
		}

		unsigned char *peer_addr = wfd_session_get_peer_addr(session);
		if (!peer_addr) {
			WDS_LOGE("Session do not has peer");
			break;
		}

		if (event->event_id == WFD_OEM_EVENT_GO_NEG_FAIL) {
			wfd_oem_conn_data_s *edata = (wfd_oem_conn_data_s*) event->edata;
			if (edata && edata->status < 0 && session->connecting_120) {
				if (session->retry_gsrc) {
					g_source_remove(session->retry_gsrc);
					session->retry_gsrc = 0;
				}
				session->retry_gsrc = g_idle_add((GSourceFunc) _wfd_connection_retry, session);
				WDS_LOGD("Connection will be retried");
				break;
			}
		}

		wifi_direct_client_noti_s noti;
		memset(&noti, 0x0, sizeof(wifi_direct_client_noti_s));
		noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP;
		noti.error = WIFI_DIRECT_ERROR_CONNECTION_FAILED;
		snprintf(noti.param1, MACSTR_LEN, MACSTR, MAC2STR(peer_addr));
		wfd_client_send_event(manager, &noti);

		if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
			wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
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
	}
	break;

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
	case WFD_OEM_EVENT_SERV_DISC_RESP:
	{
		wifi_direct_client_noti_s noti;
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
				memset(&noti, 0x0, sizeof(wifi_direct_client_noti_s));
				noti.event = WIFI_DIRECT_CLI_EVENT_SERVICE_DISCOVERY_FOUND;
				noti.type = service->protocol;
				if (service->protocol == WFD_OEM_SERVICE_TYPE_BONJOUR) {
					g_snprintf(noti.param1, MACSTR_LEN, MACSTR, MAC2STR(event->dev_addr));
					g_snprintf(noti.param2, 256, "%s|%s", service->data.bonjour.query, service->data.bonjour.rdata);
					WDS_LOGD("Found service: [%d: %s] - [" MACSECSTR "]", service->protocol,
								service->data.bonjour.query, MAC2SECSTR(event->dev_addr));
				} else if (service->protocol == WFD_OEM_SERVICE_TYPE_BT_ADDR) {
					g_snprintf(noti.param1, MACSTR_LEN, MACSTR, MAC2STR(event->dev_addr));
					g_snprintf(noti.param2, MACSTR_LEN, "%s", service->data.vendor.data2);
					WDS_LOGD("Found service: [%d: %s] - [" MACSECSTR "]", service->protocol,
								service->data.vendor.data2, MAC2SECSTR(event->dev_addr));
				} else {
					WDS_LOGD("Found service is not supported");
					goto next;
				}
				wfd_client_send_event(manager, &noti);
next:
				temp = g_list_next(temp);
				service = NULL;
				count++;
			}
		} else if (event->edata_type == WFD_OEM_EDATA_TYPE_SERVICE) {
			wfd_oem_service_data_s *edata = (wfd_oem_service_data_s*) event->edata;

			memset(&noti, 0x0, sizeof(wifi_direct_client_noti_s));
			noti.event = WIFI_DIRECT_CLI_EVENT_SERVICE_DISCOVERY_FOUND;
			if(!edata) {
				noti.type = -1;
			} else {
				noti.type = edata->type;
				g_snprintf(noti.param1, MACSTR_LEN, MACSTR, MAC2STR(event->dev_addr));
				switch(edata->type) {
					case WFD_OEM_SERVICE_TYPE_BT_ADDR:
						g_snprintf(noti.param2, MACSTR_LEN, MACSTR, MAC2STR(edata->data));
						break;
					case WFD_OEM_SERVICE_TYPE_CONTACT_INFO:
						g_snprintf(noti.param2, MACSTR_LEN, "%s", edata->value);
						break;
					default:
						WDS_LOGE("Unknown type [type ID: %d]", edata->type);
				}
			}
			wfd_client_send_event(manager, &noti);
		}
	}
	break;
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

	default:
		WDS_LOGE("Unknown event [event ID: %d]", event->event_id);
	break;
	}

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

