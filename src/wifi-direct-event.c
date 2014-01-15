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
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include <glib.h>

#include <wifi-direct-internal.h>

#include "wifi-direct-manager.h"
#include "wifi-direct-oem.h"
#include "wifi-direct-peer.h"
#include "wifi-direct-group.h"
#include "wifi-direct-session.h"
#include "wifi-direct-event.h"
#include "wifi-direct-client.h"
#include "wifi-direct-state.h"
#include "wifi-direct-util.h"


static int _wfd_event_check_socket(int sock)
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

static int _wfd_event_send_to_client(int sock, char *data, int data_len)
{
	__WDS_LOG_FUNC_ENTER__;
	int wbytes = 0;
	int left_len = data_len;
	char *ptr = data;
	int res = 0;

	if (sock < SOCK_FD_MIN || !data || data_len < 0) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	res = _wfd_event_check_socket(sock);
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
			WDS_LOGE("Failed to write data into socket[%d]. [%s]", sock, strerror(errno));
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
			strncpy(peer->dev_name, data->name, DEV_NAME_LEN);
			peer->dev_name[DEV_NAME_LEN] = '\0';
			WDS_LOGD("Device name is changed [" MACSTR ": %s]", MAC2STR(peer->dev_addr), peer->dev_name);
		}
	}
	memcpy(peer->intf_addr, data->p2p_intf_addr, MACADDR_LEN);
	peer->pri_dev_type = data->pri_dev_type;
	peer->sec_dev_type = data->sec_dev_type;
	peer->config_methods = data->config_methods;
	peer->dev_flags = data->dev_flags;
	peer->group_flags = data->group_flags;
	peer->dev_role = data->dev_role;

	struct timeval tval;
	gettimeofday(&tval, NULL);
	peer->time = tval.tv_sec;

	WDS_LOGI("Update time [%s - %ld]", peer->dev_name, peer->time);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
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

	WDS_LOGD("Event[%d] from " MACSTR, event->event_id, MAC2STR(event->dev_addr));

	switch (event->event_id) {
	case WFD_OEM_EVENT_DEACTIVATED:
		manager->req_wps_mode = WFD_WPS_MODE_PBC;
		break;
	case WFD_OEM_EVENT_PEER_FOUND:
	{
		wfd_oem_dev_data_s *edata = (wfd_oem_dev_data_s*) event->edata;
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
			noti.event = WIFI_DIRECT_CLI_EVENT_DISCOVER_FOUND_PEERS;
			noti.error = WIFI_DIRECT_ERROR_NONE;
			wfd_client_send_event(manager, &noti);
		}
	}
	break;
	case WFD_OEM_EVENT_PROV_DISC_REQ:
	case WFD_OEM_EVENT_PROV_DISC_RESP:
	case WFD_OEM_EVENT_PROV_DISC_DISPLAY:
	case WFD_OEM_EVENT_PROV_DISC_KEYPAD:
	{
		wfd_device_s *peer = wfd_peer_find_by_dev_addr(manager, event->dev_addr);
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
		noti.event = WIFI_DIRECT_CLI_EVENT_INVITATION_REQ;
		noti.error = WIFI_DIRECT_ERROR_NONE;
		snprintf(noti.param1, sizeof(noti.param1), MACSTR, MAC2STR(event->dev_addr));
		wfd_client_send_event(manager, &noti);
	}
	break;
	case WFD_OEM_EVENT_GO_NEG_REQ:
	case WFD_OEM_EVENT_GO_NEG_DONE:
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
			WDS_LOGE("Unexpected event. Session is NULL [peer: " MACSTR "]",
										MAC2STR(event->dev_addr));
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
		memcpy(peer->intf_addr, event->intf_addr, MACADDR_LEN);
		peer->state = WFD_PEER_STATE_CONNECTED;

		if (event->event_id == WFD_OEM_EVENT_STA_CONNECTED) {	// GO
			wifi_direct_client_noti_s noti;
			memset(&noti, 0x0, sizeof(wifi_direct_client_noti_s));
			noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP;
			noti.error = WIFI_DIRECT_ERROR_NONE;
			snprintf(noti.param1, MACSTR_LEN, MACSTR, MAC2STR(peer->dev_addr));
			wfd_client_send_event(manager, &noti);

			wfd_util_dhcps_wait_ip_leased(peer);
			wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
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

		peer = wfd_group_find_member_by_addr(group, event->intf_addr);
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
			snprintf(noti.param1, MACSTR_LEN, MACSTR, MAC2STR(peer_addr));
			/* If there is no member, GO should be destroyed */
			if (!group->member_count) {
				wfd_oem_destroy_group(manager->oem_ops, group->ifname);
				wfd_destroy_group(manager, group->ifname);
			}
		} else if (manager->state == WIFI_DIRECT_STATE_DISCONNECTING) {
			noti.event = WIFI_DIRECT_CLI_EVENT_DISCONNECTION_RSP;
			noti.error = WIFI_DIRECT_ERROR_NONE;
			snprintf(noti.param1, MACSTR_LEN, MACSTR, MAC2STR(peer_addr));
		} else if (manager->state == WIFI_DIRECT_STATE_CONNECTING &&
					/* Some devices(GO) send disconnection message before connection completed.
					 * This message should be ignored when device is not GO */
					manager->local->dev_role == WFD_DEV_ROLE_GO) {
			noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP;
			noti.error = WIFI_DIRECT_ERROR_CONNECTION_FAILED;
			snprintf(noti.param1, MACSTR_LEN, MACSTR, MAC2STR(peer_addr));
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
		wfd_oem_group_data_s *edata = event->edata;
		wfd_group_s *group = (wfd_group_s*) manager->group;

		if (!group) {
			if (!manager->session) {
				WDS_LOGE("Unexpected Event. Group should be removed(Client)");
				wfd_oem_destroy_group(manager->oem_ops, event->ifname);
				break;
			}

			group = wfd_create_group(manager, event->ifname, event->dev_role, edata->go_dev_addr);
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
				wfd_group_complete(manager, event->ifname, event->dev_role, edata->go_dev_addr);
			} else {
				WDS_LOGE("Unexpected event. Group already exist");
				break;
			}
		}

		strncpy(group->ssid, edata->ssid, DEV_NAME_LEN);
		group->ssid[DEV_NAME_LEN-1] = '\0';
		strncpy(group->pass,edata->pass, PASSPHRASE_LEN);
		group->pass[PASSPHRASE_LEN] = '\0';
		group->freq = edata->freq;
		manager->group = group;
		manager->local->dev_role = event->dev_role;

		wifi_direct_client_noti_s noti;
		memset(&noti, 0x0, sizeof(wifi_direct_client_noti_s));
		if (group->role == WFD_DEV_ROLE_GC) {
			wfd_destroy_session(manager);
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
			snprintf(noti.param1, MACSTR_LEN, MACSTR, MAC2STR(peer_addr));
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
	case WFD_OEM_EVENT_PROV_DISC_FAIL:
	case WFD_OEM_EVENT_GO_NEG_FAIL:
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

		/* After connection failed, scan again */
		wfd_oem_scan_param_s param;
		memset(&param, 0x0, sizeof(wfd_oem_scan_param_s));
		param.scan_mode = WFD_OEM_SCAN_MODE_ACTIVE;
		param.scan_time = 2;
		param.scan_type = WFD_OEM_SCAN_TYPE_SOCIAL;
		wfd_oem_start_scan(manager->oem_ops, &param);
		manager->scan_mode = WFD_SCAN_MODE_ACTIVE;
	}
	break;
	default:
		WDS_LOGE("Unknown event [event ID: %d]", event->event_id);
	break;
	}

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

