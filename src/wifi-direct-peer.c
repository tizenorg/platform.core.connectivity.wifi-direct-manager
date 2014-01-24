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
 * This file implements wifi direct peer functions.
 *
 * @file		wifi-direct-peer.c
 * @author	Gibyoung Kim (lastkgb.kim@samsung.com)
 * @version	0.7
 */

#include <stdio.h>
#include <stdlib.h>

#include <glib.h>

#include <wifi-direct-internal.h>

#include "wifi-direct-manager.h"
#include "wifi-direct-oem.h"
#include "wifi-direct-util.h"
#include "wifi-direct-peer.h"
#include "wifi-direct-session.h"


wfd_device_s *wfd_add_peer(void *data, unsigned char *dev_addr, char *dev_name)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = (wfd_manager_s*) data;
	wfd_device_s *peer = NULL;

	if (!data || !dev_addr || !dev_name) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return NULL;
	}

	peer = wfd_peer_find_by_dev_addr(manager, dev_addr);
	if (peer) {
		WDS_LOGE("Peer already exist[" MACSTR "]", MAC2STR(dev_addr));
		__WDS_LOG_FUNC_EXIT__;
		return NULL;
	}

	peer = (wfd_device_s*) calloc(1, sizeof(wfd_device_s));
	memcpy(peer->dev_addr, dev_addr, MACADDR_LEN);
	strncpy(peer->dev_name, dev_name, DEV_NAME_LEN);
	peer->dev_name[DEV_NAME_LEN-1] = '\0';

	manager->peers = g_list_prepend(manager->peers, peer);
	manager->peer_count++;
	WDS_LOGD("peer_count[%d]", manager->peer_count);
	__WDS_LOG_FUNC_EXIT__;
	return peer;
}

int wfd_remove_peer(void *data, unsigned char *dev_addr)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = (wfd_manager_s*) data;
	wfd_device_s *peer = NULL;

	if (!data || !dev_addr) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	peer = wfd_peer_find_by_dev_addr(manager, dev_addr);
	if (!peer) {
		WDS_LOGE("Failed to find peer device");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	manager->peers = g_list_remove(manager->peers, peer);
	manager->peer_count--;

	wfd_manager_init_service(peer);
	free(peer);
	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_update_peer_time(void*data, unsigned char *peer_addr)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = (wfd_manager_s*) data;
	wfd_device_s *peer = NULL;

	if (!manager || !peer_addr) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	peer = wfd_peer_find_by_dev_addr(manager, peer_addr);
	if (!peer) {
		WDS_LOGE("Peer not found [" MACSTR "]", MAC2STR(peer_addr));
		return -1;
	}

	struct timeval tval;
	gettimeofday(&tval, NULL);
	peer->time = tval.tv_sec;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_update_peer(void *data, wfd_device_s *peer)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = (wfd_manager_s*) data;
	wfd_oem_device_s *oem_dev = NULL;
	int res = 0;

	if (!peer) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	res = wfd_oem_get_peer_info(manager->oem_ops, peer->dev_addr, &oem_dev);
	if (res < 0) {
		WDS_LOGE("Failed to get peer information");
		return -1;
	}

	if (oem_dev->age > 4 && peer->state == WFD_PEER_STATE_DISCOVERED) {
		WDS_LOGE("Too old age to update peer");
		return -1;
	}
	strncpy(peer->dev_name, oem_dev->dev_name, DEV_NAME_LEN);
	peer->dev_name[DEV_NAME_LEN] = '\0';
	memcpy(peer->intf_addr, oem_dev->intf_addr, MACADDR_LEN);
	memcpy(peer->go_dev_addr, oem_dev->go_dev_addr, MACADDR_LEN);
	peer->dev_role = oem_dev->dev_role;
	peer->config_methods = oem_dev->config_methods;
	peer->pri_dev_type = oem_dev->pri_dev_type;
	peer->sec_dev_type = oem_dev->sec_dev_type;
	peer->dev_flags = oem_dev->dev_flags;
	peer->group_flags = oem_dev->group_flags;
	peer->wps_mode =  oem_dev->wps_mode;

	struct timeval tval;
	gettimeofday(&tval, NULL);
	peer->time = tval.tv_sec;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_peer_clear_all(void *data)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = (wfd_manager_s*) data;
	wfd_device_s *peer = NULL;
	GList *temp = NULL;

	if (manager->peer_count == 0) {
		WDS_LOGD("Peer not exist");
		return -1;
	}

	temp = g_list_first(manager->peers);
	while(temp) {
		peer = (wfd_device_s*) temp->data;
		wfd_manager_init_service(peer);
		free(peer);
		temp = g_list_next(temp);
		manager->peer_count--;
	}
	g_list_free(manager->peers);
	manager->peers = NULL;

	if (manager->peer_count){
		WDS_LOGE("Peer count is not synced. left count=%d", manager->peer_count);
		manager->peer_count = 0;
		return 1;
	}
	
	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

wfd_device_s *wfd_peer_find_by_dev_addr(void *data, unsigned char *dev_addr)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = (wfd_manager_s*) data;
	wfd_device_s *peer = NULL;
	GList *temp = NULL;

	if (!data || !dev_addr) {
		WDS_LOGE("Invalid parameter");
		return NULL;
	}

	if (manager->peer_count == 0) {
		WDS_LOGE("There is no peer data");
		return NULL;
	}

	temp = g_list_first(manager->peers);
	while (temp) {
		peer = temp->data;
		if (!memcmp(peer->dev_addr, dev_addr, MACADDR_LEN)) {
			WDS_LOGD("Peer device found[" MACSTR "]", MAC2STR(dev_addr));
			break;
		}
		temp = g_list_next(temp);
		peer = NULL;
	}

	__WDS_LOG_FUNC_EXIT__;
	return peer;
}

wfd_device_s *wfd_peer_find_by_intf_addr(void *data, unsigned char *intf_addr)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = (wfd_manager_s*) data;
	wfd_device_s *peer = NULL;
	GList *temp = NULL;

	if (!data || !intf_addr) {
		WDS_LOGE("Invalid parameter");
		return NULL;
	}

	if (manager->peer_count == 0) {
		WDS_LOGE("There is no peer data");
		return NULL;
	}

	temp = g_list_first(manager->peers);
	while (temp) {
		peer = temp->data;
		if (!memcmp(peer->intf_addr, intf_addr, MACADDR_LEN)) {
			WDS_LOGD("Peer device found[" MACSTR "]", MAC2STR(intf_addr));
			break;
		}
		temp = g_list_next(temp);
		peer = NULL;
	}

	__WDS_LOG_FUNC_EXIT__;
	return peer;
}

wfd_device_s *wfd_peer_find_by_addr(void *data, unsigned char *addr)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = (wfd_manager_s*) data;
	wfd_device_s *peer = NULL;
	GList *temp = NULL;

	if (!data || !addr) {
		WDS_LOGE("Invalid parameter");
		return NULL;
	}

	if (manager->peer_count == 0) {
		WDS_LOGE("There is no peer data");
		return NULL;
	}

	temp = g_list_first(manager->peers);
	while (temp) {
		peer = temp->data;
		if (!memcmp(peer->dev_addr, addr, MACADDR_LEN) ||
				!memcmp(peer->intf_addr, addr, MACADDR_LEN)) {
			WDS_LOGE("Peer device found[" MACSTR "]", MAC2STR(addr));
			break;
		}
		temp = g_list_next(temp);
		peer = NULL;
	}

	__WDS_LOG_FUNC_EXIT__;
	return peer;
}

wfd_device_s *wfd_peer_find_current_peer(void *data)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *peer = NULL;
	wfd_manager_s *manager = (wfd_manager_s*) data;
	if (!manager) {
		WDS_LOGE("Invalid parameter");
		return NULL;
	}
	
	wfd_session_s *session = manager->session;
	if (!session) {
		WDS_LOGE("Session not found");
		return NULL;
	}

	peer = session->peer;

	__WDS_LOG_FUNC_EXIT__;
	return peer;
}

int wfd_peer_set_data(unsigned char *dev_addr, int type, int data)
{
	__WDS_LOG_FUNC_ENTER__;
	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_peer_get_data(unsigned char *dev_addr, int type, int data)
{
	__WDS_LOG_FUNC_ENTER__;
	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

