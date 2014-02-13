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
 * This file implements wifi direct oem functions.
 *
 * @file		wifi-direct-oem.c
 * @author	Gibyoung Kim (lastkgb.kim@samsung.com)
 * @version	0.7
 */

#include <stdio.h>

#include <glib.h>

#include <wifi-direct-internal.h>

#include "wifi-direct-manager.h"
#include "wifi-direct-util.h"
#include "wifi-direct-oem.h"

int wfd_oem_init(wfd_oem_ops_s *ops, wfd_oem_event_cb event_callback, void *user_data)
{
	if (!ops || !ops->init) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->init(event_callback, user_data);
}

int wfd_oem_deinit(wfd_oem_ops_s *ops)
{
	if (!ops || !ops->deinit) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->deinit();
}

int wfd_oem_activate(wfd_oem_ops_s *ops)
{
	if (!ops || !ops->activate) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->activate();
}

int wfd_oem_deactivate(wfd_oem_ops_s *ops)
{
	if (!ops || !ops->deactivate) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->deactivate();
}

int wfd_oem_start_scan(wfd_oem_ops_s *ops, wfd_oem_scan_param_s *param)
{
	if (!ops || !ops->start_scan) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->start_scan(param);
}

int wfd_oem_stop_scan(wfd_oem_ops_s *ops)
{
	if (!ops || !ops->stop_scan) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->stop_scan();
}

int wfd_oem_get_visibility(wfd_oem_ops_s *ops, int *visibility)
{
	if (!ops || !ops->get_visibility) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->get_visibility(visibility);
}

int wfd_oem_set_visibility(wfd_oem_ops_s *ops, int visibility)
{
	if (!ops || !ops->set_visibility) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->set_visibility(visibility);
}

int wfd_oem_get_scan_result(wfd_oem_ops_s *ops, GList **peers, int *peer_count)
{
	if (!ops || !ops->get_scan_result) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->get_scan_result(peers, peer_count);
}

int wfd_oem_get_peer_info(wfd_oem_ops_s *ops, unsigned char *peer_addr, wfd_oem_device_s **peer)
{
	if (!ops || !ops->get_peer_info) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->get_peer_info(peer_addr, peer);
}

int wfd_oem_prov_disc_req(wfd_oem_ops_s *ops, unsigned char *peer_addr, wfd_oem_wps_mode_e wps_mode, int join)
{
	if (!ops || !ops->prov_disc_req) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->prov_disc_req(peer_addr, wps_mode, join);
}

int wfd_oem_connect(wfd_oem_ops_s *ops, unsigned char *peer_addr, wfd_oem_conn_param_s *param)
{
	if (!ops || !ops->connect) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->connect(peer_addr, param);
}

int wfd_oem_reject_connection(wfd_oem_ops_s *ops, unsigned char *peer_addr)
{
	if (!ops || !ops->reject_connection) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->reject_connection(peer_addr);
}

int wfd_oem_cancel_connection(wfd_oem_ops_s *ops, unsigned char *peer_addr)
{
	if (!ops || !ops->cancel_connection) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->cancel_connection(peer_addr);
}

int wfd_oem_disconnect(wfd_oem_ops_s *ops, unsigned char *peer_addr)
{
	if (!ops || !ops->disconnect) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->disconnect(peer_addr);
}

int wfd_oem_get_connected_peers(wfd_oem_ops_s *ops, GList **peers, int *peer_count)
{
	if (!ops || !ops->get_connected_peers) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->get_connected_peers(peers, peer_count);
}

int wfd_oem_get_pin(wfd_oem_ops_s *ops, char *pin)
{
	if (!ops || !ops->get_pin) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->get_pin(pin);
}

int wfd_oem_set_pin(wfd_oem_ops_s *ops, char *pin)
{
	if (!ops || !ops->set_pin) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->set_pin(pin);
}
//int wfd_oem_generate_pin(char *pin)
int wfd_oem_get_supported_wps_mode(wfd_oem_ops_s *ops, int *wps_mode)
{
	if (!ops || !ops->get_supported_wps_mode) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->get_supported_wps_mode(wps_mode);
}

int wfd_oem_create_group(wfd_oem_ops_s *ops, int persistent, int freq)
{
	if (!ops || !ops->create_group) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->create_group(persistent, freq);
}

int wfd_oem_destroy_group(wfd_oem_ops_s *ops, const char *ifname)
{
	if (!ops || !ops->destroy_group) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->destroy_group(ifname);
}

int wfd_oem_invite(wfd_oem_ops_s *ops, unsigned char *peer_addr, wfd_oem_invite_param_s *param)
{
	if (!ops || !ops->invite) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->invite(peer_addr, param);
}

int wfd_oem_wps_start(wfd_oem_ops_s *ops, unsigned char *peer_addr, int wps_mode, const char *pin)
{
	if (!ops || !ops->wps_start) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->wps_start(peer_addr, wps_mode, pin);
}

int wfd_oem_enrollee_start(wfd_oem_ops_s *ops, unsigned char *peer_addr, int wps_mode, const char *pin)
{
	if (!ops || !ops->enrollee_start) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->enrollee_start(peer_addr, wps_mode, pin);
}

int wfd_oem_wps_cancel(wfd_oem_ops_s *ops)
{
	if (!ops) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->wps_cancel();
}

int wfd_oem_get_dev_name(wfd_oem_ops_s *ops, char *dev_name)
{
	if (!ops || !ops->get_dev_name) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->get_dev_name(dev_name);
}

int wfd_oem_set_dev_name(wfd_oem_ops_s *ops, char *dev_name)
{
	if (!ops || !ops->set_dev_name) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->set_dev_name(dev_name);
}

int wfd_oem_get_dev_mac(wfd_oem_ops_s *ops, char *dev_mac)
{
	if (!ops || !ops->get_dev_mac) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->get_dev_mac(dev_mac);
}

int wfd_oem_get_dev_type(wfd_oem_ops_s *ops, int *pri_dev_type, int *sec_dev_type)
{
	if (!ops || !ops->get_dev_type) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->get_dev_type(pri_dev_type, sec_dev_type);
}

int wfd_oem_set_dev_type(wfd_oem_ops_s *ops, int pri_dev_type, int sec_dev_type)
{
	if (!ops || !ops->set_dev_type) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->set_dev_type(pri_dev_type, sec_dev_type);
}

int wfd_oem_get_go_intent(wfd_oem_ops_s *ops, int *go_intent)
{
	if (!ops || !ops->get_go_intent) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->get_go_intent(go_intent);
}

int wfd_oem_set_go_intent(wfd_oem_ops_s *ops, int go_intent)
{
	if (!ops || !ops->set_go_intent) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->set_go_intent(go_intent);
}

int wfd_oem_get_persistent_groups(wfd_oem_ops_s *ops, wfd_oem_persistent_group_s **groups, int *group_count)
{
	if (!ops || !ops->get_persistent_groups) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->get_persistent_groups(groups, group_count);
}

int wfd_oem_remove_persistent_group(wfd_oem_ops_s *ops, char *ssid, unsigned char *bssid)
{
	if (!ops || !ops->remove_persistent_group) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->remove_persistent_group(ssid, bssid);

}

int wfd_oem_set_persistent_reconnect(wfd_oem_ops_s *ops, unsigned char *bssid, int reconnect)
{
	if (!ops || !ops->set_persistent_reconnect) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->set_persistent_reconnect(bssid, reconnect);
}

int wfd_oem_service_add(wfd_oem_ops_s *ops, wfd_oem_service_e type, char *data)
{
	if (!ops || !ops->service_add) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->service_add(type, data);
}

int wfd_oem_service_del(wfd_oem_ops_s *ops, wfd_oem_service_e type, char *data)
{
	if (!ops || !ops->service_del) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->service_del(type, data);
}

int wfd_oem_serv_disc_req(wfd_oem_ops_s *ops, unsigned char* MAC, wfd_oem_service_e type, char *data)
{
	if (!ops || !ops->serv_disc_req) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->serv_disc_req(MAC, type, data);
}

int wfd_oem_serv_disc_cancel(wfd_oem_ops_s *ops, int identifier)
{
	if (!ops || !ops->serv_disc_cancel) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->serv_disc_cancel(identifier);
}

int wfd_oem_init_wifi_display(wfd_oem_ops_s *ops, wfd_oem_display_e type, int port, int hdcp)
{
	if (!ops || !ops->init_wifi_display) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	return ops->init_wifi_display(type, port, hdcp);
}

int wfd_oem_deinit_wifi_display(wfd_oem_ops_s *ops)
{
	if (!ops || !ops->deinit_wifi_display) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}
	return ops->deinit_wifi_display();
}
