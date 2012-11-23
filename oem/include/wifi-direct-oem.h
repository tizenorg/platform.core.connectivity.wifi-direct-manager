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
 
#ifndef __WIFI_DIRECT_OEM_H_
#define __WIFI_DIRECT_OEM_H_

#include "wifi-direct.h"
#include "wifi-direct-internal.h"
#include "wifi-direct-event-handler.h"


int wfd_oem_init(wfd_oem_event_cb event_callback);
int wfd_oem_destroy(void);
int wfd_oem_activate(void);
int wfd_oem_deactivate(void);
int wfd_oem_connect(unsigned char mac_addr[6], wifi_direct_wps_type_e wps_config);
int wfd_ws_wps_pbc_start(void);
int wfd_oem_disconnect(void);
int wfd_oem_disconnect_sta(unsigned char mac_addr[6]);	
bool wfd_oem_is_discovery_enabled(void);
int wfd_oem_start_discovery(bool listen_only, int timeout);
int wfd_oem_cancel_discovery(void);
int wfd_oem_get_discovery_result(wfd_discovery_entry_s ** peer_list, int* peer_num);
int wfd_oem_get_peer_info(unsigned char *mac_addr, wfd_discovery_entry_s **peer);
int wfd_oem_send_provision_discovery_request(unsigned char mac_addr[6], wifi_direct_wps_type_e config_method, int is_peer_go);
int wfd_oem_send_invite_request(unsigned char dev_mac_addr[6]);
int wfd_oem_create_group(char* ssid);
int wfd_oem_cancel_group(void);
int wfd_oem_activate_pushbutton(void);
char* wfd_oem_get_default_interface_name(void);
bool wfd_oem_dhcpc_get_ip_address(char *ipaddr_buf, int len, int is_IPv6);
char* wfd_oem_get_ip(void);
int wfd_oem_set_ssid(char* ssid);
bool wfd_oem_is_groupowner(void);
bool wfd_oem_is_groupclient(void);
int wfd_oem_get_ssid(char* ssid, int len);
char* wfd_oem_get_ip(void);
int wfd_oem_set_wps_pin(char* pin);
int wfd_oem_get_wps_pin(char* wps_pin, int len);
int wfd_oem_generate_wps_pin(void);
int wfd_oem_set_wpa_passphrase(char* wpa_key);
int wfd_oem_get_supported_wps_mode(void);
int wfd_oem_get_connected_peers_info(wfd_connected_peer_info_s ** peer_list, int* peer_num);
int wfd_oem_get_connected_peers_count(int* peer_num);
int wfd_oem_set_oem_loglevel(int is_increase);
int wfd_oem_get_go_intent(int* intent); 
int wfd_oem_set_go_intent(int intent); 
int wfd_oem_set_device_type(wifi_direct_primary_device_type_e primary_cat, wifi_direct_secondary_device_type_e sub_cat);
int wfd_oem_get_device_mac_address(unsigned char* device_mac);
int wfd_oem_get_disassoc_sta_mac(unsigned char mac_addr[6]);
int wfd_oem_get_assoc_sta_mac(unsigned char mac_addr[6]);
int wfd_oem_get_requestor_mac(unsigned char mac_addr[6]);
int wfd_oem_get_operating_channel(void);
int wfd_oem_get_persistent_group_info(wfd_persistent_group_info_s ** persistent_group_list, int* persistent_group_num);
int wfd_oem_remove_persistent_group(wfd_persistent_group_info_s * persistent_group);

struct wfd_oem_operations {
	int (*wfd_oem_init)(wfd_oem_event_cb event_callback);
	int (*wfd_oem_destroy)(void);
	int (*wfd_oem_activate)(void);
	int (*wfd_oem_deactivate)(void);
	int (*wfd_oem_connect)(unsigned char mac_addr[6], wifi_direct_wps_type_e wps_config);
	int (*wfd_oem_wps_pbc_start)(void);
	int (*wfd_oem_disconnect)(void);
	int (*wfd_oem_disconnect_sta)(unsigned char mac_addr[6]);
	bool (*wfd_oem_is_discovery_enabled)(void);
	int (*wfd_oem_start_discovery)(bool listen_only, int timeout);
	int (*wfd_oem_cancel_discovery)(void);
	int (*wfd_oem_get_discovery_result)(wfd_discovery_entry_s ** peer_list, int* peer_num);
	int (*wfd_oem_get_peer_info)(unsigned char *mac_addr, wfd_discovery_entry_s **peer);
	int (*wfd_oem_send_provision_discovery_request)(unsigned char mac_addr[6], wifi_direct_wps_type_e config_method, int is_peer_go);
	int (*wfd_oem_send_invite_request)(unsigned char dev_mac_addr[6]);
	int (*wfd_oem_create_group)(char* ssid);
	int (*wfd_oem_cancel_group)(void);
	int (*wfd_oem_activate_pushbutton)(void);
	char* (*wfd_oem_get_default_interface_name)(void);
	bool (*wfd_oem_dhcpc_get_ip_address)(char *ipaddr_buf, int len, int is_IPv6);
	char* (*wfd_oem_get_ip)(void);
	int (*wfd_oem_set_ssid)(char* ssid);
	bool (*wfd_oem_is_groupowner)(void);
	bool (*wfd_oem_is_groupclient)(void);
	int (*wfd_oem_get_ssid)(char* ssid, int len);
	int (*wfd_oem_set_wps_pin)(char* pin);
	int (*wfd_oem_get_wps_pin)(char* wps_pin, int len);
	int (*wfd_oem_generate_wps_pin)(void);
	int (*wfd_oem_set_wpa_passphrase)(char* wpa_key);
	int (*wfd_oem_get_supported_wps_mode)(void);
	int (*wfd_oem_get_connected_peers_info)(wfd_connected_peer_info_s ** peer_list, int* peer_num);
	int (*wfd_oem_get_connected_peers_count)(int* peer_num);
	int (*wfd_oem_set_oem_loglevel)(int is_increase);
	int (*wfd_oem_get_go_intent)(int* intent); 
	int (*wfd_oem_set_go_intent)(int intent);
	int (*wfd_oem_set_device_type)(wifi_direct_primary_device_type_e primary_cat, wifi_direct_secondary_device_type_e sub_cat);
	int (*wfd_oem_get_device_mac_address)(unsigned char* device_mac);
	int (*wfd_oem_get_disassoc_sta_mac)(unsigned char* mac_addr);
	int (*wfd_oem_get_assoc_sta_mac)(unsigned char* mac_addr);
	int (*wfd_oem_get_requestor_mac)(unsigned char* mac_addr);
	int (*wfd_oem_get_operating_channel)(void);
	int (*wfd_oem_get_persistent_group_info)(wfd_persistent_group_info_s ** persistent_group_list, int* persistent_group_num);
	int (*wfd_oem_remove_persistent_group)(wfd_persistent_group_info_s * persistent_group);
	
};

extern unsigned char g_incomming_peer_mac_address[6];
extern char g_incomming_peer_ssid[32 + 1];
extern struct wfd_oem_operations *g_ops;


int plugin_load(struct wfd_oem_operations **ops);

#endif		//__WIFI_DIRECT_OEM_H_

