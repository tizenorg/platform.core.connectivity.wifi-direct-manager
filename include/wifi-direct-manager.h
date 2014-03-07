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
 * This file declares wifi direct manager functions and structures.
 *
 * @file		wifi-direct-manager.h
 * @author	Gibyoung Kim (lastkgb.kim@samsung.com)
 * @version	0.7
 */

#ifndef __WIFI_DIRECT_MANAGER_H__
#define __WIFI_DIRECT_MANAGER_H__

#define DEFAULT_DEVICE_NAME "Tizen_Device"
#define DEFAULT_IFNAME "p2p0"
#define GROUP_IFNAME "p2p-wlan0-0"
#define WFD_MAX_CLIENT 16
#define WFD_MAX_STATION 8

#define DEV_NAME_LEN 32
#define MACADDR_LEN 6
#define MACSTR_LEN 18
#define IPADDR_LEN 4
#define IPSTR_LEN 16
#define PINSTR_LEN 8
#define PASSPHRASE_LEN 8
#define QUERY_HANDLE_LIMIT 256

#if 0
typedef enum {
	WFD_STATE_DEACTIVATED,
	WFD_STATE_ACTIVATED,
	WFD_STATE_IDLE,			// passive scaning
	WFD_STATE_SCANNING,		// active scanning
	WFD_STATE_CONNECTING,
	WFD_STATE_CONNECTED,
} wfd_state_e;
#endif

typedef enum {
	WFD_WPS_MODE_NONE,
	WFD_WPS_MODE_PBC = 0x1,
	WFD_WPS_MODE_DISPLAY = 0x2,
	WFD_WPS_MODE_KEYPAD = 0x4,
} wfd_wps_mode_e;

typedef enum {
	WFD_DEV_ROLE_NONE,
	WFD_DEV_ROLE_GC,
	WFD_DEV_ROLE_GO,
} wfd_dev_role_e;

typedef enum {
	WFD_SCAN_MODE_NONE,
	WFD_SCAN_MODE_ACTIVE,
	WFD_SCAN_MODE_PASSIVE,
} wfd_scan_mode_e;

typedef struct {
	int allowed;
	char dev_name[DEV_NAME_LEN+1];
	unsigned char mac_addr[6];
}device_s;

typedef struct {
	wifi_direct_display_type_e type;
	char dev_info[2];
	int ctrl_port;
	int max_tput;
	int availability;
	int hdcp_support;
}wfd_display_info_s;

typedef struct {
	wifi_direct_service_type_e service_type;
	int ref_counter;
	char *service_string;
	int service_str_length;
} wfd_service_s;

typedef struct {
	int handle;
	int ref_counter;
	unsigned char mac_addr[6];
	wifi_direct_service_type_e service_type;
	char *query_string;
}wfd_query_s;

typedef enum {
	WFD_PEER_STATE_DISCOVERED,
	WFD_PEER_STATE_CONNECTING,
	WFD_PEER_STATE_CONNECTED,
} wfd_peer_state_e;

typedef struct {
	int state;
	unsigned long time;

	char dev_name[DEV_NAME_LEN+1];
	unsigned char dev_addr[MACADDR_LEN];
	unsigned char intf_addr[MACADDR_LEN];
	unsigned char go_dev_addr[MACADDR_LEN];
	int channel;
	int dev_role;
	int config_methods;
	int pri_dev_type;
	int sec_dev_type;
	int dev_flags;
	int group_flags;
	int wps_mode;

	GList *services;
	wfd_display_info_s *wifi_display;

	unsigned char ip_addr[IPADDR_LEN];
} wfd_device_s;

typedef struct {
	GMainLoop *main_loop;

	int serv_sock;
	unsigned int client_handle;	// for accept clients
	GList *clients;
	unsigned int client_count;

	int state;
	unsigned int exit_timer;

	wfd_device_s *local;
	int go_intent;
	int req_wps_mode;
	int max_station;
	int autoconnection;
	int scan_mode;

	GList *peers;
	unsigned int peer_count;

	void *session;

	void *group;

	GList *query_handles;
	GList *access_list;

	void *oem_ops;
	void *plugin_handle;
} wfd_manager_s;

wfd_manager_s *wfd_get_manager();
int wfd_local_reset_data(wfd_manager_s *manager);
int wfd_local_get_dev_name(char *dev_name);
int wfd_local_set_dev_name(char *dev_name);
int wfd_local_get_dev_mac(unsigned char *dev_mac);
int wfd_local_get_intf_mac(unsigned char *intf_mac);
int wfd_local_get_ip_addr(char *ip_str);
int wfd_local_get_supported_wps_mode(int *wps_mode);
int wfd_local_set_req_wps_mode(int req_wps_mode);
int wfd_local_get_wps_mode(int *wps_mode);
int wfd_local_get_req_wps_mode(int *req_wps_mode);

int wfd_local_get_display_port(int *port);
int wfd_local_get_display_type(wifi_direct_display_type_e *type);

int wfd_manager_get_go_intent(int *go_intent);
int wfd_manager_set_go_intent(int go_intent);
int wfd_manager_get_max_station(int *max_station);
int wfd_manager_set_max_station(int max_station);
int wfd_manager_get_autoconnection(int *autoconnection);
int wfd_manager_set_autoconnection(int autoconnection);
int wfd_manager_get_req_wps_mode(int *req_wps_mode);
int wfd_manager_set_req_wps_mode(int req_wps_mode);

int wfd_manager_access_control(wfd_manager_s *manager, unsigned char *dev_addr);
int wfd_manager_add_to_access_list(wfd_manager_s *manager, wfd_device_s *peer, int allowed);
int wfd_manager_del_from_access_list(wfd_manager_s *manager, unsigned char *mac);

int wfd_manager_service_add(wfd_manager_s *manager, wifi_direct_service_type_e type, char *data);
int wfd_manager_service_del(wfd_manager_s *manager, wifi_direct_service_type_e  type, char *data);
int wfd_manager_serv_disc_req(wfd_manager_s *manager, unsigned char* mad_addr, wifi_direct_service_type_e  type, char *data);
int wfd_manager_serv_disc_cancel(wfd_manager_s *manager, int handle);
int wfd_manager_init_service(wfd_device_s *device);
int wfd_manager_init_query(wfd_manager_s *manager);

int wfd_manager_init_wifi_display(wifi_direct_display_type_e type, int port, int hdcp);
int wfd_manager_deinit_wifi_display();

int wfd_manager_local_config_set(wfd_manager_s *manager);
int wfd_manager_activate(wfd_manager_s *manager);
int wfd_manager_deactivate(wfd_manager_s *manager);
int wfd_manager_connect(wfd_manager_s *manager, unsigned char *peer_addr);
int wfd_manager_accept_connection(wfd_manager_s *manager, unsigned char *peer_addr);
int wfd_manager_cancel_connection(wfd_manager_s *manager, unsigned char *peer_addr);
int wfd_manager_reject_connection(wfd_manager_s *manager, unsigned char *peer_addr);
int wfd_manager_disconnect(wfd_manager_s *manager, unsigned char *peer_addr);
int wfd_manager_disconnect_all(wfd_manager_s *manager);
int wfd_manager_get_peers(wfd_manager_s *manager, wfd_discovery_entry_s **peers);
int wfd_manager_get_connected_peers(wfd_manager_s *manager, wfd_connected_peer_info_s **peers_data);
wfd_device_s *wfd_manager_find_connected_peer(wfd_manager_s *manager, unsigned char *peer_addr);
wfd_device_s *wfd_manager_get_current_peer(wfd_manager_s *manager);
int wfd_manager_get_goup_ifname(char **ifname);

#endif /* __WIFI_DIRECT_MANAGER_H__ */
