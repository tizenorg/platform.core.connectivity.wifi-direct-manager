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
 * This file declares wifi direct oem functions and structures.
 *
 * @file		wifi-direct-ome.h
 * @author	Gibyoung Kim (lastkgb.kim@samsung.com)
 * @version	0.7
 */

#ifndef __WIFI_DIRECT_OEM_H__
#define __WIFI_DIRECT_OEM_H__

#define SUPPL_PLUGIN_PATH "/usr/lib/wifi-direct-plugin-wpasupplicant.so"

#define OEM_MACSTR_LEN 18
#define OEM_MACADDR_LEN 6
#define OEM_PINSTR_LEN 8
#define OEM_PASS_PHRASE_LEN 8
#define OEM_DEV_NAME_LEN 32
#define OEM_IFACE_NAME_LEN 16

typedef enum {
	WFD_OEM_EVENT_NONE,
	WFD_OEM_EVENT_DEACTIVATED,
	WFD_OEM_EVENT_PEER_FOUND,
	WFD_OEM_EVENT_PEER_DISAPPEARED,
	WFD_OEM_EVENT_DISCOVERY_FINISHED,

	WFD_OEM_EVENT_PROV_DISC_REQ,	// 5
	WFD_OEM_EVENT_PROV_DISC_DISPLAY,
	WFD_OEM_EVENT_PROV_DISC_KEYPAD,
	WFD_OEM_EVENT_PROV_DISC_RESP,
	WFD_OEM_EVENT_PROV_DISC_FAIL,

	WFD_OEM_EVENT_GO_NEG_REQ,	// 10
	WFD_OEM_EVENT_GO_NEG_FAIL,
	WFD_OEM_EVENT_GO_NEG_DONE,
	WFD_OEM_EVENT_WPS_FAIL,
	WFD_OEM_EVENT_WPS_DONE,
	WFD_OEM_EVENT_KEY_NEG_FAIL,	// 15
	WFD_OEM_EVENT_KEY_NEG_DONE,

	WFD_OEM_EVENT_CONN_FAIL,
	WFD_OEM_EVENT_CONN_DONE,

	WFD_OEM_EVENT_GROUP_CREATED,
	WFD_OEM_EVENT_GROUP_DESTROYED,	// 20

	WFD_OEM_EVENT_INVITATION_REQ,
	WFD_OEM_EVENT_INVITATION_RES,
	WFD_OEM_EVENT_STA_CONNECTED,
	WFD_OEM_EVENT_STA_DISCONNECTED,

	WFD_OEM_EVENT_CONNECTED,	// 25
	WFD_OEM_EVENT_DISCONNECTED,

	WFD_OEM_EVENT_SERV_DISC_RESP,

	WFD_OEM_EVENT_TERMINATING,

	WFD_OEM_EVENT_MAX,
} wfd_oem_event_e;

typedef enum
{
	WFD_OEM_DISPLAY_SOURCE,
	WFD_OEM_DISPLAY_PRIMARY_SINK,
	WFD_OEM_DISPLAY_SECONDARY_SINK,
	WFD_OEM_DISPLAY_DUAL_ROLE,
}wfd_oem_display_e;

typedef struct {
	wfd_oem_display_e type;
	char dev_info[2];
	int ctrl_port;
	int max_tput;
	int availability;
	int hdcp_support;
}wfd_oem_display_info_s;

typedef struct {
	int age;
	char dev_name[OEM_DEV_NAME_LEN+1];
	unsigned char dev_addr[OEM_MACADDR_LEN];
	unsigned char intf_addr[OEM_MACADDR_LEN];
	unsigned char go_dev_addr[OEM_MACADDR_LEN];
	int channel;
	int dev_role;
	int config_methods;
	int pri_dev_type;
	int sec_dev_type;
	int dev_flags;
	int group_flags;
	int wps_mode;

	wfd_oem_display_info_s wifi_display;

} wfd_oem_device_s;

typedef struct {
	unsigned char p2p_dev_addr[OEM_MACADDR_LEN];
	unsigned char p2p_intf_addr[OEM_MACADDR_LEN];
	char name[OEM_DEV_NAME_LEN + 1];
	int pri_dev_type;
	int sec_dev_type;
	int config_methods;
	int dev_flags;
	int group_flags;
	int dev_role;
	unsigned char p2p_go_addr[OEM_MACADDR_LEN];

	wfd_oem_display_info_s wifi_display;

} wfd_oem_dev_data_s;

typedef struct {
	unsigned char peer_intf_addr[OEM_MACADDR_LEN];
	int dev_pwd_id;
	int status;
	int error;
} wfd_oem_conn_data_s;

typedef struct {
	unsigned char go_dev_addr[OEM_MACADDR_LEN];
	unsigned char bssid[OEM_MACADDR_LEN];
	int listen;
	int status;
} wfd_oem_invite_data_s;

typedef struct {
	char ssid[OEM_DEV_NAME_LEN+1];
	int freq;
	char pass[OEM_PASS_PHRASE_LEN+1];
	unsigned char go_dev_addr[OEM_MACADDR_LEN];
} wfd_oem_group_data_s;

typedef struct {
	int event_id;
	unsigned char dev_addr[OEM_MACADDR_LEN];	// device address
	unsigned char intf_addr[OEM_MACADDR_LEN];
	int wps_mode;
	char wps_pin[OEM_PINSTR_LEN+1];	// just for DISPLAY
	char ifname[OEM_IFACE_NAME_LEN+1];
	int dev_role;
	int edata_type;
	void *edata;
} wfd_oem_event_s;

typedef enum {
	WFD_OEM_EDATA_TYPE_NONE,
	WFD_OEM_EDATA_TYPE_DEVICE,
	WFD_OEM_EDATA_TYPE_CONN,
	WFD_OEM_EDATA_TYPE_INVITE,
	WFD_OEM_EDATA_TYPE_GROUP,
	WFD_OEM_EDATA_TYPE_SERVICE,
} ws_event_type_e;

typedef enum {
	WFD_OEM_SCAN_MODE_ACTIVE,
	WFD_OEM_SCAN_MODE_PASSIVE,
} wfd_oem_scan_mode_e;

typedef enum {
	WFD_OEM_SCAN_TYPE_FULL,
	WFD_OEM_SCAN_TYPE_SOCIAL,
	WFD_OEM_SCAN_TYPE_SPECIFIC,
} wfd_oem_scan_type_e;

typedef enum {
	WFD_OEM_WPS_MODE_NONE,
	WFD_OEM_WPS_MODE_PBC = 0x1,
	WFD_OEM_WPS_MODE_DISPLAY = 0x2,
	WFD_OEM_WPS_MODE_KEYPAD = 0x4,
} wfd_oem_wps_mode_e;

#define WFD_OEM_GROUP_FLAG_GROUP_OWNER 0x1
#define WFD_OEM_GROUP_FLAG_PERSISTENT_GROUP 0x2

typedef enum {
	WFD_OEM_CONN_TYPE_NONE,
	WFD_OEM_CONN_TYPE_JOIN,
	WFD_OEM_CONN_TYPE_AUTH,
	WFD_OEM_CONN_TYPE_PERSISTENT = 0x4,
} wfd_oem_conn_flag_e;

typedef enum {
	WFD_OEM_DEV_ROLE_NONE,
	WFD_OEM_DEV_ROLE_GC,
	WFD_OEM_DEV_ROLE_GO,
} wfd_oem_dev_role_e;

typedef enum
{
	WFD_OEM_SERVICE_ALL,
	WFD_OEM_SERVICE_BONJOUR,
	WFD_OEM_SERVICE_UPNP,
	WFD_OEM_SERVICE_WSDISCOVERY,
	WFD_OEM_SERVICE_WIFIDISPLAY,
	WFD_OEM_SERVICE_VENDORSPEC = 0xff,
} wfd_oem_service_e;

typedef struct {
	int scan_mode;
	int scan_time;
	int scan_type;
	int freq;
	int refresh;
} wfd_oem_scan_param_s;

typedef struct {
	int wps_mode;
	int conn_flags;	// join, auth, persistent
	int go_intent;
	int freq;
	char wps_pin[OEM_PINSTR_LEN+1];
} wfd_oem_conn_param_s;

typedef struct {
	int net_id;
	char *ifname;
	unsigned char go_dev_addr[OEM_MACADDR_LEN];
} wfd_oem_invite_param_s;

typedef struct
{
	int network_id;
	char ssid[OEM_DEV_NAME_LEN + 1];
	unsigned char go_mac_address[OEM_MACADDR_LEN];
} wfd_oem_persistent_group_s;

typedef int (*wfd_oem_event_cb) (void *user_data, void *event);

typedef struct _wfd_oem_ops_s {
	int (*init) (wfd_oem_event_cb event_callback, void *user_data);
	int (*deinit) (void);
	int (*activate) (void);
	int (*deactivate) (void);
	int (*start_scan) (wfd_oem_scan_param_s *param);
	int (*stop_scan) (void);
	int (*get_visibility) (int *visibility);
	int (*set_visibility) (int visibility);
	int (*get_scan_result) (GList **peers, int *peer_count);
	int (*get_peer_info) (unsigned char *peer_addr, wfd_oem_device_s **peer);
	int (*prov_disc_req) (unsigned char *peer_addr, wfd_oem_wps_mode_e wps_mode, int join);
	int (*connect) (unsigned char *peer_addr, wfd_oem_conn_param_s *param);
	int (*disconnect) (unsigned char *peer_addr);
	int (*reject_connection) (unsigned char *peer_addr);
	int (*cancel_connection) (unsigned char *peer_addr);
	int (*get_connected_peers) (GList **peers, int *peer_count);
	int (*wps_start) (unsigned char *peer_addr, int wps_mode, const char *pin);
	int (*enrollee_start) (unsigned char *peer_addr, int wps_mode, const char *pin);
	int (*wps_cancel) (void);
	int (*get_pin) (char *pin);
	int (*set_pin) (char *pin);
//	int (*generate_pin) (char *pin);
	int (*get_supported_wps_mode) (int *wps_mode);
	int (*create_group) (int persistent, int freq);
	int (*destroy_group) (const char *ifname);
	int (*invite) (unsigned char *peer_addr, wfd_oem_invite_param_s *param);

	int (*get_dev_name) (char *dev_name);
	int (*set_dev_name) (char *dev_name);
	int (*get_dev_mac) (char *dev_mac);
	int (*get_dev_type) (int *pri_dev_type, int *sec_dev_type);
	int (*set_dev_type) (int pri_dev_type, int sec_dev_type);
	int (*get_go_intent) (int *go_intent);
	int (*set_go_intent) (int go_intent);

	int (*get_persistent_groups) (wfd_oem_persistent_group_s **groups, int *group_count);
	int (*remove_persistent_group) (char *ssid, unsigned char *bssid);
	int (*set_persistent_reconnect) (unsigned char *bssid, int reconnect);

	int (*service_add) (wfd_oem_service_e type,char *data);
	int (*service_del) (wfd_oem_service_e type,char *data);
	int (*serv_disc_req) (unsigned char* MAC, wfd_oem_service_e type,char *data);
	int (*serv_disc_cancel) (int identifier);

	int (*init_wifi_display) (wfd_oem_display_e type, int port, int hdcp);
	int (*deinit_wifi_display) (void);
} wfd_oem_ops_s;

int wfd_oem_init(wfd_oem_ops_s *ops, wfd_oem_event_cb event_callback, void *user_data);
int wfd_oem_destroy(wfd_oem_ops_s *ops);
int wfd_oem_activate(wfd_oem_ops_s *ops);
int wfd_oem_deactivate(wfd_oem_ops_s *ops);
int wfd_oem_start_scan(wfd_oem_ops_s *ops, wfd_oem_scan_param_s *param);
int wfd_oem_stop_scan(wfd_oem_ops_s *ops);
int wfd_oem_get_visibility(wfd_oem_ops_s *ops, int *visibility);
int wfd_oem_set_visibility(wfd_oem_ops_s *ops, int visibility);
int wfd_oem_get_scan_result(wfd_oem_ops_s *ops, GList **peers, int *peer_count);
int wfd_oem_get_peer_info(wfd_oem_ops_s *ops, unsigned char *peer_addr, wfd_oem_device_s **peer);
int wfd_oem_prov_disc_req(wfd_oem_ops_s *ops, unsigned char *peer_addr, wfd_oem_wps_mode_e wps_mode, int join);
int wfd_oem_connect(wfd_oem_ops_s *ops, unsigned char *peer_addr, wfd_oem_conn_param_s *param);
int wfd_oem_disconnect(wfd_oem_ops_s *ops, unsigned char *peer_addr);
int wfd_oem_reject_connection(wfd_oem_ops_s *ops, unsigned char *peer_addr);
int wfd_oem_cancel_connection(wfd_oem_ops_s *ops, unsigned char *peer_addr);
int wfd_oem_get_connected_peers(wfd_oem_ops_s *ops, GList **peers, int *peer_count);
int wfd_oem_wps_start(wfd_oem_ops_s *ops, unsigned char *peer_addr, int wps_mode, const char *pin);
int wfd_oem_enrollee_start(wfd_oem_ops_s *ops, unsigned char *peer_addr, int wps_mode, const char *pin);
int wfd_oem_wps_cancel(wfd_oem_ops_s *ops);
int wfd_oem_get_pin(wfd_oem_ops_s *ops, char *pin);
int wfd_oem_set_pin(wfd_oem_ops_s *ops, char *pin);
//int wfd_oem_generate_pin(wfd_oem_ops_s *ops, char *pin);
int wfd_oem_get_supported_wps_mode(wfd_oem_ops_s *ops, int *wps_mode);
int wfd_oem_create_group(wfd_oem_ops_s *ops, int persistent, int freq);
int wfd_oem_destroy_group(wfd_oem_ops_s *ops, const char *ifname);
int wfd_oem_invite(wfd_oem_ops_s *ops, unsigned char *peer_addr, wfd_oem_invite_param_s *param);

int wfd_oem_get_dev_name(wfd_oem_ops_s *ops, char *dev_name);
int wfd_oem_set_dev_name(wfd_oem_ops_s *ops, char *dev_name);
int wfd_oem_get_dev_mac(wfd_oem_ops_s *ops, char *dev_mac);
int wfd_oem_get_dev_type(wfd_oem_ops_s *ops, int *pri_dev_type, int *sec_dev_type);
int wfd_oem_set_dev_type(wfd_oem_ops_s *ops, int priv_dev_type, int sec_dev_type);
int wfd_oem_get_go_intent(wfd_oem_ops_s *ops, int *go_intent);
int wfd_oem_set_go_intent(wfd_oem_ops_s *ops, int go_intent);

int wfd_oem_get_persistent_groups(wfd_oem_ops_s *ops, wfd_oem_persistent_group_s **groups, int *group_count);
int wfd_oem_remove_persistent_group(wfd_oem_ops_s *ops, char *ssid, unsigned char *bssid);
int wfd_oem_set_persistent_reconnect(wfd_oem_ops_s *ops, unsigned char *bssid, int reconnect);

int wfd_oem_service_add(wfd_oem_ops_s *ops, wfd_oem_service_e type, char *data);
int wfd_oem_service_del(wfd_oem_ops_s *ops, wfd_oem_service_e type, char *data);
int wfd_oem_serv_disc_req(wfd_oem_ops_s *ops, unsigned char* MAC, wfd_oem_service_e type, char *data);
int wfd_oem_serv_disc_cancel(wfd_oem_ops_s *ops, int identifier);

int wfd_oem_init_wifi_display(wfd_oem_ops_s *ops, wfd_oem_display_e type, int port, int hdcp);
int wfd_oem_deinit_wifi_display(wfd_oem_ops_s *ops);

#endif /* __WIFI_DIRECT_OEM_H__ */
