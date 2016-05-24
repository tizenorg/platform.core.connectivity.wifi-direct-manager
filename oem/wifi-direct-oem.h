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
#define SUPPL_PLUGIN_64BIT_PATH "/usr/lib64/wifi-direct-plugin-wpasupplicant.so"


#define OEM_MACSTR_LEN 18
#define OEM_MACADDR_LEN 6
#define OEM_IPADDR_LEN 4
#define OEM_PINSTR_LEN 8
#define OEM_PASS_PHRASE_LEN 64
#define OEM_DEV_NAME_LEN 32
#define OEM_IFACE_NAME_LEN 16
#define OEM_SERVICE_TYPE_LEN 8
#define OEM_QUERY_ID_LEN 15
#define OEM_SERVICE_MAX_LEN 1024

#if defined(TIZEN_FEATURE_ASP)
/* Referring to Wi-Fi Peer-to-Peer Services Technical Specification v1.1
 * The default P2Ps PIN is 12345670. Any device decided to be GO will use
 * that as device password
 */
#define OEM_DEFAULT_P2PS_PIN "12345670"
#endif /* TIZEN_FEATURE_ASP */

#define OEM_MAX_PEER_NUM 8

typedef enum {
	WFD_OEM_SC_SUCCESS = 0,
	WFD_OEM_SC_FAIL_INFO_CURRENTLY_UNAVAILABLE = 1,
	WFD_OEM_SC_FAIL_INCOMPATIBLE_PARAMS = 2,
	WFD_OEM_SC_FAIL_LIMIT_REACHED = 3,
	WFD_OEM_SC_FAIL_INVALID_PARAMS = 4,
	WFD_OEM_SC_FAIL_UNABLE_TO_ACCOMMODATE = 5,
	WFD_OEM_SC_FAIL_PREV_PROTOCOL_ERROR = 6,
	WFD_OEM_SC_FAIL_NO_COMMON_CHANNELS = 7,
	WFD_OEM_SC_FAIL_UNKNOWN_GROUP = 8,
	WFD_OEM_SC_FAIL_BOTH_GO_INTENT_15 = 9,
	WFD_OEM_SC_FAIL_INCOMPATIBLE_PROV_METHOD = 10,
	WFD_OEM_SC_FAIL_REJECTED_BY_USER = 11,
#if defined(TIZEN_FEATURE_ASP)
	WFD_OEM_SC_SUCCESS_ACCEPTED_BY_USER = 12,
#endif /* TIZEN_FEATURE_ASP */
} wfd_oem_status_code_e;

typedef enum {
	WFD_OEM_WPA_STATE_DISCONNECTED,
	WFD_OEM_WPA_STATE_INTERFACE_DISABLED,
	WFD_OEM_WPA_STATE_INACTIVE,
	WFD_OEM_WPA_STATE_SCANNING,
	WFD_OEM_WPA_STATE_AUTHENTICATING,
	WFD_OEM_WPA_STATE_ASSOCIATING,
	WFD_OEM_WPA_STATE_ASSOCIATED,
	WFD_OEM_WPA_STATE_4WAY_HANDSHAKE,
	WFD_OEM_WPA_STATE_GROUP_HANDSHAKE,
	WFD_OEM_WPA_STATE_COMPLETED,
	WFD_OEM_WPA_STATE_MAX,
} ws_wpa_state_type_e;

#if defined(TIZEN_FEATURE_ASP)
typedef enum {
	WFD_OEM_ASP_SESSION_ROLE_NONE = 0x00,  /**< Session network role none */
	WFD_OEM_ASP_SESSION_ROLE_NEW = 0x01,  /**< Session network role new */
	WFD_OEM_ASP_SESSION_ROLE_CLIENT = 0x02,  /**< Session network role client */
	WFD_OEM_ASP_SESSION_ROLE_GO = 0x04,  /**< Session network role GO */
} wfd_oem_asp_network_role_e;
#endif /* TIZEN_FEATURE_ASP */

typedef enum {
	WFD_OEM_EVENT_NONE,
	WFD_OEM_EVENT_DEACTIVATED,
	WFD_OEM_EVENT_PEER_FOUND,
	WFD_OEM_EVENT_PEER_DISAPPEARED,
	WFD_OEM_EVENT_DISCOVERY_FINISHED,

	WFD_OEM_EVENT_PROV_DISC_REQ,	// 5
	WFD_OEM_EVENT_PROV_DISC_RESP,
	WFD_OEM_EVENT_PROV_DISC_FAIL,

	WFD_OEM_EVENT_GO_NEG_REQ,
	WFD_OEM_EVENT_GO_NEG_FAIL,
	WFD_OEM_EVENT_GO_NEG_DONE,	// 10
	WFD_OEM_EVENT_WPS_FAIL,
	WFD_OEM_EVENT_WPS_DONE,
	WFD_OEM_EVENT_KEY_NEG_FAIL,
	WFD_OEM_EVENT_KEY_NEG_DONE,

	WFD_OEM_EVENT_CONN_FAIL,	// 15
	WFD_OEM_EVENT_CONN_DONE,

	WFD_OEM_EVENT_GROUP_CREATED,
	WFD_OEM_EVENT_GROUP_DESTROYED,

	WFD_OEM_EVENT_INVITATION_REQ,
	WFD_OEM_EVENT_INVITATION_RES,	// 20
	WFD_OEM_EVENT_STA_CONNECTED,
	WFD_OEM_EVENT_STA_DISCONNECTED,

	WFD_OEM_EVENT_TERMINATING,	// 25

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
	WFD_OEM_EVENT_SERV_DISC_RESP,
	WFD_OEM_EVENT_SERV_DISC_STARTED,
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

	WFD_OEM_EVENT_GROUP_FORMATION_FAILURE,
	WFD_OEM_EVENT_INVITATION_ACCEPTED,
#if defined(TIZEN_FEATURE_ASP)
	WFD_OEM_EVENT_ASP_SERV_RESP,
#endif /* TIZEN_FEATURE_ASP */

	WFD_OEM_EVENT_MAX,
} wfd_oem_event_e;

#ifdef TIZEN_FEATURE_WIFI_DISPLAY
typedef enum {
	WFD_OEM_DISPLAY_TYPE_SOURCE,
	WFD_OEM_DISPLAY_TYPE_PRISINK,
	WFD_OEM_DISPLAY_TYPE_SECSINK,
	WFD_OEM_DISPLAY_TYPE_DUAL,
} wfd_oem_display_type_e;

typedef struct {
	int type;
	int availability;
	int wsd_support;
	int tdls_support;
	int hdcp_support;
	int sync_support;
	int port;
	int max_tput;
} wfd_oem_display_s;
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

#if defined(TIZEN_FEATURE_ASP)
typedef struct {
	unsigned int adv_id;
	unsigned int config_method;
	long long unsigned search_id;
	unsigned char service_type_length;
	char *service_type;
} wfd_oem_advertise_service_s;
#endif /* TIZEN_FEATURE_ASP */

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
#ifdef TIZEN_FEATURE_WIFI_DISPLAY
	wfd_oem_display_s display;
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */
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
	int device_go_intent;
#ifdef TIZEN_FEATURE_WIFI_DISPLAY
	wfd_oem_display_s display;
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */
	unsigned char p2p_go_addr[OEM_MACADDR_LEN];
#if defined(TIZEN_FEATURE_ASP)
	int has_asp_services;
#endif /* TIZEN_FEATURE_ASP */
} wfd_oem_dev_data_s;

typedef struct {
	char ssid[OEM_DEV_NAME_LEN+1];
	unsigned char peer_device_addr[OEM_MACADDR_LEN];
	unsigned char peer_intf_addr[OEM_MACADDR_LEN];
	int persistent_group;
	int wps_mode;
	int status;
	int error;
} wfd_oem_conn_data_s;

typedef struct {
	unsigned char sa[OEM_MACADDR_LEN];
	unsigned char go_dev_addr[OEM_MACADDR_LEN];
	unsigned char bssid[OEM_MACADDR_LEN];
	int persistent_id;
	int oper_freq;
	int listen;
	int status;
} wfd_oem_invite_data_s;

typedef struct {
	char ssid[OEM_DEV_NAME_LEN+1];
	int freq;
	char pass[OEM_PASS_PHRASE_LEN+1];
	unsigned char go_dev_addr[OEM_MACADDR_LEN];
#ifdef TIZEN_FEATURE_IP_OVER_EAPOL
	unsigned char ip_addr[OEM_IPADDR_LEN];
	unsigned char ip_addr_mask[OEM_IPADDR_LEN];
	unsigned char ip_addr_go[OEM_IPADDR_LEN];
#endif /* TIZEN_FEATURE_IP_OVER_EAPOL */
} wfd_oem_group_data_s;

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
typedef enum {
	WFD_OEM_SERV_STATUS_SUCCESS,
	WFD_OEM_SERV_STATUS_FAIL,
} wfd_oem_serv_status_e;

typedef enum {
	WFD_OEM_SERV_TYPE_ALL,
	WFD_OEM_SERV_TYPE_BTADDR,
} wfd_oem_serv_type_e;

typedef struct {
	int status;
	int type;
	unsigned char data[OEM_MACADDR_LEN];
	unsigned char value[20];
} wfd_oem_service_data_s;
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

typedef struct {
	int event_id;
	unsigned char dev_addr[OEM_MACADDR_LEN];	// device address
	unsigned char intf_addr[OEM_MACADDR_LEN];
	int wps_mode;
	char wps_pin[OEM_PINSTR_LEN+1];	// just for DISPLAY
	char ifname[OEM_IFACE_NAME_LEN+1];
	int dev_role;
	unsigned char ip_addr_peer[OEM_IPADDR_LEN];
	int edata_type;
	void *edata;
#if defined(TIZEN_FEATURE_ASP)
	void *asp_services;
#endif /* TIZEN_FEATURE_ASP */
} wfd_oem_event_s;

typedef enum {
	WFD_OEM_EDATA_TYPE_NONE,
	WFD_OEM_EDATA_TYPE_DEVICE,
	WFD_OEM_EDATA_TYPE_CONN,
	WFD_OEM_EDATA_TYPE_INVITE,
	WFD_OEM_EDATA_TYPE_GROUP,
	WFD_OEM_EDATA_TYPE_SERVICE,
	WFD_OEM_EDATA_TYPE_NEW_SERVICE,
#if defined(TIZEN_FEATURE_ASP)
	WFD_OEM_EDATA_TYPE_ASP_SERVICE,
#endif /* TIZEN_FEATURE_ASP */
} ws_event_type_e;

typedef enum {
	WFD_OEM_SCAN_MODE_ACTIVE,
	WFD_OEM_SCAN_MODE_PASSIVE,
} wfd_oem_scan_mode_e;

typedef enum {
	WFD_OEM_SCAN_TYPE_FULL,
	WFD_OEM_SCAN_TYPE_SOCIAL,
	WFD_OEM_SCAN_TYPE_SPECIFIC,
	WFD_OEM_SCAN_TYPE_CHANNEL1,
	WFD_OEM_SCAN_TYPE_CHANNEL6,
	WFD_OEM_SCAN_TYPE_CHANNEL11,
	WFD_OEM_SCAN_TYPE_GO_FREQ,
} wfd_oem_scan_type_e;

typedef enum {
	WFD_OEM_WPS_MODE_NONE,
	WFD_OEM_WPS_MODE_PBC = 0x1,
	WFD_OEM_WPS_MODE_DISPLAY = 0x2,
	WFD_OEM_WPS_MODE_KEYPAD = 0x4,
#if defined(TIZEN_FEATURE_ASP)
	WFD_OEM_WPS_MODE_P2PS = 0x8,
#endif /* TIZEN_FEATURE_ASP */
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

typedef struct {
	int scan_mode;
	int scan_time;
	int scan_type;
	int freq;
	int refresh;
#if defined(TIZEN_FEATURE_ASP)
	char *seek;
#endif /* TIZEN_FEATURE_ASP */
} wfd_oem_scan_param_s;

typedef struct {
	int wps_mode;
	int conn_flags;	// join, auth, persistent
	int go_intent;
	int freq;
	char wps_pin[OEM_PINSTR_LEN+1];
} wfd_oem_conn_param_s;

typedef struct {
	int persistent;
	int persistent_group_id;
	int freq;
	char passphrase[OEM_PASS_PHRASE_LEN + 1];
} wfd_oem_group_param_s;

typedef struct {
	int net_id;
	char *ifname;
	unsigned char go_dev_addr[OEM_MACADDR_LEN];
} wfd_oem_invite_param_s;

typedef enum {
	WFD_OEM_CONFIG_ATTR_STR_DEVICE_NAME,
	WFD_OEM_CONFIG_ATTR_STR_SSID_POSTFIX,
	WFD_OEM_CONFIG_ATTR_STR_COUNTRY,
	WFD_OEM_CONFIG_ATTR_NUM_GO_INTENT,
	WFD_OEM_CONFIG_ATTR_NUM_LISTEN_FREQ,
	WFD_OEM_CONFIG_ATTR_NUM_OPER_FREQ,
	WFD_OEM_CONFIG_ATTR_NUM_PREF_FREQ,
	WFD_OEM_CONFIG_ATTR_NUM_PERSIST_RECONN,
	WFD_OEM_CONFIG_ATTR_NUM_WIFI_DISPLAY,
	WFD_OEM_CONFIG_ATTR_NUM_P2P_DISABLED,
	WFD_OEM_CONFIG_ATTR_NUM_MAX_STA,
	WFD_OEM_CONFIG_ATTR_LIMIT = WFD_OEM_CONFIG_ATTR_NUM_MAX_STA,
} wfd_oem_conf_attr_e;

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
typedef enum {
	WFD_OEM_SERVICE_TYPE_ALL,
	WFD_OEM_SERVICE_TYPE_BONJOUR,
	WFD_OEM_SERVICE_TYPE_UPNP,
	WFD_OEM_SERVICE_TYPE_WS_DISCOVERY,
	WFD_OEM_SERVICE_TYPE_WIFI_DISPLAY,
	WFD_OEM_SERVICE_TYPE_VENDOR = 0xff,
} wfd_oem_service_type_e;

typedef enum {
	WFD_OEM_BONJOUR_RDATA_PTR = 0x0c,
	WFD_OEM_BONJOUR_RDATA_TXT = 0x10,
}wfd_oem_bonjour_rdata_type_e;

typedef struct {
	/** Device address for which service discovery is requested */
	char dev_addr[OEM_MACSTR_LEN+1];

	/** service type requested */
	char service_type[OEM_SERVICE_TYPE_LEN+1];

	/** query identifier returned by wpa_supplicant for each service discovery request */
	char query_id[OEM_QUERY_ID_LEN+1];
} wfd_oem_service_s;

typedef struct {
	int protocol;
	int trans_id;
	int status;
	char *str_ptr;
	union {
		struct {
			char *version;
			char *service;
		} upnp;
		struct {
			char *query;
			char *rdata;
			wfd_oem_bonjour_rdata_type_e rdata_type;
		} bonjour;
		struct {
			char *data1;
			char *data2;
		} vendor;
	} data;
} wfd_oem_new_service_s;
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

#define WFD_OEM_STR_PROTO_WPA "WPA"
#define WFD_OEM_STR_PROTO_RSN "RSN"
#define WFD_OEM_STR_KEY_MGMT_IEEE8021X "WPA-EAP"
#define WFD_OEM_STR_KEY_MGMT_PSK "WPA-PSK"
#define WFD_OEM_STR_KEY_MGMT_NONE "WPA-NONE"
#define WFD_OEM_STR_CIPHER_NONE "NONE"
#define WFD_OEM_STR_CIPHER_WEP40 "WEP40"
#define WFD_OEM_STR_CIPHER_WEP104 "WEP104"
#define WFD_OEM_STR_CIPHER_TKIP "TKIP"
#define WFD_OEM_STR_CIPHER_CCMP "CCMP"
#define WFD_OEM_STR_AUTH_ALG_OPEN "OPEN"
#define WFD_OEM_STR_MODE_GC "0"
#define WFD_OEM_STR_MODE_GO "3"

typedef enum {
	WFD_OEM_PROTO_WPA = 0x01, /* WPA */
	WFD_OEM_PROTO_RSN = 0x02, /* RSN */
} wfd_oem_proto_e;

typedef enum {
	WFD_OEM_KEY_MGMT_IEEE8021X = 0x01,	/* WPA-EAP */
	WFD_OEM_KEY_MGMT_PSK = 0x02,	/* WPA-PSK */
	WFD_OEM_KEY_MGMT_NONE = 0x04, /* WPA-NONE */
} wfd_oem_key_mgmt_e;

typedef enum {
	WFD_OEM_CIPHER_NONE = 0x01, /* NONE */
	WFD_OEM_CIPHER_WEP40 = 0x02, /* WEP40 */
	WFD_OEM_CIPHER_WEP104 = 0x04, /* WEP104 */
	WFD_OEM_CIPHER_TKIP = 0x08, /* TKIP */
	WFD_OEM_CIPHER_CCMP = 0x10, /* CCMP */
} wfd_oem_cipher_e;

typedef enum {
	WFD_OEM_AUTH_ALG_OPEN = 0x01, /* OPEN */
}wfd_oem_auth_alg_e;

typedef enum {
	WFD_OEM_PERSISTENT_MODE_GC = 0x0,
	WFD_OEM_PERSISTENT_MODE_GO = 0x3,
} wfd_oem_persistent_mode_e;

#if defined(TIZEN_FEATURE_ASP)
typedef enum
{
	WFD_OEM_TYPE_ADVERTISE,
	WFD_OEM_TYPE_SEEK,
	WFD_OEM_TYPE_MAX,
} wfd_oem_asp_service_type_e;

typedef struct {
	wfd_oem_asp_service_type_e type;
	unsigned int adv_id;
	long long unsigned search_id;
	int auto_accept;
	int discovery_tech;
	unsigned char preferred_connection;

	unsigned char status;
	unsigned char role;
	unsigned int config_method;
	unsigned char tran_id;

	char *instance_name;
	char *service_name;
	char *service_type;
	char *service_info;
	char *rsp_info;
} wfd_oem_asp_service_s;
#endif /* TIZEN_FEATURE_ASP */
typedef struct
{
	int network_id;
	char ssid[OEM_DEV_NAME_LEN + 1];
	unsigned char go_mac_address[OEM_MACADDR_LEN];
	char psk[OEM_PASS_PHRASE_LEN +1];
	int proto;
	int key_mgmt;
	int pairwise;
	int group;
	int auth_alg;
	int mode;
	int p2p_client_num;
	unsigned char p2p_client_list[OEM_MACADDR_LEN][OEM_MAX_PEER_NUM];
} wfd_oem_persistent_group_s;

typedef int (*wfd_oem_event_cb) (void *user_data, void *event);

typedef struct _wfd_oem_ops_s {
	int (*init) (wfd_oem_event_cb event_callback, void *user_data);
	int (*deinit) (void);
	int (*activate) (int concurrent);
	int (*deactivate) (int concurrent);
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
	int (*generate_pin) (char **pin);
	int (*get_supported_wps_mode) (int *wps_mode);
	int (*create_group) (wfd_oem_group_param_s *param);
	int (*destroy_group) (const char *ifname);
	int (*invite) (unsigned char *peer_addr, wfd_oem_invite_param_s *param);

	int (*get_dev_name) (char *dev_name);
	int (*set_dev_name) (char *dev_name);
	int (*get_dev_mac) (char *dev_mac);
	int (*get_dev_type) (int *pri_dev_type, int *sec_dev_type);
	int (*set_dev_type) (int pri_dev_type, int sec_dev_type);
	int (*get_go_intent) (int *go_intent);
	int (*set_go_intent) (int go_intent);
	int (*set_country) (char *ccode);
//	int (*get_country) (char **ccode);

	int (*get_persistent_groups) (wfd_oem_persistent_group_s **groups, int *group_count);
	int (*remove_persistent_group) (char *ssid, unsigned char *bssid);
	int (*set_persistent_reconnect) (unsigned char *bssid, int reconnect);

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
	int (*start_service_discovery) (unsigned char mac_addr[6], int service_type);
	int (*cancel_service_discovery) (unsigned char mac_addr[6], int service_type);

	int (*serv_add) (wfd_oem_new_service_s *service);
	int (*serv_del) (wfd_oem_new_service_s *service);
	int (*serv_disc_start) (wfd_oem_new_service_s *service);
	int (*serv_disc_stop) (int handle);
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

#ifdef TIZEN_FEATURE_WIFI_DISPLAY
	int (*miracast_init) (int enable);
	int (*set_display) (wfd_oem_display_s *wifi_display);
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

	int (*refresh) (void);
	int (*save_config) (void);
	int (*set_operating_channel)(int channel);
	int (*remove_all_network)(void);
	int (*get_wpa_status)(int *wpa_status);

#if defined(TIZEN_FEATURE_ASP)
	int (*advertise_service)(wfd_oem_asp_service_s *service, int replace);
	int (*cancel_advertise_service)(wfd_oem_asp_service_s *service);
	int (*seek_service)(wfd_oem_asp_service_s *service);
	int (*cancel_seek_service)(wfd_oem_asp_service_s *service);
#endif /* TIZEN_FEATURE_ASP */
} wfd_oem_ops_s;

int wfd_oem_init(wfd_oem_ops_s *ops, wfd_oem_event_cb event_callback, void *user_data);
int wfd_oem_destroy(wfd_oem_ops_s *ops);
int wfd_oem_activate(wfd_oem_ops_s *ops, int concurrent);
int wfd_oem_deactivate(wfd_oem_ops_s *ops, int concurrent);
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
int wfd_oem_generate_pin(wfd_oem_ops_s *ops, char **pin);
int wfd_oem_get_supported_wps_mode(wfd_oem_ops_s *ops, int *wps_mode);
int wfd_oem_create_group(wfd_oem_ops_s *ops, wfd_oem_group_param_s *param);
int wfd_oem_destroy_group(wfd_oem_ops_s *ops, const char *ifname);
int wfd_oem_invite(wfd_oem_ops_s *ops, unsigned char *peer_addr, wfd_oem_invite_param_s *param);

int wfd_oem_get_dev_name(wfd_oem_ops_s *ops, char *dev_name);
int wfd_oem_set_dev_name(wfd_oem_ops_s *ops, char *dev_name);
int wfd_oem_get_dev_mac(wfd_oem_ops_s *ops, char *dev_mac);
int wfd_oem_get_dev_type(wfd_oem_ops_s *ops, int *pri_dev_type, int *sec_dev_type);
int wfd_oem_set_dev_type(wfd_oem_ops_s *ops, int priv_dev_type, int sec_dev_type);
int wfd_oem_get_go_intent(wfd_oem_ops_s *ops, int *go_intent);
int wfd_oem_set_go_intent(wfd_oem_ops_s *ops, int go_intent);
int wfd_oem_set_country(wfd_oem_ops_s *ops, char *ccode);

int wfd_oem_get_persistent_groups(wfd_oem_ops_s *ops, wfd_oem_persistent_group_s **groups, int *group_count);
int wfd_oem_remove_persistent_group(wfd_oem_ops_s *ops, char *ssid, unsigned char *bssid);
int wfd_oem_set_persistent_reconnect(wfd_oem_ops_s *ops, unsigned char *bssid, int reconnect);

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
int wfd_oem_start_service_discovery(wfd_oem_ops_s *ops, unsigned char *peer_addr, int service_type);
int wfd_oem_cancel_service_discovery(wfd_oem_ops_s *ops, unsigned char *peer_addr, int service_type);

int wfd_oem_serv_add(wfd_oem_ops_s *ops, wfd_oem_new_service_s *service);
int wfd_oem_serv_del(wfd_oem_ops_s *ops, wfd_oem_new_service_s *service);
int wfd_oem_serv_disc_start(wfd_oem_ops_s *ops, wfd_oem_new_service_s *service);
int wfd_oem_serv_disc_stop(wfd_oem_ops_s *ops, int handle);
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

#ifdef TIZEN_FEATURE_WIFI_DISPLAY
int wfd_oem_miracast_init(wfd_oem_ops_s *ops, int enable);
int wfd_oem_set_display(wfd_oem_ops_s *ops, wfd_oem_display_s *wifi_display);
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

int wfd_oem_refresh(wfd_oem_ops_s *ops);
#if defined(TIZEN_FEATURE_ASP)
int wfd_oem_advertise_service(wfd_oem_ops_s *ops, wfd_oem_asp_service_s *service, int replace);
int wfd_oem_cancel_advertise_service(wfd_oem_ops_s *ops, wfd_oem_asp_service_s *service);
int wfd_oem_seek_service(wfd_oem_ops_s *ops, wfd_oem_asp_service_s *service);
int wfd_oem_cancel_seek_service(wfd_oem_ops_s *ops, wfd_oem_asp_service_s *service);
#endif /* TIZEN_FEATURE_ASP */

#endif /* __WIFI_DIRECT_OEM_H__ */
