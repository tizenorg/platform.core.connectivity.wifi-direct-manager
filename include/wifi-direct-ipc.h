/*
 * wifi-direct
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Sungsik Jang <sungsik.jang@samsung.com>, Dongwook Lee <dwmax.lee@samsung.com>
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

#ifndef __WIFI_DIRECT_IPC_H__
#define __WIFI_DIRECT_IPC_H__

#include "wifi-direct-error.h"

#define true 1
#define false 0

#define WFD_INVALID_ID	-1

#ifndef O_NONBLOCK
#define O_NONBLOCK  O_NDELAY
#endif /** O_NONBLOCK */


#ifndef _UINT32_TYPE_H_
#define _UINT32_TYPE_H_
typedef unsigned int uint32;
#endif /** _UINT32_TYPE_H_ */

typedef unsigned int ipv4_addr_t;

#ifndef TRUE
#define TRUE 1
#endif /** TRUE */

#ifndef FALSE
#define FALSE 0
#endif /** FALSE */

#define WIFI_DIRECT_MAX_SSID_LEN 32
#define WIFI_DIRECT_MAX_DEVICE_NAME_LEN 32
#define WIFI_DIRECT_WPS_PIN_LEN 8
#define WIFI_DIRECT_MAX_SERVICES_LEN 1024
#define WIFI_DIRECT_MAX_SERVICE_NAME_LEN 256

#define VCONFKEY_IFNAME "memory/private/wifi_direct_manager/p2p_ifname"
#define VCONFKEY_LOCAL_IP "memory/private/wifi_direct_manager/p2p_local_ip"
#define VCONFKEY_SUBNET_MASK "memory/private/wifi_direct_manager/p2p_subnet_mask"
#define VCONFKEY_GATEWAY "memory/private/wifi_direct_manager/p2p_gateway"

/**
 * Wi-Fi Direct connection state
 */
typedef enum {
	WFD_EVENT_CONNECTION_REQ,  /**< Connection is requested */
	WFD_EVENT_CONNECTION_WPS_REQ,  /**< WPS is requested */
	WFD_EVENT_CONNECTION_IN_PROGRESS,  /**< Connection in progress */
	WFD_EVENT_CONNECTION_RSP,  /**< Connected */
	WFD_EVENT_DISASSOCIATION_IND,  /**< Disconnected by remote Group Client */
	WFD_EVENT_DISCONNECTION_RSP,  /**< Disconnected by local device */
	WFD_EVENT_DISCONNECTION_IND,  /**< Disconnected by remote Group Owner */
	WFD_EVENT_GROUP_CREATED,  /**< Group is created */
	WFD_EVENT_GROUP_DESTROYED,  /**< Group is destroyed */
} wfd_connection_event_e;

/**
 * @brief Enumeration for Wi-Fi Direct secondary device type.
 * @since_tizen 2.3
 */
typedef enum {
	WFD_SECONDARY_DEVICE_TYPE_COMPUTER_PC = 1,  /**< PC */
	WFD_SECONDARY_DEVICE_TYPE_COMPUTER_SERVER = 2,  /**< Server */
	WFD_SECONDARY_DEVICE_TYPE_COMPUTER_MEDIA_CENTER = 3,  /**< Media Center */
	WFD_SECONDARY_DEVICE_TYPE_COMPUTER_UMPC = 4,  /**< UMPC */
	WFD_SECONDARY_DEVICE_TYPE_COMPUTER_NOTEBOOK = 5,  /**< Notebook */
	WFD_SECONDARY_DEVICE_TYPE_COMPUTER_DESKTOP = 6,  /**< Desktop */
	WFD_SECONDARY_DEVICE_TYPE_COMPUTER_MID = 7,  /**< MID */
	WFD_SECONDARY_DEVICE_TYPE_COMPUTER_NETBOOK = 8,  /**< Netbook */
	WFD_SECONDARY_DEVICE_TYPE_INPUT_KEYBOARD = 1,  /**< Keyboard */
	WFD_SECONDARY_DEVICE_TYPE_INPUT_MOUSE = 2,  /**< Mouse */
	WFD_SECONDARY_DEVICE_TYPE_INPUT_JOYSTICK = 3,  /**< Joystick */
	WFD_SECONDARY_DEVICE_TYPE_INPUT_TRACKBALL = 4,  /**< Trackball */
	WFD_SECONDARY_DEVICE_TYPE_INPUT_CONTROLLER = 5,  /**< Controller */
	WFD_SECONDARY_DEVICE_TYPE_INPUT_REMOTE = 6,  /**< Remote */
	WFD_SECONDARY_DEVICE_TYPE_INPUT_TOUCHSCREEN = 7,  /**< Touchscreen */
	WFD_SECONDARY_DEVICE_TYPE_INPUT_BIOMETRIC_READER = 8,  /**< Biometric reader */
	WFD_SECONDARY_DEVICE_TYPE_INPUT_BARCODE_READER = 9,  /**< Barcode reader */
	WFD_SECONDARY_DEVICE_TYPE_PRINTER_PRINTER = 1,  /**< Printer */
	WFD_SECONDARY_DEVICE_TYPE_PRINTER_SCANNER = 2,  /**< Scanner */
	WFD_SECONDARY_DEVICE_TYPE_PRINTER_FAX = 3,  /**< Fax */
	WFD_SECONDARY_DEVICE_TYPE_PRINTER_COPIER = 4,  /**< Copier */
	WFD_SECONDARY_DEVICE_TYPE_PRINTER_ALL_IN_ONE = 5,  /**< All-in-one */
	WFD_SECONDARY_DEVICE_TYPE_CAMERA_DIGITAL_STILL = 1,  /**< Digital still camera */
	WFD_SECONDARY_DEVICE_TYPE_CAMERA_VIDEO = 2,  /**< Video camera */
	WFD_SECONDARY_DEVICE_TYPE_CAMERA_WEBCAM = 3,  /**< Webcam */
	WFD_SECONDARY_DEVICE_TYPE_CAMERA_SECURITY = 4,     /**< Security camera */
	WFD_SECONDARY_DEVICE_TYPE_STORAGE_NAS = 1,  /**< NAS */
	WFD_SECONDARY_DEVICE_TYPE_NETWORK_INFRA_AP = 1,  /**< AP */
	WFD_SECONDARY_DEVICE_TYPE_NETWORK_INFRA_ROUTER = 2,  /**< Router */
	WFD_SECONDARY_DEVICE_TYPE_NETWORK_INFRA_SWITCH = 3,  /**< Switch */
	WFD_SECONDARY_DEVICE_TYPE_NETWORK_INFRA_GATEWAY = 4,  /**< Gateway */
	WFD_SECONDARY_DEVICE_TYPE_DISPLAY_TV = 1,  /**< TV */
	WFD_SECONDARY_DEVICE_TYPE_DISPLAY_PIC_FRAME = 2,  /**< Picture frame */
	WFD_SECONDARY_DEVICE_TYPE_DISPLAY_PROJECTOR = 3,  /**< Projector */
	WFD_SECONDARY_DEVICE_TYPE_DISPLAY_MONITOR = 4,  /**< Monitor */
	WFD_SECONDARY_DEVICE_TYPE_MULTIMEDIA_DAR = 1,  /**< DAR */
	WFD_SECONDARY_DEVICE_TYPE_MULTIMEDIA_PVR = 2,  /**< PVR */
	WFD_SECONDARY_DEVICE_TYPE_MULTIMEDIA_MCX = 3,  /**< MCX */
	WFD_SECONDARY_DEVICE_TYPE_MULTIMEDIA_STB = 4,  /**< Set-top box */
	WFD_SECONDARY_DEVICE_TYPE_MULTIMEDIA_MS_MA_ME = 5,  /**< Media Server / Media Adapter / Media Extender */
	WFD_SECONDARY_DEVICE_TYPE_MULTIMEDIA_PVP = 6,  /**< Portable video player */
	WFD_SECONDARY_DEVICE_TYPE_GAME_XBOX = 1,  /**< Xbox */
	WFD_SECONDARY_DEVICE_TYPE_GAME_XBOX_360 = 2,  /**< Xbox 360 */
	WFD_SECONDARY_DEVICE_TYPE_GAME_PS = 3,  /**< Playstation */
	WFD_SECONDARY_DEVICE_TYPE_GAME_CONSOLE = 4,  /**< Console */
	WFD_SECONDARY_DEVICE_TYPE_GAME_PORTABLE = 5,  /**< Portable */
	WFD_SECONDARY_DEVICE_TYPE_TELEPHONE_WINDOWS_MOBILE = 1,  /**< Windows Mobile */
	WFD_SECONDARY_DEVICE_TYPE_TELEPHONE_PHONE_SINGLE = 2,  /**< Phone - single mode */
	WFD_SECONDARY_DEVICE_TYPE_TELEPHONE_PHONE_DUAL = 3,  /**< Phone - dual mode */
	WFD_SECONDARY_DEVICE_TYPE_TELEPHONE_SMARTPHONE_SINGLE = 4,  /**< Smart Phone - single mode */
	WFD_SECONDARY_DEVICE_TYPE_TELEPHONE_SMARTPHONE_DUAL = 5,  /**< Smart Phone - dual mode */
	WFD_SECONDARY_DEVICE_TYPE_AUDIO_TUNER = 1,  /**< Tuner */
	WFD_SECONDARY_DEVICE_TYPE_AUDIO_SPEAKER = 2,  /**< Speaker */
	WFD_SECONDARY_DEVICE_TYPE_AUDIO_PMP = 3, /**< Portable Music Player */
	WFD_SECONDARY_DEVICE_TYPE_AUDIO_HEADSET = 4,  /**< Headset */
	WFD_SECONDARY_DEVICE_TYPE_AUDIO_HEADPHONE = 5,  /**< Headphone */
	WFD_SECONDARY_DEVICE_TYPE_AUDIO_MIC = 6,  /**< Microphone */
} wfd_secondary_device_type_e;

/**
 * @brief Enumeration for Wi-Fi Direct primary device type.
 * @since_tizen 2.3
 */
typedef enum {
	WFD_PRIMARY_DEVICE_TYPE_COMPUTER = 1,  /**< Computer */
	WFD_PRIMARY_DEVICE_TYPE_INPUT_DEVICE = 2,  /**< Input device */
	WFD_PRIMARY_DEVICE_TYPE_PRINTER = 3,  /**< Printer */
	WFD_PRIMARY_DEVICE_TYPE_CAMERA = 4,  /**< Camera */
	WFD_PRIMARY_DEVICE_TYPE_STORAGE = 5,  /**< Storage */
	WFD_PRIMARY_DEVICE_TYPE_NETWORK_INFRA = 6,  /**< Network Infrastructure */
	WFD_PRIMARY_DEVICE_TYPE_DISPLAY = 7,  /**< Display */
	WFD_PRIMARY_DEVICE_TYPE_MULTIMEDIA_DEVICE = 8,  /**< Multimedia device */
	WFD_PRIMARY_DEVICE_TYPE_GAME_DEVICE = 9,  /**< Game device */
	WFD_PRIMARY_DEVICE_TYPE_TELEPHONE = 10,  /**< Telephone */
	WFD_PRIMARY_DEVICE_TYPE_AUDIO = 11,  /**< Audio */
	WFD_PRIMARY_DEVICE_TYPE_OTHER =  255  /**< Others */
} wfd_primary_device_type_e;

/**
 * @brief Enumeration for Wi-Fi WPS type.
 * @since_tizen 2.3
 */
typedef enum {
	WFD_WPS_TYPE_NONE = 0x00,  /**< No WPS type */
	WFD_WPS_TYPE_PBC = 0x01,  /**< Push Button Configuration */
	WFD_WPS_TYPE_PIN_DISPLAY = 0x02,  /**< Display PIN code */
	WFD_WPS_TYPE_PIN_KEYPAD = 0x04,  /**< Provide the keypad to input the PIN */
} wfd_wps_type_e;


/**
 * @brief Enumeration for Wi-Fi Direct Discovery Channel.
 * @since_tizen 2.3
 */
typedef enum {
	WFD_DISCOVERY_FULL_SCAN = 0,  /**< Scan full channel*/
	WFD_DISCOVERY_SOCIAL_CHANNEL = 1611,  /**< Scan social channel*/
	WFD_DISCOVERY_CHANNEL1 = 1,  /**< Scan channel 1*/
	WFD_DISCOVERY_CHANNEL6 = 6,  /**< Scan channel 6*/
	WFD_DISCOVERY_CHANNEL11 = 11,  /**< Scan channel 11*/
} wfd_discovery_channel_e;


/**
 * Wi-Fi Direct configuration data structure for IPC
 */
typedef struct
{
	char device_name[WIFI_DIRECT_MAX_DEVICE_NAME_LEN + 1];
	int channel;
	wfd_wps_type_e wps_config;
	int max_clients;
	gboolean hide_SSID;
	int group_owner_intent;
	gboolean want_persistent_group;
	gboolean listen_only;
	gboolean auto_connection;
	wfd_primary_device_type_e primary_dev_type;
	wfd_secondary_device_type_e secondary_dev_type;
} wfd_config_data_s;


/**
 * Wi-Fi Direct buffer structure to store result of peer discovery for IPC
 */
typedef struct
{
	char device_name[WIFI_DIRECT_MAX_DEVICE_NAME_LEN + 1];
	unsigned char mac_address[6];
	unsigned char intf_address[6];
	int channel;
	gboolean is_connected;
	gboolean is_group_owner;
	gboolean is_persistent_go;
	unsigned int category;
	unsigned int subcategory;
	unsigned int services;
	unsigned int wps_device_pwd_id;
	unsigned int wps_cfg_methods;
	gboolean is_wfd_device;
} wfd_discovery_entry_s;


/**
 * Wi-Fi Direct buffer structure to store information of connected peer
 */
typedef struct
{
	char device_name[WIFI_DIRECT_MAX_DEVICE_NAME_LEN + 1];
	unsigned char ip_address[4];
	unsigned char mac_address[6];
	unsigned char intf_address[6];
	int channel;
	gboolean is_p2p;
	unsigned short category;
	unsigned short subcategory;
	unsigned int services;
	gboolean is_wfd_device;
} wfd_connected_peer_info_s;


typedef struct
{
	int network_id;
	char ssid[WIFI_DIRECT_MAX_SSID_LEN + 1];
	unsigned char go_mac_address[6];
} wfd_persistent_group_info_s;

#endif	/* __WIFI_DIRECT_IPC_H__ */
