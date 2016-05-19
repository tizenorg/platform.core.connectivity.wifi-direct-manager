/*
 * Network Configuration Module
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
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
 * This file implements wifi direct manager interface functions.
 *
 * @file        wifi-direct-iface.c
 * @author      Nishant Chaprana (n.chaprana@samsung.com)
 * @version     0.1
 */

#include <stdlib.h>

#include <wifi-direct.h>

#include "wifi-direct-dbus.h"
#include "wifi-direct-iface.h"
#include "wifi-direct-ipc.h"
#include "wifi-direct-error.h"
#include "wifi-direct-log.h"
#include "wifi-direct-manager.h"
#include "wifi-direct-oem.h"
#include "wifi-direct-session.h"
#include "wifi-direct-util.h"
#include "wifi-direct-group.h"
#include "wifi-direct-state.h"
#include <vconf.h>
#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
#include "wifi-direct-service.h"
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

#define WFD_DBUS_REPLY_ERROR_NONE(invocation) \
	g_dbus_method_invocation_return_value((invocation), g_variant_new("(i)", WIFI_DIRECT_ERROR_NONE))

#define WFD_DBUS_REPLY_PARAMS(invocation, params) \
	g_dbus_method_invocation_return_value((invocation), (params))

static int macaddr_atoe(const char *p, unsigned char mac[])
{
	int i = 0;

	for (;;) {
		mac[i++] = (char) strtoul(p, (char **) &p, 16);
		if (!*p++ || i == 6)
			break;
	}

	return (i == 6);
}

// introspection xml to register interfaces
const gchar wfd_manager_introspection_xml[] = {
	"<node name='/net/wifidirect'>"
		"<interface name='net.wifidirect'>"
			"<method name='Activate'>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='Deactivate'>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='StartDiscovery'>"
				"<arg type='a{sv}' name='parameters' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='StopDiscovery'>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='GetDiscoveredPeers'>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='aa{sv}' name='peer_details_list' direction='out'/>"
			"</method>"
			"<method name='Connect'>"
				"<arg type='s' name='mac_address' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='Disconnect'>"
				"<arg type='s' name='mac_address' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='CancelConnection'>"
				"<arg type='s' name='mac_address' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='AcceptConnection'>"
				"<arg type='s' name='mac_address' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='RejectConnection'>"
				"<arg type='s' name='mac_address' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='DisconnectAll'>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='GetConnectedPeers'>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='aa{sv}' name='peer_details_list' direction='out'/>"
			"</method>"
			"<method name='IsDiscoverable'>"
				"<arg type='b' name='result' direction='out'/>"
			"</method>"
			"<method name='IsListeningOnly'>"
				"<arg type='b' name='result' direction='out'/>"
			"</method>"
			"<method name='GetPeerInfo'>"
				"<arg type='s' name='mac_address' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='a{sv}' name='peer_details' direction='out'/>"
			"</method>"
			"<method name='GetState'>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='i' name='state' direction='out'/>"
			"</method>"
			"<signal name='Activation'>"
				"<arg type='i' name='error_code'/>"
			"</signal>"
			"<signal name='Deactivation'>"
				"<arg type='i' name='error_code'/>"
			"</signal>"
			"<signal name='Connection'>"
				"<arg type='i' name='error_code'/>"
				"<arg type='i' name='connection_state'/>"
				"<arg type='s' name='peer_mac_address'/>"
			"</signal>"
			"<signal name='Disconnection'>"
				"<arg type='i' name='error_code'/>"
				"<arg type='i' name='connection_state'/>"
				"<arg type='s' name='peer_mac_address'/>"
			"</signal>"
			"<signal name='ListenStarted'>"
			"</signal>"
			"<signal name='DiscoveryStarted'>"
			"</signal>"
			"<signal name='DiscoveryFinished'>"
			"</signal>"
			"<signal name='PeerFound'>"
				"<arg type='s' name='peer_mac_address'/>"
			"</signal>"
			"<signal name='PeerLost'>"
				"<arg type='s' name='peer_mac_address'/>"
			"</signal>"
			"<signal name='PeerIPAssigned'>"
				"<arg type='s' name='peer_mac_address'/>"
				"<arg type='s' name='assigned_ip_address'/>"
			"</signal>"
		"</interface>"
		"<interface name='net.wifidirect.group'>"
			"<method name='CreateGroup'>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='DestroyGroup'>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='IsGroupOwner'>"
				"<arg type='b' name='result' direction='out'/>"
			"</method>"
			"<method name='IsAutoGroup'>"
				"<arg type='b' name='result' direction='out'/>"
			"</method>"
			"<method name='ActivatePushButton'>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='GetPersistentGroups'>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='aa{sv}' name='result' direction='out'/>"
			"</method>"
			"<method name='RemovePersistentGroup'>"
				"<arg type='s' name='mac_address' direction='in'/>"
				"<arg type='s' name='ssid' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='SetPassphrase'>"
				"<arg type='s' name='passphrase' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='GetPassphrase'>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='s' name='passphrase' direction='out'/>"
			"</method>"
			"<method name='SetPersistentGroupEnabled'>"
				"<arg type='b' name='enable' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='IsPersistentGroupEnabled'>"
				"<arg type='b' name='result' direction='out'/>"
			"</method>"
			"<signal name='Created'>"
			"</signal>"
			"<signal name='Destroyed'>"
			"</signal>"
		"</interface>"
		"<interface name='net.wifidirect.config'>"
			"<method name='GetDeviceName'>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='s' name='device_name' direction='out'/>"
			"</method>"
			"<method name='SetDeviceName'>"
				"<arg type='s' name='device_name' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='SetWpsPin'>"
				"<arg type='s' name='wps_pin' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='GetWpsPin'>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='s' name='wps_pin' direction='out'/>"
			"</method>"
			"<method name='GenerateWpsPin'>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='s' name='wps_pin' direction='out'/>"
			"</method>"
			"<method name='GetSupportedWpsMode'>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='i' name='config_methods' direction='out'/>"
			"</method>"
			"<method name='GetReqWpsMode'>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='i' name='req_wps_mode' direction='out'/>"
			"</method>"
			"<method name='SetReqWpsMode'>"
				"<arg type='i' name='req_wps_mode' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='GetLocalWpsMode'>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='i' name='local_wps_mode' direction='out'/>"
			"</method>"
			"<method name='GetIPAddress'>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='s' name='local_ip_address' direction='out'/>"
			"</method>"
			"<method name='GetMacAddress'>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='s' name='local_mac_address' direction='out'/>"
			"</method>"
			"<method name='GetGoIntent'>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='i' name='go_intent' direction='out'/>"
			"</method>"
			"<method name='SetGoIntent'>"
				"<arg type='i' name='go_intent' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='GetMaxClient'>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='i' name='max_client' direction='out'/>"
			"</method>"
			"<method name='SetMaxClient'>"
				"<arg type='i' name='max_client' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='SetAutoConnectionMode'>"
				"<arg type='b' name='auto_connection_mode' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='IsAutoConnectionMode'>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='b' name='result' direction='out'/>"
			"</method>"
			"<method name='GetOperatingChannel'>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='i' name='operating_channel' direction='out'/>"
			"</method>"
			"<method name='SetAutoConnectionPeer'>"
				"<arg type='s' name='peer_mac_address' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='GetConnectingPeer'>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='s' name='local_mac_address' direction='out'/>"
			"</method>"
			"<method name='GetInterfaceName'>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='s' name='ifname' direction='out'/>"
			"</method>"
			"<method name='GetSubnetMask'>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='s' name='subnet_mask' direction='out'/>"
			"</method>"
			"<method name='GetGateway'>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='s' name='gateway_address' direction='out'/>"
			"</method>"
			"<method name='GetSessionTimer'>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='i' name='session_timer' direction='out'/>"
			"</method>"
			"<method name='SetSessionTimer'>"
				"<arg type='i' name='session_timer' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='SetAutoGroupRemoval'>"
				"<arg type='b' name='enable' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
		"</interface>"
#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
		"<interface name='net.wifidirect.service'>"
			"<method name='StartDiscovery'>"
				"<arg type='i' name='service_type' direction='in'/>"
				"<arg type='s' name='mac_addr' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='StopDiscovery'>"
				"<arg type='i' name='service_type' direction='in'/>"
				"<arg type='s' name='mac_addr' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='Register'>"
				"<arg type='i' name='service_type' direction='in'/>"
				"<arg type='s' name='info_string' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='i' name='service_id' direction='out'/>"
			"</method>"
			"<method name='Deregister'>"
				"<arg type='i' name='service_id' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<signal name='DiscoveryStarted'>"
			"</signal>"
			"<signal name='DiscoveryFound'>"
				"<arg type='i' name='service_type'/>"
				"<arg type='s' name='response_data'/>"
				"<arg type='s' name='peer_mac_address'/>"
			"</signal>"
			"<signal name='DiscoveryFinished'>"
			"</signal>"
		"</interface>"
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */
#ifdef TIZEN_FEATURE_WIFI_DISPLAY
		"<interface name='net.wifidirect.display'>"
			"<method name='Init'>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='Deinit'>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='SetConfig'>"
				"<arg type='i' name='type' direction='in'/>"
				"<arg type='i' name='port' direction='in'/>"
				"<arg type='i' name='hdcp' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='SetAvailiability'>"
				"<arg type='i' name='availability' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
			"</method>"
			"<method name='GetPeerType'>"
				"<arg type='s' name='peer_mac_addr' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='i' name='result' direction='out'/>"
			"</method>"
			"<method name='GetPeerAvailability'>"
				"<arg type='s' name='peer_mac_addr' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='i' name='result' direction='out'/>"
			"</method>"
			"<method name='GetPeerHdcp'>"
				"<arg type='s' name='peer_mac_addr' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='i' name='result' direction='out'/>"
			"</method>"
			"<method name='GetPeerPort'>"
				"<arg type='s' name='peer_mac_addr' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='i' name='result' direction='out'/>"
			"</method>"
			"<method name='GetPeerThroughput'>"
				"<arg type='s' name='peer_mac_addr' direction='in'/>"
				"<arg type='i' name='error_code' direction='out'/>"
				"<arg type='i' name='result' direction='out'/>"
			"</method>"
		"</interface>"
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */
	"</node>"
};


static void __wfd_manager_manage_iface_handler(const gchar *method_name,
					      GVariant    *parameters,
					      GDBusMethodInvocation *invocation)
{
	int ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
	wfd_manager_s *manager = wfd_get_manager();
	GVariant *return_parameters = NULL;
	GError *err = NULL;
	gchar* dbus_error_name = NULL;
	WDS_LOGD("%s", method_name);

	if (!g_strcmp0(method_name, "Activate")) {

		WFD_DBUS_REPLY_ERROR_NONE(invocation);

		ret = wfd_manager_activate(manager);
		wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
					     "Activation",
					     g_variant_new("(i)", ret));
		return;

	} else if (!g_strcmp0(method_name, "Deactivate")) {

		if (manager->state < WIFI_DIRECT_STATE_ACTIVATED) {
			WDS_LOGE("Already deactivated");
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		WFD_DBUS_REPLY_ERROR_NONE(invocation);

		ret = wfd_manager_deactivate(manager);
		wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
					     "Deactivation",
					     g_variant_new("(i)", ret));
		return;

	} else if (!g_strcmp0(method_name, "StartDiscovery")) {
		gboolean mode = FALSE;
		gint32 timeout = 0;
		guint32 channel = 0;
		const gchar *type = NULL;
		GVariantIter *iter = NULL;
		gchar *key = NULL;
		GVariant *var = NULL;

		g_variant_get(parameters, "(a{sv})", &iter);
		while (g_variant_iter_loop(iter, "{sv}", &key, &var)) {
			if (!g_strcmp0(key, "Mode"))
				g_variant_get(var, "b", &mode);
			else if (!g_strcmp0(key, "Timeout"))
				g_variant_get(var, "i", &timeout);
			else if (!g_strcmp0(key, "Type"))
				g_variant_get(var, "&s", &type);
			else if (!g_strcmp0(key, "Channel"))
				g_variant_get(var, "i", &channel);
			else
				;/* Do Nothing */
		}
		g_variant_iter_free(iter);

		if (manager->state != WIFI_DIRECT_STATE_ACTIVATED &&
				manager->state != WIFI_DIRECT_STATE_DISCOVERING &&
				manager->state != WIFI_DIRECT_STATE_GROUP_OWNER) {
			WDS_LOGE("Wi-Fi Direct is not available status for scanning.");
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		if (mode && (manager->local->dev_role == WFD_DEV_ROLE_GO)) {
			WDS_LOGW("Wi-Fi Direct device is already visible, do not start listen");
			ret = WIFI_DIRECT_ERROR_NONE;
			return_parameters = g_variant_new("(i)", ret);
			goto done;
		}

		WFD_DBUS_REPLY_ERROR_NONE(invocation);

		ret = wfd_manager_start_discovery(manager, mode, timeout, type, channel);
		if (ret == WIFI_DIRECT_ERROR_NONE) {
			if (mode == WFD_OEM_SCAN_MODE_PASSIVE) {
				wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
							     "ListenStarted",
							     NULL);
			} else {
				wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
							     "DiscoveryStarted",
							     NULL);
			}
		}
		return;

	} else if (!g_strcmp0(method_name, "StopDiscovery")) {
		int mode =  manager->scan_mode;
		if (manager->state != WIFI_DIRECT_STATE_ACTIVATED &&
				manager->state != WIFI_DIRECT_STATE_DISCOVERING) {
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		WFD_DBUS_REPLY_ERROR_NONE(invocation);

		ret = wfd_manager_cancel_discovery(manager);
		if (ret == WIFI_DIRECT_ERROR_NONE && mode == WFD_SCAN_MODE_PASSIVE)
			wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
						     "DiscoveryFinished", NULL);
		return;

	} else if (!g_strcmp0(method_name, "GetDiscoveredPeers")) {
		wfd_discovery_entry_s *peers = NULL;
		GVariantBuilder *builder_peers = NULL;
		int peer_cnt = 0;
		int i = 0;

		builder_peers = g_variant_builder_new(G_VARIANT_TYPE("aa{sv}"));

		peer_cnt = wfd_manager_get_peers(manager, &peers);
		WDS_LOGD("Peer count [%d], Peer list [%p]", peer_cnt, peers);
		if (peer_cnt < 0) {
			WDS_LOGE("Failed to get scan result");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		if (peer_cnt > 255)
			peer_cnt = 255;

		for (i = 0; i < peer_cnt; i++) {
			GVariantBuilder builder_peer;
			g_variant_builder_init(&builder_peer, G_VARIANT_TYPE("a{sv}"));

			g_variant_builder_add(&builder_peer, "{sv}",
					"DeviceName",
					g_variant_new_string(peers[i].device_name));
			g_variant_builder_add(&builder_peer, "{sv}",
					"DeviceAddress",
					wfd_manager_dbus_pack_ay(peers[i].mac_address, MACADDR_LEN));
			g_variant_builder_add(&builder_peer, "{sv}",
					"InterfaceAddress",
					wfd_manager_dbus_pack_ay(peers[i].intf_address, MACADDR_LEN));
			g_variant_builder_add(&builder_peer, "{sv}",
					"Channel",
					g_variant_new_uint16(peers[i].channel));
#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
			g_variant_builder_add(&builder_peer, "{sv}",
					"Services",
					g_variant_new_uint16(peers[i].services));
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */
			g_variant_builder_add(&builder_peer, "{sv}",
					"IsGroupOwner",
					g_variant_new_boolean(peers[i].is_group_owner));
			g_variant_builder_add(&builder_peer, "{sv}",
					"IsPersistentGO",
					g_variant_new_boolean(peers[i].is_persistent_go));
			g_variant_builder_add(&builder_peer, "{sv}",
					"IsConnected",
					g_variant_new_boolean(peers[i].is_connected));
			g_variant_builder_add(&builder_peer, "{sv}",
					"WpsDevicePwdID",
					g_variant_new_uint16(peers[i].wps_device_pwd_id));
			g_variant_builder_add(&builder_peer, "{sv}",
					"WpsCfgMethods",
					g_variant_new_uint16(peers[i].wps_cfg_methods));
			g_variant_builder_add(&builder_peer, "{sv}",
					"Category",
					g_variant_new_uint16(peers[i].category));
			g_variant_builder_add(&builder_peer, "{sv}",
					"SubCategory",
					g_variant_new_uint16(peers[i].subcategory));
#ifdef TIZEN_FEATURE_WIFI_DISPLAY
			g_variant_builder_add(&builder_peer, "{sv}",
					"IsWfdDevice",
					g_variant_new_boolean(peers[i].is_wfd_device));
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

			WDS_LOGD("%dth peer [%s]", i, peers[i].device_name);
			g_variant_builder_add_value(builder_peers, g_variant_builder_end(&builder_peer));
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(iaa{sv})", ret, builder_peers);
		g_variant_builder_unref(builder_peers);
		goto done;

	} else if (!g_strcmp0(method_name, "Connect")) {
		const char *peer_mac_address = NULL;
		unsigned char mac_addr[MACADDR_LEN] = {0, };

		if (manager->state != WIFI_DIRECT_STATE_ACTIVATED &&
				manager->state != WIFI_DIRECT_STATE_DISCOVERING &&
				manager->state != WIFI_DIRECT_STATE_GROUP_OWNER) {
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		wfd_group_s *group = (wfd_group_s*) manager->group;
		if (group && group->member_count >= manager->max_station) {
			ret = WIFI_DIRECT_ERROR_TOO_MANY_CLIENT;
			goto failed;
		}

		WFD_DBUS_REPLY_ERROR_NONE(invocation);

		g_variant_get(parameters, "(&s)", &peer_mac_address);
		macaddr_atoe(peer_mac_address, mac_addr);

		ret = wfd_manager_connect(manager, mac_addr);
		if (ret == WIFI_DIRECT_ERROR_NONE)
			wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
						     "Connection",
						     g_variant_new("(iis)", WIFI_DIRECT_ERROR_NONE,
									    WFD_EVENT_CONNECTION_IN_PROGRESS,
									    peer_mac_address));
		return;

	} else if (!g_strcmp0(method_name, "Disconnect")) {
		const char *peer_mac_address = NULL;
		unsigned char mac_addr[MACADDR_LEN] = {0, };

		if (!manager->group || manager->state < WIFI_DIRECT_STATE_CONNECTED) {
			if (WIFI_DIRECT_STATE_DISCOVERING == manager->state) {
				ret = wfd_oem_stop_scan(manager->oem_ops);
				if (ret < 0) {
					WDS_LOGE("Failed to stop scan");
					ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
					goto failed;
				}
				WDS_LOGI("Succeeded to stop scan");
				if (WFD_DEV_ROLE_GO == manager->local->dev_role) {
					wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
					wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
				} else {
					wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
					wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
				}
			} else {
				ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
				goto failed;
			}
		}

		WFD_DBUS_REPLY_ERROR_NONE(invocation);

		g_variant_get(parameters, "(&s)", &peer_mac_address);
		macaddr_atoe(peer_mac_address, mac_addr);

		ret = wfd_manager_disconnect(manager, mac_addr);
		if (ret == WIFI_DIRECT_ERROR_NONE)
			wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
						     "Disconnection",
						     g_variant_new("(iis)", WIFI_DIRECT_ERROR_NONE,
									    WFD_EVENT_DISCONNECTION_RSP,
									    peer_mac_address));
		return;

	} else if (!g_strcmp0(method_name, "CancelConnection")) {
		const char *peer_mac_address = NULL;
		unsigned char mac_addr[MACADDR_LEN] = {0, };

		if (!manager->session && manager->state != WIFI_DIRECT_STATE_CONNECTING) {
			WDS_LOGE("It's not CONNECTING state");
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		WFD_DBUS_REPLY_ERROR_NONE(invocation);

		g_variant_get(parameters, "(&s)", &peer_mac_address);
		macaddr_atoe(peer_mac_address, mac_addr);

		ret = wfd_manager_cancel_connection(manager, mac_addr);
		if (ret == WIFI_DIRECT_ERROR_NONE)
			wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
						     "Connection",
						     g_variant_new("(iis)", WIFI_DIRECT_ERROR_CONNECTION_CANCELED,
									    WFD_EVENT_CONNECTION_RSP,
									    peer_mac_address));
		return;

	} else if (!g_strcmp0(method_name, "AcceptConnection")) {
		const char *peer_mac_address = NULL;
		unsigned char mac_addr[MACADDR_LEN] = {0, };

		if (manager->state != WIFI_DIRECT_STATE_CONNECTING) {
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		wfd_group_s *group = (wfd_group_s*) manager->group;
		if (group && group->member_count >= manager->max_station) {
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		WFD_DBUS_REPLY_ERROR_NONE(invocation);

		g_variant_get(parameters, "(&s)", &peer_mac_address);
		macaddr_atoe(peer_mac_address, mac_addr);

		ret = wfd_manager_accept_connection(manager, mac_addr);
		if (ret == WIFI_DIRECT_ERROR_NONE) {
			wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
						     "Connection",
						     g_variant_new("(iis)", WIFI_DIRECT_ERROR_NONE,
									    WFD_EVENT_CONNECTION_IN_PROGRESS,
									    peer_mac_address));
		} else {
			wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
						     "Connection",
						     g_variant_new("(iis)", WIFI_DIRECT_ERROR_OPERATION_FAILED,
									    WFD_EVENT_CONNECTION_RSP,
									    peer_mac_address));
		}
		return;

	} else if (!g_strcmp0(method_name, "RejectConnection")) {
		wfd_session_s *session = manager->session;
		const char *peer_mac_address = NULL;
		unsigned char mac_addr[MACADDR_LEN] = {0, };

		if (!session || manager->state != WIFI_DIRECT_STATE_CONNECTING) {
			WDS_LOGE("It's not permitted with this state [%d]", manager->state);
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		if (session->direction != SESSION_DIRECTION_INCOMING) {
			WDS_LOGE("Only incomming session can be rejected");
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		WFD_DBUS_REPLY_ERROR_NONE(invocation);

		g_variant_get(parameters, "(&s)", &peer_mac_address);
		macaddr_atoe(peer_mac_address, mac_addr);

		ret = wfd_manager_reject_connection(manager, mac_addr);
		if (ret == WIFI_DIRECT_ERROR_NONE)
			wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
						     "Connection",
						     g_variant_new("(iis)", WIFI_DIRECT_ERROR_CONNECTION_CANCELED,
									    WFD_EVENT_CONNECTION_RSP,
									    peer_mac_address));
		return;

	} else if (!g_strcmp0(method_name, "DisconnectAll")) {

		if (!manager->group || manager->state < WIFI_DIRECT_STATE_CONNECTED) {
			if (WIFI_DIRECT_STATE_DISCOVERING == manager->state) {
				ret = wfd_oem_stop_scan(manager->oem_ops);
				if (ret < 0) {
					WDS_LOGE("Failed to stop scan");
					ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
					goto failed;
				}
				WDS_LOGI("Succeeded to stop scan");
				if (WFD_DEV_ROLE_GO == manager->local->dev_role) {
					wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
					wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
				} else {
					wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
					wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
				}
			} else {
				ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
				goto failed;
			}
		}

		WFD_DBUS_REPLY_ERROR_NONE(invocation);

		ret = wfd_manager_disconnect_all(manager);
		if (ret == WIFI_DIRECT_ERROR_NONE)
			wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
						     "Disconnection",
						     g_variant_new("(iis)", ret,
									    WFD_EVENT_DISCONNECTION_RSP,
									    ""));
		return;

	} else if (!g_strcmp0(method_name, "GetConnectedPeers")) {
		wfd_connected_peer_info_s *peers = NULL;
		GVariantBuilder *builder_peers = NULL;
		int peer_cnt = 0;
		int i = 0;

		builder_peers = g_variant_builder_new(G_VARIANT_TYPE("aa{sv}"));

		// even though status is not CONNECTED, this command can be excuted only when group exist
		if (!manager->group && manager->state < WIFI_DIRECT_STATE_CONNECTED) {
			WDS_LOGD("It's not connected state [%d]", manager->state);
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		peer_cnt = wfd_manager_get_connected_peers(manager, &peers);
		WDS_LOGD("Peer count [%d], Peer list [%x]", peer_cnt, peers);
		if (peer_cnt < 0) {
			WDS_LOGE("Failed to get scan result");
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		for (i = 0; i < peer_cnt; i++) {
			GVariantBuilder builder_peer;
			g_variant_builder_init(&builder_peer, G_VARIANT_TYPE("a{sv}"));

			g_variant_builder_add(&builder_peer, "{sv}",
					"DeviceName",
					g_variant_new_string(peers[i].device_name));
			g_variant_builder_add(&builder_peer, "{sv}",
					"DeviceAddress",
					wfd_manager_dbus_pack_ay(peers[i].mac_address, MACADDR_LEN));
			g_variant_builder_add(&builder_peer, "{sv}",
					"InterfaceAddress",
					wfd_manager_dbus_pack_ay(peers[i].intf_address, MACADDR_LEN));
			g_variant_builder_add(&builder_peer, "{sv}",
					"IPAddress",
					wfd_manager_dbus_pack_ay(peers[i].ip_address, IPADDR_LEN));
			g_variant_builder_add(&builder_peer, "{sv}",
					"Channel",
					g_variant_new_uint16(peers[i].channel));
#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
			g_variant_builder_add(&builder_peer, "{sv}",
					"Services",
					g_variant_new_uint16(peers[i].services));
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */
			g_variant_builder_add(&builder_peer, "{sv}",
					"Category",
					g_variant_new_uint16(peers[i].category));
			g_variant_builder_add(&builder_peer, "{sv}",
					"SubCategory",
					g_variant_new_uint16(peers[i].subcategory));
			g_variant_builder_add(&builder_peer, "{sv}",
					"IsP2P",
					g_variant_new_boolean(peers[i].is_p2p));
#ifdef TIZEN_FEATURE_WIFI_DISPLAY
			g_variant_builder_add(&builder_peer, "{sv}",
					"IsWfdDevice",
					g_variant_new_boolean(peers[i].is_wfd_device));
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

			WDS_LOGD("%dth peer [%s]", i, peers[i].device_name);
			g_variant_builder_add_value(builder_peers, g_variant_builder_end(&builder_peer));
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(iaa{sv})", ret, builder_peers);
		g_variant_builder_unref(builder_peers);
		goto done;

	} else if (!g_strcmp0(method_name, "IsDiscoverable")) {
		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(b)",
						   (manager->state == WIFI_DIRECT_STATE_DISCOVERING ||
						    wfd_group_is_autonomous(manager->group) == TRUE));
		goto done;

	} else if (!g_strcmp0(method_name, "IsListeningOnly")) {
		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(b)", (manager->scan_mode == WFD_SCAN_MODE_PASSIVE));
		goto done;

	} else if (!g_strcmp0(method_name, "GetPeerInfo")) {
		wfd_discovery_entry_s *peer = NULL;
		GVariantBuilder *builder_peer = NULL;
		const char *peer_mac_address = NULL;
		unsigned char mac_addr[MACADDR_LEN] = {0, };

		g_variant_get(parameters, "(&s)", &peer_mac_address);
		macaddr_atoe(peer_mac_address, mac_addr);

		builder_peer = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));

		ret = wfd_manager_get_peer_info(manager, mac_addr, &peer);
		if (ret < 0 || !peer) {
			WDS_LOGE("Failed to get peer info");
			g_free(peer);
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		g_variant_builder_add(builder_peer, "{sv}",
				"DeviceName",
				g_variant_new_string(peer->device_name));
		g_variant_builder_add(builder_peer, "{sv}",
				"DeviceAddress",
				wfd_manager_dbus_pack_ay(peer->mac_address, MACADDR_LEN));
		g_variant_builder_add(builder_peer, "{sv}",
				"InterfaceAddress",
				wfd_manager_dbus_pack_ay(peer->intf_address, MACADDR_LEN));
		g_variant_builder_add(builder_peer, "{sv}",
				"Channel",
				g_variant_new_uint16(peer->channel));
#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
		g_variant_builder_add(builder_peer, "{sv}",
				"Services",
				g_variant_new_uint16(peer->services));
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */
		g_variant_builder_add(builder_peer, "{sv}",
				"IsGroupOwner",
				g_variant_new_boolean(peer->is_group_owner));
		g_variant_builder_add(builder_peer, "{sv}",
				"IsPersistentGO",
				g_variant_new_boolean(peer->is_persistent_go));
		g_variant_builder_add(builder_peer, "{sv}",
				"IsConnected",
				g_variant_new_boolean(peer->is_connected));
		g_variant_builder_add(builder_peer, "{sv}",
				"WpsDevicePwdID",
				g_variant_new_uint16(peer->wps_device_pwd_id));
		g_variant_builder_add(builder_peer, "{sv}",
				"WpsCfgMethods",
				g_variant_new_uint16(peer->wps_cfg_methods));
		g_variant_builder_add(builder_peer, "{sv}",
				"Category",
				g_variant_new_uint16(peer->category));
		g_variant_builder_add(builder_peer, "{sv}",
				"SubCategory",
				g_variant_new_uint16(peer->subcategory));
#ifdef TIZEN_FEATURE_WIFI_DISPLAY
		g_variant_builder_add(builder_peer, "{sv}",
				"IsWfdDevice",
				g_variant_new_boolean(peer->is_wfd_device));
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(ia{sv})", ret, builder_peer);
		g_variant_builder_unref(builder_peer);
		g_free(peer);
		goto done;

	} else if (!g_strcmp0(method_name, "GetState")) {
		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(ii)", ret, manager->state);
		goto done;

	} else {
		WDS_LOGD("method not handled");
		ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
		goto failed;
	}

done:
	WFD_DBUS_REPLY_PARAMS(invocation, return_parameters);
	return;

failed:

//g_dbus_method_invocation_return_dbus_error(invocation, WFD_MANAGER_SERVICE ".Error", ".OperationFailed");

	wfd_error_set_gerror(ret, &err);
	dbus_error_name = g_dbus_error_encode_gerror(err);
	WDS_LOGD("g_dbus_method_invocation_return_gerror with [%s]", dbus_error_name);
	g_free(dbus_error_name);
	g_dbus_method_invocation_return_gerror(invocation, err);
	g_clear_error(&err);
	return;
}

static void __wfd_manager_group_iface_handler(const gchar *method_name,
					     GVariant    *parameters,
					     GDBusMethodInvocation *invocation)
{
	int ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
	wfd_manager_s *manager = wfd_get_manager();
	GVariant *return_parameters = NULL;
	GError *err = NULL;
	WDS_LOGD("%s", method_name);

	if (!g_strcmp0(method_name, "CreateGroup")) {
		wfd_group_s *group = manager->group;
		wfd_oem_group_param_s param;

		if (group || manager->state < WIFI_DIRECT_STATE_ACTIVATED) {
			WDS_LOGE("Group already exist or not a proper state");
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

#ifdef TIZEN_WLAN_BOARD_SPRD
		group = wfd_create_pending_group(manager, manager->local->dev_addr);
#else
		group = wfd_create_pending_group(manager, manager->local->intf_addr);
#endif
		if (!group) {
			WDS_LOGE("Failed to create pending group");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}
		group->flags |= WFD_GROUP_FLAG_AUTONOMOUS;
		manager->group = group;

		memset(&param, 0x0, sizeof(param));

		param.persistent = (manager->local->group_flags &
					WFD_GROUP_FLAG_PERSISTENT);
		memcpy(&(param.passphrase), manager->local->passphrase,
					sizeof(param.passphrase));

#ifndef TIZEN_WLAN_BOARD_SPRD
		param.freq = WFD_FREQ_2G;
#endif

		ret = wfd_oem_create_group(manager->oem_ops, &param);
		if (ret < 0) {
			WDS_LOGE("Failed to create group");
			wfd_destroy_group(manager, GROUP_IFNAME);
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		WDS_LOGD("Succeeded to create pending group");
		memset(manager->local->passphrase, 0x0, PASSPHRASE_LEN_MAX + 1);
		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(i)", ret);
		goto done;

	} else if (!g_strcmp0(method_name, "DestroyGroup")) {
		wfd_group_s *group = manager->group;
		if (!group && manager->state < WIFI_DIRECT_STATE_CONNECTED) {
			WDS_LOGE("Group not exist");
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		ret = wfd_oem_destroy_group(manager->oem_ops, group->ifname);
		if (ret < 0) {
			WDS_LOGE("Failed to destroy group");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		ret = wfd_destroy_group(manager, group->ifname);
		if (ret < 0)
			WDS_LOGE("Failed to destroy group");

		wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);

		WFD_DBUS_REPLY_ERROR_NONE(invocation);

		wfd_manager_dbus_emit_signal(WFD_MANAGER_GROUP_INTERFACE,
				"Destroyed", NULL);
		return;

	} else if (!g_strcmp0(method_name, "IsGroupOwner")) {
		gboolean result;
		wfd_device_s *local = manager->local;
		result = local->dev_role == WFD_DEV_ROLE_GO;
		WDS_LOGI("Is group owner : [%s]", result ? "Yes" : "No");
		return_parameters = g_variant_new("(b)", result);
		goto done;

	} else if (!g_strcmp0(method_name, "IsAutoGroup")) {
		int result;
		if ((result = wfd_group_is_autonomous(manager->group)) < 0)
			result = 0;

		WDS_LOGI("Is autonomous group : [%s]", result ? "Yes" : "No");
		return_parameters = g_variant_new("(b)", result);
		goto done;

	} else if (!g_strcmp0(method_name, "ActivatePushButton")) {
		if (manager->local->dev_role != WFD_DEV_ROLE_GO) {
			WDS_LOGE("Wi-Fi Direct is not Group Owner.");
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		ret = wfd_oem_wps_start(manager->oem_ops, NULL,
				WFD_WPS_MODE_PBC, NULL);
		if (ret < 0) {
			WDS_LOGE("Failed to start wps");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}
		return_parameters = g_variant_new("(i)", ret);
		goto done;

	} else if (!g_strcmp0(method_name, "GetPersistentGroups")) {
		int persistent_group_count = 0;
		wfd_persistent_group_info_s *plist;
		GVariantBuilder *builder_groups = NULL;
		int i = 0;

		if (manager->state < WIFI_DIRECT_STATE_ACTIVATED) {
			WDS_LOGE("Wi-Fi Direct is not activated.");
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}


		ret = wfd_oem_get_persistent_groups(manager->oem_ops,
				(wfd_oem_persistent_group_s**) &plist, &persistent_group_count);
		if (ret < 0) {
			WDS_LOGE("Error!! wfd_oem_get_persistent_group_info() failed..");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		builder_groups = g_variant_builder_new(G_VARIANT_TYPE("aa{sv}"));

		for (i = 0; i < persistent_group_count; i++) {
			GVariantBuilder builder_group;
			g_variant_builder_init(&builder_group, G_VARIANT_TYPE("a{sv}"));

			g_variant_builder_add(&builder_group, "{sv}",
					"NetworkID",
					g_variant_new_uint32(plist[i].network_id));
			g_variant_builder_add(&builder_group, "{sv}",
					"SSID",
					g_variant_new_string(plist[i].ssid));
			g_variant_builder_add(&builder_group, "{sv}",
					"GOMacAddress",
					wfd_manager_dbus_pack_ay(plist[i].go_mac_address, MACADDR_LEN));

			WDS_LOGD("%dth peer [%s]", i, plist[i].ssid);
			g_variant_builder_add_value(builder_groups, g_variant_builder_end(&builder_group));
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(iaa{sv})", ret, builder_groups);
		g_variant_builder_unref(builder_groups);
		goto done;

	} else if (!g_strcmp0(method_name, "RemovePersistentGroup")) {
		gchar *ssid;
		gchar *mac_address;
		unsigned char go_mac_address[6];
		if (manager->state < WIFI_DIRECT_STATE_ACTIVATED) {
			WDS_LOGE("Wi-Fi Direct is not activated.");
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		g_variant_get(parameters, "(&s&s)", &mac_address, &ssid);
		macaddr_atoe(mac_address, go_mac_address);
		WDS_LOGD("Remove persistent group [%s][" MACSTR "]", ssid, MAC2STR(go_mac_address));

		ret = wfd_oem_remove_persistent_group(manager->oem_ops, ssid,
				go_mac_address);
		if (ret < 0) {
			WDS_LOGE("Failed to remove persistent group");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}
		return_parameters = g_variant_new("(i)", ret);
		goto done;

	} else if (!g_strcmp0(method_name, "SetPassphrase")) {
		gchar *passphrase;
		int passphrase_len = 0;
		wfd_group_s *group = manager->group;

		if (group) {
			WDS_LOGE("Group already exists");
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		g_variant_get(parameters, "(&s)", &passphrase);
		passphrase_len = strlen(passphrase);

		if (passphrase_len < PASSPHRASE_LEN_MIN ||
				passphrase_len > PASSPHRASE_LEN_MAX) {
			WDS_LOGE("Passphrase length incorrect [%s]:[%d]",
					passphrase, passphrase_len);
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		g_strlcpy(manager->local->passphrase, passphrase, PASSPHRASE_LEN_MAX + 1);
		WDS_LOGI("Passphrase string [%s]", manager->local->passphrase);

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(i)", ret);
		goto done;

	} else if (!g_strcmp0(method_name, "GetPassphrase")) {
		wfd_group_s *group = manager->group;
		if (!group) {
			WDS_LOGE("Group not exist");
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		if (group->role == WFD_DEV_ROLE_GC) {
			WDS_LOGE("Device is not GO");
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(is)", ret, group->passphrase);
		WDS_LOGI("group->pass : [%s]", group->passphrase);
		goto done;


	} else if (!g_strcmp0(method_name, "SetPersistentGroupEnabled")) {
		gboolean enabled;

		g_variant_get(parameters, "(b)", &enabled);
		WDS_LOGI("Activate Persistent Group : [%s]",
				enabled ? "True" : "False");
		if (enabled)
			manager->local->group_flags |= WFD_GROUP_FLAG_PERSISTENT;
		else
			manager->local->group_flags &= ~(WFD_GROUP_FLAG_PERSISTENT);
		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(i)", ret);
		goto done;

	} else if (!g_strcmp0(method_name, "IsPersistentGroupEnabled")) {
		gboolean result;
		result = ((manager->local->group_flags &
					WFD_GROUP_FLAG_PERSISTENT)
				== WFD_GROUP_FLAG_PERSISTENT);
		WDS_LOGI("Is persistent group : [%s]", result ? "Yes" : "No");
		return_parameters = g_variant_new("(b)", result);
		goto done;

	} else {
		ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
		goto failed;
	}

done:
	WFD_DBUS_REPLY_PARAMS(invocation, return_parameters);
	return;

failed:
	wfd_error_set_gerror(ret, &err);
	g_dbus_method_invocation_return_gerror(invocation, err);
	g_clear_error(&err);
	return;
}

static void __wfd_manager_config_iface_handler(const gchar *method_name,
					      GVariant    *parameters,
					      GDBusMethodInvocation *invocation)
{
	int ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
	wfd_manager_s *manager = wfd_get_manager();
	GVariant *return_parameters = NULL;
	GError *err = NULL;
	WDS_LOGD("%s", method_name);

	if (!g_strcmp0(method_name, "GetDeviceName")) {
		char device_name[WIFI_DIRECT_MAX_DEVICE_NAME_LEN+1] = {0, };

		ret = wfd_local_get_dev_name(device_name);
		if (ret < 0) {
			WDS_LOGE("Failed to get device name");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		} else {

			ret = WIFI_DIRECT_ERROR_NONE;
			return_parameters = g_variant_new("(is)", ret, device_name);
		}
		goto done;

	} else if (!g_strcmp0(method_name, "SetDeviceName")) {
		const char *device_name = NULL;
		g_variant_get(parameters, "(&s)", &device_name);

		ret = wfd_local_set_dev_name((char *)device_name);
		if (ret < 0) {
			WDS_LOGE("Failed to set device name");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(i)", ret);
		goto done;

	} else if (!g_strcmp0(method_name, "GetWpsPin")) {
		wfd_session_s *session = (wfd_session_s*) manager->session;
		if (!session || manager->auto_pin[0] != 0) {
			WDS_LOGE("Session not exist");
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		if (session->wps_pin[0] == '\0') {
			WDS_LOGE("WPS PIN is not set");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(is)", ret, session->wps_pin);
		goto done;

	} else if (!g_strcmp0(method_name, "SetWpsPin")) {
		const char *pin = NULL;
		wfd_session_s *session = (wfd_session_s*) manager->session;

		g_variant_get(parameters, "(&s)", &pin);

		if (!session) {
			WDS_LOGE("Session not exist");
			g_strlcpy(manager->auto_pin, pin, strlen(pin) + 1);
		} else {
			g_strlcpy(session->wps_pin, pin, strlen(pin) + 1);
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(i)", ret);
		goto done;

	} else if (!g_strcmp0(method_name, "GetSupportedWpsMode")) {
		int config_methods = 0;

		ret = wfd_local_get_supported_wps_mode(&config_methods);
		if (ret < 0) {
			WDS_LOGE("Failed to get supported wps mode");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(ii)", ret, config_methods);
		goto done;

	} else if (!g_strcmp0(method_name, "GetReqWpsMode")) {
		int wps_mode = 0;

		ret = wfd_manager_get_req_wps_mode(&wps_mode);
		if (ret < 0) {
			WDS_LOGE("Failed to get request wps mode");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(ii)", ret, wps_mode);
		goto done;

	} else if (!g_strcmp0(method_name, "SetReqWpsMode")) {
		int type = 0;

		g_variant_get(parameters, "(i)", &type);
		ret = wfd_manager_set_req_wps_mode(type);
		if(ret < 0) {
			WDS_LOGE("Failed to set request wps mode");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(i)", ret);
		goto done;

	} else if (!g_strcmp0(method_name, "GetLocalWpsMode")) {
		int wps_mode = 0;

		ret = wfd_local_get_wps_mode(&wps_mode);
		if (ret < 0) {
			WDS_LOGE("Failed to get request wps mode");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(ii)", ret, wps_mode);
		goto done;

	} else if (!g_strcmp0(method_name, "GetIPAddress")) {
		char ip_addr_str[IPSTR_LEN+1] = {0, };

		if (manager->state < WIFI_DIRECT_STATE_CONNECTED) {
			WDS_LOGE("Device is not connected yet");
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		ret = wfd_local_get_ip_addr((char *)ip_addr_str);
		if (ret < 0) {
			WDS_LOGE("Failed to get local IP address");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		return_parameters = g_variant_new("(is)", ret, ip_addr_str);
		WDS_LOGI("IP addr : [%s]", ip_addr_str);
		goto done;

	} else if (!g_strcmp0(method_name, "GetMacAddress")) {
		char device_mac[MACSTR_LEN+1] = {0, };

		ret = wfd_local_get_dev_mac(device_mac);
		if (ret < 0) {
			WDS_LOGE("Failed to get device mac");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(is)", ret, device_mac);
		goto done;

	} else if (!g_strcmp0(method_name, "GetGoIntent")) {
		int go_intent = 0;

		ret = wfd_manager_get_go_intent(&go_intent);
		if (ret < 0) {
			WDS_LOGE("Failed to get GO intent");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(ii)", ret, go_intent);
		goto done;

	} else if (!g_strcmp0(method_name, "SetGoIntent")) {
		int go_intent = 0;

		g_variant_get(parameters, "(i)", &go_intent);
		ret = wfd_manager_set_go_intent(go_intent);
		if(ret < 0) {
			WDS_LOGE("Failed to set GO intent");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(i)", ret);
		goto done;

	} else if (!g_strcmp0(method_name, "GetMaxClient")) {
		int max_client = 0;

		ret = wfd_manager_get_max_station(&max_client);
		if (ret < 0) {
			WDS_LOGE("Failed to get max station");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(ii)", ret, max_client);
		goto done;

	} else if (!g_strcmp0(method_name, "SetMaxClient")) {
		int max_client = 0;
		g_variant_get(parameters, "(i)", &max_client);

		ret = wfd_manager_set_max_station(max_client);
		if(ret < 0) {
			WDS_LOGE("Failed to set max station");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(i)", ret);
		goto done;

	} else if (!g_strcmp0(method_name, "SetAutoConnectionMode")) {
		gboolean mode = FALSE;

		g_variant_get(parameters, "(b)", &mode);
		ret = wfd_manager_set_autoconnection(mode);
		if(ret < 0) {
			WDS_LOGE("Failed to set autoconnection");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(i)", ret);
		goto done;

	} else if (!g_strcmp0(method_name, "IsAutoConnectionMode")) {
		int mode = 0;

		ret = wfd_manager_get_autoconnection(&mode);
		if (ret < 0) {
			WDS_LOGE("Failed to get autoconnection");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(ib)", ret, mode);
		goto done;

	} else if (!g_strcmp0(method_name, "GetOperatingChannel")) {
		int channel = 0;

		wfd_group_s *group = manager->group;
		if (!group) {
			WDS_LOGE("Group not exist");
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		channel = wfd_util_freq_to_channel(group->freq);
		if (channel < 0) {
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(ii)", ret, channel);
		goto done;

	} else if (!g_strcmp0(method_name, "SetAutoConnectionPeer")) {
		ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		goto failed;

	} else if (!g_strcmp0(method_name, "GetInterfaceName")) {
		wfd_group_s *group = (wfd_group_s *)manager->group;
		if (!group) {
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}
		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(is)", ret, group->ifname);
		goto done;

	} else if (!g_strcmp0(method_name, "GetSubnetMask")) {
			char *get_str = NULL;
			char subnet_mask[IPSTR_LEN+1] = {0, };

			get_str = vconf_get_str(VCONFKEY_SUBNET_MASK);
			if (!get_str) {
				WDS_LOGE("Get Subnet Mask failed");
				ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
				goto failed;
			}
			WDS_LOGD("VCONFKEY_SUBNET_MASK(%s) : %s", VCONFKEY_SUBNET_MASK,
				get_str);
			ret = WIFI_DIRECT_ERROR_NONE;
			g_strlcpy(subnet_mask, get_str, IPSTR_LEN + 1);
			return_parameters = g_variant_new("(is)", ret, subnet_mask);
			free(get_str);
			goto done;

	} else if (!g_strcmp0(method_name, "GetGateway")) {
			char *get_str = NULL;
			char gateway_addr[IPSTR_LEN+1] = {0, };
			get_str = vconf_get_str(VCONFKEY_GATEWAY);
			if (!get_str) {
				WDS_LOGE("Get Gateway failed");
				ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
				goto failed;
			}
			WDS_LOGD("VCONFKEY_GATEWAY_ADDR(%s) : %s", VCONFKEY_GATEWAY,
				get_str);
			ret = WIFI_DIRECT_ERROR_NONE;
			g_strlcpy(gateway_addr, get_str, IPSTR_LEN + 1);
			return_parameters = g_variant_new("(is)", ret, gateway_addr);
			free(get_str);
			goto done;

	} else if (!g_strcmp0(method_name, "GetSessionTimer")) {

		int session_timer = 0;
		ret = WIFI_DIRECT_ERROR_NONE;
		session_timer = manager->session_timer;
		WDS_LOGD("Get Session Timer value is %d", session_timer);
		return_parameters = g_variant_new("(ii)", ret, session_timer);
		goto done;

	} else if (!g_strcmp0(method_name, "SetSessionTimer")) {

		int session_timer = 0;
		g_variant_get(parameters, "(i)", &session_timer);
		WDS_LOGD("Set Session Timer value is %d", session_timer);
		manager->session_timer = session_timer;
		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(i)", ret);
		goto done;

	} else if (!g_strcmp0(method_name, "SetAutoGroupRemoval")) {
		gboolean enable;


		g_variant_get(parameters, "(b)", &enable);
		WDS_LOGE("Activate Auto Group Removal Mode : [%s]",
				enable ? "True" : "False");

		if (manager->state < WIFI_DIRECT_STATE_ACTIVATED) {
			WDS_LOGE("Wi-Fi Direct is not activated.");
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		if (enable) {
			manager->auto_group_remove_enable = TRUE;

			/* Enable Group destroy only if state is connecting */
			if (manager->state == WIFI_DIRECT_STATE_CONNECTING) {
				WDS_LOGE("Wi-Fi Direct state is CONNECTING");
				ret = WIFI_DIRECT_ERROR_NONE;
				return_parameters = g_variant_new("(i)", ret);
				goto done;
			}
			/* Remove group immediately if no connected peer found */
			if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
				wfd_group_s *group = (wfd_group_s*) manager->group;
				if (group && !group->member_count && wfd_util_is_remove_group_allowed())
					wfd_oem_destroy_group(manager->oem_ops, group->ifname);
			  }

		} else
			manager->auto_group_remove_enable = FALSE;


		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(i)", ret);
		goto done;

	}  else {
		WDS_LOGE("method not handled");
		ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		goto failed;
	}

done:
	WFD_DBUS_REPLY_PARAMS(invocation, return_parameters);
	return;

failed:
	wfd_error_set_gerror(ret, &err);
	g_dbus_method_invocation_return_gerror(invocation, err);
	g_clear_error(&err);
	return;
}

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
static void __wfd_manager_service_iface_handler(const gchar *method_name,
					       GVariant    *parameters,
					       GDBusMethodInvocation *invocation)
{
	int ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
	wfd_manager_s *manager = wfd_get_manager();
	GVariant *return_parameters = NULL;
	GError *err = NULL;
	WDS_LOGD("%s", method_name);

	if (!g_strcmp0(method_name, "StartDiscovery")) {
		const char *mac_address = NULL;
		int service_type;
		unsigned char mac_addr[MACADDR_LEN] = {0, };

		if (manager->state < WIFI_DIRECT_STATE_ACTIVATED) {
			WDS_LOGE("Wi-Fi Direct is not activated.");
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		g_variant_get(parameters, "(i&s)", &service_type, &mac_address);
		WDS_LOGD("Service type [%d]", service_type);
		macaddr_atoe(mac_address, mac_addr);

		ret = wfd_oem_start_service_discovery(manager->oem_ops,
				mac_addr, service_type);
		if (ret < 0) {
			WDS_LOGE("Failed to start service discovery");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		WFD_DBUS_REPLY_ERROR_NONE(invocation);

		wfd_manager_dbus_emit_signal(WFD_MANAGER_SERVICE_INTERFACE,
				"DiscoveryStarted", NULL);
		return;

	} else if (!g_strcmp0(method_name, "StopDiscovery")) {
		const char *mac_address = NULL;
		int service_type;
		unsigned char mac_addr[MACADDR_LEN] = {0, };

		if (manager->state < WIFI_DIRECT_STATE_ACTIVATED) {
			WDS_LOGE("Wi-Fi Direct is not activated.");
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		g_variant_get(parameters, "(i&s)", &service_type, &mac_address);
		WDS_LOGD("Service type [%d]", service_type);
		macaddr_atoe(mac_address, mac_addr);

		ret = wfd_oem_cancel_service_discovery(manager->oem_ops,
				mac_addr, service_type);
		if (ret < 0) {
			WDS_LOGE("Failed to cancel service discovery");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}
		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(i)", ret);
		goto done;

	} else if (!g_strcmp0(method_name, "Register")) {
		int service_type;
		int service_id = 0;
		const char *info_str = NULL;

		if (manager->state < WIFI_DIRECT_STATE_ACTIVATED) {
			WDS_LOGE("Wi-Fi Direct is not activated.");
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		g_variant_get(parameters, "(i&s)", &service_type, &info_str);
		WDS_LOGD("Register service [%d: %s]", service_type, info_str);

		ret = wfd_service_add(service_type, (char *)info_str, &service_id);
		if (ret < 0) {
			WDS_LOGE("Failed to add service");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(ii)", ret, service_id);
		goto done;

	} else if (!g_strcmp0(method_name, "Deregister")) {
		int service_id = 0;

		if (manager->state < WIFI_DIRECT_STATE_ACTIVATED) {
			WDS_LOGE("Wi-Fi Direct is not activated.");
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		g_variant_get(parameters, "(i)", &service_id);
		WDS_LOGD("Service id [%d]", service_id);

		ret = wfd_service_del(service_id);
		if (ret < 0) {
			WDS_LOGE("Failed to delete service");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(i)", ret);
		goto done;

	} else {
		WDS_LOGD("method not handled");
		ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		goto failed;
	}

done:
	WFD_DBUS_REPLY_PARAMS(invocation, return_parameters);
	return;

failed:
	wfd_error_set_gerror(ret, &err);
	g_dbus_method_invocation_return_gerror(invocation, err);
	g_clear_error(&err);
	return;
}
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

#ifdef TIZEN_FEATURE_WIFI_DISPLAY
static void __wfd_manager_display_iface_handler(const gchar *method_name,
					       GVariant    *parameters,
					       GDBusMethodInvocation *invocation)
{
	int ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
	wfd_manager_s *manager = wfd_get_manager();
	GVariant *return_parameters = NULL;
	GError *err = NULL;
	WDS_LOGD("%s", method_name);

	if (!g_strcmp0(method_name, "Init")) {
		if (manager->state < WIFI_DIRECT_STATE_ACTIVATED) {
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		wfd_device_s * device = manager->local;

		ret = wfd_oem_miracast_init(manager->oem_ops, TRUE);
		if (ret < 0) {
			WDS_LOGE("Failed to initialize display");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		device->display.type = WIFI_DISPLAY_DEFAULT_TYPE;
		device->display.port = WIFI_DISPLAY_DEFAULT_PORT;
		device->display.availability = WIFI_DISPLAY_DEFAULT_AVAIL;
		device->display.hdcp_support = WIFI_DISPLAY_DEFAULT_HDCP;

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(i)", ret);
		goto done;

	} else if (!g_strcmp0(method_name, "Deinit")) {
		if (manager->state < WIFI_DIRECT_STATE_ACTIVATED) {
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		wfd_device_s * device = manager->local;

		ret = wfd_oem_miracast_init(manager->oem_ops, FALSE);
		if (ret < 0) {
			WDS_LOGE("Failed to deinitialize display");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		memset(&(device->display), 0x0, sizeof(wfd_display_type_e));

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(i)", ret);
		goto done;

	} else if (!g_strcmp0(method_name, "SetConfig")) {
		int type, port, hdcp;
		g_variant_get(parameters, "(iii)", &type, &port, &hdcp);

		if (manager->state < WIFI_DIRECT_STATE_ACTIVATED) {
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		WDS_LOGD("type %d port %d hdcp %d", type, port, hdcp);

		ret = wfd_manager_set_display_device(type, port, hdcp);
		if(ret < 0) {
			WDS_LOGE("Failed to set display device settings");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(i)", ret);
		goto done;

	} else if (!g_strcmp0(method_name, "SetAvailiability")) {
		int availability;
		g_variant_get(parameters, "(i)", &availability);

		if(manager->state < WIFI_DIRECT_STATE_ACTIVATED) {
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		ret = wfd_manager_set_session_availability(availability);
		if (ret < 0) {
			WDS_LOGE("Failed to set session availability");
			ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			goto failed;
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(i)", ret);
		goto done;

	} else if (!g_strcmp0(method_name, "GetPeerType")) {
		wfd_device_s *peer = NULL;
		const char *mac_address = NULL;
		unsigned char mac_addr[MACADDR_LEN] = {0, };

		g_variant_get(parameters, "(&s)", &mac_address);
		macaddr_atoe(mac_address, mac_addr);

		if(manager->state < WIFI_DIRECT_STATE_ACTIVATED) {
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		peer = wfd_manager_get_peer_by_addr(manager, mac_addr);
		if(!peer) {
			WDS_LOGE("Failed to get peer");
			ret = WIFI_DIRECT_ERROR_INVALID_PARAMETER;
			goto failed;
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(ii)", ret, peer->display.type);
		goto done;

	} else if (!g_strcmp0(method_name, "GetPeerAvailability")) {
		wfd_device_s *peer = NULL;
		const char *mac_address = NULL;
		unsigned char mac_addr[MACADDR_LEN] = {0, };

		g_variant_get(parameters, "(&s)", &mac_address);
		macaddr_atoe(mac_address, mac_addr);

		if(manager->state < WIFI_DIRECT_STATE_ACTIVATED) {
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		peer = wfd_manager_get_peer_by_addr(manager, mac_addr);
		if(!peer) {
			WDS_LOGE("Failed to get peer");
			ret = WIFI_DIRECT_ERROR_INVALID_PARAMETER;
			goto failed;
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(ii)", ret, peer->display.availability);
		goto done;

	} else if (!g_strcmp0(method_name, "GetPeerHdcp")) {
		wfd_device_s *peer = NULL;
		const char *mac_address = NULL;
		unsigned char mac_addr[MACADDR_LEN] = {0, };

		g_variant_get(parameters, "(&s)", &mac_address);
		macaddr_atoe(mac_address, mac_addr);

		if(manager->state < WIFI_DIRECT_STATE_ACTIVATED) {
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		peer = wfd_manager_get_peer_by_addr(manager, mac_addr);
		if(!peer) {
			WDS_LOGE("Failed to get peer");
			ret = WIFI_DIRECT_ERROR_INVALID_PARAMETER;
			goto failed;
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(ii)", ret, peer->display.hdcp_support);
		goto done;

	} else if (!g_strcmp0(method_name, "GetPeerPort")) {
		wfd_device_s *peer = NULL;
		const char *mac_address = NULL;
		unsigned char mac_addr[MACADDR_LEN] = {0, };

		g_variant_get(parameters, "(&s)", &mac_address);
		macaddr_atoe(mac_address, mac_addr);

		if(manager->state < WIFI_DIRECT_STATE_ACTIVATED) {
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		peer = wfd_manager_get_peer_by_addr(manager, mac_addr);
		if(!peer) {
			WDS_LOGE("Failed to get peer");
			ret = WIFI_DIRECT_ERROR_INVALID_PARAMETER;
			goto failed;
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(ii)", ret, peer->display.port);
		goto done;

	} else if (!g_strcmp0(method_name, "GetPeerThroughput")) {
		wfd_device_s *peer = NULL;
		const char *mac_address = NULL;
		unsigned char mac_addr[MACADDR_LEN] = {0, };

		g_variant_get(parameters, "(&s)", &mac_address);
		macaddr_atoe(mac_address, mac_addr);

		if(manager->state < WIFI_DIRECT_STATE_ACTIVATED) {
			ret = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			goto failed;
		}

		peer = wfd_manager_get_peer_by_addr(manager, mac_addr);
		if(!peer) {
			WDS_LOGE("Failed to get peer");
			ret = WIFI_DIRECT_ERROR_INVALID_PARAMETER;
			goto failed;
		}

		ret = WIFI_DIRECT_ERROR_NONE;
		return_parameters = g_variant_new("(ii)", ret, peer->display.max_tput);
		goto done;

	} else {
		WDS_LOGD("method not handled");
		ret = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		goto failed;
	}

done:
	WFD_DBUS_REPLY_PARAMS(invocation, return_parameters);
	return;

failed:
	wfd_error_set_gerror(ret, &err);
	g_dbus_method_invocation_return_gerror(invocation, err);
	g_clear_error(&err);
	return;
}
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

static struct {
	guint reg_id;
	const gchar *iface_name;
        void (*function) (const gchar *method_name,
			 GVariant    *parameters,
			 GDBusMethodInvocation *invocation);
} wfd_manager_iface_map[] = {
	{
		0,
		WFD_MANAGER_MANAGE_INTERFACE,
		__wfd_manager_manage_iface_handler
	},
	{
		0,
		WFD_MANAGER_GROUP_INTERFACE,
		__wfd_manager_group_iface_handler
	},
	{
		0,
		WFD_MANAGER_CONFIG_INTERFACE,
		__wfd_manager_config_iface_handler
	},
#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
	{
		0,
		WFD_MANAGER_SERVICE_INTERFACE,
		__wfd_manager_service_iface_handler
	},
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */
#ifdef TIZEN_FEATURE_WIFI_DISPLAY
	{
		0,
		WFD_MANAGER_DISPLAY_INTERFACE,
		__wfd_manager_display_iface_handler
	},
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */
	{
		0,
		NULL,
		NULL
	}
};

// GDBus method handler
static void wfd_manager_method_call_handler (GDBusConnection       *connection,
					     const gchar           *sender,
					     const gchar           *object_path,
					     const gchar           *interface_name,
					     const gchar           *method_name,
					     GVariant              *parameters,
					     GDBusMethodInvocation *invocation,
					     gpointer               user_data)
{
	int count = 0;

	/* Method Call */
	WDS_LOGD("interface : [%s], method : [%s]", interface_name, method_name);
	DBUS_DEBUG_VARIANT(parameters);

	while (wfd_manager_iface_map[count].iface_name != NULL) {
		if (!g_strcmp0(interface_name, wfd_manager_iface_map[count].iface_name)) {

			wfd_manager_iface_map[count].function(method_name,
							      parameters,
							      invocation);
			break;
		}
		count++;
	}
}

static const GDBusInterfaceVTable wfd_manager_interface_vtable =
				{wfd_manager_method_call_handler, NULL, NULL};

void wfd_manager_dbus_unregister(void)
{
	int count = 0;

	wfd_error_deregister();

	while (wfd_manager_iface_map[count].iface_name != NULL) {
		wfd_manager_dbus_iface_unregister(wfd_manager_iface_map[count].reg_id);
		count++;
	}
}

gboolean wfd_manager_dbus_register(void)
{
	GDBusNodeInfo *node_info = NULL;
	GError *Error = NULL;
	int count = 0;

	wfd_error_register();

	node_info = g_dbus_node_info_new_for_xml(wfd_manager_introspection_xml, &Error);
	if (node_info == NULL) {
		WDS_LOGE("Failed to get node info, Error: %s", Error->message);
		g_clear_error(&Error);
		return FALSE;
	}

	while (wfd_manager_iface_map[count].iface_name != NULL) {
		wfd_manager_iface_map[count].reg_id =
			wfd_manager_dbus_iface_register(wfd_manager_iface_map[count].iface_name,
							WFD_MANAGER_PATH,
							node_info,
							&wfd_manager_interface_vtable);

		WDS_LOGD("Registered Interface [%d, %s]",
					wfd_manager_iface_map[count].reg_id,
					wfd_manager_iface_map[count].iface_name);

		count++;
	}

	g_dbus_node_info_unref(node_info);
	return TRUE;
}
