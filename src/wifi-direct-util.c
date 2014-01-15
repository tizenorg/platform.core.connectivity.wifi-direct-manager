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
 * This file implements wifi direct utility functions.
 *
 * @file		wifi-direct-util.c
 * @author	Gibyoung Kim (lastkgb.kim@samsung.com)
 * @version	0.7
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>

#include <glib.h>

#include <vconf.h>
#include <app_service.h>
#include <wifi-direct.h>
#include <wifi-direct-internal.h>

#include "wifi-direct-manager.h"
#include "wifi-direct-state.h"
#include "wifi-direct-event.h"
#include "wifi-direct-util.h"

static int _txt_to_mac(char *txt, unsigned char *mac)
{
	int i = 0;

	for (;;) {
		mac[i++] = (char) strtoul(txt, &txt, 16);
		if (!*txt++ || i == 6)
			break;
	}

	if (i != MACADDR_LEN)
		return -1;

	WDS_LOGD("Converted MAC address [" MACSTR "]", MAC2STR(mac));
	return 0;
}

static int _txt_to_ip(char *txt, unsigned char *ip)
{
	int i = 0;

	for (;;) {
		ip[i++] = (char) strtoul(txt, &txt, 10);
		if (!*txt++ || i == 4)
			break;
	}

	if (i != 4)
		return -1;

	WDS_LOGD("Converted IP address [" IPSTR "]", IP2STR(ip));
	return 0;
}

int wfd_util_freq_to_channel(int freq)
{
	if (freq < 2412 || freq > 5825) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	if (freq >= 5180)
		return 36 + (freq - 5180)/5;
	else if (freq <= 2472)
		return 1 + (freq - 2412)/5;
	else if (freq == 2484)
		return 14;
	else
		return -1;
}

int wfd_util_get_phone_name(char *phone_name)
{
	__WDS_LOG_FUNC_ENTER__;
	char *name = NULL;

	name = vconf_get_str(VCONFKEY_SETAPPL_DEVICE_NAME_STR);
	if (!name) {
		WDS_LOGE( "Failed to get vconf value for %s", VCONFKEY_SETAPPL_DEVICE_NAME_STR);
		return -1;
	}
	strncpy(phone_name, name, DEV_NAME_LEN);
	phone_name[DEV_NAME_LEN] = '\0';

	WDS_LOGD( "[%s: %s]", VCONFKEY_SETAPPL_DEVICE_NAME_STR, phone_name);
	free(name);
	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

void _wfd_util_dev_name_changed_cb(keynode_t *key, void* data)
{
	__WDS_LOG_FUNC_ENTER__;
	char dev_name[DEV_NAME_LEN] = {0, };
	int res = 0;

	res = wfd_util_get_phone_name(dev_name);
	if (res < 0) {
		WDS_LOGE("Failed to get phone name(vconf)");
		return;
	}
	WDS_LOGD("Device name changed as [%s]", dev_name);

	res = wfd_local_set_dev_name(dev_name);
	if (res < 0)
		WDS_LOGE("Failed to set device name");
	__WDS_LOG_FUNC_EXIT__;
	return;
}

void wfd_util_set_dev_name_notification()
{
	__WDS_LOG_FUNC_ENTER__;

	vconf_notify_key_changed(VCONFKEY_SETAPPL_DEVICE_NAME_STR, _wfd_util_dev_name_changed_cb, NULL);

	__WDS_LOG_FUNC_EXIT__;
	return;
}

void wfd_util_unset_dev_name_notification()
{
	__WDS_LOG_FUNC_ENTER__;

	vconf_ignore_key_changed(VCONFKEY_SETAPPL_DEVICE_NAME_STR, _wfd_util_dev_name_changed_cb);

	__WDS_LOG_FUNC_EXIT__;
	return;
}

int wfd_util_check_wifi_state()
{
	__WDS_LOG_FUNC_ENTER__;
	int wifi_state = 0;
	int res = 0;

	/* vconf key and value (vconf-keys.h)
#define VCONFKEY_WIFI_STATE "memory/wifi/state"
enum {
        VCONFKEY_WIFI_OFF = 0x00,
        VCONFKEY_WIFI_UNCONNECTED,
        VCONFKEY_WIFI_CONNECTED,
        VCONFKEY_WIFI_TRANSFER,
        VCONFKEY_WIFI_STATE_MAX
};
	 */

	res = vconf_get_int(VCONFKEY_WIFI_STATE, &wifi_state);
	if (res < 0) {
		WDS_LOGE("Failed to get vconf value [%s]", VCONFKEY_WIFI_STATE);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}
	WDS_LOGD("[%s: %d]", VCONFKEY_WIFI_STATE, wifi_state);

	if (wifi_state > VCONFKEY_WIFI_OFF) {
		WDS_LOGD("Wi-Fi is on");
		__WDS_LOG_FUNC_EXIT__;
		return 1;
	}
	WDS_LOGD( "OK. Wi-Fi is off\n");

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_util_check_mobile_ap_state()
{
	__WDS_LOG_FUNC_ENTER__;
	int mobile_ap_state = 0;
	int res = 0;

	res = vconf_get_int(VCONFKEY_MOBILE_HOTSPOT_MODE, &mobile_ap_state);
	if (res < 0) {
		WDS_LOGE("Failed to get vconf value[%s]", VCONFKEY_MOBILE_HOTSPOT_MODE);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}
	WDS_LOGD("[%s: %d]", VCONFKEY_MOBILE_HOTSPOT_MODE, mobile_ap_state);

	if (mobile_ap_state != VCONFKEY_MOBILE_HOTSPOT_MODE_NONE) {
		WDS_LOGD("Mobile AP is on");
		__WDS_LOG_FUNC_EXIT__;
		return 1;
	}
	WDS_LOGD( "OK. Mobile AP is off\n");

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_util_wifi_direct_activatable()
{
	__WDS_LOG_FUNC_ENTER__;
	int res = 0;

	res = wfd_util_check_wifi_state();
	if (res < 0) {
		WDS_LOGE("Failed to check Wi-Fi state");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	} else if (res > 0) {
		WDS_LOGE("Wi-Fi is On");
		return WIFI_DIRECT_ERROR_WIFI_USED;
	} else {
		WDS_LOGE("Wi-Fi is Off");
		return WIFI_DIRECT_ERROR_NONE;
	}

	res = wfd_util_check_mobile_ap_state();
	if (res < 0) {
		WDS_LOGE("Failed to check Mobile AP state");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	} else if (res > 0) {
		WDS_LOGE("Mobile AP is On");
		return WIFI_DIRECT_ERROR_MOBILE_AP_USED;
	} else {
		WDS_LOGE("Mobile AP is Off");
		return WIFI_DIRECT_ERROR_NONE;
	}
}

int wfd_util_get_wifi_direct_state()
{
	__WDS_LOG_FUNC_ENTER__;
	int state = 0;
	int res = 0;

	res = vconf_get_int(VCONFKEY_WIFI_DIRECT_STATE, &state);
	if (res < 0) {
		WDS_LOGE("Failed to get vconf value [%s]\n", VCONFKEY_WIFI_DIRECT_STATE);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	__WDS_LOG_FUNC_EXIT__;
	return state;
}

int wfd_util_set_wifi_direct_state(int state)
{
	__WDS_LOG_FUNC_ENTER__;
	int vconf_state = 0;
	int res = 0;

	// TODO: check validity of state

	if (state == WIFI_DIRECT_STATE_ACTIVATED)
		vconf_state = VCONFKEY_WIFI_DIRECT_ACTIVATED;
	else if (state == WIFI_DIRECT_STATE_DEACTIVATED)
		vconf_state= VCONFKEY_WIFI_DIRECT_DEACTIVATED;
	else if (state == WIFI_DIRECT_STATE_CONNECTED)
		vconf_state = VCONFKEY_WIFI_DIRECT_CONNECTED;
	else if (state == WIFI_DIRECT_STATE_GROUP_OWNER)
		vconf_state = VCONFKEY_WIFI_DIRECT_GROUP_OWNER;
	else if (state == WIFI_DIRECT_STATE_DISCOVERING)
		vconf_state = VCONFKEY_WIFI_DIRECT_DISCOVERING;
	WDS_LOGD("Vconf key set [%s: %d]", VCONFKEY_WIFI_DIRECT_STATE, vconf_state);

	res = vconf_set_int(VCONFKEY_WIFI_DIRECT_STATE, vconf_state);
	if (res < 0) {
		WDS_LOGE("Failed to set vconf [%s]", VCONFKEY_WIFI_DIRECT_STATE);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_util_get_local_dev_mac(unsigned char *dev_mac)
{
	__WDS_LOG_FUNC_ENTER__;
	FILE *fd = NULL;
	char local_mac[MACSTR_LEN] = {0, };
	char *ptr = NULL;
	int res = 0;

	errno = 0;
	fd = fopen(DEFAULT_MAC_FILE_PATH, "r");
	if (!fd) {
		WDS_LOGE("Failed to open MAC info file (%s)", strerror(errno));
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	errno = 0;
	ptr = fgets(local_mac, MACSTR_LEN, fd);
	if (!ptr) {
		WDS_LOGE("Failed to read file or no data read(%s)", strerror(errno));
		fclose(fd);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}
	WDS_LOGD("Local MAC address [%s]", ptr);

	res = _txt_to_mac(local_mac, dev_mac);
	if (res < 0) {
		WDS_LOGE("Failed to convert text to MAC address");
		fclose(fd);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	dev_mac[0] |= 0x2;
	WDS_LOGD("Local Device MAC address [" MACSTR "]", MAC2STR(dev_mac));

	fclose(fd);
	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_util_start_wifi_direct_popup()
{
	__WDS_LOG_FUNC_ENTER__;

	service_h service;
	service_create(&service);
	service_set_operation(service, SERVICE_OPERATION_DEFAULT);
	service_set_package(service, "org.tizen.wifi-direct-popup");
	service_send_launch_request(service, NULL, NULL);
	service_destroy(service);
	WDS_LOGD("Succeeded to launch wifi-direct-popup");
	__WDS_LOG_FUNC_EXIT__;
	return 0;
}


static void _dhcps_ip_leased_cb(keynode_t *key, void* data)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = wfd_get_manager();
	wfd_device_s *peer = (wfd_device_s*) data;
	wifi_direct_client_noti_s noti;
	FILE *fp = NULL;
	char buf[MAX_DHCP_DUMP_SIZE];
	char ip_str[IPSTR_LEN];
	char intf_str[MACSTR_LEN];
	unsigned char intf_addr[MACADDR_LEN];
	int n = 0;

	if (!peer) {
		WDS_LOGD("Invalid parameter");
		return;
	}
	WDS_LOGD("DHCP server: IP leased");
	memset(&noti, 0, sizeof(wifi_direct_client_noti_s));

	errno = 0;
	fp = fopen(DHCP_DUMP_FILE, "r");
	if (NULL == fp) {
		WDS_LOGE("Could not read the file(%s). [%s]", DHCP_DUMP_FILE, strerror(errno));
		return;
	}

	while(fgets(buf, MAX_DHCP_DUMP_SIZE, fp) != NULL) {
		WDS_LOGD("Read line [%s]", buf);
		n = sscanf(buf,"%s %s", intf_str, ip_str);
		WDS_LOGD("ip=[%s], mac=[%s]",ip_str, intf_str);
		if (n != 2) {
			continue;
		}
		_txt_to_mac(intf_str, intf_addr);
		if (!memcmp(peer->intf_addr, intf_addr, MACADDR_LEN)) {
			WDS_LOGD("Peer intf mac found");
			_txt_to_ip(ip_str, peer->ip_addr);
			noti.event = WIFI_DIRECT_CLI_EVENT_IP_LEASED_IND;
			snprintf(noti.param1, MACSTR_LEN, MACSTR, MAC2STR(peer->dev_addr));
			snprintf(noti.param2, IPSTR_LEN, IPSTR, IP2STR(peer->ip_addr));
			wfd_event_notify_clients(manager, &noti);
			break;
		} else {
			WDS_LOGE("Different interface address peer[" MACSTR "] vs dhcp[" MACSTR "]", MAC2STR(peer->intf_addr), MAC2STR(intf_addr));
		}
	}
	fclose(fp);

	__WDS_LOG_FUNC_EXIT__;
	return;
}

static gboolean _polling_ip(gpointer user_data)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = wfd_get_manager();
	wfd_device_s *local = (wfd_device_s*) manager->local;
	wfd_device_s *peer = (wfd_device_s*) user_data;
	char *ifname = NULL;
	static int count = 0;
	int res = 0;

	if (count > 28) {
		WDS_LOGE("Failed to get IP");
		count = 0;
		__WDS_LOG_FUNC_EXIT__;
		return FALSE;
	}
	res = wfd_manager_get_goup_ifname(&ifname);
	if (res < 0 || !ifname) {
		WDS_LOGE("Failed to get group interface name");
		return FALSE;
	}

	res = wfd_util_dhcpc_get_ip(ifname, local->ip_addr, 0);
	if (res < 0) {
		WDS_LOGE("Failed to get local IP for interface %s(count=%d)", ifname, count++);
		__WDS_LOG_FUNC_EXIT__;
		return TRUE;
	}
	WDS_LOGD("Succeeded to get local(client) IP [" IPSTR "] for iface[%s]",
				    IP2STR(local->ip_addr), ifname);

	res = wfd_util_dhcpc_get_server_ip(peer->ip_addr);
	if (res < 0) {
		WDS_LOGE("Failed to get peer(server) IP(count=%d)", count++);
		__WDS_LOG_FUNC_EXIT__;
		return TRUE;
	}
	WDS_LOGD("Succeeded to get server IP [" IPSTR "]", IP2STR(peer->ip_addr));
	count = 0;

	wfd_state_set(manager, WIFI_DIRECT_STATE_CONNECTED);
	wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_CONNECTED);
	wifi_direct_client_noti_s noti;
	memset(&noti, 0x0, sizeof(wifi_direct_client_noti_s));
	noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP;
	noti.error = WIFI_DIRECT_ERROR_NONE;
	snprintf(noti.param1, MACSTR_LEN, MACSTR, MAC2STR(peer->dev_addr));
	wfd_event_notify_clients(manager, &noti);

	__WDS_LOG_FUNC_EXIT__;
	return FALSE;
}

int wfd_util_dhcps_start()
{
	__WDS_LOG_FUNC_ENTER__;
	int res = 0;

	vconf_set_int(VCONFKEY_DHCPS_IP_LEASE, 0);
	res = system("/usr/bin/wifi-direct-dhcp.sh server");
	WDS_LOGD("[/usr/bin/wifi-direct-dhcp.sh server] returns %d", res);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_util_dhcps_wait_ip_leased(wfd_device_s *peer)
{
	__WDS_LOG_FUNC_ENTER__;

	if (!peer) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	vconf_set_int(VCONFKEY_DHCPS_IP_LEASE, 0);
	vconf_notify_key_changed(VCONFKEY_DHCPS_IP_LEASE, _dhcps_ip_leased_cb, peer);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_util_dhcps_stop()
{
	__WDS_LOG_FUNC_ENTER__;
	int res = 0;

	vconf_ignore_key_changed(VCONFKEY_DHCPS_IP_LEASE, _dhcps_ip_leased_cb);
	vconf_set_int(VCONFKEY_DHCPS_IP_LEASE, 0);

	res = system("/usr/bin/wifi-direct-dhcp.sh stop");
	WDS_LOGD("[/usr/bin/wifi-direct-dhcp.sh stop] returns %d", res);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_util_dhcpc_start(wfd_device_s *peer)
{
	__WDS_LOG_FUNC_ENTER__;
	int res = 0;

	if (!peer) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	res = system("/usr/bin/wifi-direct-dhcp.sh client");
	WDS_LOGD("[/usr/bin/wifi-direct-dhcp.sh client] returns %d", res);
	g_timeout_add(250, (GSourceFunc) _polling_ip, peer);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_util_dhcpc_stop()
{
	__WDS_LOG_FUNC_ENTER__;
	int res = 0;

	res = system("/usr/bin/wifi-direct-dhcp.sh stop");
	WDS_LOGD("[/usr/bin/wifi-direct-dhcp.sh stop] returns %d", res);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_util_dhcpc_get_ip(char *ifname, unsigned char *ip_addr, int is_IPv6)
{
	__WDS_LOG_FUNC_ENTER__;
	struct ifreq ifr;
	struct sockaddr_in *sin = NULL;
	char *ip_str = NULL;
	int sock = -1;
	int res = -1;

	if (!ifname || !ip_addr) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	errno = 0;
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < SOCK_FD_MIN) {
		WDS_LOGE("Failed to create socket. [%s]", strerror(errno));
		if (sock >= 0)
			close(sock);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	ifr.ifr_addr.sa_family = AF_INET;
	memset(ifr.ifr_name, 0x00, 16);
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

	errno = 0;
	res = ioctl(sock, SIOCGIFADDR, &ifr);
	if (res < 0) {
		WDS_LOGE("Failed to get IP from socket. [%s]", strerror(errno));
		close(sock);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}
	close(sock);

	sin = (struct sockaddr_in*) &ifr.ifr_broadaddr;
	ip_str = inet_ntoa(sin->sin_addr);
	_txt_to_ip(ip_str, ip_addr);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_util_dhcpc_get_server_ip(unsigned char* ip_addr)
{
	__WDS_LOG_FUNC_ENTER__;
	char* get_str = NULL;
	int count = 0;

	if (!ip_addr) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	while(count < 10) {
		get_str = vconf_get_str(VCONFKEY_DHCPC_SERVER_IP);
		if (!get_str) {
			WDS_LOGE("Failed to get vconf value[%s]", VCONFKEY_DHCPC_SERVER_IP);
			__WDS_LOG_FUNC_EXIT__;
			return -1;
		}
		WDS_LOGD("VCONFKEY_DHCPC_SERVER_IP(%s) : %s\n", VCONFKEY_DHCPC_SERVER_IP, get_str);
		_txt_to_ip(get_str, ip_addr);
		if (*ip_addr)
			break;
		count++;
	}

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

