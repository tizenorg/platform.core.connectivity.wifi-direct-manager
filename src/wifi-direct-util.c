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
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#include <glib.h>

#include <vconf.h>
#include <tzplatform_config.h>
#if defined(TIZEN_FEATURE_DEFAULT_CONNECTION_AGENT)
#include <systemd/sd-login.h>
#include <aul.h>
#endif
#include <wifi-direct.h>

#include "wifi-direct-ipc.h"
#include "wifi-direct-manager.h"
#include "wifi-direct-state.h"
#include "wifi-direct-util.h"
#include "wifi-direct-oem.h"
#include "wifi-direct-group.h"
#include "wifi-direct-session.h"
#include "wifi-direct-error.h"
#include "wifi-direct-log.h"
#include "wifi-direct-dbus.h"

#include <linux/unistd.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/route/neighbour.h>

#define TIZEN_P2P_GO_IPADDR "192.168.49.1"
#define MAX_SIZE_ERROR_BUFFER 256

#if defined TIZEN_MOBILE
#define DEFAULT_MAC_FILE_PATH tzplatform_mkpath(TZ_SYS_ETC, ".mac.info")
#endif /* TIZEN_MOBILE */

#if defined TIZEN_TV
#	if defined TIZEN_WIFI_MODULE_BUNDLE
#		define DEFAULT_MAC_FILE_PATH "/sys/class/net/wlan0/address"
#	else /* TIZEN_WIFI_MODULE_BUNDLE */
#		define DEFAULT_MAC_FILE_PATH "/sys/class/net/p2p0/address"
#	endif /* TIZEN_WIFI_MODULE_BUNDLE */
#endif /* TIZEN_TV */

#ifndef DEFAULT_MAC_FILE_PATH
#	define DEFAULT_MAC_FILE_PATH "/sys/class/net/p2p0/address"
#endif

#define COUNTRY_CODE_FILE tzplatform_mkpath(TZ_SYS_RO_ETC, "wifi-direct/ccode.conf")

static int _txt_to_mac(char *txt, unsigned char *mac)
{
	int i = 0;

	for (;;) {
		mac[i++] = (char) strtoul(txt, &txt, 16);
		if (i == MACADDR_LEN || !*txt++)
			break;
	}

	if (i != MACADDR_LEN)
		return -1;

	WDS_LOGD("Converted MAC address [" MACSECSTR "]",
					MAC2SECSTR(mac));
	return 0;
}

static int _txt_to_ip(char *txt, unsigned char *ip)
{
	int i = 0;

	for (;;) {
		ip[i++] = (char) strtoul(txt, &txt, 10);
		if (i == IPADDR_LEN || !*txt++)
			break;
	}

	if (i != IPADDR_LEN)
		return -1;

	WDS_LOGD("Converted IP address [" IPSECSTR "]", IP2SECSTR(ip));
	return 0;
}

#if !(__GNUC__ <= 4 && __GNUC_MINOR__ < 8)
int wfd_util_get_current_time(unsigned long *cur_time)
{
	struct timespec time;
	int res;

	errno = 0;
	res = clock_gettime(CLOCK_REALTIME, &time);
	if (!res) {
		WDS_LOGD("Succeeded to get current real time");
		*cur_time = time.tv_sec;
		return 0;
	}
	WDS_LOGE("Failed to get current real time(%s)", strerror(errno));

	errno = 0;
	res = clock_gettime(CLOCK_MONOTONIC, &time);
	if (!res) {
		WDS_LOGD("Succeeded to get current system time");
		*cur_time = time.tv_sec;
		return 0;
	}
	WDS_LOGE("Failed to get current system time(%s)", strerror(errno));

	return -1;
}
#endif

#if defined(TIZEN_FEATURE_DEFAULT_CONNECTION_AGENT)
static int __wfd_util_find_login_user(uid_t *uid)
{
	uid_t *uids;
	int ret, i;
	char *state;

	ret = sd_get_uids(&uids);
	if (ret <= 0)
		return -1;

	for (i = 0; i < ret ; i++) {
		if (sd_uid_get_state(uids[i], &state) < 0) {
			free(uids);
			return -1;
		} else {
			if (!strncmp(state, "online", 6)) {
				*uid = uids[i];
				free(uids);
				free(state);
				return 0;
			}
		}
	 }
	free(uids);
	free(state);
	return -1;
}
#endif

gboolean wfd_util_execute_file(const char *file_path,
	char *const args[], char *const envs[])
{
	pid_t pid = 0;
	int rv = 0;
	errno = 0;
	register unsigned int index = 0;

	while (args[index] != NULL) {
		WDS_LOGD("[%s]", args[index]);
		index++;
	}

	if (!(pid = fork())) {
		WDS_LOGD("pid(%d), ppid(%d)", getpid(), getppid());
		WDS_LOGD("Inside child, exec (%s) command", file_path);

		errno = 0;
		if (execve(file_path, args, envs) == -1) {
			WDS_LOGE("Fail to execute command (%s)", strerror(errno));
			exit(1);
		}
	} else if (pid > 0) {
		if (waitpid(pid, &rv, 0) == -1)
			WDS_LOGD("wait pid (%u) rv (%d)", pid, rv);
		if (WIFEXITED(rv))
			WDS_LOGD("exited, rv=%d", WEXITSTATUS(rv));
		else if (WIFSIGNALED(rv))
			WDS_LOGD("killed by signal %d", WTERMSIG(rv));
		else if (WIFSTOPPED(rv))
			WDS_LOGD("stopped by signal %d", WSTOPSIG(rv));
		else if (WIFCONTINUED(rv))
			WDS_LOGD("continued");
		return TRUE;
	}

	WDS_LOGE("failed to fork (%s)", strerror(errno));
	return FALSE;
}

int wfd_util_channel_to_freq(int channel)
{
	if (channel < 1 || channel > 161 ||
		(channel > 48 && channel < 149) ||
		(channel > 14 && channel < 36)) {
		WDS_LOGE("Unsupported channel[%d]", channel);
		return -1;
	}

	if (channel >= 36)
		return 5000 + 5*channel;
	else if (channel == 14)
		return 2484;
	else
		return 2407 + 5*channel;
}

int wfd_util_freq_to_channel(int freq)
{
	if (freq < 2412 || freq > 5825 ||
		(freq > 2484 && freq < 5180)) {
		WDS_LOGE("Unsupported frequency[%d]", freq);
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
		WDS_LOGE("Failed to get vconf value for %s", VCONFKEY_SETAPPL_DEVICE_NAME_STR);
		return -1;
	}
	g_strlcpy(phone_name, name, DEV_NAME_LEN + 1);
	WDS_LOGD("[%s: %s]", VCONFKEY_SETAPPL_DEVICE_NAME_STR, phone_name);
	g_free(name);
	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

void _wfd_util_dev_name_changed_cb(keynode_t *key, void *data)
{
	__WDS_LOG_FUNC_ENTER__;
	char dev_name[DEV_NAME_LEN+1] = {0, };
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
	int res = 0;

	res = vconf_notify_key_changed(VCONFKEY_SETAPPL_DEVICE_NAME_STR, _wfd_util_dev_name_changed_cb, NULL);
	if (res) {
		WDS_LOGE("Failed to set vconf notification callback(SETAPPL_DEVICE_NAME_STR)");
		return;
	}

	__WDS_LOG_FUNC_EXIT__;
	return;
}

void wfd_util_unset_dev_name_notification()
{
	__WDS_LOG_FUNC_ENTER__;
	int res = 0;

	res = vconf_ignore_key_changed(VCONFKEY_SETAPPL_DEVICE_NAME_STR, _wfd_util_dev_name_changed_cb);
	if (res) {
		WDS_LOGE("Failed to set vconf notification callback(SETAPPL_DEVICE_NAME_STR)");
		return;
	}

	__WDS_LOG_FUNC_EXIT__;
	return;
}


void _wfd_util_check_country_cb(keynode_t *key, void *data)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = (wfd_manager_s*) data;
	int res = 0;
	int plmn = 0;
	char mcc[4] = {0, };
	char *ccode;
	GKeyFile *keyfile = NULL;
	const char *file_path = COUNTRY_CODE_FILE;
	GError * err = NULL;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		return;
	}

	res = vconf_get_int(VCONFKEY_TELEPHONY_PLMN, &plmn);
	if (res) {
		WDS_LOGE("Failed to get vconf value for PLMN(%d)", res);
		return;
	}

	snprintf(mcc, 4, "%d", plmn);

	keyfile = g_key_file_new();
	res = g_key_file_load_from_file(keyfile, file_path, 0, &err);
	if (!res) {
		WDS_LOGE("Failed to load key file(%s)", err->message);
		g_key_file_free(keyfile);
		return;
	}

	ccode = g_key_file_get_string(keyfile, "ccode_map", mcc, &err);
	if (!ccode) {
		WDS_LOGE("Failed to get country code string(%s)", err->message);
		return;
	}

	res = wfd_oem_set_country(manager->oem_ops, ccode);
	if (res < 0) {
		WDS_LOGE("Failed to set contry code");
		return;
	}
	WDS_LOGD("Succeeded to set country code(%s)", ccode);

	__WDS_LOG_FUNC_EXIT__;
	return;
}

int wfd_util_set_country()
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = wfd_get_manager();
	int res = 0;

	_wfd_util_check_country_cb(NULL, manager);

	res = vconf_notify_key_changed(VCONFKEY_TELEPHONY_PLMN, _wfd_util_check_country_cb, manager);
	if (res) {
		WDS_LOGE("Failed to set vconf notification callback(TELEPHONY_PLMN)");
		return -1;
	}

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_util_unset_country()
{
	__WDS_LOG_FUNC_ENTER__;
	int res = 0;

	res = vconf_ignore_key_changed(VCONFKEY_TELEPHONY_PLMN, _wfd_util_check_country_cb);
	if (res) {
		WDS_LOGE("Failed to unset vconf notification callback(TELEPHONY_PLMN)");
		return -1;
	}

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_util_check_wifi_state()
{
	__WDS_LOG_FUNC_ENTER__;
	int wifi_state = 0;
	int res = 0;

/* vconf key and value (vconf-keys.h)
#define VCONFKEY_WIFI_STATE	"memory/wifi/state"
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
	WDS_LOGD("OK. Wi-Fi is off\n");

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

	if ((mobile_ap_state & VCONFKEY_MOBILE_HOTSPOT_MODE_WIFI)
		|| (mobile_ap_state & VCONFKEY_MOBILE_HOTSPOT_MODE_WIFI_AP)) {
		WDS_LOGD("Mobile AP is on");
		__WDS_LOG_FUNC_EXIT__;
		return 1;
	}
	WDS_LOGD("OK. Mobile AP is off\n");

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_util_wifi_direct_activatable()
{
	__WDS_LOG_FUNC_ENTER__;

#ifndef TIZEN_WLAN_CONCURRENT_ENABLE
	int res_wifi = 0;

	res_wifi = wfd_util_check_wifi_state();
	if (res_wifi < 0) {
		WDS_LOGE("Failed to check Wi-Fi state");
		__WDS_LOG_FUNC_EXIT__;
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	} else if (res_wifi > 0) {
		WDS_LOGE("Wi-Fi is On");
		__WDS_LOG_FUNC_EXIT__;
		return WIFI_DIRECT_ERROR_WIFI_USED;
	} else {
		WDS_LOGE("Wi-Fi is Off");
		__WDS_LOG_FUNC_EXIT__;
		return WIFI_DIRECT_ERROR_NONE;
	}
#endif

#if defined TIZEN_TETHERING_ENABLE
	int res_mobap = 0;

	res_mobap = wfd_util_check_mobile_ap_state();
	if (res_mobap < 0) {
		WDS_LOGE("Failed to check Mobile AP state");
		__WDS_LOG_FUNC_EXIT__;
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	} else if (res_mobap > 0) {
		WDS_LOGE("Mobile AP is On");
		__WDS_LOG_FUNC_EXIT__;
		return WIFI_DIRECT_ERROR_MOBILE_AP_USED;
	} else {
		WDS_LOGE("Mobile AP is Off");
		__WDS_LOG_FUNC_EXIT__;
		return WIFI_DIRECT_ERROR_NONE;
	}
#endif

	__WDS_LOG_FUNC_EXIT__;
	return WIFI_DIRECT_ERROR_NONE;
}

#if 0
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
#endif

int wfd_util_set_wifi_direct_state(int state)
{
	__WDS_LOG_FUNC_ENTER__;
	int vconf_state = 0;
	int res = 0;

	/* TODO: check validity of state */

	if (state == WIFI_DIRECT_STATE_ACTIVATED)
		vconf_state = VCONFKEY_WIFI_DIRECT_ACTIVATED;
	else if (state == WIFI_DIRECT_STATE_DEACTIVATED)
		vconf_state = VCONFKEY_WIFI_DIRECT_DEACTIVATED;
	else if (state == WIFI_DIRECT_STATE_CONNECTED)
		vconf_state = VCONFKEY_WIFI_DIRECT_CONNECTED;
	else if (state == WIFI_DIRECT_STATE_GROUP_OWNER)
		vconf_state = VCONFKEY_WIFI_DIRECT_GROUP_OWNER;
	else if (state == WIFI_DIRECT_STATE_DISCOVERING)
		vconf_state = VCONFKEY_WIFI_DIRECT_DISCOVERING;
	else {
		WDS_LOGE("This state cannot be set as wifi_direct vconf state[%d]", state);
		return 0;
	}
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
	const char *file_path = DEFAULT_MAC_FILE_PATH;
	FILE *fd = NULL;
	char local_mac[MACSTR_LEN] = {0, };
	char *ptr = NULL;
	int res = 0;

	errno = 0;
	fd = fopen(file_path, "r");
	if (!fd) {
		WDS_LOGE("Failed to open MAC info file [%s] (%s)", file_path , strerror(errno));
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
	WDS_SECLOGD("Local MAC address [%s]", ptr);

	res = _txt_to_mac(local_mac, dev_mac);
	if (res < 0) {
		WDS_LOGE("Failed to convert text to MAC address");
		fclose(fd);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	WDS_LOGD("Local Device MAC address [" MACSECSTR "]", MAC2SECSTR(dev_mac));

	fclose(fd);
	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

#ifdef TIZEN_FEATURE_DEFAULT_CONNECTION_AGENT
int wfd_util_start_wifi_direct_popup()
{
	__WDS_LOG_FUNC_ENTER__;

	uid_t uid = 0;
	int ret = 0;
	ret = __wfd_util_find_login_user(&uid);
	if (ret < 0) {
		WDS_LOGE("__wfd_util_find_login_user Failed !");
		return -1;
	}

	if (AUL_R_OK != aul_launch_app_for_uid(
		"org.tizen.wifi-direct-popup", NULL, uid)) {
		WDS_LOGE("aul_launch_for_uid Failed !");
		return -1;
	}

	WDS_LOGD("Succeeded to launch wifi-direct-popup");
	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_util_stop_wifi_direct_popup()
{
	__WDS_LOG_FUNC_ENTER__;

	uid_t uid = 0;
	int ret = 0;
	ret = __wfd_util_find_login_user(&uid);
	if (ret < 0) {
		WDS_LOGE("__wfd_util_find_login_user Failed !");
		return -1;
	}

	int pid = aul_app_get_pid_for_uid("org.tizen.wifi-direct-popup", uid);
	if (pid > 0) {
		if (aul_terminate_pid_for_uid(pid, uid) != AUL_R_OK) {
			WDS_LOGD("Failed to destroy wifi-direct-popup pid[%d]", pid);
			return -1;
		} else {
			WDS_LOGD("Succeeded to destroy wifi-direct-popup");
		}
	} else {
		WDS_LOGD("Wifi-direct-popup not running");
	}

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}
#endif /* TIZEN_FEATURE_DEFAULT_CONNECTION_AGENT */

int _connect_remote_device(char *ip_str)
{
	int sock;
	int flags;
	int res = 0;
	struct sockaddr_in remo_addr;

	errno = 0;
	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		WDS_LOGE("Failed to create socket to remote device(%s)", strerror(errno));
		return -1;
	}

	flags = fcntl(sock, F_GETFL, 0);
	res = fcntl(sock, F_SETFL, flags | O_NONBLOCK);
	if (res < 0) {
		WDS_LOGE("File descriptor create failed");
		close(sock);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	memset(&remo_addr, 0x0, sizeof(remo_addr));
	remo_addr.sin_family = AF_INET;
	remo_addr.sin_addr.s_addr = inet_addr(ip_str);
	remo_addr.sin_port = htons(9999);

	errno = 0;
	res = connect(sock, (struct sockaddr*) &remo_addr, sizeof(remo_addr));
	if (res < 0) {
		WDS_LOGE("Failed to connect to server socket [%s]", strerror(errno));
		close(sock);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	WDS_SECLOGD("Status of connection to remote device[%s] - (%s)", ip_str, strerror(errno));

	close(sock);

	return 0;
}

static void _dhcps_ip_leased_cb(keynode_t *key, void* data)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *peer = (wfd_device_s*) data;
	FILE *fp = NULL;
	char buf[MAX_DHCP_DUMP_SIZE];
	char ip_str[IPSTR_LEN] = {0, };
	char intf_str[MACSTR_LEN];
	unsigned char intf_addr[MACADDR_LEN];
	char peer_mac_address[MACSTR_LEN+1] = {0,};
	char assigned_ip_address[IPSTR_LEN+1] = {0,};
	int n = 0;

	if (!peer) {
		WDS_LOGD("Invalid parameter");
		return;
	}
	WDS_LOGD("DHCP server: IP leased");

	errno = 0;
	fp = fopen(DHCP_DUMP_FILE, "r");
	if (NULL == fp) {
		WDS_LOGE("Could not read the file(%s). [%s]", DHCP_DUMP_FILE, strerror(errno));
		return;
	}

	while (fgets(buf, MAX_DHCP_DUMP_SIZE, fp) != NULL) {
		WDS_LOGD("Read line [%s]", buf);
		n = sscanf(buf, "%17s %15s", intf_str, ip_str);
		WDS_LOGD("ip=[%s], mac=[%s]", ip_str, intf_str);
		if (n != 2)
			continue;

		_txt_to_mac(intf_str, intf_addr);
		if (!memcmp(peer->intf_addr, intf_addr, MACADDR_LEN)) {
			WDS_LOGD("Peer intf mac found");
			_txt_to_ip(ip_str, peer->ip_addr);
			_connect_remote_device(ip_str);
			g_snprintf(peer_mac_address, MACSTR_LEN, MACSTR, MAC2STR(peer->dev_addr));
			g_snprintf(assigned_ip_address, IPSTR_LEN, IPSTR, IP2STR(peer->ip_addr));
			wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
						     "PeerIPAssigned",
						     g_variant_new("(ss)", peer_mac_address,
									   assigned_ip_address));
			break;
		} else {
			WDS_LOGD("Different interface address peer[" MACSECSTR "] vs dhcp[" MACSECSTR "]",
						MAC2SECSTR(peer->intf_addr), MAC2SECSTR(intf_addr));
		}
	}
	fclose(fp);

	vconf_ignore_key_changed(VCONFKEY_DHCPS_IP_LEASE, _dhcps_ip_leased_cb);
	vconf_set_int(VCONFKEY_DHCPS_IP_LEASE, 0);

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
	char ip_str[IPSTR_LEN] = {0, };
	static int count = 0;
	int res = 0;

	if (!peer) {
		WDS_LOGE("peer data is not exists");
		return FALSE;
	}

	res = wfd_manager_get_goup_ifname(&ifname);
	if (res < 0 || !ifname) {
		WDS_LOGE("Failed to get group interface name");
		return FALSE;
	}

	if (count > 28) {
		WDS_LOGE("Failed to get IP");
		count = 0;
		wfd_oem_destroy_group(manager->oem_ops, ifname);
		__WDS_LOG_FUNC_EXIT__;
		return FALSE;
	}
	res = wfd_util_local_get_ip(ifname, local->ip_addr, 0);
	if (res < 0) {
		WDS_LOGE("Failed to get local IP for interface %s(count=%d)", ifname, count++);
		__WDS_LOG_FUNC_EXIT__;
		return TRUE;
	}
	WDS_LOGD("Succeeded to get local(client) IP [" IPSECSTR "] for iface[%s]",
				    IP2SECSTR(local->ip_addr), ifname);

	res = wfd_util_dhcpc_get_server_ip(peer->ip_addr);
	if (res < 0) {
		WDS_LOGE("Failed to get peer(server) IP(count=%d)", count++);
		__WDS_LOG_FUNC_EXIT__;
		return TRUE;
	}
	WDS_LOGD("Succeeded to get server IP [" IPSECSTR "]", IP2SECSTR(peer->ip_addr));
	count = 0;

	g_snprintf(ip_str, IPSTR_LEN, IPSTR, IP2STR(peer->ip_addr));
	_connect_remote_device(ip_str);

	wfd_state_set(manager, WIFI_DIRECT_STATE_CONNECTED);
	wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_CONNECTED);
	wfd_destroy_session(manager);

	char peer_mac_address[MACSTR_LEN+1] = {0, };

	g_snprintf(peer_mac_address, MACSTR_LEN, MACSTR, MAC2STR(peer->dev_addr));
	wfd_manager_dbus_emit_signal(WFD_MANAGER_MANAGE_INTERFACE,
				     "Connection",
				     g_variant_new("(iis)", WIFI_DIRECT_ERROR_NONE,
							    WFD_EVENT_CONNECTION_RSP,
							    peer_mac_address));

	__WDS_LOG_FUNC_EXIT__;
	return FALSE;
}

int wfd_util_dhcps_start(char *ifname)
{
	__WDS_LOG_FUNC_ENTER__;
	gboolean rv = FALSE;
	char *const iface = ifname;
	const char *path = "/usr/bin/wifi-direct-dhcp.sh";
	char *const args[] = { "/usr/bin/wifi-direct-dhcp.sh", "server", iface, NULL };
	char *const envs[] = { NULL };
	wfd_manager_s *manager = wfd_get_manager();

	vconf_set_int(VCONFKEY_DHCPS_IP_LEASE, 0);

	rv = wfd_util_execute_file(path, args, envs);

	if (rv != TRUE) {
		WDS_LOGE("Failed to start wifi-direct-dhcp.sh server");
		return -1;
	}

	/*
	 * As we are GO so IP should be updated
	 * before sending Group Created Event
	 */
	vconf_set_str(VCONFKEY_IFNAME, GROUP_IFNAME);
	vconf_set_str(VCONFKEY_LOCAL_IP, "192.168.49.1");
	vconf_set_str(VCONFKEY_SUBNET_MASK, "255.255.255.0");
	vconf_set_str(VCONFKEY_GATEWAY, "192.168.49.1");

	WDS_LOGD("Successfully started wifi-direct-dhcp.sh server");

	_txt_to_ip(TIZEN_P2P_GO_IPADDR, manager->local->ip_addr);

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

int wfd_util_dhcps_stop(char *ifname)
{
	__WDS_LOG_FUNC_ENTER__;
	gboolean rv = FALSE;
	char *const iface = ifname;
	const char *path = "/usr/bin/wifi-direct-dhcp.sh";
	char *const args[] = { "/usr/bin/wifi-direct-dhcp.sh", "stop", iface, NULL };
	char *const envs[] = { NULL };

	vconf_ignore_key_changed(VCONFKEY_DHCPS_IP_LEASE, _dhcps_ip_leased_cb);
	vconf_set_int(VCONFKEY_DHCPS_IP_LEASE, 0);

	rv = wfd_util_execute_file(path, args, envs);

	if (rv != TRUE) {
		WDS_LOGE("Failed to stop wifi-direct-dhcp.sh");
		return -1;
	}
	WDS_LOGD("Successfully stopped wifi-direct-dhcp.sh");

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_util_dhcpc_start(char *ifname, wfd_device_s *peer)
{
	__WDS_LOG_FUNC_ENTER__;
	gboolean rv = FALSE;
	char *const iface = ifname;
	const char *path = "/usr/bin/wifi-direct-dhcp.sh";
	char *const args[] = { "/usr/bin/wifi-direct-dhcp.sh", "client", iface, NULL };
	char *const envs[] = { NULL };

	if (!peer) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	rv = wfd_util_execute_file(path, args, envs);
	if (rv != TRUE) {
		WDS_LOGE("Failed to start wifi-direct-dhcp.sh client");
		return -1;
	}
	WDS_LOGD("Successfully started wifi-direct-dhcp.sh client");

	g_timeout_add(250, (GSourceFunc) _polling_ip, peer);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_util_dhcpc_stop(char *ifname)
{
	__WDS_LOG_FUNC_ENTER__;
	gboolean rv = FALSE;
	char *const iface = ifname;
	const char *path = "/usr/bin/wifi-direct-dhcp.sh";
	char *const args[] = { "/usr/bin/wifi-direct-dhcp.sh", "stop", iface, NULL };
	char *const envs[] = { NULL };

	rv = wfd_util_execute_file(path, args, envs);

	if (rv != TRUE) {
		WDS_LOGE("Failed to stop wifi-direct-dhcp.sh");
		return -1;
	}
	WDS_LOGD("Successfully stopped wifi-direct-dhcp.sh");

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_util_local_get_ip(char *ifname, unsigned char *ip_addr, int is_IPv6)
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
	memset(ifr.ifr_name, 0x00, IFNAMSIZ);
	g_strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

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

	while (count < 10) {
		get_str = vconf_get_str(VCONFKEY_DHCPC_SERVER_IP);
		if (!get_str) {
			WDS_LOGE("Failed to get vconf value[%s]", VCONFKEY_DHCPC_SERVER_IP);
			__WDS_LOG_FUNC_EXIT__;
			return -1;
		}

		if (strcmp(get_str, ZEROIP) == 0) {
			WDS_LOGE("Failed to get vconf value[%s]", VCONFKEY_DHCPC_SERVER_IP);
			g_free(get_str);
			__WDS_LOG_FUNC_EXIT__;
			return -1;
		}

		WDS_LOGD("VCONFKEY_DHCPC_SERVER_IP(%s) : %s\n", VCONFKEY_DHCPC_SERVER_IP, get_str);
		_txt_to_ip(get_str, ip_addr);
		g_free(get_str);
		if (*ip_addr)
			break;
		count++;
	}

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

#ifdef TIZEN_FEATURE_IP_OVER_EAPOL
static int _wfd_util_set_vconf_for_static_ip(const char *ifname, char *static_ip)
{
	__WDS_LOG_FUNC_ENTER__;

	if (!ifname || !static_ip)
		return -1;

	vconf_set_str(VCONFKEY_IFNAME, ifname);
	vconf_set_str(VCONFKEY_LOCAL_IP, static_ip);
	vconf_set_str(VCONFKEY_SUBNET_MASK, "255.255.255.0");
	vconf_set_str(VCONFKEY_GATEWAY, "192.168.49.1");

	__WDS_LOG_FUNC_EXIT__;

	return 0;
}


static int _wfd_util_static_ip_set(const char *ifname, unsigned char *static_ip)
{
	__WDS_LOG_FUNC_ENTER__;
	int res = 0;
	unsigned char ip_addr[IPADDR_LEN];
	char ip_str[IPSTR_LEN] = {0, };

	int if_index;
	int nl_sock = -1;
	struct sockaddr_nl dst_addr;

	struct {
		struct nlmsghdr     nh;
		struct ifaddrmsg    ifa;
		char            attrbuf[1024];
	} req;
	struct rtattr *rta;
	struct iovec iov;
	struct msghdr nl_msg;

	if (!ifname || !static_ip) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	/* Get index of interface */
	if_index = if_nametoindex(ifname);
	if (if_index < 0) {
		WDS_LOGE("Failed to get interface index. [%s]", strerror(errno));
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	WDS_LOGD("Creating a Netlink Socket");
	nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nl_sock < 0) {
		WDS_LOGE("Failed to create socket. [%s]", strerror(errno));
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	memset(&dst_addr, 0, sizeof(dst_addr));
	dst_addr.nl_family =  AF_NETLINK;
	dst_addr.nl_pid = 0;

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.nh.nlmsg_type = RTM_NEWADDR;
	req.nh.nlmsg_flags = NLM_F_CREATE | NLM_F_EXCL | NLM_F_REQUEST;

	req.ifa.ifa_family = AF_INET;
	req.ifa.ifa_prefixlen = 24;
	req.ifa.ifa_flags = IFA_F_PERMANENT;
	req.ifa.ifa_scope = 0;
	req.ifa.ifa_index = if_index;

	rta = (struct rtattr *)(req.attrbuf);
	rta->rta_type = IFA_LOCAL;
	rta->rta_len = RTA_LENGTH(IPADDR_LEN);
	memcpy(RTA_DATA(rta), static_ip, IPADDR_LEN);
	req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + rta->rta_len;

	rta = (struct rtattr *)(req.attrbuf + rta->rta_len);
	rta->rta_type = IFA_BROADCAST;
	rta->rta_len = RTA_LENGTH(IPADDR_LEN);
	memcpy(ip_addr, static_ip, IPADDR_LEN);
	ip_addr[3] = 0xff;
	memcpy(RTA_DATA(rta), ip_addr, IPADDR_LEN);
	req.nh.nlmsg_len += rta->rta_len;

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = &req;
	iov.iov_len = req.nh.nlmsg_len;

	memset(&nl_msg, 0, sizeof(nl_msg));
	nl_msg.msg_name = (void *)&dst_addr;
	nl_msg.msg_namelen = sizeof(dst_addr);
	nl_msg.msg_iov = &iov;
	nl_msg.msg_iovlen = 1;

	res = sendmsg(nl_sock, &nl_msg, 0);
	if (res < 0)
		WDS_LOGE("Failed to sendmsg. [%s]", strerror(errno));
	else
		WDS_LOGD("Succed to sendmsg. [%d]", res);

	close(nl_sock);
	WDS_LOGE("Succeeded to set local(client) IP [" IPSTR "] for iface[%s]",
				IP2STR(static_ip), ifname);

	snprintf(ip_str, IPSTR_LEN, IPSTR, IP2STR(static_ip));
	_wfd_util_set_vconf_for_static_ip(ifname, ip_str);

	__WDS_LOG_FUNC_EXIT__;
	return res;
}

int wfd_util_ip_over_eap_assign(wfd_device_s *peer, const char *ifname)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = wfd_get_manager();
	wfd_device_s *local = (wfd_device_s*) manager->local;

	char ip_str[IPSTR_LEN] = {0, };

	if (!peer) {
		WDS_LOGE("Invalid paramater");
		return -1;
	}

	_wfd_util_static_ip_set(ifname, peer->client_ip_addr);
	memcpy(peer->ip_addr, peer->go_ip_addr, IPADDR_LEN);
	memcpy(local->ip_addr, peer->client_ip_addr, IPADDR_LEN);

	g_snprintf(ip_str, IPSTR_LEN, IPSTR, IP2STR(peer->ip_addr));
	_connect_remote_device(ip_str);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}
#endif /* TIZEN_FEATURE_IP_OVER_EAPOL */

int wfd_util_ip_unset(const char *ifname)
{
	__WDS_LOG_FUNC_ENTER__;
	int res = 0;
	unsigned char ip_addr[IPADDR_LEN];
	char error_buf[MAX_SIZE_ERROR_BUFFER] = {0, };

	int if_index;
	int nl_sock = -1;
	struct sockaddr_nl dst_addr;

	struct {
		struct nlmsghdr     nh;
		struct ifaddrmsg    ifa;
		char            attrbuf[1024];
	} req;
	struct rtattr *rta;
	struct iovec iov;
	struct msghdr nl_msg;

	if (!ifname) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	res = wfd_util_local_get_ip((char *)ifname, ip_addr, 0);
	if (res < 0) {
		WDS_LOGE("Failed to get local IP for interface %s", ifname);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}
	WDS_LOGE("Succeeded to get local(client) IP [" IPSTR "] for iface[%s]",
			IP2STR(ip_addr), ifname);

	if_index = if_nametoindex(ifname);
	if (if_index < 0) {
		strerror_r(errno, error_buf, MAX_SIZE_ERROR_BUFFER);
		WDS_LOGE("Failed to get interface index. [%s]", error_buf);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	WDS_LOGD("Creating a Netlink Socket");
	nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nl_sock < 0) {
		strerror_r(errno, error_buf, MAX_SIZE_ERROR_BUFFER);
		WDS_LOGE("Failed to create socket. [%s]", error_buf);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	WDS_LOGD("Set dst socket address to kernel");
	memset(&dst_addr, 0, sizeof(dst_addr));
	dst_addr.nl_family =  AF_NETLINK;
	dst_addr.nl_pid = 0;

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.nh.nlmsg_type = RTM_DELADDR;
	req.nh.nlmsg_flags = NLM_F_REQUEST;

	req.ifa.ifa_family = AF_INET;
	req.ifa.ifa_prefixlen = 32;
	req.ifa.ifa_flags = IFA_F_PERMANENT;
	req.ifa.ifa_scope = 0;
	req.ifa.ifa_index = if_index;

	rta = (struct rtattr *)(req.attrbuf);
	rta->rta_type = IFA_LOCAL;
	rta->rta_len = RTA_LENGTH(IPADDR_LEN);
	memcpy(RTA_DATA(rta), ip_addr, IPADDR_LEN);
	req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + rta->rta_len;

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = &req;
	iov.iov_len = req.nh.nlmsg_len;

	memset(&nl_msg, 0, sizeof(nl_msg));
	nl_msg.msg_name = (void *)&dst_addr;
	nl_msg.msg_namelen = sizeof(dst_addr);
	nl_msg.msg_iov = &iov;
	nl_msg.msg_iovlen = 1;

	res = sendmsg(nl_sock, &nl_msg, 0);
	if (res < 0) {
		strerror_r(errno, error_buf, MAX_SIZE_ERROR_BUFFER);
		WDS_LOGE("Failed to sendmsg. [%s]", error_buf);
	} else {
		WDS_LOGD("Succeed to sendmsg. [%d]", res);
	}

	close(nl_sock);

	__WDS_LOG_FUNC_EXIT__;
	return res;
}

gboolean wfd_util_is_remove_group_allowed(void)
{
	wfd_manager_s *manager = wfd_get_manager();

	if (!manager->auto_group_remove_enable)
		return FALSE;

	return TRUE;
}
