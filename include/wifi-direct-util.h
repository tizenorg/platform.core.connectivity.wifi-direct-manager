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
 * This file declares wifi direct util functions.
 *
 * @file		wifi-direct-util.h
 * @author	Gibyoung Kim (lastkgb.kim@samsung.com)
 * @version	0.7
 */

#ifndef __WIFI_DIRECT_UTIL_H__
#define __WIFI_DIRECT_UTIL_H__

#define DEFAULT_MAC_FILE_PATH "/opt/etc/.mac.info"
#define DEFAULT_DEVICE_LIST_FILE_PATH "/usr/etc/wifi_direct/access_list"
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#define IP2STR(a) (a)[0], (a)[1], (a)[2], (a)[3]
#define IPSTR "%d.%d.%d.%d"

#define VCONFKEY_DHCPS_IP_LEASE "memory/private/wifi_direct_manager/dhcp_ip_lease"
#define VCONFKEY_DHCPC_SERVER_IP "memory/private/wifi_direct_manager/dhcpc_server_ip"
#define DHCP_DUMP_FILE "/tmp/dhcp-client-table"
#define MAX_DHCP_DUMP_SIZE 64    // Single lease format: [99:66:dd:00:11:aa 192.168.16.20 00:00:60]

#define SOCK_FD_MIN 0

#ifdef USE_DLOG
#include <dlog.h>

#undef LOG_TAG
#define LOG_TAG "WIFI_DIRECT_MANAGER"

#define WDS_LOGV(format, args...) LOGV(format, ##args)
#define WDS_LOGD(format, args...) LOGD(format, ##args)
#define WDS_LOGI(format, args...) LOGI(format, ##args)
#define WDS_LOGW(format, args...) LOGW(format, ##args)
#define WDS_LOGE(format, args...) LOGE(format, ##args)
#define WDS_LOGF(format, args...) LOGF(format, ##args)

#define __WDS_LOG_FUNC_ENTER__ LOGV("Enter")
#define __WDS_LOG_FUNC_EXIT__ LOGV("Quit")

#else /* USE_DLOG */

#define WDS_LOGV(format, args...)
#define WDS_LOGD(format, args...)
#define WDS_LOGI(format, args...)
#define WDS_LOGW(format, args...)
#define WDS_LOGE(format, args...)
#define WDS_LOGF(format, args...)

#define __WDS_LOG_FUNC_ENTER__
#define __WDS_LOG_FUNC_EXIT__

#endif /* USE_DLOG */

gboolean wfd_util_execute_file(const char *file_path, char *const args[], char *const envs[]);
int wfd_util_freq_to_channel(int freq);
int wfd_util_get_phone_name(char *phone_name);
void wfd_util_set_dev_name_notification();
void wfd_util_unset_dev_name_notification();
int wfd_util_check_wifi_state();
int wfd_util_check_mobile_ap_state();
int wfd_util_wifi_direct_activatable();
int wfd_util_get_wifi_direct_state();
int wfd_util_set_wifi_direct_state(int state);
int wfd_util_get_local_dev_mac(unsigned char *dev_mac);

int wfd_util_get_access_list(GList **access_list);
int wfd_util_rewrite_device_list_to_file(GList *access_list);
int wfd_util_add_device_to_list(wfd_device_s *peer, int allowed);
int wfd_util_reset_access_list();
int wfd_util_start_wifi_direct_popup();
int wfd_util_dhcps_start();
int wfd_util_dhcps_wait_ip_leased(wfd_device_s *peer);
int wfd_util_dhcps_stop();
int wfd_util_dhcpc_start(wfd_device_s *peer);
int wfd_util_dhcpc_stop();
int wfd_util_dhcpc_get_ip(char *ifname, unsigned char *ip_addr, int is_IPv6);
int wfd_util_dhcpc_get_server_ip(unsigned char* ip_addr);

#endif /* __WIFI_DIRECT_UTIL_H__ */
