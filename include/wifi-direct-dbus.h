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
 * This file declares wifi direct dbus utility functions.
 *
 * @file        wifi-direct-dbus.h
 * @author      Nishant Chaprana (n.chaprana@samsung.com)
 * @version     0.1
 */

#ifndef __WIFI_DIRECT_DBUS_H__
#define __WIFI_DIRECT_DBUS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <gio/gio.h>

#define WFD_MANAGER_SERVICE                     "net.wifidirect"
#define WFD_MANAGER_PATH                        "/net/wifidirect"
#define WFD_MANAGER_MANAGE_INTERFACE            WFD_MANAGER_SERVICE
#define WFD_MANAGER_GROUP_INTERFACE             WFD_MANAGER_SERVICE ".group"
#define WFD_MANAGER_CONFIG_INTERFACE            WFD_MANAGER_SERVICE ".config"
#define WFD_MANAGER_SERVICE_INTERFACE           WFD_MANAGER_SERVICE ".service"
#define WFD_MANAGER_DISPLAY_INTERFACE           WFD_MANAGER_SERVICE ".display"
#if defined(TIZEN_FEATURE_ASP)
#define WFD_MANAGER_ASP_INTERFACE               WFD_MANAGER_SERVICE ".asp"
#endif

#define WFD_MANAGER_DBUS_REPLY_TIMEOUT          10 * 1000
#define WFD_MANAGER_DBUS_REPLY_TIMEOUT_SYNC     10 * 1000
#define DBUS_OBJECT_PATH_MAX                    150

#define DBUS_DEBUG_VARIANT(parameters) \
	do {\
		gchar *parameters_debug_str = NULL;\
		if (parameters)\
			parameters_debug_str = g_variant_print(parameters, TRUE);\
		WDS_LOGD("signal params [%s]", parameters_debug_str ? parameters_debug_str : "NULL");\
		g_free(parameters_debug_str);\
	} while (0)

gboolean wfd_manager_dbus_init(void);

void wfd_manager_dbus_deinit(void);

guint wfd_manager_dbus_iface_register(const gchar* iface_name,
				      const gchar* iface_path,
				      GDBusNodeInfo *node_info,
				      const GDBusInterfaceVTable *interface_vtable);

gboolean wfd_manager_dbus_iface_unregister(guint reg_id);

gboolean wfd_manager_dbus_emit_signal(const gchar *interface_name,
				      const gchar *signal_name,
				      GVariant *parameters);

GVariant* wfd_manager_dbus_pack_ay(const unsigned char *src, int size);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_NETDBUS_H__ */
