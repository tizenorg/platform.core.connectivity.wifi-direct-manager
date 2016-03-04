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
 * This file implements wifi direct dbus utility functions.
 *
 * @file        wifi-direct-dbus.c
 * @author      Nishant Chaprana (n.chaprana@samsung.com)
 * @version     0.1
 */

#include "wifi-direct-dbus.h"
#include "wifi-direct-log.h"

static GDBusConnection *connection = NULL;
static guint g_owner_id = 0;  //Name Owner ID

static GDBusConnection *__dbus_get_gdbus_conn(void)
{
	return connection;
}

static void __on_name_acquired(GDBusConnection *connection,
			       const gchar *name,
			       gpointer user_data)
{
	WDS_LOGD("on_name_acquired: %s", name);
}

static void __on_name_lost(GDBusConnection *connection,
			   const gchar *name,
			   gpointer user_data)
{
	WDS_LOGD("on_name_lost: %s", name);
}

guint wfd_manager_dbus_iface_register(const gchar* iface_name,
				      const gchar* iface_path,
				      const gchar *xml_data,
				      const GDBusInterfaceVTable *interface_vtable)
{
	GDBusNodeInfo *node_info = NULL;
	GDBusInterfaceInfo *interface_info = NULL;
	GError *Error = NULL;
	guint reg_id = 0;
	GDBusConnection *connection = NULL;

	connection = __dbus_get_gdbus_conn();
	if (connection == NULL) {
		WDS_LOGE("Dbus connection not yet initiated");
		return 0;
	}

	if (!iface_name || !iface_path || !xml_data || !interface_vtable) {
		WDS_LOGE("Invalid Parameters");
		return 0;
	}

	node_info = g_dbus_node_info_new_for_xml(xml_data, &Error);
	if (node_info == NULL) {
		WDS_LOGE("Failed to get node info, Error: %s", Error->message);
		g_clear_error(&Error);
		return 0;
	}

	/* Register interface */
	interface_info = g_dbus_node_info_lookup_interface(node_info, iface_name);
	if (interface_info == NULL) {
		WDS_LOGE("Failed to get interface info");
		g_dbus_node_info_unref(node_info);
		return 0;
	}

	reg_id = g_dbus_connection_register_object(connection, iface_path,
			interface_info, interface_vtable,
			NULL, NULL, &Error);
	if (reg_id == 0) {
		WDS_LOGE("Failed to register: %s", Error->message);
		g_clear_error(&Error);
		g_dbus_node_info_unref(node_info);
		return 0;
	}

	WDS_LOGD("Interface Registration ID [%d], Interface Name [%s]", reg_id, iface_name);

	g_dbus_node_info_unref(node_info);
	return reg_id;
}

gboolean wfd_manager_dbus_iface_unregister(guint reg_id)
{
	GDBusConnection *connection = NULL;

	connection = __dbus_get_gdbus_conn();
	if (connection == NULL) {
		WDS_LOGE("Dbus connection not yet initiated");
		return FALSE;
	}

	if(reg_id > 0) {
		if(g_dbus_connection_unregister_object (connection, reg_id) == FALSE)
			WDS_LOGE("netconfig network migration unregister object");
	}

	return TRUE;
}

gboolean wfd_manager_dbus_init(void)
{
	GError *Error = NULL;

	if (connection != NULL) {
		WDS_LOGE("Conenciton already present");
		return TRUE;
	}

	connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &Error);
	if(connection == NULL) {
		WDS_LOGE("Failed to get connection, Error[%s]", Error->message);
		g_error_free(Error);
		return FALSE;
	}

	g_owner_id = g_bus_own_name_on_connection(connection,
						  WFD_MANAGER_SERVICE,
						  G_BUS_NAME_OWNER_FLAGS_NONE,
						  __on_name_acquired,
						  __on_name_lost,
						  NULL,
						  NULL);
	if (g_owner_id == 0) {
		WDS_LOGE("Failed to get bus name");
		return FALSE;
	}
	WDS_LOGD("DBus Owner id is [%d]", g_owner_id);

	connection = connection;
	return TRUE;
}

void wfd_manager_dbus_deinit(void)
{
	if (connection == NULL || g_owner_id == 0)
		return;

	g_object_unref(connection);
	g_bus_unown_name(g_owner_id);
}

gboolean wfd_manager_dbus_emit_signal(const gchar *interface_name,
				      const gchar *signal_name,
				      GVariant *parameters)
{
	gboolean rv = FALSE;
	GError *error = NULL;
	GDBusConnection *connection;

	connection = __dbus_get_gdbus_conn();
	if (connection == NULL) {
		WDS_LOGE("GDBusconnection is NULL");
		return 0;
	}

	DBUS_DEBUG_VARIANT(parameters);

	rv = g_dbus_connection_emit_signal(connection,
					   NULL,
					   WFD_MANAGER_PATH,
					   interface_name,
					   signal_name,
					   parameters,
					   &error);
	if (rv != TRUE) {
		WDS_LOGE("Failed to get node info, Error: %s", error->message);
		g_error_free(error);
	} else {
		WDS_LOGD("[%s] signal sent on [%s] interface", signal_name, interface_name);
	}

	return rv;
}

GVariant* wfd_manager_dbus_pack_ay(const unsigned char *src, int size)
{
	GVariantBuilder *builder = NULL;
	GVariant *iter = NULL;
	int i = 0;

	if (!src) {
		WDS_LOGE("Invalid parameter");
		return NULL;
	}

	builder = g_variant_builder_new(G_VARIANT_TYPE("ay"));

	for(i = 0; i < size; i++)
		g_variant_builder_add(builder, "y", src[i]);

	iter = g_variant_new("ay", builder);

	g_variant_builder_unref (builder);
	return iter;
}
