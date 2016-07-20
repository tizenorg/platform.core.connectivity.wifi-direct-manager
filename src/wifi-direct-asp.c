/*
 * Network Configuration Module
 *
 * Copyright (c) 2016 Samsung Electronics Co., Ltd. All rights reserved.
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
 * This file implements wifi direct manager Application Service Platform(ASP) functions.
 *
 * @file        wifi-direct-asp.c
 * @author      Jiung Yu (jiung.yu@samsung.com)
 * @version     0.1
 */

#include <stdlib.h>

#include <glib.h>

#include <wifi-direct.h>

#include "wifi-direct-ipc.h"
#include "wifi-direct-dbus.h"
#include "wifi-direct-log.h"
#include "wifi-direct-manager.h"
#include "wifi-direct-oem.h"
#include "wifi-direct-util.h"

#if defined(TIZEN_FEATURE_ASP)
#include "wifi-direct-asp.h"
#endif /* TIZEN_FEATURE_ASP */

void wfd_asp_session_request(wfd_oem_asp_prov_s *prov_param)
{
	GVariantBuilder *builder = NULL;
	GVariant *parameter = NULL;
	GVariant *get_pin = NULL;

	builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(builder, "{sv}",
			"adv_id",
			g_variant_new_uint32(prov_param->adv_id));
	g_variant_builder_add(builder, "{sv}",
			"session_mac",
			wfd_manager_dbus_pack_ay(prov_param->session_mac, MACADDR_LEN));
	g_variant_builder_add(builder, "{sv}",
			"session_id",
			g_variant_new_uint32(prov_param->session_id));

	if (prov_param->network_config == WFD_WPS_MODE_KEYPAD)
		get_pin = g_variant_new_boolean(TRUE);
	else
		get_pin = g_variant_new_boolean(FALSE);
	g_variant_builder_add(builder, "{sv}",
			"get_pin",
			get_pin);

	if (prov_param->wps_pin[0])
		g_variant_builder_add(builder, "{sv}",
				"pin",
				g_variant_new_string(prov_param->wps_pin));
	parameter = g_variant_new("(a{sv})", builder);
	g_variant_builder_unref(builder);

	wfd_manager_dbus_emit_signal(WFD_MANAGER_ASP_INTERFACE, "SessionRequest", parameter);
	return;
}

void wfd_asp_session_config_request(unsigned int session_id, int get_pin, char *pin)
{
	GVariantBuilder *builder = NULL;
	GVariant *parameter = NULL;

	builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(builder, "{sv}",
			"session_id",
			g_variant_new_uint32(session_id));
	g_variant_builder_add(builder, "{sv}",
			"get_pin",
			g_variant_new_int32(get_pin));
	if (pin)
		g_variant_builder_add(builder, "{sv}",
				"pin",
				g_variant_new_string(pin));
	parameter = g_variant_new("(a{sv})", builder);
	g_variant_builder_unref(builder);

	wfd_manager_dbus_emit_signal(WFD_MANAGER_ASP_INTERFACE, "SessionRequest", parameter);
	return;
}

void wfd_asp_connect_status(unsigned char *session_mac,
		unsigned int session_id, int status, char *deferred)
{
	GVariantBuilder *builder = NULL;
	GVariant *parameter = NULL;

	builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(builder, "{sv}",
			"session_mac",
			wfd_manager_dbus_pack_ay(session_mac, MACADDR_LEN));
	g_variant_builder_add(builder, "{sv}",
			"session_id",
			g_variant_new_uint32(session_id));
	g_variant_builder_add(builder, "{sv}",
			"status",
			g_variant_new_int32(status));
	if (deferred)
		g_variant_builder_add(builder, "{sv}",
				"deferred",
				g_variant_new_string(deferred));
	parameter = g_variant_new("(a{sv})", builder);
	g_variant_builder_unref(builder);

	wfd_manager_dbus_emit_signal(WFD_MANAGER_ASP_INTERFACE, "ConnectStatus", parameter);
	return;
}
