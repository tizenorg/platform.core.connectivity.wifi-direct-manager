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
 * This file implements wifi direct manager dbus error functions.
 *
 * @file        wifi-direct-error.c
 * @author      Nishant Chaprana (n.chaprana@samsung.com)
 * @version     0.1
 */

#include <glib.h>
#include "wifi-direct-error.h"
#include "wifi-direct-dbus.h"
#include "wifi-direct-log.h"

#define WFD_MANAGER_QUARK (g_quark_from_string ("wifi-direct-error-quark"))

static void wfd_error_invalid_parameter(GError **error)
{
	*error = g_dbus_error_new_for_dbus_error(
		"net.wifidirect.Error.InvalidParameter",
		"net.wifidirect.Error.InvalidParameter");
	/*
	g_set_error(error,
			WFD_MANAGER_QUARK,
			WIFI_DIRECT_ERROR_INVALID_PARAMETER,
			WFD_MANAGER_ERROR_INTERFACE ".InvalidParameter");
			*/
}

static void wfd_error_not_permitted(GError **error)
{
	*error = g_dbus_error_new_for_dbus_error(
		"net.wifidirect.Error.NotPermitted",
		"net.wifidirect.Error.NotPermitted");
/*
	g_set_error(error,
			WFD_MANAGER_QUARK,
			WIFI_DIRECT_ERROR_NOT_PERMITTED,
			WFD_MANAGER_ERROR_INTERFACE ".NotPermitted");
			*/
}

static void wfd_error_operation_failed(GError **error)
{
	*error = g_dbus_error_new_for_dbus_error(
		"net.wifidirect.Error.OperationFailed",
		"net.wifidirect.Error.OperationFailed");
	/*
	g_set_error(error,
			WFD_MANAGER_QUARK,
			WIFI_DIRECT_ERROR_OPERATION_FAILED,
			WFD_MANAGER_ERROR_INTERFACE ".OperationFailed");
			*/
}

static void wfd_error_too_many_client(GError **error)
{
	*error = g_dbus_error_new_for_dbus_error(
		"net.wifidirect.Error.TooManyClient",
		"net.wifidirect.Error.TooManyClient");
/*
	g_set_error(error,
			WFD_MANAGER_QUARK,
			WIFI_DIRECT_ERROR_TOO_MANY_CLIENT,
			WFD_MANAGER_ERROR_INTERFACE ".TooManyClient");
			*/
}

void wfd_error_set_gerror(wifi_direct_error_e error_code, GError **error)
{
	switch (error_code) {
	case WIFI_DIRECT_ERROR_INVALID_PARAMETER:
		wfd_error_invalid_parameter(error);
		break;
	case WIFI_DIRECT_ERROR_NOT_PERMITTED:
		wfd_error_not_permitted(error);
		break;
	case WIFI_DIRECT_ERROR_OPERATION_FAILED:
		wfd_error_operation_failed(error);
		break;
	case WIFI_DIRECT_ERROR_TOO_MANY_CLIENT:
		wfd_error_too_many_client(error);
		break;
	default:
		WDS_LOGD("Error Not handled [%d]", error_code);
		wfd_error_operation_failed(error);
	}
}

void wfd_error_register(void)
{
	g_dbus_error_register_error(WFD_MANAGER_QUARK,
			WIFI_DIRECT_ERROR_INVALID_PARAMETER,
			"net.wifidirect.Error.InvalidParameter");


	g_dbus_error_register_error(WFD_MANAGER_QUARK,
			WIFI_DIRECT_ERROR_NOT_PERMITTED,
			"net.wifidirect.Error.NotPermitted");


	g_dbus_error_register_error(WFD_MANAGER_QUARK,
			WIFI_DIRECT_ERROR_OPERATION_FAILED,
			"net.wifidirect.Error.OperationFailed");


	g_dbus_error_register_error(WFD_MANAGER_QUARK,
			WIFI_DIRECT_ERROR_TOO_MANY_CLIENT,
			"net.wifidirect.Error.TooManyClient");
}

void wfd_error_deregister(void)
{
	g_dbus_error_unregister_error(WFD_MANAGER_QUARK,
			WIFI_DIRECT_ERROR_INVALID_PARAMETER,
			"net.wifidirect.Error.InvalidParameter");


	g_dbus_error_unregister_error(WFD_MANAGER_QUARK,
			WIFI_DIRECT_ERROR_NOT_PERMITTED,
			"net.wifidirect.Error.NotPermitted");


	g_dbus_error_unregister_error(WFD_MANAGER_QUARK,
			WIFI_DIRECT_ERROR_OPERATION_FAILED,
			"net.wifidirect.Error.OperationFailed");


	g_dbus_error_unregister_error(WFD_MANAGER_QUARK,
			WIFI_DIRECT_ERROR_TOO_MANY_CLIENT,
			"net.wifidirect.Error.TooManyClient");

}
