/*
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd All Rights Reserved 
 *
 * This file is part of <Wi-Fi Direct>
 * Written by Sungsik Jang<sngsik.jang@samsung.com>, Dongwook Lee<dwmax.lee@samsung.com>
 *
 * PROPRIETARY/CONFIDENTIAL
 *
 * This software is the confidential and proprietary information of SAMSUNG ELECTRONICS ("Confidential Information").
 * You shall not disclose such Confidential Information and shall use it only in accordance
 * with the terms of the license agreement you entered into with SAMSUNG ELECTRONICS.
 * SAMSUNG make no representations or warranties about the suitability of the software,
 * either express or implied, including but not limited to the implied warranties of merchantability,
 * fitness for a particular purpose, or non-infringement.
 * SAMSUNG shall not be liable for any damages suffered by licensee as a result of using,
 * modifying or distributing this software or its derivatives.
 *
 */

#include <glib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#include "vconf-keys.h"

#include "wifi-direct-service.h"
#include "wifi-direct-utils.h"

#include <app_service.h>

int wfd_server_check_valid(wifi_direct_cmd_e cmd)
{
	int state;
	int valid = false;
	wfd_server_control_t *wfd_server = wfd_server_get_control();

	__WFD_SERVER_FUNC_ENTER__;

	state = wfd_server->state;
	switch (cmd)
	{
	case WIFI_DIRECT_CMD_ACTIVATE:
		{
			if (state == WIFI_DIRECT_STATE_DEACTIVATED)
				valid = true;
			else
				valid = false;
		}
		break;
	case WIFI_DIRECT_CMD_DEACTIVATE:
		{
			if (state == WIFI_DIRECT_STATE_DEACTIVATED ||
				state == WIFI_DIRECT_STATE_DEACTIVATING ||
				state == WIFI_DIRECT_STATE_ACTIVATING)
				valid = false;
			else
				valid = true;
		}
		break;
	case WIFI_DIRECT_CMD_START_DISCOVERY:
	case WIFI_DIRECT_CMD_CANCEL_DISCOVERY:
		{
			if (state == WIFI_DIRECT_STATE_ACTIVATED ||
				state == WIFI_DIRECT_STATE_DISCOVERING ||
				state == WIFI_DIRECT_STATE_CONNECTED ||
				state == WIFI_DIRECT_STATE_GROUP_OWNER)
				valid = true;
			else
				valid = false;
		}
		break;
	case WIFI_DIRECT_CMD_CONNECT:
		{
			if (state == WIFI_DIRECT_STATE_ACTIVATED ||
				state == WIFI_DIRECT_STATE_DISCOVERING ||
				state == WIFI_DIRECT_STATE_GROUP_OWNER)
				valid = true;
			else
				valid = false;
		}
		break;
	case WIFI_DIRECT_CMD_CREATE_GROUP:
		{
			if (state == WIFI_DIRECT_STATE_ACTIVATED ||
				state == WIFI_DIRECT_STATE_DISCOVERING)
				valid = true;
			else
				valid = false;
		}
		break;
	case WIFI_DIRECT_CMD_ACTIVATE_PUSHBUTTON:
	case WIFI_DIRECT_CMD_GET_SUPPORTED_WPS_MODE:
	case WIFI_DIRECT_CMD_GET_GO_INTENT:
	case WIFI_DIRECT_CMD_SET_GO_INTENT:
	case WIFI_DIRECT_CMD_IS_DISCOVERABLE:
	case WIFI_DIRECT_CMD_IS_LISTENING_ONLY:
	case WIFI_DIRECT_CMD_GET_OWN_GROUP_CHANNEL:
	case WIFI_DIRECT_CMD_GET_PERSISTENT_GROUP_INFO:
	case WIFI_DIRECT_CMD_REMOVE_PERSISTENT_GROUP:
		{
			if (state == WIFI_DIRECT_STATE_DEACTIVATED ||
				state == WIFI_DIRECT_STATE_DEACTIVATING ||
				state == WIFI_DIRECT_STATE_ACTIVATING)
				valid = false;
			else
				valid = true;
		}
		break;

	case WIFI_DIRECT_CMD_CANCEL_GROUP:
		{
			if (state == WIFI_DIRECT_STATE_GROUP_OWNER)
				valid = true;
			else if ((state == WIFI_DIRECT_STATE_CONNECTING) && (wfd_server->autonomous_group_owner == true))
				valid = true;
			else
				valid = false;
		}
		break;

	case WIFI_DIRECT_CMD_DISCONNECT:
		{
			if (state == WIFI_DIRECT_STATE_GROUP_OWNER ||
				state == WIFI_DIRECT_STATE_CONNECTED ||
				state == WIFI_DIRECT_STATE_CONNECTING)
				valid = true;
			else
				valid = false;
		}
		break;

	default:
		valid = true;
		break;
	}

	__WFD_SERVER_FUNC_EXIT__;

	return valid;
}


void start_wifi_direct_service()
{
	__WFD_SERVER_FUNC_ENTER__;

	//system("launch_app com.samsung.fileshare-service");
	service_h service;
	service_create(&service);
	service_set_operation(service, SERVICE_OPERATION_DEFAULT);
	service_set_package(service, "com.samsung.fileshare-service");
	service_send_launch_request(service, NULL, NULL);
	service_destroy(service);

	__WFD_SERVER_FUNC_EXIT__;
	
}

void stop_wifi_direct_service()
{
	// 2012-01-04: Dongwook. Let ftm-serviced quit by itself for gracefull termination.
	// system("killall ftm-serviced");
}

void start_wifi_direct_ui_appl()
{
	__WFD_SERVER_FUNC_ENTER__;

	//system("launch_app com.samsung.wifi-direct-popup");
	service_h service;
	service_create(&service);
	service_set_operation(service, SERVICE_OPERATION_DEFAULT);
	service_set_package(service, "com.samsung.wifi-direct-popup");
	service_send_launch_request(service, NULL, NULL);
	service_destroy(service);

	__WFD_SERVER_FUNC_EXIT__;

}


void stop_wifi_direct_ui_appl()
{
	// 2012-02-24: Dongwook. Let wifi-direct-popup quit by itself for gracefull termination.
	// system("killall wifi-direct-popup");
}



void wfd_server_set_state(int state)
{
	wfd_server_control_t *wfd_server = wfd_server_get_control();

	__WFD_SERVER_FUNC_ENTER__;

	if (state < WIFI_DIRECT_STATE_DEACTIVATED
		|| state > WIFI_DIRECT_STATE_GROUP_OWNER)
	{
		WFD_SERVER_LOG(WFD_LOG_ASSERT, "Error : Invalid State\n");
		return;
	}

	WFD_SERVER_LOG(WFD_LOG_ASSERT, "State Change: [%d,%s] ---->[%d,%s]\n",
				   wfd_server->state, wfd_print_state(wfd_server->state),
				   state, wfd_print_state(state));

	if (wfd_server->state != WIFI_DIRECT_STATE_CONNECTING &&
		state == WIFI_DIRECT_STATE_CONNECTING)
	{

		// stop timer for discover
		wfd_timer_discovery_cancel();

		// start timer for connection
		wfd_timer_connection_start();
	}

	if (wfd_server->state < WIFI_DIRECT_STATE_CONNECTED &&
		state >= WIFI_DIRECT_STATE_CONNECTED)
	{
		start_wifi_direct_service();
	}

	if (wfd_server->state == WIFI_DIRECT_STATE_CONNECTING &&
		state != WIFI_DIRECT_STATE_CONNECTING)
	{
		// stop timer for connection
		wfd_timer_connection_cancel();
	}

	if (wfd_server->state >= WIFI_DIRECT_STATE_CONNECTED &&
		state < WIFI_DIRECT_STATE_CONNECTED)
	{
		stop_wifi_direct_service();
	}

	if (wfd_server->state != WIFI_DIRECT_STATE_DEACTIVATED &&
		state == WIFI_DIRECT_STATE_DEACTIVATED)
	{
		wfd_termination_timer_start();
		wfd_timer_discovery_cancel();
	}
	else
	{
		wfd_termination_timer_cancel();
	}

	if (wfd_server->state < WIFI_DIRECT_STATE_ACTIVATED &&
		state == WIFI_DIRECT_STATE_ACTIVATED)
	{
		start_wifi_direct_ui_appl();
	}

	// Reset autonomous group owner flag
	if (wfd_server->state == WIFI_DIRECT_STATE_GROUP_OWNER &&
		state != WIFI_DIRECT_STATE_GROUP_OWNER)
	{
		if (wfd_server->autonomous_group_owner == true)
		{
			WFD_SERVER_LOG(WFD_LOG_LOW, "[Reset autonomous group owner flag]\n");
			wfd_server->autonomous_group_owner = false;
		}
	}


	wfd_server->state = state;

#if 0
	// Check discovery state...
	if (state == WIFI_DIRECT_STATE_ACTIVATED
		&& wfd_oem_is_discovery_enabled() == true)
	{
		WFD_SERVER_LOG(WFD_LOG_LOW, "state is changed to [WIFI_DIRECT_STATE_DISCOVERING]\n");
		wfd_server->state = WIFI_DIRECT_STATE_DISCOVERING;
	}
#endif

	switch (wfd_server->state)
	{
		//if (wfd_check_wifi_direct_state() < 0)
		//WFD_SERVER_LOG(WFD_LOG_ASSERT, "wfd_check_wifi_direct_state() failed\n");

	case WIFI_DIRECT_STATE_DEACTIVATED:
		{
			if (wfd_set_wifi_direct_state(VCONFKEY_WIFI_DIRECT_DEACTIVATED) < 0)
				WFD_SERVER_LOG(WFD_LOG_ASSERT, "wfd_set_wifi_direct_state() failed\n");
			else
				stop_wifi_direct_ui_appl();
		}
		break;

	case WIFI_DIRECT_STATE_ACTIVATED:
		{
			if (wfd_set_wifi_direct_state(VCONFKEY_WIFI_DIRECT_ACTIVATED) < 0)
				WFD_SERVER_LOG(WFD_LOG_ASSERT, "wfd_set_wifi_direct_state() failed\n");
		}
		break;

	case WIFI_DIRECT_STATE_DISCOVERING:
		{
			if (wfd_set_wifi_direct_state(VCONFKEY_WIFI_DIRECT_DISCOVERING) < 0)
				WFD_SERVER_LOG(WFD_LOG_ASSERT, "wfd_set_wifi_direct_state() failed\n");
		}
		break;

	case WIFI_DIRECT_STATE_CONNECTED:
		{
			if (wfd_set_wifi_direct_state(VCONFKEY_WIFI_DIRECT_CONNECTED) < 0)
				WFD_SERVER_LOG(WFD_LOG_ASSERT, "wfd_set_wifi_direct_state() failed\n");
		}
		break;

	case WIFI_DIRECT_STATE_GROUP_OWNER:
		{
			if (wfd_set_wifi_direct_state(VCONFKEY_WIFI_DIRECT_GROUP_OWNER) < 0)
				WFD_SERVER_LOG(WFD_LOG_ASSERT, "wfd_set_wifi_direct_state() failed\n");
		}
		break;

	// for Net-Config can check the status of wifi-direct 
	case WIFI_DIRECT_STATE_ACTIVATING:
		{
			if (wfd_set_wifi_direct_state(VCONFKEY_WIFI_DIRECT_ACTIVATED) < 0)
				WFD_SERVER_LOG(WFD_LOG_ASSERT, "wfd_set_wifi_direct_state() failed\n");
		}
		break;

	default:
		break;
	}

	__WFD_SERVER_FUNC_EXIT__;

	return;
}

int wfd_server_get_state()
{
	wfd_server_control_t *wfd_server = wfd_server_get_control();
	return wfd_server->state;
}
