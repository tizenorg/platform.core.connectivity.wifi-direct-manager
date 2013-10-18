#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>

#include "wifi-direct-oem.h"
#include "wfd-plugin-wpasupplicant.h"


static struct wfd_oem_ops supplicant_ops = {
	.init = ws_init,
	.deinit = ws_deinit,
	.activate = ws_activate,
	.deactivate = ws_deactivate,

	.start_scan = ws_start_scan,
	.stop_scan = ws_stop_scan,
	.get_visibility = ws_get_visibility,
	.set_visibility = ws_set_visibility,
	.get_scan_result = ws_get_scan_result,
	.get_peer_info = ws_get_peer_info,

	.prov_disc_req = ws_prov_disc_req,

	.connect = ws_connect;
	.disconnect = ws_disconnect,
	.reject_connection = ws_reject_connection,
	.cancel_connection = ws_cancel_connection,
	.get_connected_peers = ws_get_connected_peers,
	.get_pin = ws_get_pin,
	.set_pin = ws_set_pin,
	.get_supported_wps_mode = ws_get_supported_wps_mode,

	.create_group = ws_create_group,
	.destroy_group = ws_destroy_group,
	.invite = ws_invite,
	.wps_start = ws_wps_start,

	.get_dev_name = ws_get_dev_name,
	.set_dev_name = ws_set_dev_name,
	.get_dev_mac = ws_get_dev_mac,
	.get_dev_type = ws_get_dev_type,
	.set_dev_type = ws_set_dev_type,
	.get_go_intent = ws_get_go_intent,
	.set_go_intent = ws_set_go_intent,
	.get_persistent_groups = ws_get_persistent_groups,
	.remove_persistent_group = ws_remove_persistent_group,
	.set_persistent_reconnect = ws_set_persistent_reconnect,
	};

static ws_plugin_data_s *g_pd;

int wfd_plugin_load( struct wfd_oem_ops_s **ops)
{

	return -1;
}

int ws_init(wfd_oem_event_cb callback, void *user_data)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_deinit()
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_activate()
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_deactivate()
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_start_scan(wfd_oem_scan_param_s *param)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_stop_scan()
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_get_visibility(int *visibility)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_set_visibility(int visibility)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_get_scan_result(GList **peers, int *peer_count)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_get_peer_info(const char *peer_addr, wfd_oem_device_s **peer)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_prov_disc_req(unsigned char *peer_addr, wfd_oem_wps_mode_e wps_mode, int join)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_connect(const char *peer_addr, wfd_oem_conn_param_s *param)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_disconnect(const char *peer_addr)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_reject_connection(unsigned char *peer_addr)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_cancel_connection(unsigned char *peer_addr)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_get_connected_peers(GList **peers, int *peer_count)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_get_pin(char *pin)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_set_pin(char *pin)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_get_supported_wps_mode()
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_create_group(int persistent, int freq)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_destroy_group(const char *ifname)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_invite(const char *peer_addr, wfd_oem_invite_param_s *param)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

// Only group owner can use this command
int ws_wps_start(const char *peer_addr, int wps_mode, const char *pin)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_get_dev_name(char *dev_name)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_set_dev_name(char *dev_name)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_get_dev_mac(char *dev_mac)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_get_dev_type(int *pri_dev_type, int *sec_dev_type)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_set_dev_type(int pri_dev_type, int sec_dev_type)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_get_go_intent(int *go_intent)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_set_go_intent(int go_intent)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_get_persistent_groups(wfd_oem_persistent_group_s **groups, int *group_count)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_remove_persistent_group(const char *bssid)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

int ws_set_persistent_reconnect(const char *bssid, int reconnect)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}
