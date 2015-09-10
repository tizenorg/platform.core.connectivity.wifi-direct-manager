#!/bin/sh
INTERFACE_NAME="wlan0"
INTERFACE_PREFIX="wlan"
DEFAULT_IP="192.168.49.1"
DEFAULT_NET="192.168.49.1/24"
DEFAULT_BRD="192.168.49.255"

interface=`/sbin/ifconfig|/bin/grep ^${INTERFACE_NAME}|/usr/bin/cut -d" " -f1`
#interface=`/sbin/ifconfig|/bin/grep ^${INTERFACE_NAME}|/usr/bin/cut -d":" -f1`
#interface=`/usr/sbin/ip link|/bin/grep ^${INTERFACE_NAME}|/usr/bin/cut -d":" -f2`
echo "interface is ${INTERFACE_PREFIX}: ${interface}."

start_dhcp_server()
{
	if [ "X${interface}" == "X" ]; then
		echo "interface(${INTERFACE_PREFIX}) is not up"
		return 0
	fi

	/bin/rm /var/lib/misc/udhcpd.leases
	/bin/touch /var/lib/misc/udhcpd.leases
	/sbin/ifconfig ${INTERFACE_NAME} ${DEFAULT_IP} up
	/usr/sbin/ip addr add ${DEFAULT_NET} brd ${DEFAULT_BRD} dev ${interface}
	/usr/sbin/dhcpd /usr/etc/wifi-direct/dhcpd.${INTERFACE_PREFIX}.conf -f &

	route=`/bin/cat /usr/etc/wifi-direct/dhcpd.${INTERFACE_PREFIX}.conf | /bin/grep router | /bin/awk '{print $3}'`
	if [ -z $route ]; then
		route="192.168.49.1"
	fi
	subnet=`/bin/cat /usr/etc/wifi-direct/dhcpd.${INTERFACE_PREFIX}.conf | /bin/grep subnet | /bin/awk '{print $3}'`

	if [ -z $subnet ]; then
		subnet="255.255.255.0"
	fi

	/usr/bin/vconftool set -t string memory/private/wifi_direct_manager/p2p_ifname ${interface} -f
	/usr/bin/vconftool set -t string memory/private/wifi_direct_manager/p2p_subnet_mask ${subnet} -f
	/usr/bin/vconftool set -t string memory/private/wifi_direct_manager/p2p_gateway ${route} -f
	/usr/bin/vconftool set -t string memory/private/wifi_direct_manager/p2p_local_ip ${DEFAULT_IP} -f
}

start_dhcp_client()
{
	if [ "X${interface}" == "X" ]; then
		echo "interface(${INTERFACE_PREFIX}) is not up"
		return 0
	fi

	/usr/bin/vconftool set -t string memory/private/wifi_direct_manager/dhcpc_server_ip "0.0.0.0" -f
	/usr/bin/dhcp -i ${INTERFACE_NAME} -s /usr/etc/wifi-direct/udhcp_script.non-autoip &
}


clean_vconfs()
{
	/usr/bin/vconftool set -t string memory/private/wifi_direct_manager/p2p_ifname "" -f
	/usr/bin/vconftool set -t string memory/private/wifi_direct_manager/p2p_subnet_mask "" -f
	/usr/bin/vconftool set -t string memory/private/wifi_direct_manager/p2p_gateway "" -f
	/usr/bin/vconftool set -t string memory/private/wifi_direct_manager/p2p_local_ip "" -f
	/usr/bin/vconftool set -t string memory/private/wifi_direct_manager/dhcpc_server_ip "0.0.0.0" -f
}

stop_dhcp()
{
	/usr/bin/pkill -x dhcp
	/usr/bin/pkill -x dhcpd
	/sbin/ifconfig ${interface} 0.0.0.0
}

is_running()
{
	program=$1
	run=`/bin/ps -eo comm|/bin/grep ${program}`
	if [ "X${run}" == "X" ]; then
		echo "${program} is not running"
	else
		echo "${program} is already running"
	fi
}

status_dhcp()
{
	is_running /usr/bin/dhcp
	is_running /usr/sbin/dhcpd
}


case $1 in
"server")
stop_dhcp
start_dhcp_server
;;
"client")
clean_vconfs
stop_dhcp
start_dhcp_client
;;
"stop")
clean_vconfs
stop_dhcp
;;
"status")
status_dhcp
;;
*)
/bin/echo wifi-direct-dhcp.sh [server] [client] [stop] [status]
exit 1
;;
esac

