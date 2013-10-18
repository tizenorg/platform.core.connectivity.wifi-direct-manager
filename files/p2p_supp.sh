#!/bin/sh

start()
{
	HARDWARE_MODEL=`grep Hardware /proc/cpuinfo | awk "{print \\$3}"`
	/bin/echo "Hardware Model=${HARDWARE_MODEL}"

	case $HARDWARE_MODEL in
		"SLP_PQ")	/bin/echo "This is PQ"
			/usr/sbin/wpa_supplicant -t -B -ddd -g/var/run/wpa_global -f/var/log/p2p_supplicant.log
		;;
		"U1SLP" | "U1HD")	/bin/echo "This is U1SLP"
			/usr/sbin/wpa_supplicant -t -B -ddd -Dwext -f/var/log/p2p_supplicant.log
		;;
		"SLP7_C210")	/bin/echo "This is C210"
			/usr/sbin/wpa_supplicant -t -B -ddd -Dwext -f/var/log/p2p_supplicant.log
		;;
		"SLP10_C210")
			/usr/sbin/wpa_supplicant -t -B -ddd -Dwext -f/var/log/p2p_supplicant.log
		;;
		*)
			/usr/sbin/wpa_supplicant -t -B -ddd -g/var/run/wpa_global -f/var/log/p2p_supplicant.log
		;;
	esac
}

stop()
{
	killall wpa_supplicant
}

case $1 in
"start")
start
;;
"stop")
stop
;;
*)
/bin/echo p2p_supp.sh [start] [stop]
exit 1
;;
esac
