#!/bin/sh
# check if node has wifi
if [ ! -L /sys/class/ieee80211/phy0/device/driver ] && [ ! -L /sys/class/ieee80211/phy1/device/driver ]; then
	echo "node has no wifi, aborting."
	exit
fi
# check if node uses ath9k wifi driver
if ! expr "$(readlink /sys/class/ieee80211/phy0/device/driver)" : ".*/ath9k" >/dev/null; then
	if ! expr "$(readlink /sys/class/ieee80211/phy1/device/driver)" : ".*/ath9k" >/dev/null; then
		echo "node doesn't use the ath9k wifi driver, aborting."
		exit
	fi
fi
# don't do anything while an autoupdater process is running
pgrep autoupdater >/dev/null
if [ "$?" == "0" ]; then
	echo "autoupdater is running, aborting."
	exit
fi
# check if the queue is stopped because it got full
if [ "$(grep BE /sys/kernel/debug/ieee80211/phy0/ath9k/queues | cut -d":" -f7 | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')" -eq 0 ]; then
	STOPPEDQUEUE=0
else
	STOPPEDQUEUE=1
	echo "observed a stopped queue. continuing."
fi
# check if there are calibration errors
if [ "$(grep Calibration /sys/kernel/debug/ieee80211/phy0/ath9k/reset | cut -d":" -f2 | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')" -eq 0  ]; then
	CALIBERRORS=0
else
	CALIBERRORS=1
	echo "observed a calibration error. continuing."
fi
# abort if neither stopped queue nor calibration errors appeared
if [ "$STOPPEDQUEUE" -eq 0 ] && [ "$CALIBERRORS" -eq 0 ]; then
	echo "no errors observed, aborting."
	exit
fi
# check if there are connections to other nodes via wireless meshing
batctl o | egrep -q "ibss0|mesh0"
if [ "$?" == "0" ]; then
	MESHPARTNERS="1"
	echo "found wifi mesh partners."
fi
# check for clients on each wifi device
iw dev | grep Interface | cut -d" " -f2 | while read wifidev; do
	iw dev $wifidev station dump 2>/dev/null | grep -q Station
	if [ "$?" == "0" ]; then
		WIFICLIENTS="1"
		echo "found clients on wifi device $wifidev."
	fi
done
TMPFILE="/tmp/wifi-connections-active"
# restart wifi only, if there were connections after the last wifi restart and they vanished again
if [ "$MESHPARTNERS" == "1" ] || [ "$WIFICLIENTS" == "1" ]; then
	if [ -f "$TMPFILE" ]; then
		echo "everything seems to be ok, aborting."
		exit
	else
		echo "there are clients again after a previous boot or wifi restart, creating tempfile."
		touch $TMPFILE
		exit
	fi
else
	if [ -f "$TMPFILE" ]; then
		wifi
		echo "$(date +%Y-%m-%d:%H:%M:%S)" > /tmp/wifi-last-restart-reasons-calib${CALIBERRORS}-queue${STOPPEDQUEUE}
		echo "there were clients before, but they vanished. restarted wifi and deleting tempfile."
		rm $TMPFILE
	fi
fi
