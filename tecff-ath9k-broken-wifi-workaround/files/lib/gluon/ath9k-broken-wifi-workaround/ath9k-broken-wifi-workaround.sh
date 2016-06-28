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
WIFICONNECTIONS=0
# check if there are connections to other nodes via wireless meshing
if [ "$(batctl o | egrep "ibss0|mesh0" | wc -l)" -gt 0 ]; then
	WIFICONNECTIONS=1
	echo "found wifi mesh partners."
elif [ "$(batctl tl | grep W | wc -l)" -gt 0 ]; then
	# note: this doesn't help if the clients are on 5GHz, which might be unaffected by the bug
	WIFICONNECTIONS=1
	echo "found batman local clients."
else
	PIPE=$(mktemp -u -t workaround-pipe-XXXXXX)
	# check for clients on private wifi device
	mkfifo $PIPE
	iw dev | grep "Interface wlan0" | cut -d" " -f2 > $PIPE &
	while read wifidev; do
		iw dev $wifidev station dump 2>/dev/null | grep -q Station
		if [ "$?" == "0" ]; then
			WIFICONNECTIONS=1
			echo "found wifi clients."
			break
		fi
	done < $PIPE
	rm $PIPE
fi
TMPFILE="/tmp/wifi-connections-active"
# restart wifi only, if there were connections after the last wifi restart or reboot and they vanished again
if [ ! -f "$TMPFILE" ] && [ "$WIFICONNECTIONS" -eq 1 ]; then
	echo "there are connections again after a previous boot or wifi restart, creating tempfile."
	touch $TMPFILE
elif [ -f "$TMPFILE" ] && [ "$WIFICONNECTIONS" -eq 0 ]; then
	# there were connections before, but they disappeared since the last check
	wifi
	echo "$(date +%Y-%m-%d:%H:%M:%S)" > /tmp/wifi-last-restart
	echo "there were connections before, but they vanished. restarted wifi and deleting tempfile."
	rm $TMPFILE
else
	echo "everything seems to be ok."
fi
