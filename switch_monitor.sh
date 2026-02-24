#!/bin/bash

set -e

usage() {
	echo "Usage: $0 {start|stop}"
	exit 1
}

if [ $# -ne 1 ]; then
	usage
fi

case "$1" in
	start)
		sudo airmon-ng check kill
		sudo airmon-ng start wlp4s0
		sudo iw wlp4s0mon set channel 6
		;;
	stop)
		sudo airmon-ng stop wlp4s0mon
		sudo systemctl restart NetworkManager
		;;
	*)
		usage
		;;
esac