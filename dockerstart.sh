#!/bin/bash

echo "============================================="
echo "Starting Honeypot containers"
echo "============================================="

start_container(){
	NAME=$1
	PORT=$2

	docker start "$NAME" >/dev/null 2>&1

	if docker ps --format '{{.Names}}' | grep -q "^$NAME$"; then
	echo "$NAME is running -> port $PORT listening"
	else
	echo "$NAME failed to start"
	fi
}
start_container ntth-device 2222
start_container smb-honeypot 445
start_container http-hp 8080

echo "============================================="
