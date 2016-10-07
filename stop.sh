#!/bin/bash

if [ -e .procid ]; then
	procid=$(<.procid)
	kill -9 $procid
	if [ $? -eq 0 ]; then
		echo Stopped/Killed process: $procid 
	else
		echo Failed to Stop/Kill process: $procid 
	fi
else
	echo "No info available about the previouse launch!"
fi
