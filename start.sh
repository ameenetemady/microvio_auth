#!/bin/bash
appName=${PWD##*/}
nodejs app.js >> out.txt 2>> err.txt &
procid=$!
echo $procid > .procid
echo $appName started with process id: $procid
