#!/bin/bash

pgrep skydive | xargs sudo kill

./skydive analyzer &

./skydive agent -c etc/skydive.yml &
