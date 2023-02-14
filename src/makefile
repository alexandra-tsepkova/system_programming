all: build setup

build:  main.c fntf_detect.c
	gcc main.c fntf_detect.c -o my_detector

setup:
	cp my_detector /usr/local/bin/
	cp my_detector.service /etc/systemd/system/
	systemctl enable my_detector.service
	systemctl start my_detector.service

status:
	systemctl status my_detector.service

stop:
	systemctl stop my_detector.service
