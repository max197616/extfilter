#!/bin/sh

cp extfilter.service /etc/systemd/system/
systemctl daemon-reload
#systemctl enable extfilter
#systemctl start extfilter
