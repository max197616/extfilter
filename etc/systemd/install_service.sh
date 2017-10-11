#!/bin/sh

cp extfilter.service /etc/systemd/system/
cp dpdk-devbind.service /etc/systemd/system/
cp igb_uio_module.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable dpdk-devbind
systemctl enable igb_uio_module
#systemctl enable extfilter
#systemctl start extfilter
