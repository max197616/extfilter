
extFilter
===========
Application for blocking websites from Roskomnadzor [blacklist] registry with DPDK.

Featureset
----------
Application blocks certain sites via analysing mirrored client’s traffic.
In case requested HTTP site is found in blacklist, client request will be redirected to a special web page or request connection will be dropped.
HTTPS blocking is based on domain name (or IP) in client hello of request. In case requested HTTPS site is found in blacklist, client request connection will be dropped.
For sending data to client you need configured IP interface which is managed by OS core.
Additionally, notify function is presented in application, one is able to notify clients with periodic redirect to a special page.

Requirements
----------
Application requires:

- [Poco](https://pocoproject.org) >= 1.6
- [DPDK](https://dpdk.org) = 17.05.01
- git

Make
------
- [Install and setup DPDK](http://dpdk.org/doc/quick-start)
- Generate configure
```bash
./autogen.sh
```
- Run configure
```bash
./configure --with-dpdk_target=<target> --with-dpdk_home=<path_to_compiled_dpdk>
```
- Make application
```bash
make
```

DPDK setup
--------------
For DPDK to work correctly, huge-pages has to be setup and enabled and NICs have to be bound in DPDK

Excample for CentOS 7:

- Create dpdk-tune directory in /usr/lib/tuned

- Create file tuned.conf in dpdk-tune directory with following contents:
```
[main]
include=latency-performance

[bootloader]
cmdline=isolcpus=1,2,3 default_hugepagesz=1G hugepagesz=1G hugepages=4
```
isolcpus=1,2,3 - Cores to be used with dpdk/extfilter.
default_hugepagesz=1G hugepagesz=1G - Memory page size for dpdk/extfilter.
hugepages=4 - Number of memory pages for dpdk/extfilter (4GB in this example case).

- Activate profile
```bash
tuned-adm profile dpdk-tune
```

- Reboot server.

- Load necessary drivers by using commands below:
```bash
modprobe uio
insmod /path/to/dpdk/build/kmod/igb_uio.ko
```

- Bind NIC to dpdk
```bash
/path/to/dpdk/usertools/dpdk-devbind.py --bind=igb_uio dev_pci_num
```
You can get dev_pci_num with command:
```bash
/path/to/dpdk/usertools/dpdk-devbind.py --status
```


Run
------
All application settings are defined in configuration file.
For application running you should define configuration file with CLI option: --config-file <path/to/config_file>
For setup daemon mode use CLI options: --daemon --pidfile=</path/to/file.pid>

Blacklist files
------------------------
Blacklist files format is [nfqfilter](https://github.com/max197616/nfqfilter).

Blacklist updates
-----------------------------
Use SIGHUP for rereading updated blacklists without daemon restart.

Project support
------
If you would like to support project just donate to Yandex.Money wallet: 410014706910423
