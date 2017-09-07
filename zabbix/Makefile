all: main.c getdata.c
	gcc -v -O2 main.c getdata.c -o zabbix_data
install: zabbix_data
	cp zabbix_data /usr/local/bin

