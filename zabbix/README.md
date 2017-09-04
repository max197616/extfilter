Это минимальный пакет для мониторинга extFilter через файл /var/run/extFilter_stat в zabbix.
Установка:
make && make install
Необходимо также установить zabbix-agent.

Затем добавить в файл /etc/zabbix/zabbix_agent.conf строку
UserParameter=extfilter.stat[*],zabbix_data $1
и перезапустить сервис агента.

Затем импорти ровать шаблон через WEB-интерфейс.