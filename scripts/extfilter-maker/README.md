extfilter-maker
===========
Скрипт для создания входных конфигурационных файлов программы extFilter.

Функционал
----------
Скрипт получает данные из БД, сформированные скриптом [zapret.pl](https://github.com/max197616/zapret) и формирует конфигурационные файлы. В случае наличия изменений в данных файлах, происходит перезапуск(использутеся systemd) extFilter.
