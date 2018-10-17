# LoadBalancerTester
Test LoadBalancersfor routing misconfigs

Для тестирования ошибок в конфигурации балансировщиков.
Основная идея(подсказанная D0znpp)- взять список доменов и на каждый сходить с различными http-заголовками Host. 
А потом сравнить результаты с оригинальным ответом.

Скрипт берет файл с доменами и в мультипотоковом режиме собирает статистику (код и размер ответа) для каждого домена в режиме HTTP и HTTPS (оригинальный ответ).
Затем скрипт для каждого домена подставляет различные HTTP Host заголовки.
Итоговый результат выводится в виде таблицы для каждого домена. Строки с несовпадающими с оригинальным запросом результатами подствечиваются красным.

Есть возможность фильтровать коды ответов (например, не рассматривать 404-й код).

Usage:
./loadbalancer.py -d domains.txt

-d, --domainsfile  - domain names file
--hs - Do not show size filter
--hc - Do not show code filter
-A, --user-agent - User-Agents string
-p, --proxy - Proxy in http://127.0.0.1:8080 format
--xf - Filter exceptions. Disable checks for error-connection domains (if domain not resoved or connection time-out)
--debug - Show debug messages
-t, --threads - Threads num
--timeout - Request timeout in sec. Default 2
-f, --follow - Request follow redirectons

