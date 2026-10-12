---
title: Готовые фильтры
lead: Выражения под типовые задачи. Скопируйте, подставьте свои адреса и порты.
---

Синтаксис описан в разделе [фильтры отображения](filters.md), все поля — в [справочнике](filter-fields.md).

## Адреса и узлы

| Задача | Фильтр |
|---|---|
| Весь трафик узла | `ip.addr == 10.10.1.15` |
| Только исходящий от узла | `ip.src == 10.10.1.15` |
| Между двумя узлами | `ip.addr == 10.10.1.15 && ip.addr == 10.10.4.21` |
| Вся подсеть | `ip.addr == 10.10.0.0/16` |
| Всё, кроме узла | `ip.addr != 10.10.1.15` |
| Трафик наружу из локальной сети | `ip.src == 192.168.0.0/16 && ip.dst != 192.168.0.0/16` |
| По MAC-адресу | `eth.addr == 00:1f:1a:2b:3c:01` |
| Широковещательные кадры | `eth.dst == ff:ff:ff:ff:ff:ff` |
| Групповые (multicast) кадры | `eth.ig == 1` |
| IPv6 link-local | `ipv6.addr == fe80::/10` |

## Порты и протоколы

| Задача | Фильтр |
|---|---|
| Один порт TCP | `tcp.port == 443` |
| Несколько портов | `tcp.port in {80 443 8080 8443}` |
| Порт назначения | `tcp.dstport == 22` |
| Диапазон портов | `tcp.dstport >= 49152 && tcp.dstport <= 65535` |
| Только DNS и DHCP | `dns or dhcp` |
| Всё, кроме ARP и ICMP | `!arp && !icmp && !icmpv6` |
| Только IPv6 | `ipv6` |
| Кадры с меткой VLAN 100 | `vlan.id == 100` |

## TCP: соединения

| Задача | Фильтр |
|---|---|
| Начало соединений (первый SYN) | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| Ответы сервера на SYN | `tcp.flags.syn == 1 && tcp.flags.ack == 1` |
| Сбросы соединений | `tcp.flags.reset == 1` |
| Завершения соединений | `tcp.flags.fin == 1` |
| Все пакеты одного потока | `tcp.stream == 8` |
| Только пакеты с данными | `tcp.len > 0` |
| Пакеты без данных (чистые ACK) | `tcp && tcp.len == 0 && tcp.flags.syn == 0 && tcp.flags.fin == 0 && tcp.flags.reset == 0` |

## TCP: проблемы

| Задача | Фильтр |
|---|---|
| Любая пометка анализа | `tcp.analysis.flags` |
| Только настоящие проблемы | `tcp.analysis.flags && !tcp.analysis.window_update && !tcp.analysis.keep_alive` |
| Повторные передачи | `tcp.analysis.retransmission` |
| Быстрые повторные передачи | `tcp.analysis.fast_retransmission` |
| Дубликаты ACK | `tcp.analysis.duplicate_ack` |
| Сегменты не по порядку | `tcp.analysis.out_of_order` |
| Пропуски в захвате | `tcp.analysis.lost_segment` |
| Нулевое окно | `tcp.analysis.zero_window` |
| Медленные подтверждения (дольше 200 мс) | `tcp.analysis.ack_rtt > 0.2` |
| Проблемы одного узла | `tcp.analysis.flags && ip.addr == 10.10.1.15` |

## DNS

| Задача | Фильтр |
|---|---|
| Запросы | `dns.flags.response == 0` |
| Ответы | `dns.flags.response == 1` |
| Запросы имени | `dns.qry.name == api.example.com` |
| Имена, содержащие слово | `dns.qry.name contains "example"` |
| Ошибки в ответах | `dns.flags.response == 1 && dns.flags.rcode != 0` |
| «Нет такого имени» (NXDOMAIN) | `dns.flags.rcode == 3` |
| Запросы IPv6-адресов (AAAA) | `dns.qry.type == 28` |
| Ответы с конкретным адресом | `dns.a == 10.10.4.21` |
| Обрезанные ответы | `dns.flags.truncated == 1` |

## HTTP

| Задача | Фильтр |
|---|---|
| Запросы | `http.request` |
| Ответы | `http.response` |
| Запросы к хосту | `http.host == api.example.com` |
| Метод POST | `http.request.method == POST` |
| Адрес содержит строку | `http.request.uri contains "/login"` |
| Ошибки клиента и сервера | `http.response.code >= 400` |
| Только ошибки сервера | `http.response.code >= 500` |
| Перенаправления | `http.response.code in {301 302 303 307 308}` |
| По User-Agent | `http.user_agent contains "curl"` |
| С заголовком Authorization | `http.authorization` |
| С cookie | `http.cookie or http.set_cookie` |

## TLS

| Задача | Фильтр |
|---|---|
| Все рукопожатия ClientHello | `tls.handshake.type == 1` |
| ServerHello | `tls.handshake.type == 2` |
| Сертификаты | `tls.handshake.type == 11` |
| Соединения с сервером по имени | `tls.handshake.extensions_server_name contains "example"` |
| Клиент предлагает TLS 1.3 | `tls.handshake.extensions.supported_version == 0x0304` |
| Оповещения (alert) | `tls.alert_message.level` |
| Фатальные оповещения | `tls.alert_message.level == 2` |
| Сертификат на имя | `x509sat.subject.cn contains "example"` |
| TLS не на стандартном порту | `tls && tcp.port != 443` |

## ICMP

| Задача | Фильтр |
|---|---|
| Ping: запросы | `icmp.type == 8` |
| Ping: ответы | `icmp.type == 0` |
| Узел или порт недоступен | `icmp.type == 3` |
| Истекло время жизни (traceroute) | `icmp.type == 11` |
| Требуется фрагментация | `icmp.type == 3 && icmp.code == 4` |
| Ошибки ICMPv6 | `icmpv6.type < 128` |

## ARP и DHCP

| Задача | Фильтр |
|---|---|
| ARP-запросы | `arp.opcode == 1` |
| ARP-ответы | `arp.opcode == 2` |
| Кто спрашивает адрес | `arp.dst.proto_ipv4 == 10.10.0.1` |
| Самообъявления (gratuitous) | `arp.isgratuitous == 1` |
| DHCP Discover | `dhcp.option.dhcp == 1` |
| DHCP Offer и ACK | `dhcp.option.dhcp in {2 5}` |
| DHCP NAK | `dhcp.option.dhcp == 6` |
| По имени клиента | `dhcp.option.hostname contains "ws-"` |
| Выданный адрес | `dhcp.ip.your == 10.10.1.77` |

## Время и размер

| Задача | Фильтр |
|---|---|
| Отрезок по времени от начала | `frame.time_relative >= 10 && frame.time_relative <= 20` |
| Пауза перед пакетом больше секунды | `frame.time_delta > 1` |
| Крупные пакеты | `frame.len > 1400` |
| Диапазон номеров | `frame.number >= 100 && frame.number <= 200` |
| Малое время жизни | `ip.ttl < 5` |
| Фрагменты IP | `ip.flags.mf == 1 or ip.frag_offset > 0` |

Диапазон времени проще выделить мышью на [I/O-графике](statistics.md) или [временной шкале](timeline.md) — фильтр подставится сам.

## Поиск по содержимому

| Задача | Фильтр |
|---|---|
| Текст в данных TCP | `tcp.payload contains "password"` |
| Байты в данных TCP | `tcp.payload contains 16:03:01` |
| Текст в данных UDP | `udp.payload contains "M-SEARCH"` |
| Повреждённые пакеты | `_ws.malformed` |
| Нераспознанные данные | `data` |

Поиск по содержимому читает и разбирает каждый пакет, поэтому на больших захватах он медленный. Сузьте его быстрым условием: `tcp.port == 80 && tcp.payload contains "password"`.
