---
title: Справочник полей
lead: Все поля, по которым можно фильтровать, — 301 поле 18 протоколов.
---

Тот же список есть в программе: **Инструменты → Справочник полей фильтра**. Там он всегда соответствует установленной версии и в нём есть поиск.

Колонки таблиц:

- **Поле** — имя для [фильтра](filters.md);
- **Тип** — какие значения и операторы допустимы, см. [типы полей](filters.md);
- **Быстрое** — «да», если поле проверяется по индексу без разбора пакета.

Поля типа `protocol` и «наличие» пишутся без оператора: `dns`, `tcp.analysis.retransmission`.


## Кадр

Сведения о пакете в целом: номер, длина, время, интерфейс.

| Поле | Тип | Описание | Быстрое |
|---|---|---|---|
| `_ws.malformed` | protocol | Malformed Packet | да |
| `data` | protocol | Data | да |
| `data.data` | bytes | Данные |  |
| `data.len` | uint | Длина |  |
| `frame` | protocol | Frame | да |
| `frame.cap_len` | uint | Захваченная длина | да |
| `frame.encap_type` | string | Тип инкапсуляции |  |
| `frame.interface_id` | uint | Интерфейс | да |
| `frame.len` | uint | Длина кадра | да |
| `frame.number` | uint | Номер кадра | да |
| `frame.protocols` | string | Протоколы в кадре |  |
| `frame.time` | string | Время прихода |  |
| `frame.time_delta` | float | Время от предыдущего кадра |  |
| `frame.time_epoch` | float | Время (Unix epoch) |  |
| `frame.time_relative` | float | Время от первого кадра | да |

## Ethernet

| Поле | Тип | Описание | Быстрое |
|---|---|---|---|
| `eth` | protocol | Ethernet II | да |
| `eth.addr` | mac | Address | да |
| `eth.dst` | mac | Назначение | да |
| `eth.ig` | bool | Бит IG |  |
| `eth.len` | uint | Длина |  |
| `eth.lg` | bool | Бит LG |  |
| `eth.padding` | bytes | Padding |  |
| `eth.src` | mac | Источник | да |
| `eth.type` | uint | Тип |  |

## VLAN (802.1Q)

| Поле | Тип | Описание | Быстрое |
|---|---|---|---|
| `vlan` | protocol | 802.1Q Virtual LAN | да |
| `vlan.dei` | bool | DEI |  |
| `vlan.etype` | uint | Тип |  |
| `vlan.id` | uint | Идентификатор VLAN |  |
| `vlan.priority` | uint | Приоритет |  |

## Linux cooked capture (SLL)

| Поле | Тип | Описание | Быстрое |
|---|---|---|---|
| `sll` | protocol | Linux cooked capture | да |
| `sll.etype` | uint | Protocol |  |
| `sll.halen` | uint | Link-layer address length |  |
| `sll.hatype` | uint | Link-layer address type |  |
| `sll.ifindex` | uint | Interface index |  |
| `sll.pkttype` | uint | Packet type |  |
| `sll.src.eth` | mac | Source |  |

## Loopback

| Поле | Тип | Описание | Быстрое |
|---|---|---|---|
| `null` | protocol | Null/Loopback | да |
| `null.family` | uint | Family |  |

## ARP

| Поле | Тип | Описание | Быстрое |
|---|---|---|---|
| `arp` | protocol | Address Resolution Protocol | да |
| `arp.dst.hw_mac` | mac | MAC получателя |  |
| `arp.dst.proto_ipv4` | ipv4 | IP получателя |  |
| `arp.hw.size` | uint | Размер аппаратного адреса |  |
| `arp.hw.type` | uint | Тип оборудования |  |
| `arp.isgratuitous` | bool | Gratuitous ARP |  |
| `arp.opcode` | uint | Код операции |  |
| `arp.proto.size` | uint | Размер протокольного адреса |  |
| `arp.proto.type` | uint | Тип протокола |  |
| `arp.src.hw_mac` | mac | MAC отправителя |  |
| `arp.src.proto_ipv4` | ipv4 | IP отправителя |  |

## IPv4

| Поле | Тип | Описание | Быстрое |
|---|---|---|---|
| `ip` | protocol | Internet Protocol Version 4 | да |
| `ip.addr` | ipv4 | Source or Destination Address | да |
| `ip.checksum` | uint | Контрольная сумма заголовка |  |
| `ip.checksum.status` | string | Статус контрольной суммы |  |
| `ip.dsfield` | uint | Поле DS |  |
| `ip.dsfield.dscp` | uint | DSCP |  |
| `ip.dsfield.ecn` | uint | ECN |  |
| `ip.dst` | ipv4 | Адрес назначения | да |
| `ip.flags` | uint | Флаги |  |
| `ip.flags.df` | bool | Не фрагментировать |  |
| `ip.flags.mf` | bool | Есть ещё фрагменты |  |
| `ip.flags.rb` | bool | Зарезервированный бит |  |
| `ip.frag_offset` | uint | Смещение фрагмента |  |
| `ip.hdr_len` | uint | Длина заголовка |  |
| `ip.id` | uint | Идентификация |  |
| `ip.len` | uint | Общая длина |  |
| `ip.options` | bytes | Опции |  |
| `ip.proto` | uint | Протокол |  |
| `ip.src` | ipv4 | Адрес источника | да |
| `ip.ttl` | uint | TTL |  |
| `ip.version` | uint | Версия |  |

## IPv6

| Поле | Тип | Описание | Быстрое |
|---|---|---|---|
| `ipv6` | protocol | Internet Protocol Version 6 | да |
| `ipv6.addr` | ipv6 | Source or Destination Address | да |
| `ipv6.dst` | ipv6 | Адрес назначения | да |
| `ipv6.ext.len` | uint | Length |  |
| `ipv6.flow` | uint | Метка потока |  |
| `ipv6.fragment.id` | uint | Identification |  |
| `ipv6.fragment.more` | bool | More Fragments |  |
| `ipv6.fragment.offset` | uint | Offset |  |
| `ipv6.hlim` | uint | Hop Limit |  |
| `ipv6.nxt` | uint | Следующий заголовок |  |
| `ipv6.plen` | uint | Длина полезной нагрузки |  |
| `ipv6.src` | ipv6 | Адрес источника | да |
| `ipv6.tclass` | uint | Класс трафика |  |
| `ipv6.version` | uint | Версия |  |

## ICMP

| Поле | Тип | Описание | Быстрое |
|---|---|---|---|
| `icmp` | protocol | Internet Control Message Protocol | да |
| `icmp.checksum` | uint | Контрольная сумма |  |
| `icmp.code` | uint | Код |  |
| `icmp.data` | bytes | Данные |  |
| `icmp.ident` | uint | Идентификатор |  |
| `icmp.mtu` | uint | MTU of next hop |  |
| `icmp.redir_gw` | ipv4 | Gateway Address |  |
| `icmp.seq` | uint | Порядковый номер |  |
| `icmp.type` | uint | Тип |  |

## ICMPv6

| Поле | Тип | Описание | Быстрое |
|---|---|---|---|
| `icmpv6` | protocol | Internet Control Message Protocol v6 | да |
| `icmpv6.checksum` | uint | Контрольная сумма |  |
| `icmpv6.code` | uint | Код |  |
| `icmpv6.data` | bytes | Data |  |
| `icmpv6.echo.identifier` | uint | Идентификатор |  |
| `icmpv6.echo.sequence_number` | uint | Порядковый номер |  |
| `icmpv6.mtu` | uint | MTU |  |
| `icmpv6.nd.na.flag` | uint | Flags |  |
| `icmpv6.nd.ns.target_address` | ipv6 | Целевой адрес |  |
| `icmpv6.nd.ra.cur_hop_limit` | uint | Cur hop limit |  |
| `icmpv6.nd.ra.router_lifetime` | uint | Router lifetime (s) |  |
| `icmpv6.opt.linkaddr` | mac | Link-layer address |  |
| `icmpv6.type` | uint | Тип |  |

## TCP

Поля `tcp.analysis.*` — результаты анализа потока, а не байты пакета.

| Поле | Тип | Описание | Быстрое |
|---|---|---|---|
| `tcp` | protocol | Transmission Control Protocol | да |
| `tcp.ack` | uint | Номер подтверждения (Ack) |  |
| `tcp.ack_raw` | uint | Номер подтверждения (исходный) |  |
| `tcp.analysis.ack_lost_segment` | наличие | ACKed segment that wasn't captured | да |
| `tcp.analysis.ack_rtt` | float | RTT подтверждения сегмента |  |
| `tcp.analysis.duplicate_ack` | наличие | Duplicate ACK | да |
| `tcp.analysis.fast_retransmission` | наличие | This frame is a (suspected) fast retransmission | да |
| `tcp.analysis.flags` | наличие | TCP Analysis Flags | да |
| `tcp.analysis.keep_alive` | наличие | TCP keep-alive segment | да |
| `tcp.analysis.lost_segment` | наличие | Previous segment(s) not captured | да |
| `tcp.analysis.out_of_order` | наличие | This frame is a (suspected) out-of-order segment | да |
| `tcp.analysis.retransmission` | наличие | This frame is a (suspected) retransmission | да |
| `tcp.analysis.reused_ports` | наличие | A new tcp session is started with the same ports | да |
| `tcp.analysis.window_update` | наличие | TCP window update | да |
| `tcp.analysis.zero_window` | наличие | TCP Zero Window segment | да |
| `tcp.checksum` | uint | Контрольная сумма |  |
| `tcp.dstport` | uint | Порт назначения | да |
| `tcp.flags` | uint | Флаги | да |
| `tcp.flags.ack` | bool | Acknowledgment | да |
| `tcp.flags.ae` | bool | Accurate ECN | да |
| `tcp.flags.cwr` | bool | Congestion Window Reduced | да |
| `tcp.flags.ece` | bool | ECN-Echo | да |
| `tcp.flags.fin` | bool | Fin | да |
| `tcp.flags.push` | bool | Push | да |
| `tcp.flags.res` | bool | Reserved |  |
| `tcp.flags.reset` | bool | Reset | да |
| `tcp.flags.str` | string | Флаги TCP |  |
| `tcp.flags.syn` | bool | Syn | да |
| `tcp.flags.urg` | bool | Urgent | да |
| `tcp.hdr_len` | uint | Длина заголовка |  |
| `tcp.len` | uint | Длина сегмента |  |
| `tcp.nxtseq` | uint | Следующий порядковый номер |  |
| `tcp.options` | bytes | Опции |  |
| `tcp.options.mss_val` | uint | Значение MSS |  |
| `tcp.options.timestamp.tsecr` | uint | Timestamp echo reply |  |
| `tcp.options.timestamp.tsval` | uint | Timestamp value |  |
| `tcp.options.wscale.shift` | uint | Сдвиг масштаба окна |  |
| `tcp.payload` | bytes | Полезная нагрузка TCP |  |
| `tcp.port` | uint | Source or Destination Port | да |
| `tcp.segment_data` | bytes | Данные ретранслированного сегмента |  |
| `tcp.seq` | uint | Порядковый номер (Seq) |  |
| `tcp.seq_raw` | uint | Порядковый номер (исходный) |  |
| `tcp.srcport` | uint | Порт источника | да |
| `tcp.stream` | uint | Индекс потока | да |
| `tcp.time_relative` | float | Время от первого кадра потока |  |
| `tcp.urgent_pointer` | uint | Указатель срочности |  |
| `tcp.window_size` | uint | Расчётный размер окна |  |
| `tcp.window_size_scalefactor` | int | Коэффициент масштабирования окна |  |
| `tcp.window_size_value` | uint | Окно |  |

## UDP

| Поле | Тип | Описание | Быстрое |
|---|---|---|---|
| `udp` | protocol | User Datagram Protocol | да |
| `udp.checksum` | uint | Контрольная сумма |  |
| `udp.dstport` | uint | Порт назначения | да |
| `udp.length` | uint | Длина |  |
| `udp.payload` | bytes | UDP payload |  |
| `udp.port` | uint | Source or Destination Port | да |
| `udp.srcport` | uint | Порт источника | да |
| `udp.stream` | uint | Индекс потока | да |

## DNS

| Поле | Тип | Описание | Быстрое |
|---|---|---|---|
| `dns` | protocol | Domain Name System | да |
| `dns.a` | ipv4 | Адрес |  |
| `dns.aaaa` | ipv6 | Адрес AAAA |  |
| `dns.cname` | string | CNAME |  |
| `dns.count.add_rr` | uint | Дополнительных RR |  |
| `dns.count.answers` | uint | Ответов (RR) |  |
| `dns.count.auth_rr` | uint | Авторитетных RR |  |
| `dns.count.queries` | uint | Вопросов |  |
| `dns.flags` | uint | Флаги |  |
| `dns.flags.authoritative` | bool | Authoritative |  |
| `dns.flags.opcode` | uint | Opcode |  |
| `dns.flags.rcode` | uint | Reply code |  |
| `dns.flags.recavail` | bool | Recursion available |  |
| `dns.flags.recdesired` | bool | Recursion desired |  |
| `dns.flags.response` | bool | Response |  |
| `dns.flags.truncated` | bool | Truncated |  |
| `dns.id` | uint | Идентификатор транзакции |  |
| `dns.length` | uint | Length |  |
| `dns.mx.mail_exchange` | string | Mail Exchange |  |
| `dns.mx.preference` | uint | Preference |  |
| `dns.ns` | string | Name Server |  |
| `dns.ptr.domain_name` | string | Domain Name |  |
| `dns.qry.class` | uint | Класс |  |
| `dns.qry.name` | string | Имя |  |
| `dns.qry.type` | uint | Тип |  |
| `dns.rdata` | bytes | Data |  |
| `dns.resp.class` | uint | Класс |  |
| `dns.resp.len` | uint | Длина данных |  |
| `dns.resp.name` | string | Имя |  |
| `dns.resp.ttl` | uint | TTL |  |
| `dns.resp.type` | uint | Тип |  |
| `dns.soa.mname` | string | Primary name server |  |
| `dns.srv.port` | uint | Port |  |
| `dns.srv.target` | string | Target |  |
| `dns.txt` | string | TXT |  |

## DHCP

| Поле | Тип | Описание | Быстрое |
|---|---|---|---|
| `dhcp` | protocol | Dynamic Host Configuration Protocol | да |
| `dhcp.cookie` | uint | Magic cookie |  |
| `dhcp.file` | string | Boot file name |  |
| `dhcp.flags` | uint | Bootp flags |  |
| `dhcp.hops` | uint | Hops |  |
| `dhcp.hw.len` | uint | Hardware address length |  |
| `dhcp.hw.mac_addr` | mac | MAC клиента |  |
| `dhcp.hw.type` | uint | Hardware type |  |
| `dhcp.id` | uint | Идентификатор транзакции |  |
| `dhcp.ip.client` | ipv4 | IP клиента |  |
| `dhcp.ip.relay` | ipv4 | IP агента ретрансляции |  |
| `dhcp.ip.server` | ipv4 | IP следующего сервера |  |
| `dhcp.ip.your` | ipv4 | Выданный IP (yiaddr) |  |
| `dhcp.option.client_id` | bytes | Client identifier |  |
| `dhcp.option.dhcp` | uint | DHCP |  |
| `dhcp.option.dhcp_server_id` | ipv4 | Идентификатор DHCP-сервера |  |
| `dhcp.option.domain_name` | string | Domain Name |  |
| `dhcp.option.domain_name_server` | ipv4 | DNS-сервер |  |
| `dhcp.option.hostname` | string | Имя хоста |  |
| `dhcp.option.ip_address_lease_time` | uint | Срок аренды |  |
| `dhcp.option.request_list_item` | uint | Parameter Request List Item |  |
| `dhcp.option.requested_ip_address` | ipv4 | Запрошенный IP |  |
| `dhcp.option.router` | ipv4 | Маршрутизатор |  |
| `dhcp.option.subnet_mask` | ipv4 | Маска подсети |  |
| `dhcp.option.type` | uint | Option |  |
| `dhcp.option.vendor_class_id` | string | Vendor class identifier |  |
| `dhcp.secs` | uint | Seconds elapsed |  |
| `dhcp.server` | string | Server host name |  |
| `dhcp.type` | uint | Тип сообщения |  |

## HTTP

| Поле | Тип | Описание | Быстрое |
|---|---|---|---|
| `http` | protocol | Hypertext Transfer Protocol | да |
| `http.accept` | string | Accept |  |
| `http.authorization` | string | Authorization |  |
| `http.connection` | string | Connection |  |
| `http.content_length` | uint | Длина содержимого |  |
| `http.content_type` | string | Content-Type |  |
| `http.continuation` | bytes | Continuation |  |
| `http.cookie` | string | Cookie |  |
| `http.file_data` | bytes | Данные тела |  |
| `http.host` | string | Host |  |
| `http.location` | string | Location |  |
| `http.referer` | string | Referer |  |
| `http.request` | bool | Request |  |
| `http.request.line` | string | Request line |  |
| `http.request.method` | string | Метод |  |
| `http.request.uri` | string | URI |  |
| `http.request.version` | string | Версия |  |
| `http.response` | bool | Response |  |
| `http.response.code` | uint | Код состояния |  |
| `http.response.line` | string | Response line |  |
| `http.response.phrase` | string | Текст состояния |  |
| `http.response.version` | string | Версия |  |
| `http.server` | string | Server |  |
| `http.set_cookie` | string | Set-Cookie |  |
| `http.transfer_encoding` | string | Transfer-Encoding |  |
| `http.user_agent` | string | User-Agent |  |

## TLS

| Поле | Тип | Описание | Быстрое |
|---|---|---|---|
| `tls` | protocol | Transport Layer Security | да |
| `tls.alert_message.desc` | uint | Description |  |
| `tls.alert_message.level` | uint | Level |  |
| `tls.app_data` | bytes | Зашифрованные данные приложения |  |
| `tls.handshake.certificate` | bytes | Certificate |  |
| `tls.handshake.certificate_length` | uint | Certificate Length |  |
| `tls.handshake.certificates_length` | uint | Certificates Length |  |
| `tls.handshake.cipher_suites_length` | uint | Cipher Suites Length |  |
| `tls.handshake.ciphersuite` | uint | Набор шифров |  |
| `tls.handshake.comp_method` | uint | Compression Method |  |
| `tls.handshake.encrypted` | bytes | Encrypted Handshake Message |  |
| `tls.handshake.extension.len` | uint | Length |  |
| `tls.handshake.extension.type` | uint | Type |  |
| `tls.handshake.extensions.supported_version` | uint | Supported Version |  |
| `tls.handshake.extensions_alpn_str` | string | Протокол ALPN |  |
| `tls.handshake.extensions_length` | uint | Extensions Length |  |
| `tls.handshake.extensions_server_name` | string | Имя сервера (SNI) |  |
| `tls.handshake.extensions_supported_group` | uint | Supported Group |  |
| `tls.handshake.length` | uint | Длина |  |
| `tls.handshake.random` | bytes | Random |  |
| `tls.handshake.session_id` | bytes | Идентификатор сессии |  |
| `tls.handshake.sig_hash_alg` | uint | Signature Algorithm |  |
| `tls.handshake.type` | uint | Тип сообщения рукопожатия |  |
| `tls.handshake.version` | uint | Версия |  |
| `tls.record.content_type` | uint | Тип содержимого |  |
| `tls.record.length` | uint | Длина |  |
| `tls.record.version` | uint | Версия |  |
| `tls.segment.data` | bytes | TLS segment data |  |

## Сертификаты X.509

Поля сертификатов из сообщения TLS Certificate.

| Поле | Тип | Описание | Быстрое |
|---|---|---|---|
| `x509af.notAfter` | string | Действителен до |  |
| `x509af.notBefore` | string | Действителен с |  |
| `x509ce.dNSName` | string | Subject Alternative Name |  |
| `x509sat.issuer.cn` | string | Издатель (CN) |  |
| `x509sat.subject.cn` | string | Субъект (CN) |  |

## NTP

| Поле | Тип | Описание | Быстрое |
|---|---|---|---|
| `ntp` | protocol | Network Time Protocol | да |
| `ntp.flags` | uint | Flags |  |
| `ntp.flags.li` | uint | Leap Indicator |  |
| `ntp.flags.mode` | uint | Mode |  |
| `ntp.flags.vn` | uint | Version number |  |
| `ntp.org` | string | Метка отправителя |  |
| `ntp.ppoll` | int | Peer Polling Interval |  |
| `ntp.precision` | int | Peer Clock Precision |  |
| `ntp.rec` | string | Метка приёма |  |
| `ntp.refid` | bytes | Reference ID |  |
| `ntp.reftime` | string | Опорная метка времени |  |
| `ntp.rootdelay` | float | Root Delay |  |
| `ntp.rootdispersion` | float | Root Dispersion |  |
| `ntp.stratum` | uint | Страта |  |
| `ntp.xmt` | string | Метка передачи |  |
