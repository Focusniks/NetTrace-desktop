# NetTrace — анализатор сетевого трафика

Локальное desktop-приложение для ручного исследования PCAP/PCAPNG: список пакетов,
дерево протоколов, hex-просмотр с подсветкой полей, TCP/UDP-потоки, лестничная
диаграмма последовательности, узлы, соединения, статистика, временная шкала.
Приложение показывает факты и не делает выводов об инцидентах.

Стек: Rust (ядро) · Tauri 2 (оболочка) · React + TypeScript (UI). Архитектура — в
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Установка

Скачайте `NetTrace_X.Y.Z_x64-setup.exe` со страницы
[Releases](https://github.com/Focusniks/NetTrace-desktop/releases/latest) и запустите.
Права администратора не нужны. Установщик не подписан сертификатом, поэтому Windows
SmartScreen может предупредить: «Подробнее» → «Выполнить в любом случае».

NetTrace сам проверяет обновления при запуске и предлагает установить новую версию;
пакеты обновлений проверяются по цифровой подписи. Проверку можно отключить в меню
«Помощь». Как выпускать версии — [docs/RELEASING.md](docs/RELEASING.md).

## Возможности

- Живой захват с выбранного интерфейса: список интерфейсов с адресами,
  BPF-фильтр захвата, неразборчивый режим, пакеты появляются в списке в реальном времени,
  автопрокрутка, остановка/перезапуск (Ctrl+E / Ctrl+R), сохранение захвата.
  Требуется [Npcap](https://npcap.com) (Windows) или libpcap (Linux/macOS).

- PCAP (µs/ns, modified), PCAPNG (SHB/IDB/EPB/SPB/PB, несколько интерфейсов);
  Ethernet, 802.1Q, Linux SLL/SLL2, Raw IP, BSD/OpenBSD loopback.
- Диссекторы: Ethernet II, VLAN, ARP, IPv4, IPv6 (+ext headers), ICMP, ICMPv6 (ND),
  TCP (опции, анализ), UDP, DNS (компрессия имён), DHCP, HTTP/1.x, TLS (ClientHello/SNI,
  ServerHello, сертификаты X.509: CN, срок, SAN), NTP.
- Фоновая индексация с прогрессом; список доступен во время индексации; память —
  ~64 байта метаданных на пакет, байты читаются из файла по требованию.
- Display filter: `ip.addr == 10.10.1.15 && tcp.port == 443`, `!`, `||`, `&&`,
  `and/or/not`, `contains`, `in {80 443}`, CIDR (`ip.addr == 10.0.0.0/8`), сравнения
  `< <= > >=`, поля любых диссекторов (`dns.qry.name`, `http.host`,
  `tls.handshake.extensions_server_name`, `tcp.analysis.retransmission` …).
  Визуальный конструктор генерирует обычное выражение.
- TCP-анализ: рукопожатие, iRTT/RTT, ретрансмиссии (включая быстрые), dup ACK,
  out-of-order, потерянные сегменты, zero window, keep-alive, RST/FIN, пропускная способность.
- Поиск: строка (в байтах и в декодированных полях), hex, IP, MAC, порт, протокол,
  домен (DNS/SNI/Host), номер пакета.
- Узлы, соединения (Ethernet/IP/TCP/UDP), иерархия протоколов, I/O-график, длины пакетов,
  временная шкала с выделением диапазона, технические индикаторы (факты, без вердиктов).
- Правила раскраски, настройка колонок, навигация назад/вперёд, экспорт отображаемых
  пакетов в PCAP/PCAPNG.

## Требования

- Rust stable (MSVC на Windows), Node.js ≥ 20.
- Для живого захвата: Npcap на Windows (для захвата без прав администратора при
  установке снимите «Restrict Npcap driver's access to Administrators only»), libpcap
  на Linux/macOS. Для сборки SDK не нужен — библиотека загружается при запуске.
- Windows: WebView2 (есть в Windows 10/11). Linux/macOS: зависимости Tauri 2.

## Запуск

```bash
cd apps/desktop
npm install
npx tauri dev
```

Сборка исполняемого файла (без инсталлятора):

```bash
cd apps/desktop
npx tauri build --no-bundle
```

Готовый файл: `target/release/nettrace.exe`. Установщик и выпуск версий —
[docs/RELEASING.md](docs/RELEASING.md).

## Тесты

```bash
cargo test --workspace
```

```bash
npm --prefix apps/desktop test
```

Нагрузочный тест (560 тыс. пакетов, release):

```bash
cargo test -p nettrace-engine --release -- --ignored --nocapture
```

Фикстуры генерируются из кода (`crates/testkit`), большие файлы не хранятся в репозитории:

```bash
cargo run -p nettrace-testkit --bin gen-fixtures -- fixtures --large 20000
```

## Разработка UI в браузере

Для отладки интерфейса без Tauri есть dev-мост к тому же движку (только 127.0.0.1,
в сборку приложения не входит):

```bash
cargo run -p nettrace-devbridge
```

```bash
npm --prefix apps/desktop run dev
```

Затем открыть `http://127.0.0.1:1420/?open=<путь к pcap>`.

## Безопасность

PCAP считается недоверенным входом: весь разбор — через курсор с проверкой границ,
`unsafe` запрещён на уровне workspace (кроме FFI к Npcap/libpcap в `crates/live`),
ошибка разбора пакета превращается в `[Malformed]`, паника диссектора перехватывается,
есть fuzz-тест. UI не исполняет содержимое пакетов и не открывает ссылки; CSP Tauri
запрещает внешние источники, плагины shell/opener/fs/http не подключены. Единственный
сетевой запрос — проверка обновлений на GitHub (в Rust, вне веб-интерфейса).

## Лицензия

MIT или Apache 2.0 на ваш выбор: [LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE).

## Структура

```
crates/model     DTO-контракт backend ↔ UI
crates/packet    курсор с проверкой границ, адреса, link types, время
crates/capture   чтение PCAP/PCAPNG, запись PCAP/PCAPNG, PacketSource
crates/protocol  диссекторы, реестр диссекторов и полей фильтра
crates/flow      TCP/UDP-потоки и TCP-анализ
crates/analysis  узлы, соединения, иерархия, I/O, шкала, индикаторы
crates/storage   индекс метаданных пакетов, ленивое чтение байтов
crates/query     язык фильтра: лексер, парсер, компиляция, вычисление
crates/engine    сессия анализа: индексация, представления, детали, поиск, экспорт
crates/testkit   построители пакетов и генератор фикстур
apps/desktop     Tauri-оболочка (src-tauri) и React UI (src)
tools/devbridge  dev-мост для отладки UI в браузере
```
