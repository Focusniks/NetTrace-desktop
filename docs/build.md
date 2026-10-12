---
title: Сборка из исходников
lead: Как собрать и запустить NetTrace самостоятельно — для разработки или для Linux и macOS.
---

## Что нужно

| | |
|---|---|
| Rust | Стабильная версия; на Windows — инструментарий MSVC |
| Node.js | 20 или новее |
| Windows | WebView2 — есть в Windows 10 и 11 |
| Linux, macOS | Системные зависимости [Tauri 2](https://tauri.app/start/prerequisites/) |
| Для живого захвата | Npcap на Windows, libpcap на Linux и macOS |

SDK драйвера захвата не нужен: библиотека подключается во время работы.

## Получить код

```bash
git clone https://github.com/Focusniks/NetTrace-desktop.git
```

## Запуск в режиме разработки

```bash
cd NetTrace-desktop/apps/desktop
npm install
npx tauri dev
```

Откроется окно программы; правки интерфейса применяются на лету.

## Сборка исполняемого файла

```bash
cd apps/desktop
npx tauri build --no-bundle
```

Результат — `target/release/nettrace.exe` (на Linux и macOS — `target/release/nettrace`).

Установщик для Windows и порядок выпуска версий описаны в разделе [выпуск версий](RELEASING.md).

## Тесты

Ядро:

```bash
cargo test --workspace
```

Интерфейс:

```bash
npm --prefix apps/desktop test
```

Проверка стиля и предупреждений:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Нагрузочные тесты на большом захвате:

```bash
cargo test -p nettrace-engine --release -- --ignored --nocapture
```

## Тестовые захваты

Файлы для тестов не хранятся в репозитории, а создаются кодом:

```bash
cargo run -p nettrace-testkit --bin gen-fixtures -- fixtures --large 20000
```

В папке `fixtures` появятся `demo.pcapng`, `tcp_basic.pcap`, `tcp_problems.pcap` и большой файл для нагрузки. Скриншоты этой документации сняты на `demo.pcapng`.

## Интерфейс в браузере

Для отладки интерфейса без окна Tauri есть мост к тому же движку. Он слушает только `127.0.0.1` и в сборку программы не входит.

В одном терминале:

```bash
cargo run -p nettrace-devbridge
```

В другом:

```bash
npm --prefix apps/desktop run dev
```

Затем откройте `http://localhost:1420`.

## Устройство проекта

| Каталог | Что в нём |
|---|---|
| `crates/model` | Общие типы данных |
| `crates/packet` | Адреса, время, чтение байт |
| `crates/capture` | Чтение и запись PCAP и PCAPNG |
| `crates/live` | Живой захват через Npcap или libpcap |
| `crates/protocol` | Диссекторы протоколов и реестр полей |
| `crates/flow` | Потоки и TCP-анализ |
| `crates/analysis` | Узлы, соединения, статистика, индикаторы |
| `crates/storage` | Индекс пакетов и чтение байт по требованию |
| `crates/query` | Язык фильтров |
| `crates/engine` | Сессия: индексирование, представления, поиск |
| `crates/testkit` | Построители пакетов для тестов |
| `apps/desktop` | Интерфейс на React и оболочка Tauri |
| `tools/devbridge` | Мост для отладки интерфейса в браузере |
| `docs` | Эта документация |

Как части связаны между собой — в разделе [архитектура](ARCHITECTURE.md).

## Как помочь проекту

- Сообщения об ошибках и предложения — в [Issues](https://github.com/Focusniks/NetTrace-desktop/issues).
- Исправления — через pull request. Перед отправкой запустите тесты и `clippy`.
- Правки документации: файлы лежат в `docs/` в формате Markdown; на каждой странице сайта есть ссылка «Исправить эту страницу».
