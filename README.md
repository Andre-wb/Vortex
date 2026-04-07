
```
  ██╗   ██╗ ██████╗ ██████╗ ████████╗███████╗██╗  ██╗
  ██║   ██║██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝
  ██║   ██║██║   ██║██████╔╝   ██║   █████╗   ╚███╔╝
  ╚██╗ ██╔╝██║   ██║██╔══██╗   ██║   ██╔══╝   ██╔██╗
   ╚████╔╝ ╚██████╔╝██║  ██║   ██║   ███████╗██╔╝ ██╗
    ╚═══╝   ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

<h1 align="center">VORTEX P2P Messenger</h1>

<p align="center">
  <b>100% децентрализованный мессенджер с E2E шифрованием, мультихоп-маршрутизацией и Rust крипто-ядром</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Rust-1.75+-DEA584?style=for-the-badge&logo=rust&logoColor=black" alt="Rust">
  <img src="https://img.shields.io/badge/FastAPI-0.104+-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/WebRTC-Peer--to--Peer-333333?style=for-the-badge&logo=webrtc&logoColor=white" alt="WebRTC">
  <img src="https://img.shields.io/badge/SQLite-3-003B57?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite">
  <img src="https://img.shields.io/badge/License-Apache_2.0-D22128?style=for-the-badge&logo=apache&logoColor=white" alt="License">
  <img src="https://img.shields.io/badge/Version-4.0.0-blue?style=for-the-badge" alt="Version">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/X25519-ECDH-green?style=flat-square" alt="X25519">
  <img src="https://img.shields.io/badge/AES--256--GCM-Encryption-green?style=flat-square" alt="AES-256-GCM">
  <img src="https://img.shields.io/badge/Argon2id-Password_Hashing-green?style=flat-square" alt="Argon2">
  <img src="https://img.shields.io/badge/BLAKE3-Message_Hashing-green?style=flat-square" alt="BLAKE3">
  <img src="https://img.shields.io/badge/ECIES-Key_Distribution-green?style=flat-square" alt="ECIES">
  <img src="https://img.shields.io/badge/HKDF--SHA256-Key_Derivation-green?style=flat-square" alt="HKDF">
</p>

---

## :cyclone: Что такое VORTEX

**VORTEX** — это полностью децентрализованный P2P мессенджер, разработанный с нуля без использования центральных серверов, блокчейнов или каких-либо посредников. Каждое устройство, на котором запущен VORTEX, является одновременно клиентом и сервером — полноценным узлом mesh-сети. Узлы автоматически обнаруживают друг друга в локальной сети через UDP broadcast за ~2 секунды, а в глобальном режиме используют gossip-протокол для формирования mesh-сети через интернет без центрального координатора.

В отличие от традиционных мессенджеров, где ваши сообщения проходят через серверы компании (даже при использовании E2E шифрования метаданные остаются у провайдера), VORTEX полностью исключает посредника. Сервер узла хранит **только зашифрованные данные** и физически не может расшифровать ни одно сообщение — приватные ключи пользователей никогда не покидают устройство. Система распределения ключей комнат основана на ECIES (Elliptic Curve Integrated Encryption Scheme), где ключ комнаты шифруется индивидуально для каждого участника с использованием его X25519 публичного ключа.

VORTEX объединяет передовые криптографические протоколы (X25519 + AES-256-GCM + Argon2id + BLAKE3), высокопроизводительное Rust крипто-ядро (через PyO3), мультихоп-маршрутизацию для федеративного подключения к удалённым комнатам, WebRTC для голосовых и видеозвонков, а также WAF (Web Application Firewall) для защиты от SQL-инъекций, XSS и других атак. Система поддерживает два режима работы: **локальный** (LAN mesh через UDP broadcast) и **глобальный** (интернет mesh через gossip-протокол с обфускацией трафика для обхода DPI).

```
                          ╔═══════════════════════════════════════╗
                          ║        VORTEX MESH NETWORK            ║
                          ╚═══════════════════════════════════════╝

       ┌──────────┐              ┌──────────┐              ┌──────────┐
       │  Node A  │◄────────────►│  Node B  │◄────────────►│  Node C  │
       │ (Alice)  │   E2E        │ (Bob)    │   E2E        │ (Carol)  │
       │ :9000    │   encrypted  │ :9001    │   encrypted  │ :9002    │
       └────┬─────┘              └────┬─────┘              └────┬─────┘
            │                         │                         │
            │   ┌─────────────────────┼─────────────────────┐   │
            │   │     UDP Broadcast   │   Discovery         │   │
            │   │     ← 2 sec →       │                     │   │
            │   └─────────────────────┼─────────────────────┘   │
            │                         │                         │
            ▼                         ▼                         ▼
       ┌──────────┐              ┌──────────┐              ┌──────────┐
       │  SQLite  │              │  SQLite  │              │  SQLite  │
       │ (E2E DB) │              │ (E2E DB) │              │ (E2E DB) │
       └──────────┘              └──────────┘              └──────────┘

       Каждый узел:                    Федерация:
       ─ FastAPI (HTTPS)               ─ Мультихоп A→B→C
       ─ WebSocket чат                 ─ Виртуальные комнаты
       ─ X25519 + AES-256-GCM         ─ Server-to-server relay
       ─ Rust крипто-ядро              ─ Gossip-протокол (global)
       ─ WAF / CSRF / Security         ─ Обфускация трафика (DPI)
```

### Что делает VORTEX уникальным

| Свойство | Описание |
|----------|----------|
| **Нулевой посредник** | Нет центрального сервера. Каждое устройство — полноценный узел |
| **Серверное незнание** | Сервер хранит только шифротекст. Приватные ключи не покидают устройство |
| **Автообнаружение** | UDP broadcast находит узлы в LAN за ~2 секунды |
| **Мультихоп** | Сообщения могут проходить через промежуточные узлы (A→B→C) |
| **Двойной режим** | Локальный (LAN) и глобальный (интернет через gossip) |
| **Обфускация** | Трафик маскируется под обычный HTTPS для обхода DPI |
| **Rust крипто** | CPU-интенсивные операции выполняются в нативном Rust коде |

---

## :bar_chart: VORTEX vs аналоги

### Детальная таблица сравнения

| Возможность | VORTEX | Signal | Telegram | Briar | Element/Matrix | Session | Wire |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Архитектура** | P2P mesh | Централизованный | Централизованный | P2P (Tor) | Федеративный | Децентр. (oxen) | Централизованный |
| **Центральный сервер** | Нет | Да (Signal LLC) | Да (Telegram Inc) | Нет | Да (homeserver) | Частично (Oxen) | Да (Wire Swiss) |
| **E2E шифрование по умолчанию** | Да (все чаты) | Да (все чаты) | Нет (только Secret) | Да (все чаты) | Нет (опционально) | Да (все чаты) | Да (все чаты) |
| **Шифрование групп** | AES-256-GCM | Signal Protocol | MTProto 2.0 | Bramble | Megolm/Olm | Session Protocol | Proteus |
| **Обмен ключами** | X25519 + ECIES | X3DH | DH 2048-bit | Bramble | Olm (Curve25519) | X25519 | Proteus (Curve25519) |
| **Хеширование паролей** | Argon2id | scrypt | SRP | scrypt | bcrypt | — | scrypt |
| **Хеш сообщений** | BLAKE3 | SHA-256 | SHA-256 | — | SHA-256 | — | SHA-256 |
| **Сервер видит метаданные** | Нет | Частично | Да | Нет | Да (homeserver) | Минимально | Да |
| **Сервер может прочитать** | Нет | Нет | Да (cloud chat) | Нет | Нет (если E2E) | Нет | Нет |
| **Автообнаружение в LAN** | Да (UDP, ~2с) | Нет | Нет | Да (Wi-Fi/BT) | Нет | Нет | Нет |
| **Работа без интернета** | Да (LAN/Wi-Fi) | Нет | Нет | Да (Wi-Fi/BT) | Нет | Нет | Нет |
| **Gossip-протокол** | Да | Нет | Нет | Да (Tor) | Нет | Да (Oxen) | Нет |
| **Обфускация трафика** | Да (DPI evasion) | Нет | Нет | Да (Tor) | Нет | Нет | Нет |
| **Cover traffic** | Да (fake website) | Нет | Нет | Нет | Нет | Нет | Нет |
| **Федерация** | Мультихоп relay | Нет | Нет | Нет | Да (Matrix) | Нет | Нет |
| **Голосовые звонки** | WebRTC P2P | WebRTC | Проприетарный | Нет | Jitsi/WebRTC | WebRTC | WebRTC |
| **Видеозвонки** | WebRTC P2P | WebRTC | Проприетарный | Нет | Jitsi/WebRTC | Нет | WebRTC |
| **Адаптивный битрейт** | Да (4 уровня) | Да | Да | — | Частично | Нет | Да |
| **Мониторинг качества** | Да (RTT/jitter/loss) | Нет (скрыт) | Нет | — | Нет | Нет | Нет |
| **NAT Traversal** | STUN + UDP HP | TURN/STUN | Серверы | Tor | TURN/STUN | Onion routing | TURN/STUN |
| **Wi-Fi Direct** | Да | Нет | Нет | Да | Нет | Нет | Нет |
| **BLE fallback** | Да | Нет | Нет | Да | Нет | Нет | Нет |
| **WAF** | Да (SQLi/XSS/PT) | — | — | — | — | — | — |
| **CSRF защита** | Да | — | — | — | — | — | — |
| **Rate limiting** | Token Bucket | Да | Да | — | Да | Да | Да |
| **Файлы** | До 100 МБ, resumable | До 100 МБ | До 2 ГБ | Ограничено | До 100 МБ | До 10 МБ | До 25 МБ |
| **Голосовые сообщения** | Да (waveform) | Да | Да | Нет | Нет | Нет | Да |
| **Контакты** | Да (search/add/rename) | Да (по номеру) | Да (по номеру) | Да | Да | Нет | Да |
| **PWA** | Да | Нет | Да (web) | Нет | Да | Нет | Да |
| **Уведомления** | Slide-in + badges | Push | Push | — | Push | Push | Push |
| **Фото-редактор** | Да | Да | Да | Нет | Нет | Нет | Нет |
| **Open Source** | Да (Apache 2.0) | Да (AGPL) | Клиент (GPL) | Да (GPL) | Да (Apache 2.0) | Да (GPL) | Да (GPL) |
| **Rust крипто-ядро** | Да (PyO3) | Да (libsignal) | Нет | Нет | Нет | Нет | Нет |
| **Регистрация** | Без центрального сервера | Требует номер | Требует номер | Без номера | Email/номер | Без номера | Email |
| **Кроссплатформенность** | PWA (все платформы) | iOS/Android/Desktop | Все платформы | Android | Все платформы | Все платформы | Все платформы |

### Индивидуальное сравнение

**Signal** — золотой стандарт E2E шифрования, но централизован: все сообщения проходят через серверы Signal Foundation. Если серверы Signal недоступны, мессенджер не работает. VORTEX не зависит от внешних серверов — узлы общаются напрямую. Кроме того, Signal требует номер телефона для регистрации, тогда как в VORTEX регистрация происходит локально на вашем узле.

**Telegram** — наиболее популярный мессенджер с богатым функционалом, но E2E шифрование доступно только в Secret Chats (не в группах, не по умолчанию). Облачные чаты хранятся на серверах Telegram в зашифрованном виде, но ключи хранятся там же — компания технически может прочитать сообщения. VORTEX шифрует все сообщения по умолчанию, а сервер физически не может их расшифровать.

**Briar** — наиболее близкий аналог по философии (P2P, работа без интернета), но ограничен платформой Android, не поддерживает голосовые/видеозвонки и имеет ограниченные возможности передачи файлов. VORTEX работает на всех платформах через PWA и поддерживает WebRTC звонки.

**Element/Matrix** — федеративный протокол с E2E шифрованием (Megolm), но требует homeserver для работы. Настройка homeserver сложна, а метаданные видны серверу. VORTEX не требует выделенного сервера — каждое устройство является узлом.

**Session** — децентрализованный мессенджер на сети Oxen (форк Monero). Не требует номера для регистрации, но зависит от сети Service Nodes. VORTEX не зависит от блокчейна или внешней инфраструктуры.

**Wire** — корпоративный мессенджер с E2E шифрованием, но централизован и принадлежит коммерческой компании. Метаданные хранятся на серверах Wire. VORTEX не имеет центрального оператора.

---

## :sparkles: Возможности

| Категория | Возможность | Описание |
|-----------|-------------|----------|
| :satellite: **Обнаружение** | Auto-discovery | UDP broadcast, обнаружение узлов в LAN за ~2 секунды |
| :globe_with_meridians: **Глобальный режим** | Gossip-протокол | Mesh-сеть через интернет, обмен пирами каждые 30 сек |
| :lock: **Шифрование** | E2E (X25519 + AES-256-GCM) | Все сообщения зашифрованы end-to-end, сервер не видит открытый текст |
| :key: **Ключи** | ECIES key distribution | Ключ комнаты шифруется индивидуально для каждого участника |
| :hash: **Хеширование** | BLAKE3 + Argon2id | BLAKE3 для сообщений (целостность), Argon2id для паролей |
| :door: **Комнаты** | Public / Private | До 200 участников, invite-коды, роли (owner/admin/member) |
| :envelope: **DM** | Личные сообщения | Приватные 2-person комнаты с E2E шифрованием |
| :bust_in_silhouette: **Контакты** | Управление контактами | Добавление, переименование, удаление, поиск по phone/email/IP/username |
| :bell: **Уведомления** | Slide-in banners | Непрочитанные бейджи, @ упоминания, уведомления о звонках |
| :file_folder: **Файлы** | До 100 МБ, resumable | Возобновляемая загрузка по чанкам, SHA-256 проверка целостности |
| :microphone: **Голосовые** | Voice messages + waveform | Запись голосовых сообщений с визуализацией формы волны |
| :telephone_receiver: **Звонки** | WebRTC (voice + video) | P2P звонки с мониторингом качества (RTT, jitter, packet loss) |
| :chart_with_upwards_trend: **Адаптивный битрейт** | 4 уровня качества | Автоматическая подстройка качества звонка под сетевые условия |
| :arrows_counterclockwise: **Мультихоп** | Федерация A→B→C | Подключение к комнатам на удалённых узлах через промежуточные |
| :shield: **WAF** | SQLi, XSS, Path Traversal | Web Application Firewall с rate limiting (Token Bucket) |
| :crab: **Rust ядро** | PyO3 native module | AES-GCM, BLAKE3, Argon2, X25519, SHA-256 — всё на Rust |
| :closed_lock_with_key: **SSL/TLS** | mkcert + самоподписанные | HTTPS для всех соединений между узлами |
| :hole: **NAT Traversal** | STUN + UDP Hole Punching | Прямое соединение через NAT без серверов-посредников |
| :signal_strength: **Wi-Fi Direct** | P2P без роутера | Прямое соединение между устройствами через Wi-Fi Direct |
| :iphone: **BLE** | Bluetooth Low Energy | Fallback-транспорт для передачи данных через BLE |
| :globe_with_meridians: **PWA** | Progressive Web App | Установка как приложение на любой платформе |
| :ghost: **Обфускация** | DPI evasion | Паддинг, jitter, cover headers, fake website |
| :art: **UI** | Glassmorphism | Стеклянные карточки, blur-эффекты, liquid glass анимации |
| :camera: **Фото-редактор** | Встроенный | Редактирование фото перед отправкой |

---

## :book: Содержание

- [:cyclone: Что такое VORTEX](#cyclone-что-такое-vortex)
- [:bar_chart: VORTEX vs аналоги](#bar_chart-vortex-vs-аналоги)
- [:sparkles: Возможности](#sparkles-возможности)
- [:book: Содержание](#book-содержание)
- [:package: Установка зависимостей](#package-установка-зависимостей)
- [:inbox_tray: Установка проекта](#inbox_tray-установка-проекта)
- [:rocket: Запуск](#rocket-запуск)
- [:globe_with_meridians: Режимы работы: Локальный и Глобальный](#globe_with_meridians-режимы-работы-локальный-и-глобальный)
- [:closed_lock_with_key: Настройка SSL](#closed_lock_with_key-настройка-ssl)
- [:gear: Конфигурация (.env)](#gear-конфигурация-env)
- [:building_construction: Архитектура](#building_construction-архитектура)
- [:arrows_counterclockwise: Мультихоп-маршрутизация](#arrows_counterclockwise-мультихоп-маршрутизация)
- [:lock: E2E шифрование](#lock-e2e-шифрование)
- [:envelope: Личные сообщения (DM)](#envelope-личные-сообщения-dm)
- [:bust_in_silhouette: Контакты и поиск пользователей](#bust_in_silhouette-контакты-и-поиск-пользователей)
- [:bell: Уведомления](#bell-уведомления)
- [:telephone_receiver: Мониторинг качества звонков](#telephone_receiver-мониторинг-качества-звонков)
- [:headphones: Стратегия буферизации звонков](#headphones-стратегия-буферизации-звонков)
- [:railway_car: Транспортный стек](#railway_car-транспортный-стек)
- [:globe_with_meridians: Глобальный транспорт](#globe_with_meridians-глобальный-транспорт)
- [:scroll: Протоколы](#scroll-протоколы)
- [:electric_plug: API](#electric_plug-api)
- [:shield: Безопасность и модель угроз](#shield-безопасность-и-модель-угроз)
- [:anchor: Надёжность](#anchor-надёжность)
- [:iphone: PWA](#iphone-pwa)
- [:bar_chart: Метрики и производительность](#bar_chart-метрики-и-производительность)
- [:test_tube: Тестирование](#test_tube-тестирование)
- [:file_folder: Структура проекта](#file_folder-структура-проекта)
- [:busts_in_silhouette: Разработчики](#busts_in_silhouette-разработчики)
- [:page_facing_up: Лицензия](#page_facing_up-лицензия)

---

## :package: Установка зависимостей

Перед установкой VORTEX убедитесь, что у вас установлены все необходимые системные зависимости. Ниже приведены инструкции для каждой операционной системы.

### Системные требования

| Компонент | Минимальная версия | Назначение |
|-----------|-------------------|------------|
| Python | 3.10+ | Основной runtime |
| Rust | 1.75+ | Компиляция крипто-ядра |
| Cargo | (поставляется с Rust) | Сборка Rust пакетов |
| Git | 2.0+ | Клонирование репозитория |
| mkcert | 1.4+ | Генерация SSL-сертификатов (опционально) |
| maturin | 1.0+ | Сборка PyO3 модуля (Rust→Python) |
| OpenSSL | 1.1+ | SSL/TLS (обычно предустановлен) |

<details>
<summary><b>:window: Windows</b></summary>

#### 1. Git

Скачайте и установите Git с официального сайта:
- Перейдите на https://git-scm.com/download/win
- Скачайте установщик для вашей архитектуры (64-bit)
- Запустите установщик, выбирая настройки по умолчанию
- После установки откройте Git Bash или PowerShell

```powershell
# Проверка установки
git --version
# Ожидаемый вывод: git version 2.x.x
```

#### 2. Python 3.10+

```powershell
# Вариант 1: Через Microsoft Store
# Откройте Microsoft Store → найдите "Python 3.12" → Установить

# Вариант 2: Через winget
winget install Python.Python.3.12

# Вариант 3: Через chocolatey
choco install python312

# Проверка установки
python --version
# Ожидаемый вывод: Python 3.12.x

# Убедитесь что pip работает
python -m pip --version
# Ожидаемый вывод: pip 24.x from ...
```

> **Важно**: При установке Python через инсталлятор с python.org обязательно отметьте галочку "Add Python to PATH".

#### 3. Rust + Cargo

```powershell
# Установка через rustup (рекомендуется)
# Перейдите на https://rustup.rs/ и скачайте rustup-init.exe
# Или выполните в PowerShell:
Invoke-WebRequest -Uri https://win.rustup.rs -OutFile rustup-init.exe
.\rustup-init.exe

# После установки перезапустите терминал и проверьте:
rustc --version
# Ожидаемый вывод: rustc 1.7x.x
cargo --version
# Ожидаемый вывод: cargo 1.7x.x
```

> **Важно**: На Windows для Rust может потребоваться установка Visual Studio Build Tools:
> ```powershell
> winget install Microsoft.VisualStudio.2022.BuildTools
> ```
> При установке выберите "C++ build tools" workload.

#### 4. mkcert (опционально, для доверенных SSL-сертификатов)

```powershell
# Через chocolatey
choco install mkcert

# Или через winget
winget install FiloSottile.mkcert

# Или через scoop
scoop bucket add extras
scoop install mkcert

# Проверка
mkcert --version
```

#### 5. maturin (сборка Rust→Python)

```powershell
# Установка через pip (после установки Python и Rust)
pip install maturin

# Проверка
maturin --version
# Ожидаемый вывод: maturin 1.x.x
```

</details>

<details>
<summary><b>:apple: macOS</b></summary>

#### 1. Homebrew (менеджер пакетов)

Если Homebrew ещё не установлен:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

#### 2. Git

```bash
# Git обычно предустановлен на macOS через Xcode Command Line Tools
git --version
# Если не установлен:
xcode-select --install

# Или через Homebrew:
brew install git
```

#### 3. Python 3.10+

```bash
# Через Homebrew (рекомендуется)
brew install python@3.12

# Проверка
python3 --version
# Ожидаемый вывод: Python 3.12.x

# Проверка pip
python3 -m pip --version
```

> **Примечание**: На macOS используйте `python3` и `pip3` вместо `python` и `pip`, если не настроили алиасы.

#### 4. Rust + Cargo

```bash
# Установка через rustup (рекомендуется)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Следуйте инструкциям, выберите вариант 1 (default installation)
# После установки активируйте окружение:
source $HOME/.cargo/env

# Проверка
rustc --version
# Ожидаемый вывод: rustc 1.7x.x
cargo --version
# Ожидаемый вывод: cargo 1.7x.x
```

#### 5. mkcert

```bash
# Через Homebrew
brew install mkcert

# Установка корневого CA в системное хранилище доверия
mkcert -install

# Проверка
mkcert --version
```

#### 6. maturin

```bash
# Через pip
pip3 install maturin

# Или через Homebrew
brew install maturin

# Проверка
maturin --version
```

</details>

<details>
<summary><b>:penguin: Linux (Ubuntu/Debian)</b></summary>

#### 1. Обновление системы и базовые пакеты

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y build-essential curl wget git pkg-config libssl-dev
```

#### 2. Git

```bash
# Обычно уже установлен, если нет:
sudo apt install -y git

# Проверка
git --version
```

#### 3. Python 3.10+

```bash
# Ubuntu 22.04+ обычно имеет Python 3.10+
sudo apt install -y python3 python3-pip python3-venv python3-dev

# Проверка
python3 --version
# Ожидаемый вывод: Python 3.10.x или выше

# Если нужна более новая версия:
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install -y python3.12 python3.12-venv python3.12-dev
```

#### 4. Rust + Cargo

```bash
# Установка через rustup (рекомендуется)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Выберите вариант 1 (default)
# Активируйте окружение:
source $HOME/.cargo/env

# Проверка
rustc --version
cargo --version
```

#### 5. mkcert

```bash
# Ubuntu/Debian
sudo apt install -y libnss3-tools

# Установка mkcert
# Вариант 1: через go
go install filippo.io/mkcert@latest

# Вариант 2: скачать бинарник
curl -JLO "https://dl.filippo.io/mkcert/latest?for=linux/amd64"
chmod +x mkcert-v*-linux-amd64
sudo mv mkcert-v*-linux-amd64 /usr/local/bin/mkcert

# Установка корневого CA
mkcert -install
```

#### 6. maturin

```bash
pip3 install maturin

# Проверка
maturin --version
```

#### 7. Дополнительные зависимости (для python-magic)

```bash
sudo apt install -y libmagic1
```

</details>

<details>
<summary><b>:penguin: Linux (Fedora/RHEL/CentOS)</b></summary>

#### 1. Базовые пакеты

```bash
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y curl wget git openssl-devel pkg-config
```

#### 2. Python 3.10+

```bash
sudo dnf install -y python3 python3-pip python3-devel

# Проверка
python3 --version
```

#### 3. Rust + Cargo

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

rustc --version
cargo --version
```

#### 4. mkcert

```bash
sudo dnf install -y nss-tools
# Скачайте бинарник mkcert с GitHub releases
```

#### 5. maturin

```bash
pip3 install maturin
```

#### 6. Дополнительные зависимости

```bash
sudo dnf install -y file-libs   # для python-magic
```

</details>

<details>
<summary><b>:penguin: Linux (Arch Linux)</b></summary>

#### 1. Базовые пакеты

```bash
sudo pacman -Syu
sudo pacman -S base-devel curl wget git openssl pkg-config
```

#### 2. Python 3.10+

```bash
sudo pacman -S python python-pip

python --version
```

#### 3. Rust + Cargo

```bash
sudo pacman -S rustup
rustup default stable

rustc --version
cargo --version
```

#### 4. mkcert

```bash
sudo pacman -S mkcert nss
mkcert -install
```

#### 5. maturin

```bash
pip install maturin
```

</details>

---

## :inbox_tray: Установка проекта

### Шаг 1: Клонирование репозитория

```bash
git clone https://github.com/your-username/Vortex.git
cd Vortex
```

### Шаг 2: Создание виртуального окружения Python

```bash
# Создание виртуального окружения
python3 -m venv .venv

# Активация (Linux/macOS)
source .venv/bin/activate

# Активация (Windows PowerShell)
.venv\Scripts\Activate.ps1

# Активация (Windows CMD)
.venv\Scripts\activate.bat
```

### Шаг 3: Установка Python-зависимостей

```bash
pip install -r requirements.txt
```

Список основных зависимостей:

| Пакет | Версия | Назначение |
|-------|--------|------------|
| `fastapi` | 0.104.1 | Web-фреймворк (ASGI) |
| `uvicorn[standard]` | 0.24.0 | ASGI-сервер с поддержкой WebSocket |
| `SQLAlchemy` | 2.0.47 | ORM для SQLite |
| `pydantic` | 2.0+ | Валидация данных |
| `PyJWT` | 2.8+ | JWT-токены аутентификации |
| `cryptography` | 42.0+ | X25519, HKDF, AES-GCM (Python fallback) |
| `httpx` | 0.27+ | HTTP-клиент для межузловых запросов |
| `python-magic` | 0.4.27+ | Определение MIME-типов файлов |
| `Pillow` | 1.1.7+ | Обработка изображений |
| `argon2-cffi` | 23.1+ | Argon2id хеширование паролей (Python fallback) |
| `blake3` | 0.4+ | BLAKE3 хеширование (Python fallback) |
| `maturin` | 1.0+ | Сборка Rust→Python модулей |
| `jinja2` | 3.1+ | Шаблонизатор HTML |

### Шаг 4: Сборка Rust крипто-ядра

Rust-модуль `vortex_chat` значительно ускоряет криптографические операции. Без него VORTEX будет работать на Python fallback (медленнее, но функционально идентично).

```bash
# Перейти в директорию Rust-проекта
cd rust_utils

# Собрать и установить в текущее виртуальное окружение
maturin develop --release

# Вернуться в корень проекта
cd ..
```

Для проверки успешной сборки:

```bash
python -c "import vortex_chat; print(f'Rust модуль: v{vortex_chat.VERSION}')"
# Ожидаемый вывод: Rust модуль: v0.2.0
```

Если сборка Rust не удалась, VORTEX автоматически использует Python fallback. В логах при старте вы увидите:

```
🐍 Python crypto fallback (компилируйте Rust для скорости)
```

Вместо:

```
🦀 Rust crypto: vortex_chat 0.2.0
```

### Шаг 5: Генерация SSL-сертификатов (рекомендуется)

```bash
# Создать директорию для сертификатов
mkdir -p certs

# Вариант 1: mkcert (доверенные сертификаты)
mkcert -install
mkcert -cert-file certs/vortex.crt -key-file certs/vortex.key localhost 127.0.0.1 $(hostname -I | awk '{print $1}')

# Вариант 2: openssl (самоподписанные)
openssl req -x509 -newkey rsa:4096 -keyout certs/vortex.key -out certs/vortex.crt \
    -days 365 -nodes -subj "/CN=VortexNode"
```

### Шаг 6: Первый запуск

```bash
python run.py
```

При первом запуске автоматически откроется мастер настройки (wizard) в браузере, где вы сможете задать имя устройства, порт и другие параметры.

---

## :rocket: Запуск

### Основные режимы запуска

```bash
# Стандартный запуск (wizard при первом запуске, затем узел)
python run.py

# Принудительный запуск мастера настройки
python run.py --setup

# Показать статус узла
python run.py --status

# Сбросить настройки (требует подтверждения)
python run.py --reset

# Запуск wizard на другом порту
python run.py --setup --wizard-port 9090

# Запуск без автоматического открытия браузера
python run.py --no-browser
```

### Первый запуск (мастер настройки)

При первом запуске VORTEX определяет, что узел ещё не настроен (`NODE_INITIALIZED != true` в `.env`), и автоматически запускает веб-мастер настройки на порту 7979.

Мастер настройки позволяет:

1. **Задать имя устройства** — отображаемое имя в mesh-сети
2. **Выбрать порт** — порт для HTTPS-сервера (по умолчанию 9000)
3. **Настроить SSL** — генерация или импорт сертификатов
4. **Задать параметры безопасности** — JWT секрет, CSRF токен
5. **Выбрать режим сети** — локальный (LAN) или глобальный (интернет)

После завершения настройки мастер автоматически запускает узел VORTEX.

### Запуск нескольких узлов на одной машине

Для тестирования и разработки можно запустить несколько узлов на одном компьютере:

```bash
# Терминал 1: первый узел
PORT=9000 DB_PATH=vortex1.db DEVICE_NAME="Node-Alpha" python -m uvicorn app.main:app --host 0.0.0.0 --port 9000

# Терминал 2: второй узел
PORT=9001 DB_PATH=vortex2.db DEVICE_NAME="Node-Beta" python -m uvicorn app.main:app --host 0.0.0.0 --port 9001

# Терминал 3: третий узел
PORT=9002 DB_PATH=vortex3.db DEVICE_NAME="Node-Gamma" python -m uvicorn app.main:app --host 0.0.0.0 --port 9002
```

Каждый узел должен иметь:
- Уникальный порт (`PORT`)
- Уникальную базу данных (`DB_PATH`)
- Уникальное имя (`DEVICE_NAME`)

Узлы автоматически обнаружат друг друга через UDP broadcast (если работают в одной подсети).

### Запуск с SSL

```bash
# С SSL-сертификатами
python -m uvicorn app.main:app --host 0.0.0.0 --port 9000 \
    --ssl-certfile certs/vortex.crt \
    --ssl-keyfile certs/vortex.key
```

При использовании `run.py` SSL подключается автоматически, если найдены файлы `certs/vortex.crt` и `certs/vortex.key`.

### Запуск в глобальном режиме

```bash
# Настройка через .env
echo "NETWORK_MODE=global" >> .env
echo "BOOTSTRAP_PEERS=203.0.113.10:9000,198.51.100.20:9000" >> .env
echo "OBFUSCATION_ENABLED=true" >> .env

# Запуск
python run.py
```

В глобальном режиме узел:
1. Подключается к bootstrap-пирам
2. Запускает gossip-протокол (обмен пирами каждые 30 сек)
3. Включает health-check (пинг пиров каждые 30 сек)
4. Включает обфускацию трафика (если `OBFUSCATION_ENABLED=true`)
5. Подключает cover-страницы (фейковый сайт для DPI)

---

## :globe_with_meridians: Режимы работы: Локальный и Глобальный

VORTEX поддерживает два принципиально различных режима работы, каждый из которых оптимизирован для своего сценария использования.

### Локальный режим (LAN Mesh)

Локальный режим предназначен для работы в рамках одной локальной сети (домашний Wi-Fi, корпоративная сеть, университетская сеть). Узлы обнаруживают друг друга автоматически, без какой-либо настройки.

#### Как работает UDP Discovery

```
  ┌───────────────────────────────────────────────────────────────────┐
  │                   ЛОКАЛЬНАЯ СЕТЬ (192.168.1.0/24)                 │
  │                                                                   │
  │   ┌──────────┐         UDP Broadcast          ┌──────────┐        │
  │   │  Node A  │ ◄───── 255.255.255.255:4200 ──► │  Node B  │       │
  │   │ :9000    │         каждые 2 сек            │ :9001    │       │
  │   └──────────┘                                 └──────────┘       │
  │        │                                            │             │
  │        │              UDP Broadcast                 │             │
  │        └────────────── :4200 ──────────────────────┘              │
  │                          │                                        │
  │                   ┌──────────┐                                    │
  │                   │  Node C  │                                    │
  │                   │ :9002    │                                    │
  │                   └──────────┘                                    │
  │                                                                   │
  └───────────────────────────────────────────────────────────────────┘
```

**Протокол UDP Discovery:**

1. Каждый узел каждые `UDP_INTERVAL_SEC` (по умолчанию 2) секунды отправляет UDP broadcast пакет на порт `UDP_PORT` (по умолчанию 4200) на адрес `255.255.255.255`
2. Пакет содержит JSON с информацией об узле:
   ```json
   {
     "name": "Node-Alpha",
     "port": 9000,
     "node_pubkey_hex": "a3b4c5d6...64_hex_chars..."
   }
   ```
3. Все узлы в подсети слушают порт 4200 и обновляют свой реестр пиров
4. Если узел не отправлял broadcast более `PEER_TIMEOUT_SEC` (по умолчанию 15 секунд), он считается мёртвым и удаляется из реестра
5. UDP broadcast работает только в пределах одной подсети (не проходит через роутеры)

**Преимущества локального режима:**
- Нулевая настройка — узлы находят друг друга автоматически
- Минимальная задержка — прямое соединение по LAN
- Нет зависимости от интернета — работает полностью автономно
- Низкий overhead — только UDP broadcast каждые 2 секунды

**Настройка .env для локального режима:**
```env
NETWORK_MODE=local
UDP_PORT=4200
UDP_INTERVAL_SEC=2
PEER_TIMEOUT_SEC=15
```

### Глобальный режим (Internet Mesh)

Глобальный режим предназначен для работы через интернет. Узлы формируют mesh-сеть с помощью gossip-протокола, без центрального координатора.

#### Как работает Gossip-протокол

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │                        ИНТЕРНЕТ (GLOBAL MESH)                       │
  │                                                                     │
  │   ┌──────────┐       HTTPS gossip       ┌──────────┐                │
  │   │  Node A  │◄────── каждые 30с ──────►│  Node B  │                │
  │   │ Moscow   │       3 random peers      │ Berlin   │               │
  │   │ :9000    │                           │ :9000    │               │
  │   └────┬─────┘                           └────┬─────┘               │
  │        │                                      │                     │
  │        │    ┌──────────┐     ┌──────────┐     │                     │
  │        └───►│  Node C  │◄───►│  Node D  │◄────┘                     │
  │             │ Tokyo    │     │ New York │                           │
  │             │ :9000    │     │ :9001    │                           │
  │             └──────────┘     └──────────┘                           │
  │                                                                     │
  │   Gossip:                         Health:                           │
  │   - Каждые 30 сек                - Пинг каждые 30 сек               │
  │   - 3 случайных пира             - Таймаут 90 сек                   │
  │   - Обмен списками пиров         - Удаление мёртвых                 │
  │   - Обмен публичными комнатами   - Сохранение в JSON                │
  │                                                                     │
  └─────────────────────────────────────────────────────────────────────┘
```

**Протокол Gossip:**

1. **Bootstrap**: При первом запуске узел подключается к одному или нескольким bootstrap-пирам (указанным в `BOOTSTRAP_PEERS`):
   ```
   POST /api/global/bootstrap
   {
     "sender_ip": "203.0.113.50",
     "sender_port": 9000,
     "sender_pubkey": "a3b4c5..."
   }
   ```
   Bootstrap-пир отвечает своей информацией и списком всех известных ему пиров.

2. **Gossip Loop** (каждые 30 секунд):
   - Узел выбирает до 3 случайных живых пиров
   - Отправляет им POST-запрос на `/api/global/gossip`:
     ```json
     {
       "sender_ip": "203.0.113.50",
       "sender_port": 9000,
       "sender_pubkey": "a3b4c5...",
       "peers": [{"ip": "...", "port": 9000, "node_pubkey_hex": "..."}],
       "rooms": [{"id": 1, "name": "General", "invite_code": "abc123"}]
     }
     ```
   - Получает в ответ список пиров и комнат собеседника
   - Мержит новых пиров в свой реестр
   - Сохраняет обновлённый список в `global_peers.json`

3. **Health Loop** (каждые 30 секунд):
   - Пингует всех известных пиров через `GET /api/global/node-info`
   - Обновляет `last_seen` для ответивших
   - Удаляет пиров, не отвечавших более 90 секунд

4. **Peer Persistence**: Список пиров сохраняется в `global_peers.json` при каждом изменении. При перезапуске узел загружает сохранённых пиров и не теряет связность.

**Настройка .env для глобального режима:**
```env
NETWORK_MODE=global
BOOTSTRAP_PEERS=203.0.113.10:9000,198.51.100.20:9000
OBFUSCATION_ENABLED=true
```

### Переключение между режимами

Для переключения режима достаточно изменить переменную `NETWORK_MODE` в файле `.env` и перезапустить узел:

```bash
# Переключение на глобальный режим
sed -i 's/NETWORK_MODE=local/NETWORK_MODE=global/' .env

# Добавление bootstrap-пиров
echo "BOOTSTRAP_PEERS=203.0.113.10:9000" >> .env

# Перезапуск
python run.py
```

При переключении режимов:
- Локальные данные (комнаты, пользователи, сообщения) сохраняются
- UDP discovery отключается при переходе в глобальный режим
- Gossip-протокол отключается при переходе в локальный режим

### Обфускация трафика

В глобальном режиме VORTEX поддерживает обфускацию трафика для обхода Deep Packet Inspection (DPI). Обфускация включает три компонента:

#### 1. Паддинг сообщений

Все сообщения дополняются до стандартных размеров, типичных для обычных веб-ресурсов:

| Целевой размер | Что имитирует |
|----------------|---------------|
| 256 байт | Мелкие HTML-фрагменты |
| 512 байт | CSS-стили |
| 1024 байт | Мелкие JS-скрипты |
| 2048 байт | HTML-страницы |
| 4096 байт | Средние скрипты |
| 8192 байт | Крупные стили |
| 16384 байт | Мелкие изображения |

Формат запакованного сообщения:
```
[2 байта: real_length (big-endian)][real_data][random_padding]
```

Получатель извлекает `real_length`, считывает `real_data` и отбрасывает паддинг.

#### 2. Timing Jitter

Перед каждой отправкой добавляется случайная задержка от 10 до 150 миллисекунд. Это предотвращает анализ временных паттернов трафика (timing analysis), который используется DPI для идентификации мессенджеров по характерным интервалам между пакетами.

#### 3. Cover Headers

Ко всем HTTP-ответам добавляются заголовки, характерные для обычного веб-сервера:

```http
Server: nginx/1.24.0
X-Powered-By: Express
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Cache-Control: public, max-age=3600
Vary: Accept-Encoding
```

Эти заголовки делают трафик VORTEX неотличимым от обычного HTTPS-трафика к веб-сайту.

### Cover Traffic (фейковый сайт)

При включённом глобальном режиме VORTEX подключает cover-маршруты, которые отображают фейковый бизнес-сайт "CloudSync Solutions" для всех неаутентифицированных запросов. Если DPI-система или инспектор заходит на адрес VORTEX через браузер, он видит обычный корпоративный сайт с разделами "About", "Pricing", "Contact".

```
  DPI/Сканер → GET /              → "CloudSync Solutions — Enterprise Cloud"
  DPI/Сканер → GET /about         → "About CloudSync"
  DPI/Сканер → GET /pricing       → "Coming soon"
  DPI/Сканер → GET /contact       → "support@cloudsync.example.com"

  Клиент VORTEX → POST /api/...   → Нормальная работа мессенджера
  Клиент VORTEX → WS /ws/...      → WebSocket чат
```

Это обеспечивает **plausible deniability** — правдоподобное отрицание использования мессенджера.

### Как VORTEX обходит DPI

| Техника | Что делает | От чего защищает |
|---------|-----------|-----------------|
| **SSL/TLS** | Шифрует весь HTTP-трафик | Инспекция содержимого |
| **Cover headers** | Имитирует nginx/Express | Fingerprinting сервера |
| **Padding** | Стандартизирует размеры пакетов | Анализ размеров (size analysis) |
| **Timing jitter** | Рандомизирует интервалы | Timing analysis |
| **Cover site** | Показывает фейковый сайт | Active probing |
| **Standard ports** | Использует 443/9000 | Port-based blocking |

---

## :closed_lock_with_key: Настройка SSL

VORTEX поддерживает три варианта настройки SSL/TLS:

| Вариант | Инструмент | Доверие браузера | Сложность | Рекомендуется |
|---------|-----------|------------------|-----------|---------------|
| Доверенный (mkcert) | `mkcert` | Да (автоматически) | Низкая | Да |
| Самоподписанный | `openssl` | Нет (предупреждение) | Низкая | Для тестирования |
| Без SSL | — | — | Нулевая | Только для разработки |

### Вариант 1: mkcert (рекомендуется)

mkcert создаёт сертификаты, подписанные локальным корневым CA, который устанавливается в системное хранилище доверия. Браузер не показывает предупреждения.

```bash
# Установка корневого CA (один раз)
mkcert -install

# Определяем IP-адрес
IP=$(hostname -I 2>/dev/null | awk '{print $1}' || ipconfig getifaddr en0)

# Генерация сертификата для всех возможных адресов
mkdir -p certs
mkcert -cert-file certs/vortex.crt -key-file certs/vortex.key \
    localhost 127.0.0.1 ::1 $IP "$(hostname)"

# Проверка
openssl x509 -in certs/vortex.crt -noout -dates -subject
```

### Вариант 2: OpenSSL (самоподписанный)

```bash
mkdir -p certs

# Создание приватного ключа и самоподписанного сертификата
openssl req -x509 -newkey rsa:4096 \
    -keyout certs/vortex.key \
    -out certs/vortex.crt \
    -days 365 \
    -nodes \
    -subj "/C=RU/ST=Moscow/L=Moscow/O=Vortex/CN=VortexNode" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:$(hostname -I | awk '{print $1}')"

# Проверка
openssl x509 -in certs/vortex.crt -text -noout | head -20
```

> **Примечание**: При самоподписанном сертификате браузер покажет предупреждение о недоверенном сертификате. Для WebRTC звонков между устройствами необходимо принять сертификат на каждом устройстве.

### Вариант 3: Без SSL

Для локальной разработки можно запустить без SSL:

```bash
# Убедитесь, что файлы certs/vortex.crt и certs/vortex.key НЕ существуют
# run.py автоматически определит отсутствие SSL и запустит HTTP

python run.py
```

> **Предупреждение**: Без SSL WebRTC звонки не будут работать в большинстве браузеров (требуется Secure Context). Также отсутствует шифрование на транспортном уровне.

---

## :gear: Конфигурация (.env)

Все настройки VORTEX хранятся в файле `.env` в корне проекта. При первом запуске автоматически генерируются `JWT_SECRET` и `CSRF_SECRET`.

### Полная справка по переменным окружения

| Переменная | Значение по умолчанию | Описание |
|------------|----------------------|----------|
| `JWT_SECRET` | Авто-генерация (64 hex) | Секрет для подписи JWT-токенов (HMAC-SHA256). Генерируется автоматически при первом запуске |
| `CSRF_SECRET` | Авто-генерация (64 hex) | Секрет для CSRF-токенов. Генерируется автоматически при первом запуске |
| `ACCESS_TOKEN_EXPIRE_MIN` | `60` | Время жизни access-токена в минутах |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `30` | Время жизни refresh-токена в днях |
| `HOST` | `0.0.0.0` | Хост для привязки сервера. `0.0.0.0` — слушать на всех интерфейсах |
| `PORT` | `9000` | Порт HTTPS-сервера |
| `DEVICE_NAME` | Имя хоста ОС | Отображаемое имя узла в mesh-сети |
| `DB_PATH` | `vortex.db` | Путь к SQLite базе данных |
| `UPLOAD_DIR` | `uploads` | Директория для загруженных файлов |
| `KEYS_DIR` | `keys` | Директория для X25519 ключевых пар узла |
| `ENVIRONMENT` | `development` | Окружение: `development` или `production` |
| `UDP_PORT` | `4200` | Порт для UDP broadcast discovery (локальный режим) |
| `UDP_INTERVAL_SEC` | `2` | Интервал UDP broadcast в секундах |
| `PEER_TIMEOUT_SEC` | `15` | Таймаут неактивности пира в секундах |
| `MAX_FILE_MB` | `100` | Максимальный размер загружаемого файла в МБ |
| `WAF_RATE_LIMIT_REQUESTS` | `120` | Максимальное количество запросов за окно |
| `WAF_RATE_LIMIT_WINDOW` | `60` | Длительность окна rate-limit в секундах |
| `WAF_BLOCK_DURATION` | `3600` | Длительность блокировки при превышении лимита (секунды) |
| `NETWORK_MODE` | `local` | Режим сети: `local` (LAN) или `global` (интернет) |
| `BOOTSTRAP_PEERS` | `` (пусто) | Bootstrap-пиры для глобального режима (через запятую): `ip:port,ip:port` |
| `OBFUSCATION_ENABLED` | `true` | Включить обфускацию трафика в глобальном режиме |
| `NODE_INITIALIZED` | — | Флаг инициализации узла (устанавливается wizard) |

### Пример полного .env файла

```env
# ═══════════════════════════════════════════════════════════════════════
# VORTEX Node Configuration
# ═══════════════════════════════════════════════════════════════════════

# ── Безопасность ──────────────────────────────────────────────────────
JWT_SECRET=a1b2c3d4e5f6...64_hex_chars_auto_generated...
CSRF_SECRET=f6e5d4c3b2a1...64_hex_chars_auto_generated...
ACCESS_TOKEN_EXPIRE_MIN=60
REFRESH_TOKEN_EXPIRE_DAYS=30

# ── Сервер ────────────────────────────────────────────────────────────
HOST=0.0.0.0
PORT=9000
DEVICE_NAME=Vortex-Home
ENVIRONMENT=development

# ── Хранение ─────────────────────────────────────────────────────────
DB_PATH=vortex.db
UPLOAD_DIR=uploads
KEYS_DIR=keys

# ── P2P Discovery (локальный режим) ──────────────────────────────────
UDP_PORT=4200
UDP_INTERVAL_SEC=2
PEER_TIMEOUT_SEC=15

# ── Файлы ────────────────────────────────────────────────────────────
MAX_FILE_MB=100

# ── WAF ──────────────────────────────────────────────────────────────
WAF_RATE_LIMIT_REQUESTS=120
WAF_RATE_LIMIT_WINDOW=60
WAF_BLOCK_DURATION=3600

# ── Глобальный режим ─────────────────────────────────────────────────
NETWORK_MODE=local
BOOTSTRAP_PEERS=
OBFUSCATION_ENABLED=true

# ── Флаг инициализации ───────────────────────────────────────────────
NODE_INITIALIZED=true
```

---

## :building_construction: Архитектура

### Архитектура узла

```
  ╔═══════════════════════════════════════════════════════════════════════╗
  ║                         VORTEX NODE                                   ║
  ╠═══════════════════════════════════════════════════════════════════════╣
  ║                                                                       ║
  ║   ┌─────────────────────── Middleware Stack ───────────────────────┐  ║
  ║   │                                                                │  ║
  ║   │  ┌──────────────────┐   Порядок обработки запроса (LIFO):      │  ║
  ║   │  │ SecurityHeaders  │   1. SecurityHeaders (добавляет заголовки)│ ║
  ║   │  └────────┬─────────┘   2. Logging (логирует запрос)           │  ║
  ║   │  ┌────────▼─────────┐   3. CSRF (проверяет токен)              │  ║
  ║   │  │    Logging       │   4. TokenRefresh (обновляет JWT)        │  ║
  ║   │  └────────┬─────────┘   5. WAF (SQLi/XSS/PathTraversal/Rate)   │  ║
  ║   │  ┌────────▼─────────┐   6. Obfuscation* (cover headers)        │  ║
  ║   │  │     CSRF         │                                          │  ║
  ║   │  └────────┬─────────┘   * только в глобальном режиме           │  ║
  ║   │  ┌────────▼─────────┐                                          │  ║
  ║   │  │  TokenRefresh    │                                          │  ║
  ║   │  └────────┬─────────┘                                          │  ║
  ║   │  ┌────────▼─────────┐                                          │  ║
  ║   │  │      WAF         │                                          │  ║
  ║   │  └────────┬─────────┘                                          │  ║
  ║   │  ┌────────▼─────────┐                                          │  ║
  ║   │  │  Obfuscation*    │                                          │  ║
  ║   │  └────────┬─────────┘                                          │  ║
  ║   └───────────┼────────────────────────────────────────────────────┘  ║
  ║               ▼                                                       ║
  ║   ┌─────────────────────── Router Layer ───────────────────────────┐  ║
  ║   │                                                                │  ║
  ║   │  /api/authentication/*    Auth (register, login, challenge)    │  ║
  ║   │  /api/rooms/*             Rooms (create, join, leave, members) │  ║
  ║   │  /api/dm/*                DM (create/get, list)                │  ║
  ║   │  /api/contacts/*          Contacts (list, add, update, delete) │  ║
  ║   │  /api/users/*             Search (by phone/email/IP/username)  │  ║
  ║   │  /api/peers/*             Peers (list, federated-join)         │  ║
  ║   │  /api/files/*             Files (upload, download, resumable)  │  ║
  ║   │  /api/keys/*              Keys (X25519 public key exchange)    │  ║
  ║   │  /api/federation/*        Federation (guest-login, relay)      │  ║
  ║   │  /api/global/*            Global (gossip, bootstrap, search)   │  ║
  ║   │  /api/waf/*               WAF (stats, block list)              │  ║
  ║   │  /ws/{room_id}            WebSocket Chat                       │  ║
  ║   │  /ws/signal/{room_id}     WebSocket Signaling (WebRTC)         │  ║
  ║   │  /ws/notifications        WebSocket Global Notifications       │  ║
  ║   │  /ws/fed/{virtual_id}     WebSocket Federation Relay           │  ║
  ║   │                                                                │  ║
  ║   └────────────────────────────────────────────────────────────────┘  ║
  ║               │                                                       ║
  ║               ▼                                                       ║
  ║   ┌─────────────────────── Service Layer ──────────────────────────┐  ║
  ║   │                                                                │  ║
  ║   │  ┌──────────────────┐  ┌──────────────────┐                    │  ║
  ║   │  │  ConnectionMgr   │  │   PeerRegistry   │                    │  ║
  ║   │  │  (WebSocket)     │  │  (UDP/Gossip)    │                    │  ║
  ║   │  │  - rooms dict    │  │  - active peers  │                    │  ║
  ║   │  │  - global_ws     │  │  - discovery     │                    │  ║
  ║   │  │  - dedup cache   │  │  - federation    │                    │  ║
  ║   │  │  - rate limiter  │  │  - multihop      │                    │  ║
  ║   │  └──────────────────┘  └──────────────────┘                    │  ║
  ║   │                                                                │  ║
  ║   │  ┌──────────────────┐  ┌──────────────────┐                    │  ║
  ║   │  │  GlobalTransport │  │   Federation     │                    │  ║
  ║   │  │  (gossip loop)   │  │  (server-to-srv) │                    │  ║
  ║   │  │  - health loop   │  │  - guest login   │                    │  ║
  ║   │  │  - peer merge    │  │  - virtual rooms │                    │  ║
  ║   │  │  - room search   │  │  - WS relay      │                    │  ║
  ║   │  └──────────────────┘  └──────────────────┘                    │  ║
  ║   │                                                                │  ║
  ║   └────────────────────────────────────────────────────────────────┘  ║
  ║               │                                                       ║
  ║               ▼                                                       ║
  ║   ┌─────────────────────── Crypto Layer ───────────────────────────┐  ║
  ║   │                                                                │  ║
  ║   │  ┌──────────────────┐  ┌──────────────────┐                    │  ║
  ║   │  │ Rust (vortex_chat│  │  Python fallback │                    │  ║
  ║   │  │  via PyO3)       │  │  (cryptography)  │                    │  ║
  ║   │  │                  │  │                  │                    │  ║
  ║   │  │ - AES-256-GCM    │  │ - X25519 keymgmt │                    │  ║
  ║   │  │ - BLAKE3         │  │ - ECIES          │                    │  ║
  ║   │  │ - Argon2id       │  │ - JWT (HS256)    │                    │  ║
  ║   │  │ - SHA-256 (CT)   │  │ - HKDF-SHA256    │                    │  ║
  ║   │  │ - X25519 DH      │  │                  │                    │  ║
  ║   │  │ - Key generation │  │                  │                    │  ║
  ║   │  └──────────────────┘  └──────────────────┘                    │  ║
  ║   │                                                                │  ║
  ║   └────────────────────────────────────────────────────────────────┘  ║
  ║               │                                                       ║
  ║               ▼                                                       ║
  ║   ┌─────────────────────── Storage Layer ──────────────────────────┐  ║
  ║   │                                                                │  ║
  ║   │  ┌──────────────────┐  ┌──────────────────┐                    │  ║
  ║   │  │     SQLite       │  │   File System    │                    │  ║
  ║   │  │  (vortex.db)     │  │                  │                    │  ║
  ║   │  │                  │  │  uploads/        │                    │  ║
  ║   │  │  - users         │  │  keys/           │                    │  ║
  ║   │  │  - rooms         │  │  certs/          │                    │  ║
  ║   │  │  - messages      │  │  global_peers.json│                   │  ║
  ║   │  │  - room_members  │  │                  │                    │  ║
  ║   │  │  - enc_room_keys │  │                  │                    │  ║
  ║   │  │  - pending_keys  │  │                  │                    │  ║
  ║   │  │  - contacts      │  │                  │                    │  ║
  ║   │  │  - refresh_tokens│  │                  │                    │  ║
  ║   │  │  - file_transfers│  │                  │                    │  ║
  ║   │  └──────────────────┘  └──────────────────┘                    │  ║
  ║   │                                                                │  ║
  ║   └────────────────────────────────────────────────────────────────┘  ║
  ║                                                                       ║
  ╚═══════════════════════════════════════════════════════════════════════╝
```

### Взаимодействие модулей

```
  main.py
    │
    ├── lifespan()
    │     ├── Config.ensure_dirs()          — создание директорий
    │     ├── init_db()                     — инициализация SQLite
    │     ├── load_or_create_node_keypair() — X25519 ключи узла
    │     ├── start_discovery()             — UDP broadcast (local mode)
    │     ├── global_transport.start()      — gossip (global mode)
    │     └── cleanup_sessions_loop()       — очистка resumable uploads
    │
    ├── Middleware Stack
    │     ├── SecurityHeadersMiddleware     — CSP, HSTS, X-Frame-Options
    │     ├── LoggingMiddleware             — логирование запросов
    │     ├── CSRFMiddleware                — проверка CSRF-токена
    │     ├── TokenRefreshMiddleware        — автообновление JWT
    │     ├── WAFMiddleware                 — SQLi/XSS/PathTraversal/Rate
    │     └── ObfuscationMiddleware*        — cover headers (global)
    │
    └── Routers
          ├── auth_router        → /api/authentication/*
          ├── rooms_router       → /api/rooms/*
          ├── chat_router        → /ws/*, /api/files/*
          ├── contacts_router    → /api/contacts/*
          ├── search_router      → /api/users/*
          ├── dm_router          → /api/dm/*
          ├── peers_router       → /api/peers/*
          ├── keys_router        → /api/keys/*
          ├── resumable_router   → /api/files/upload-*
          ├── federation_router  → /api/federation/*
          ├── fed_ws_router      → /ws/fed/*
          ├── waf_router         → /api/waf/*
          ├── global_router*     → /api/global/*
          └── cover_router*      → /cover, /about, /pricing, /contact
```

### Стек технологий

| Уровень | Технологии |
|---------|-----------|
| **Frontend** | Vanilla JS, CSS3 (Glassmorphism), HTML5, WebRTC API, Web Crypto API, Service Worker |
| **Backend** | Python 3.10+, FastAPI (ASGI), Uvicorn, SQLAlchemy 2.0, Pydantic 2.0 |
| **Crypto (Rust)** | PyO3, x25519-dalek, aes-gcm, blake3, argon2, sha2, hkdf |
| **Crypto (Python)** | cryptography (X25519, HKDF, AES-GCM), argon2-cffi, blake3 |
| **Database** | SQLite (через SQLAlchemy ORM) |
| **Transport** | WebSocket (uvicorn), UDP broadcast, HTTPS (httpx), WebRTC (browser) |
| **Security** | JWT (HS256), CSRF double-submit, WAF, Argon2id, rate limiting |

---

## :arrows_counterclockwise: Мультихоп-маршрутизация

Мультихоп-маршрутизация позволяет узлам подключаться к комнатам на удалённых узлах, даже если прямое соединение невозможно. Сообщения проходят через промежуточные узлы (relay).

### Схема федеративного подключения

```
  ┌──────────────────────────────────────────────────────────────────────┐
  │  МУЛЬТИХОП FEDERATION: Пользователь на Node A → комната на Node C   │
  └──────────────────────────────────────────────────────────────────────┘

  ┌──────────┐                ┌──────────┐                ┌──────────┐
  │ Браузер  │   WebSocket    │  Node A  │  Server-to-    │  Node B  │
  │ (Alice)  │ ◄─────────────►│ (home)   │  Server HTTPS  │ (relay)  │
  │          │ /ws/fed/-1     │ :9000    │ ◄────────────► │ :9001    │
  └──────────┘                └──────────┘                └────┬─────┘
                                                               │
                                    Server-to-Server HTTPS     │
                                                               │
                                                          ┌────▼─────┐
                                                          │  Node C  │
                                                          │ (target) │
                                                          │ :9002    │
                                                          │          │
                                                          │ Room:    │
                                                          │ "Gaming" │
                                                          └──────────┘
```

### Полный flow федеративного подключения

```
  Шаг 1: Пользователь на Node A хочет подключиться к комнате на Node C
  ─────────────────────────────────────────────────────────────────────

  Браузер (Alice)
      │
      │  POST /api/peers/federated-join
      │  { "peer_ip": "Node C IP", "peer_port": 9002, "invite_code": "abc123" }
      │
      ▼
  Node A (домашний узел)
      │
      │  1. POST /api/federation/guest-login → Node C
      │     { "username": "alice", "from_node": "Node A IP:9000" }
      │     ← { "remote_jwt": "eyJ..." }
      │
      │  2. POST /api/rooms/join/abc123 → Node C
      │     Authorization: Bearer <remote_jwt>
      │     ← { "room_id": 5, "room_name": "Gaming" }
      │
      │  3. Создание виртуальной комнаты (ID = -1)
      │     Хранится только в памяти Node A
      │
      │  4. Запуск WS-relay:
      │     Node A ↔ WebSocket ↔ Node C (/ws/5)
      │
      ▼
  Браузер (Alice)
      │
      │  WebSocket /ws/fed/-1 → Node A
      │  (обычный WS к домашнему узлу, без чужих SSL-сертификатов)
      │
      │  Сообщение: { action: "message", ciphertext: "..." }
      │    → Node A ретранслирует → Node C (room 5)
      │    → Node C рассылает всем участникам room 5
      │    ← Ответы ретранслируются обратно через Node A
      │
      ▼
  Результат: Alice видит комнату "Gaming" на Node C
  как обычную комнату в своём интерфейсе
```

### Характеристики мультихоп-маршрутизации

| Параметр | Значение |
|----------|----------|
| Максимальное число хопов | Не ограничено (каждый хоп — отдельное соединение) |
| TTL сообщений | Управляется на уровне WebSocket relay |
| Дедупликация | Глобальный кэш `seen_ids` (LRU, 10000 записей) |
| Виртуальные комнаты | Отрицательные ID (-1, -2, ...) |
| Хранение виртуальных комнат | Только в памяти (теряются при рестарте) |
| Аутентификация | Guest login (временный JWT для удалённого узла) |
| Шифрование | E2E сохраняется (сервер не расшифровывает) |

---

## :lock: E2E шифрование

VORTEX реализует полноценное end-to-end шифрование, при котором сервер (узел) физически не может прочитать ни одно сообщение. Вся криптография выполняется на клиенте (в браузере через Web Crypto API или на Rust через PyO3).

### Криптографические примитивы

| Примитив | Алгоритм | Назначение | Реализация |
|----------|----------|-----------|------------|
| Обмен ключами | X25519 (Curve25519 ECDH) | Diffie-Hellman для получения общего секрета | Rust (x25519-dalek) + Python (cryptography) |
| Шифрование сообщений | AES-256-GCM | Authenticated encryption с 12-byte nonce | Rust (aes-gcm) + Python (cryptography) |
| Распределение ключей | ECIES (X25519 + HKDF + AES-GCM) | Шифрование ключа комнаты для каждого участника | Rust + Python |
| Деривация ключей | HKDF-SHA256 | Получение ключа шифрования из shared secret | Rust (hkdf + sha2) + Python |
| Хеширование сообщений | BLAKE3 | Проверка целостности без расшифровки | Rust (blake3) + Python (blake3) |
| Хеширование паролей | Argon2id | Защита паролей от brute-force | Rust (argon2) + Python (argon2-cffi) |
| Хеширование токенов | SHA-256 (constant-time) | Хранение хешей refresh-токенов | Rust (sha2 + subtle) + Python |
| Подпись JWT | HMAC-SHA256 | Аутентификация запросов | Python (PyJWT) |
| Хеширование файлов | SHA-256 | Контроль целостности файлов | Python (hashlib) |

### Регистрация (генерация ключевой пары)

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │                     КЛИЕНТ (Браузер)                                │
  │                                                                     │
  │  1. Генерируем X25519 ключевую пару:                                │
  │     priv_key = crypto.getRandomValues(new Uint8Array(32))           │
  │     pub_key  = X25519.getPublicKey(priv_key)                        │
  │                                                                     │
  │  2. Сохраняем priv_key в localStorage/IndexedDB                     │
  │     (зашифрован паролем пользователя через PBKDF2)                  │
  │                                                                     │
  │  3. Отправляем на сервер:                                           │
  │     POST /api/authentication/register                               │
  │     {                                                               │
  │       "phone": "+79991234567",                                      │
  │       "username": "alice",                                          │
  │       "password": "SuperSecret123!",                                │
  │       "x25519_public_key": "a3b4c5d6e7f8...64_hex_chars"            │
  │     }                                                               │
  │                                                                     │
  └───────────────────────────────────────┬─────────────────────────────┘
                                          │
                                          ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                     СЕРВЕР (Узел)                                   │
  │                                                                     │
  │  4. Хеширует пароль: Argon2id(password) → password_hash             │
  │  5. Сохраняет в БД:                                                 │
  │     User(phone, username, password_hash, x25519_public_key)         │
  │                                                                     │
  │  Сервер НИКОГДА не видит приватный ключ.                            │
  │  x25519_public_key — единственная криптографическая информация      │
  │  которую сервер хранит о пользователе.                              │
  │                                                                     │
  └─────────────────────────────────────────────────────────────────────┘
```

### Создание комнаты

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │                     КЛИЕНТ (Создатель комнаты)                      │
  │                                                                     │
  │  1. Генерируем ключ комнаты:                                        │
  │     room_key = crypto.getRandomValues(new Uint8Array(32))           │
  │     (32 bytes = 256 bit AES ключ)                                   │
  │                                                                     │
  │  2. Шифруем room_key для себя через ECIES:                          │
  │     a. ephemeral_priv = new X25519 private key                      │
  │     b. ephemeral_pub  = X25519.getPublicKey(ephemeral_priv)         │
  │     c. shared_secret  = X25519-DH(ephemeral_priv, own_pub_key)      │
  │     d. enc_key = HKDF-SHA256(shared_secret, info="vortex-session")  │
  │     e. nonce = random(12 bytes)                                     │
  │     f. ciphertext = AES-256-GCM(room_key, enc_key, nonce)           │
  │     g. result = nonce + ciphertext + tag = 12 + 32 + 16 = 60 bytes  │
  │                                                                     │
  │  3. Отправляем:                                                     │
  │     POST /api/rooms                                                 │
  │     {                                                               │
  │       "name": "General",                                            │
  │       "encrypted_room_key": {                                       │
  │         "ephemeral_pub": "<64 hex chars>",                          │
  │         "ciphertext": "<120 hex chars>"                             │
  │       }                                                             │
  │     }                                                               │
  │                                                                     │
  └───────────────────────────────────────┬─────────────────────────────┘
                                          │
                                          ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                     СЕРВЕР                                          │
  │                                                                     │
  │  4. Создаёт Room (БЕЗ room_key в открытом виде!)                    │
  │  5. Сохраняет EncryptedRoomKey для создателя:                       │
  │     EncryptedRoomKey(                                               │
  │       room_id = new_room.id,                                        │
  │       user_id = creator.id,                                         │
  │       ephemeral_pub = "...",                                        │
  │       ciphertext = "..."                                            │
  │     )                                                               │
  │                                                                     │
  │  Сервер хранит ТОЛЬКО зашифрованный ключ комнаты.                   │
  │  Для расшифровки нужен приватный ключ пользователя.                 │
  │  Приватный ключ НИКОГДА не покидает устройство.                     │
  │                                                                     │
  └─────────────────────────────────────────────────────────────────────┘
```

### Вступление нового участника (key distribution protocol)

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │  Протокол распределения ключей при вступлении нового участника      │
  └─────────────────────────────────────────────────────────────────────┘

  Bob (новый участник)              Сервер              Alice (уже в комнате)
       │                              │                        │
       │  1. POST /api/rooms/join/    │                        │
       │     {invite_code}            │                        │
       │  ─────────────────────────►  │                        │
       │                              │                        │
       │                              │  2. Создаёт RoomMember │
       │                              │     для Bob            │
       │                              │                        │
       │                              │  3. Проверяет: есть ли │
       │                              │     EncryptedRoomKey   │
       │                              │     для Bob? → НЕТ     │
       │                              │                        │
       │                              │  4. Создаёт            │
       │                              │     PendingKeyRequest  │
       │                              │     (room_id, bob_id,  │
       │                              │      bob_pubkey)       │
       │                              │                        │
       │  ◄─── { joined: true,        │                        │
       │        has_key: false }      │                        │
       │                              │                        │
       │                              │  5. WebSocket broadcast│
       │                              │     to online members: │
       │                              │  ─────────────────────►│
       │                              │  { type: "key_request",│
       │                              │    for_user_id: bob.id,│
       │                              │    for_pubkey: "bob..."│
       │                              │  }                     │
       │                              │                        │
       │                              │  6.Alice расшифровывает│
       │                              │     room_key локально  │
       │                              │                        │
       │                              │  7. Alice делает ECIES:│
       │                              │     encrypt(room_key,  │
       │                              │             bob_pubkey)│
       │                              │                        │
       │                              │  ◄──────────────────── │
       │                              │  WS: { action:         │
       │                              │    "key_response",     │
       │                              │    for_user_id: bob.id,│
       │                              │    ephemeral_pub: "..."│
       │                              │    ciphertext: "..."   │
       │                              │  }                     │
       │                              │                        │
       │                              │  8. Сервер сохраняет   │
       │                              │     EncryptedRoomKey   │
       │                              │     для Bob            │
       │                              │                        │
       │                              │  9. Удаляет            │
       │                              │     PendingKeyRequest  │
       │                              │                        │
       │  ◄─── WS: {                  │                        │
       │    type: "room_key",         │                        │
       │    ephemeral_pub: "...",     │                        │
       │    ciphertext: "..."         │                        │
       │  }                           │                        │
       │                              │                        │
       │  10. Bob расшифровывает:     │                        │
       │      shared = DH(bob_priv,   │                        │
       │                 ephemeral_pub│                        │
       │      enc_key = HKDF(shared)  │                        │
       │      room_key = AES-GCM-     │                        │
       │        decrypt(ciphertext,   │                        │
       │                enc_key)      │                        │
       │                              │                        │
       │  11. Bob теперь может        │                        │
       │      расшифровывать          │                        │
       │      все сообщения           │                        │
       ▼                              ▼                        ▼
```

### Шифрование и расшифровка сообщений

```
  Отправка сообщения:
  ───────────────────

  Клиент (отправитель):
    1. plaintext = "Привет, мир!"
    2. nonce = random(12 bytes)
    3. ciphertext = AES-256-GCM(plaintext, room_key, nonce)
    4. content_encrypted = nonce(12) + ciphertext + tag(16)
    5. content_hash = BLAKE3(content_encrypted)
    6. WS send: { action: "message", ciphertext: content_encrypted.hex() }

  Сервер:
    7. Сохраняет Message(content_encrypted=bytes, content_hash=blake3_hash)
    8. Ретранслирует всем участникам комнаты: { ciphertext: "..." }
       Сервер видит ТОЛЬКО content_encrypted — зашифрованный blob.
       Расшифровка невозможна без room_key.

  Клиент (получатель):
    9.  content_encrypted = bytes.fromhex(ciphertext)
    10. nonce = content_encrypted[:12]
    11. ct = content_encrypted[12:]
    12. plaintext = AES-256-GCM-decrypt(ct, room_key, nonce)
    13. Отображает: "Привет, мир!"
```

### ECIES (Elliptic Curve Integrated Encryption Scheme)

ECIES используется для шифрования ключа комнаты индивидуально для каждого участника:

```
  Шифрование (любой участник → новому участнику):
  ───────────────────────────────────────────────
  1. (e_priv, e_pub) = X25519.generateKeyPair()     // эфемерная пара
  2. shared = X25519-DH(e_priv, recipient_pub)       // Diffie-Hellman
  3. enc_key = HKDF-SHA256(shared, info="vortex-session", len=32)
  4. nonce = random(12 bytes)
  5. ct = AES-256-GCM(room_key, enc_key, nonce)      // room_key = 32 bytes
  6. result = { ephemeral_pub: e_pub.hex(), ciphertext: (nonce + ct + tag).hex() }

  Расшифровка (получатель):
  ─────────────────────────
  1. shared = X25519-DH(user_priv, e_pub)            // тот же shared secret
  2. enc_key = HKDF-SHA256(shared, info="vortex-session", len=32)
  3. nonce = ciphertext[:12]
  4. room_key = AES-256-GCM-decrypt(ciphertext[12:], enc_key, nonce)
```

### Challenge-Response аутентификация (беспарольный вход)

VORTEX поддерживает беспарольную аутентификацию через X25519 challenge-response:

```
  1. Клиент → GET /api/authentication/challenge?identifier=alice
     ← { challenge_id: "abc...", challenge_hex: "def...", server_pubkey_hex: "..." }

  2. Клиент вычисляет:
     shared = X25519-DH(client_priv, server_pub)
     proof  = HMAC-SHA256(key=shared, msg=challenge_bytes).hex()

  3. Клиент → POST /api/authentication/login-key
     { challenge_id: "abc...", pubkey: "client_pub_hex", proof: "hmac_hex" }
     ← { access_token: "eyJ...", refresh_token: "..." }
```

---

## :envelope: Личные сообщения (DM)

Личные сообщения (Direct Messages) реализованы как приватные комнаты с `is_dm=True` и `max_members=2`. Шифрование DM идентично шифрованию групповых комнат — через ECIES key distribution.

### Как работают DM

1. **Создание DM**: Клиент отправляет `POST /api/dm/{target_user_id}` с зашифрованным ключом комнаты
2. **Проверка существующего DM**: Если DM между двумя пользователями уже существует, возвращается существующая комната
3. **Создание комнаты**: Создаётся комната с именем `dm:{min_id}:{max_id}`, `is_dm=True`, `max_members=2`
4. **Ключи**: `EncryptedRoomKey` для создателя, `PendingKeyRequest` для получателя
5. **Доставка ключа**: При подключении получателя к WebSocket другой участник передаёт ему ключ через ECIES

### Отличие DM от групповых комнат

| Свойство | DM | Групповая комната |
|----------|-----|-------------------|
| Максимум участников | 2 | 200 |
| `is_dm` | `True` | `False` |
| `is_private` | Всегда `True` | Настраивается |
| Имя комнаты | `dm:{min_id}:{max_id}` | Задаётся создателем |
| Invite-код | Случайный (не используется) | Для приглашения |
| Создание | `POST /api/dm/{user_id}` | `POST /api/rooms` |
| Список | `GET /api/dm/list` | `GET /api/rooms/my` |

### API Flow для DM

```
  Создание DM (Alice → Bob):
  ──────────────────────────

  Alice:
    POST /api/dm/42                    (42 = Bob's user_id)
    {
      "encrypted_room_key": {
        "ephemeral_pub": "a3b4c5...",
        "ciphertext": "d6e7f8..."
      }
    }

  Сервер:
    1. Проверяет: существует ли DM между Alice и Bob?
       → Если да: возвращает существующую комнату
       → Если нет: создаёт новую

    2. Создаёт Room(name="dm:1:42", is_dm=True, max_members=2)
    3. Создаёт RoomMember для Alice (OWNER) и Bob (MEMBER)
    4. Сохраняет EncryptedRoomKey для Alice
    5. Создаёт PendingKeyRequest для Bob

    Response:
    {
      "room": {
        "id": 15,
        "name": "dm:1:42",
        "is_dm": true,
        "is_private": true,
        "has_key": true,
        "member_count": 2
      },
      "other_user": {
        "user_id": 42,
        "username": "bob",
        "display_name": "Bob",
        "avatar_emoji": "🧑",
        "is_online": false
      }
    }
```

---

## :bust_in_silhouette: Контакты и поиск пользователей

### Управление контактами

VORTEX позволяет пользователям управлять списком контактов: добавлять, переименовывать и удалять контакты.

| Операция | Метод | Эндпоинт | Описание |
|----------|-------|----------|----------|
| Список контактов | `GET` | `/api/contacts` | Все контакты с информацией о пользователе |
| Добавить контакт | `POST` | `/api/contacts` | Добавить пользователя в контакты |
| Переименовать | `PUT` | `/api/contacts/{id}` | Задать никнейм для контакта |
| Удалить | `DELETE` | `/api/contacts/{id}` | Удалить из контактов |

#### Данные контакта

При получении списка контактов для каждого контакта возвращается:

```json
{
  "contact_id": 1,
  "user_id": 42,
  "username": "bob",
  "display_name": "Bob Smith",
  "avatar_emoji": "🧑",
  "phone": "+799****67",
  "nickname": "Bobby",
  "is_online": true,
  "dm_room_id": 15,
  "created_at": "2025-01-15T10:30:00"
}
```

**Маскирование номера телефона**: Номер телефона маскируется — показываются только первые 4 и последние 2 символа: `+799****67`. Это защищает приватность пользователей при поиске.

**Связь с DM**: Для каждого контакта автоматически определяется `dm_room_id` — ID существующей DM комнаты (если есть). Это позволяет клиенту мгновенно открыть чат с контактом.

### Поиск пользователей

VORTEX поддерживает поиск пользователей по нескольким критериям:

| Критерий | Как определяется | Пример запроса |
|----------|-----------------|----------------|
| Телефон | Регулярное выражение `^\+?\d[\d\s\-()]{5,}$` | `+79991234567` |
| Email | Наличие символа `@` | `alice@example.com` |
| IP-адрес | Регулярное выражение `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$` | `192.168.1.10` |
| Username / Display Name | Всегда (как fallback) | `alice`, `Bob Smith` |

```
  GET /api/users/search?q=alice

  Логика поиска:
  1. q = "alice" — не похож на телефон, не содержит @, не IP
  2. Ищем по username LIKE '%alice%' и display_name LIKE '%alice%'
  3. Исключаем текущего пользователя
  4. Ограничение: 20 результатов

  GET /api/users/search?q=+7999

  Логика поиска:
  1. q = "+7999" — похож на телефон
  2. Ищем по phone CONTAINS '7999'
  3. Также ищем по username/display_name (fallback)
  4. Результат: пользователи с номерами +7999xxxxxxx
```

#### Ответ поиска

```json
{
  "users": [
    {
      "user_id": 42,
      "username": "alice",
      "display_name": "Alice Wonderland",
      "avatar_emoji": "👩",
      "phone": "+799****67",
      "is_contact": false,
      "is_self": false
    }
  ]
}
```

Поле `is_contact` позволяет клиенту отобразить кнопку "Добавить в контакты" или "Уже в контактах".

---

## :bell: Уведомления

VORTEX реализует систему уведомлений через глобальный WebSocket `/ws/notifications`.

### Глобальный WebSocket уведомлений

При подключении пользователь устанавливает WebSocket-соединение на `/ws/notifications` с JWT-аутентификацией. Через этот канал приходят все уведомления:

```
  WebSocket /ws/notifications?token=<jwt>

  Типы уведомлений:
  ─────────────────

  1. Новое сообщение (в комнате, где пользователь не подключён к WS):
     { "type": "new_message", "room_id": 5, "room_name": "General",
       "sender": "alice", "preview": "(зашифровано)" }

  2. @ Упоминание:
     { "type": "mention", "room_id": 5, "room_name": "General",
       "sender": "bob", "msg_id": 142 }

  3. Входящий звонок:
     { "type": "incoming_call", "room_id": 8,
       "caller": "alice", "call_type": "video" }

  4. Запрос ключа комнаты:
     { "type": "key_request", "room_id": 5,
       "for_user_id": 42, "for_pubkey": "a3b4c5..." }

  5. Доставка ключа комнаты:
     { "type": "room_key", "room_id": 5,
       "ephemeral_pub": "...", "ciphertext": "..." }

  6. Системное сообщение:
     { "type": "system", "message": "Bob присоединился к комнате" }
```

### Slide-in баннеры

Клиентская часть VORTEX отображает уведомления как анимированные slide-in баннеры в верхней части экрана. Баннер появляется на 5 секунд и автоматически скрывается.

### Бейджи непрочитанных сообщений

Для каждой комнаты в списке отображается счётчик непрочитанных сообщений. Счётчик обновляется при получении нового сообщения через WebSocket и сбрасывается при открытии комнаты.

### Бейджи @ упоминаний

При упоминании пользователя (`@username`) рядом со счётчиком непрочитанных появляется специальный индикатор `@`. Это позволяет быстро определить комнаты, где пользователя непосредственно вызвали.

### Уведомления о входящих звонках

При входящем WebRTC-звонке отображается полноэкранное уведомление с кнопками "Принять" и "Отклонить", а также информацией о звонящем (имя, аватар, тип звонка).

---

## :telephone_receiver: Мониторинг качества звонков

VORTEX предоставляет пользователю реальные метрики качества WebRTC-звонков.

### Отображаемые метрики

| Метрика | Описание | Источник |
|---------|----------|----------|
| **RTT (Round-Trip Time)** | Задержка прохождения сигнала до собеседника и обратно | `RTCPeerConnection.getStats()` |
| **Jitter** | Вариация задержки между пакетами | `RTCPeerConnection.getStats()` |
| **Packet Loss** | Процент потерянных пакетов | `RTCPeerConnection.getStats()` |
| **Bitrate** | Текущая скорость передачи данных | Расчёт из `bytesSent`/`bytesReceived` |
| **Codec** | Используемый аудио/видео кодек | `RTCPeerConnection.getStats()` |

### Пороговые значения и цветовая индикация

| Метрика | Отлично (зелёный) | Хорошо (жёлтый) | Плохо (оранжевый) | Критично (красный) |
|---------|-------------------|------------------|--------------------|--------------------|
| RTT | < 100 мс | 100–200 мс | 200–400 мс | > 400 мс |
| Jitter | < 30 мс | 30–50 мс | 50–100 мс | > 100 мс |
| Packet Loss | < 1% | 1–3% | 3–8% | > 8% |

### Отображение в интерфейсе

```
  ┌──────────────────────────────────────────┐
  │  Качество связи: Отлично                 │
  │                                          │
  │  RTT:          45 мс                     │
  │  Jitter:       12 мс                     │
  │  Packet Loss:  0.2%                      │
  │  Bitrate:      128 kbps (audio)          │
  │                1.2 Mbps (video)          │
  │  Codec:        Opus / VP8                │
  │  Resolution:   1280x720                  │
  └──────────────────────────────────────────┘
```

---

## :headphones: Стратегия буферизации звонков

### Jitter Buffer

Для компенсации вариации задержки (jitter) используется адаптивный jitter buffer:

| Параметр | Значение | Описание |
|----------|----------|----------|
| Минимальный размер | 20 мс | При стабильном соединении |
| Максимальный размер | 200 мс | При нестабильном соединении |
| Адаптация | Динамическая | Размер подстраивается под текущий jitter |
| Алгоритм | EWMA | Exponentially Weighted Moving Average |

### Адаптивный битрейт (FSM)

VORTEX реализует конечный автомат (Finite State Machine) для адаптивной подстройки битрейта:

```
  ┌───────────┐   loss<1%, rtt<100     ┌───────────┐
  │           │ ─────────────────────► │           │
  │   HIGH    │                        │  VERY     │
  │  Quality  │ ◄───────────────────── │  HIGH     │
  │           │   loss>3% || rtt>200   │  Quality  │
  └─────┬─────┘                        └───────────┘
        │
        │ loss>5% || rtt>300
        ▼
  ┌───────────┐                        ┌───────────┐
  │           │   loss>10% || rtt>500  │           │
  │  MEDIUM   │ ─────────────────────► │   LOW     │
  │  Quality  │                        │  Quality  │
  │           │ ◄───────────────────── │           │
  └───────────┘   loss<3% && rtt<200   └───────────┘
```

### 4 уровня качества

| Уровень | Аудио битрейт | Видео битрейт | Видео разрешение | Видео FPS | Условие |
|---------|---------------|---------------|------------------|-----------|---------|
| **Very High** | 128 kbps (Opus) | 2.5 Mbps | 1280x720 (HD) | 30 | loss < 1%, RTT < 100ms |
| **High** | 64 kbps (Opus) | 1.5 Mbps | 960x540 | 30 | loss < 3%, RTT < 200ms |
| **Medium** | 32 kbps (Opus) | 600 kbps | 640x360 | 24 | loss < 8%, RTT < 400ms |
| **Low** | 16 kbps (Opus) | 200 kbps | 320x240 | 15 | fallback |

### ICE Buffering

При нестабильном соединении WebRTC может переключаться между ICE-кандидатами (STUN, TURN, relay). В этот момент:

1. Аудио/видео поток буферизируется на стороне браузера
2. При восстановлении соединения буфер воспроизводится
3. Если буфер переполняется (> 500мс), старые фреймы отбрасываются
4. Пользователь видит индикатор "Переподключение..."

---

## :railway_car: Транспортный стек

VORTEX поддерживает несколько транспортных протоколов с приоритизацией:

### Таблица приоритетов

| Приоритет | Транспорт | Условие | Задержка | Пропускная способность |
|-----------|-----------|---------|----------|----------------------|
| 1 (высший) | **Direct TCP/HTTPS** | Прямое соединение в LAN | < 1 мс | До 1 Гбит/с |
| 2 | **UDP Hole Punching** | Оба узла за NAT | 10–50 мс | До 100 Мбит/с |
| 3 | **Wi-Fi Direct** | Без роутера (P2P) | 2–5 мс | До 250 Мбит/с |
| 4 | **BLE** | Нет Wi-Fi/интернета | 50–200 мс | До 2 Мбит/с (BLE 5.0) |
| 5 (низший) | **Federation Relay** | Все остальные случаи | 50–500 мс | Зависит от промежуточных узлов |

### NAT Traversal

VORTEX реализует NAT traversal через STUN + UDP Hole Punching:

```
  ┌──────────┐         ┌──────────┐         ┌──────────┐
  │  Node A  │         │  STUN    │         │  Node B  │
  │  (NAT 1) │         │  Server  │         │  (NAT 2) │
  └────┬─────┘         └────┬─────┘         └────┬─────┘
       │                    │                    │
       │  1. STUN Binding   │                    │
       │  Request           │                    │
       │ ──────────────────►│                    │
       │                    │                    │
       │  2. STUN Binding   │                    │
       │  Response          │                    │
       │  (ext_ip:ext_port) │                    │
       │ ◄──────────────────│                    │
       │                    │                    │
       │                    │  3. STUN Binding   │
       │                    │  Request           │
       │                    │◄───────────────────│
       │                    │                    │
       │                    │  4. Response       │
       │                    │  (ext_ip:ext_port) │
       │                    │───────────────────►│
       │                    │                    │
       │  5. Обмен внешними адресами через       │
       │     signaling (WebSocket)               │
       │                    │                    │
       │  6. UDP Hole Punch ────────────────────►│
       │  ◄──────────────── UDP Hole Punch       │
       │                    │                    │
       │  7. Прямое P2P соединение               │
       │ ◄──────────────────────────────────────►│
       │                    │                    │
```

### Wi-Fi Direct

Wi-Fi Direct позволяет двум устройствам установить прямое P2P-соединение без Wi-Fi роутера. Это полезно при отсутствии инфраструктуры (на природе, в зонах бедствий, в оффлайне).

| Параметр | Значение |
|----------|----------|
| Протокол | Wi-Fi Direct (IEEE 802.11) |
| Дальность | До 200 м (прямая видимость) |
| Скорость | До 250 Мбит/с |
| Обнаружение | Wi-Fi P2P Service Discovery |
| Шифрование | WPA2 + E2E (VORTEX) |

### BLE (Bluetooth Low Energy)

BLE используется как fallback-транспорт при полном отсутствии Wi-Fi:

| Параметр | Значение |
|----------|----------|
| Протокол | Bluetooth Low Energy 5.0 |
| Дальность | До 100 м (BLE 5.0) |
| Скорость | До 2 Мбит/с (BLE 5.0) |
| MTU | 247 байт (максимум) |
| Фрагментация | Автоматическая (GATT) |
| Обнаружение | BLE Advertising |
| Шифрование | BLE Pairing + E2E (VORTEX) |

---

## :globe_with_meridians: Глобальный транспорт

Глобальный транспорт обеспечивает работу VORTEX через интернет без центрального сервера.

### Gossip-протокол

```
  Параметры gossip-протокола:
  ───────────────────────────
  _GOSSIP_INTERVAL    = 30 секунд   (между раундами gossip)
  _HEALTH_INTERVAL    = 30 секунд   (между проверками здоровья)
  _DEAD_PEER_TIMEOUT  = 90 секунд   (до удаления мёртвого пира)
  _PEER_REQUEST_TIMEOUT = 8 секунд  (таймаут HTTP-запросов к пирам)
```

### Bootstrap flow

```
  Новый узел                          Bootstrap-пир
       │                                     │
       │  POST /api/global/bootstrap         │
       │  {                                  │
       │    sender_ip: "1.2.3.4",            │
       │    sender_port: 9000,               │
       │    sender_pubkey: "abc..."          │
       │  }                                  │
       │ ──────────────────────────────────► │
       │                                     │
       │  Ответ:                             │
       │  {                                  │
       │    node_pubkey: "def...",           │
       │    version: "3.0.0",                │
       │    peers: [                         │
       │      {ip: "5.6.7.8", port: 9000},   │
       │      {ip: "9.10.11.12", port: 9001} │
       │    ],                               │
       │    rooms: [                         │
       │      {name: "General", code: "abc"} │
       │    ]                                │
       │  }                                  │
       │ ◄───────────────────────────────────│
       │                                     │
       │  Новый узел теперь знает 3 пира     │
       │  и может начать gossip              │
       │                                     │
```

### Peer Persistence (global_peers.json)

Список известных пиров сохраняется в файле `global_peers.json`:

```json
[
  {
    "ip": "203.0.113.10",
    "port": 9000,
    "node_pubkey_hex": "a3b4c5d6e7f8...",
    "last_seen": 1700000000.0,
    "rooms": [
      {"id": 1, "name": "General", "invite_code": "abc123"}
    ],
    "version": "3.0.0"
  },
  {
    "ip": "198.51.100.20",
    "port": 9001,
    "node_pubkey_hex": "f8e7d6c5b4a3...",
    "last_seen": 1700000030.0,
    "rooms": [],
    "version": "3.0.0"
  }
]
```

При перезапуске узел загружает этот файл и не теряет связность с mesh-сетью.

### Поиск комнат по mesh-сети

В глобальном режиме можно искать публичные комнаты по всей mesh-сети:

```
  GET /api/global/search-rooms-global?q=Gaming

  Внутренний процесс:
  1. Для каждого живого пира параллельно:
     GET https://{peer_ip}:{peer_port}/api/global/search-rooms?q=Gaming
  2. Собираем результаты со всех пиров
  3. Для каждой найденной комнаты добавляем peer_ip и peer_port
  4. Возвращаем пользователю

  Ответ:
  {
    "rooms": [
      {
        "id": 5,
        "name": "Gaming Hub",
        "description": "Обсуждаем игры",
        "invite_code": "gaming42",
        "peer_ip": "203.0.113.10",
        "peer_port": 9000,
        "member_count": 15
      }
    ],
    "peers_searched": 12
  }
```

### Обфускация трафика (детали)

Класс `TrafficObfuscator` реализует три метода обфускации:

**1. `pad_message(data: bytes) -> bytes`**
```
  Входные данные: b"Hello" (5 байт)
  Минимальный размер: 5 + 2 (header) = 7 байт
  Ближайший target: 256 байт
  Padding: 256 - 5 - 2 = 249 случайных байт

  Результат: [0x00, 0x05] + b"Hello" + random(249 bytes)
             ────────── 256 байт ──────────
```

**2. `add_timing_jitter() -> None`**
```python
  jitter = random.uniform(0.01, 0.15)  # от 10мс до 150мс
  await asyncio.sleep(jitter)
```

**3. `get_cover_headers() -> dict`**
```python
  {
    "Server": "nginx/1.24.0",
    "X-Powered-By": "Express",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Cache-Control": "public, max-age=3600",
    "Vary": "Accept-Encoding",
  }
```

### Cover Traffic (фейковый сайт)

Эндпоинты cover-сайта:

| Путь | Описание | Имитирует |
|------|----------|-----------|
| `/cover` | Главная страница | Корпоративный лендинг CloudSync Solutions |
| `/about` | О компании | Страница "About Us" |
| `/pricing` | Тарифы | "Coming soon" |
| `/contact` | Контакты | Email для связи |

Все cover-страницы возвращаются с заголовками `Server: nginx/1.24.0` для максимальной маскировки.

---

## :scroll: Протоколы

### WebSocket типы сообщений

#### Чат WebSocket (`/ws/{room_id}`)

| Действие (action) | Направление | Описание |
|-------------------|-------------|----------|
| `message` | Клиент → Сервер | Отправка зашифрованного сообщения |
| `new_message` | Сервер → Клиент | Доставка нового сообщения всем участникам |
| `edit` | Клиент → Сервер | Редактирование сообщения |
| `message_edited` | Сервер → Клиент | Уведомление о редактировании |
| `delete` | Клиент → Сервер | Удаление сообщения |
| `message_deleted` | Сервер → Клиент | Уведомление об удалении |
| `key_response` | Клиент → Сервер | Передача ключа комнаты новому участнику |
| `key_request` | Сервер → Клиент | Запрос ключа комнаты для нового участника |
| `room_key` | Сервер → Клиент | Доставка ключа комнаты |
| `history` | Сервер → Клиент | Загрузка истории сообщений |
| `ack` | Сервер → Клиент | Подтверждение сохранения сообщения |
| `error` | Сервер → Клиент | Сообщение об ошибке |
| `user_joined` | Сервер → Клиент | Уведомление о подключении пользователя |
| `user_left` | Сервер → Клиент | Уведомление об отключении пользователя |
| `online_list` | Сервер → Клиент | Список онлайн-пользователей |
| `typing` | Двусторонний | Индикатор набора текста |

#### Signaling WebSocket (`/ws/signal/{room_id}`)

| Тип сигнала | Направление | Описание |
|-------------|-------------|----------|
| `offer` | Клиент → Сервер → Клиент | SDP Offer для WebRTC |
| `answer` | Клиент → Сервер → Клиент | SDP Answer для WebRTC |
| `ice-candidate` | Клиент → Сервер → Клиент | ICE-кандидат |
| `call-start` | Клиент → Сервер | Начало звонка |
| `call-accept` | Клиент → Сервер | Принятие звонка |
| `call-reject` | Клиент → Сервер | Отклонение звонка |
| `call-end` | Клиент → Сервер → Клиент | Завершение звонка |
| `quality-report` | Клиент → Сервер | Отчёт о качестве (RTT, jitter, loss) |

#### Notifications WebSocket (`/ws/notifications`)

| Тип уведомления | Описание |
|-----------------|----------|
| `new_message` | Новое сообщение в комнате |
| `mention` | Упоминание через @ |
| `incoming_call` | Входящий звонок |
| `key_request` | Запрос ключа комнаты |
| `room_key` | Доставка ключа комнаты |
| `system` | Системное сообщение |
| `peer_online` | Пир подключился |
| `peer_offline` | Пир отключился |

#### Federation WebSocket (`/ws/fed/{virtual_id}`)

| Тип | Направление | Описание |
|-----|-------------|----------|
| `message` | Клиент → Node A → Node B | Сообщение ретранслируется на удалённый узел |
| `new_message` | Node B → Node A → Клиент | Ответное сообщение ретранслируется обратно |
| `history` | Node A → Клиент | История из удалённой комнаты |

### Протокол передачи файлов (Resumable Upload)

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │  ПРОТОКОЛ ВОЗОБНОВЛЯЕМОЙ ЗАГРУЗКИ ФАЙЛОВ                            │
  └─────────────────────────────────────────────────────────────────────┘

  Клиент                                        Сервер
    │                                              │
    │  1. POST /api/files/upload-init               │
    │  { filename, size, room_id, mime_type }       │
    │  ────────────────────────────────────────────►│
    │                                              │
    │  ← { upload_id: "abc123", chunk_size: 65536 }│
    │  ◄────────────────────────────────────────────│
    │                                              │
    │  2. PUT /api/files/upload-chunk/abc123        │
    │  chunk_index=0, sha256="...", data=<bytes>    │
    │  ────────────────────────────────────────────►│
    │  ← { ok: true, received: [0] }               │
    │  ◄────────────────────────────────────────────│
    │                                              │
    │  3. PUT /api/files/upload-chunk/abc123        │
    │  chunk_index=1, sha256="...", data=<bytes>    │
    │  ────────────────────────────────────────────►│
    │  ← { ok: true, received: [0, 1] }            │
    │  ◄────────────────────────────────────────────│
    │                                              │
    │  ... (повтор для каждого чанка)               │
    │                                              │
    │  N. POST /api/files/upload-complete/abc123    │
    │  ────────────────────────────────────────────►│
    │                                              │
    │  Сервер: собирает чанки, проверяет SHA-256   │
    │  ← { file_id: 42, stored_name: "abc.dat" }   │
    │  ◄────────────────────────────────────────────│
    │                                              │

  При обрыве соединения:
    │  GET /api/files/upload-status/abc123          │
    │  ────────────────────────────────────────────►│
    │  ← { received: [0, 1], total: 10 }           │
    │  ◄────────────────────────────────────────────│
    │                                              │
    │  Клиент продолжает с chunk_index=2           │
```

---

## :electric_plug: API

### Полная таблица API-эндпоинтов

#### Аутентификация (`/api/authentication`)

| Метод | Путь | Описание | Аутентификация |
|-------|------|----------|----------------|
| `POST` | `/api/authentication/register` | Регистрация нового пользователя | Нет |
| `POST` | `/api/authentication/login` | Вход по телефону/логину + пароль | Нет |
| `POST` | `/api/authentication/login-key` | Беспарольный вход через X25519 challenge-response | Нет |
| `GET` | `/api/authentication/challenge` | Получение challenge для беспарольного входа | Нет |
| `POST` | `/api/authentication/refresh` | Обновление access-токена через refresh-токен | Refresh Token |
| `POST` | `/api/authentication/logout` | Выход (отзыв refresh-токена) | JWT |
| `GET` | `/api/authentication/me` | Информация о текущем пользователе | JWT |
| `PUT` | `/api/authentication/profile` | Обновление профиля | JWT |
| `POST` | `/api/authentication/password-strength` | Проверка сложности пароля | Нет |

#### Комнаты (`/api/rooms`)

| Метод | Путь | Описание | Аутентификация |
|-------|------|----------|----------------|
| `POST` | `/api/rooms` | Создание комнаты | JWT |
| `POST` | `/api/rooms/join/{invite_code}` | Вступление в комнату по invite-коду | JWT |
| `POST` | `/api/rooms/{room_id}/provide-key` | Передача ключа комнаты ожидающему участнику | JWT |
| `GET` | `/api/rooms/{room_id}/key-bundle` | Получение зашифрованного ключа комнаты | JWT |
| `GET` | `/api/rooms/my` | Список комнат текущего пользователя | JWT |
| `GET` | `/api/rooms/public` | Список публичных комнат | Нет |
| `GET` | `/api/rooms/{room_id}` | Информация о комнате | JWT |
| `GET` | `/api/rooms/{room_id}/members` | Список участников комнаты | JWT |
| `DELETE` | `/api/rooms/{room_id}/leave` | Покинуть комнату | JWT |
| `POST` | `/api/rooms/{room_id}/kick/{target_id}` | Выгнать участника (owner/admin) | JWT |
| `DELETE` | `/api/rooms/{room_id}` | Удалить комнату (только owner) | JWT |

#### Личные сообщения (`/api/dm`)

| Метод | Путь | Описание | Аутентификация |
|-------|------|----------|----------------|
| `POST` | `/api/dm/{target_user_id}` | Создать/получить DM комнату | JWT |
| `GET` | `/api/dm/list` | Список всех DM комнат | JWT |

#### Контакты (`/api/contacts`)

| Метод | Путь | Описание | Аутентификация |
|-------|------|----------|----------------|
| `GET` | `/api/contacts` | Список контактов | JWT |
| `POST` | `/api/contacts` | Добавить контакт | JWT |
| `PUT` | `/api/contacts/{contact_id}` | Обновить никнейм контакта | JWT |
| `DELETE` | `/api/contacts/{contact_id}` | Удалить контакт | JWT |

#### Поиск пользователей (`/api/users`)

| Метод | Путь | Описание | Аутентификация |
|-------|------|----------|----------------|
| `GET` | `/api/users/search?q=...` | Поиск по телефону/email/IP/username | JWT |

#### Файлы (`/api/files`)

| Метод | Путь | Описание | Аутентификация |
|-------|------|----------|----------------|
| `POST` | `/api/files/upload/{room_id}` | Загрузка файла (обычная) | JWT |
| `GET` | `/api/files/download/{file_id}` | Скачивание файла | JWT |
| `GET` | `/api/files/room/{room_id}` | Список файлов комнаты | JWT |
| `POST` | `/api/files/upload-init` | Инициализация resumable upload | JWT |
| `PUT` | `/api/files/upload-chunk/{upload_id}` | Загрузка чанка | JWT |
| `GET` | `/api/files/upload-status/{upload_id}` | Статус resumable upload | JWT |
| `POST` | `/api/files/upload-complete/{upload_id}` | Завершение resumable upload | JWT |
| `DELETE` | `/api/files/upload-cancel/{upload_id}` | Отмена resumable upload | JWT |

#### Пиры (`/api/peers`)

| Метод | Путь | Описание | Аутентификация |
|-------|------|----------|----------------|
| `GET` | `/api/peers` | Список известных пиров | JWT |
| `POST` | `/api/peers/federated-join` | Федеративное подключение к удалённой комнате | JWT |

#### Ключи (`/api/keys`)

| Метод | Путь | Описание | Аутентификация |
|-------|------|----------|----------------|
| `GET` | `/api/keys/node-pubkey` | Публичный ключ узла | Нет |
| `GET` | `/api/keys/user/{user_id}/pubkey` | Публичный ключ пользователя | JWT |

#### Федерация (`/api/federation`)

| Метод | Путь | Описание | Аутентификация |
|-------|------|----------|----------------|
| `POST` | `/api/federation/guest-login` | Гостевой вход для федеративных узлов | Нет (server-to-server) |

#### Глобальный режим (`/api/global`)

| Метод | Путь | Описание | Аутентификация |
|-------|------|----------|----------------|
| `POST` | `/api/global/gossip` | Приём gossip-пакета | Нет (межузловой) |
| `POST` | `/api/global/bootstrap` | Bootstrap-запрос от нового узла | Нет (межузловой) |
| `GET` | `/api/global/search-rooms` | Поиск комнат на этом узле | Нет (межузловой) |
| `GET` | `/api/global/search-rooms-global` | Глобальный поиск комнат по всем пирам | JWT |
| `GET` | `/api/global/node-info` | Информация об узле | Нет |
| `GET` | `/api/global/peers` | Список глобальных пиров | JWT |
| `POST` | `/api/global/add-peer` | Ручное добавление пира | JWT |

#### WAF (`/api/waf`)

| Метод | Путь | Описание | Аутентификация |
|-------|------|----------|----------------|
| `GET` | `/api/waf/stats` | Статистика WAF | JWT |
| `GET` | `/api/waf/blocked` | Список заблокированных IP | JWT |

#### WebSocket

| Путь | Описание | Аутентификация |
|------|----------|----------------|
| `WS /ws/{room_id}` | Чат комнаты | JWT (query param) |
| `WS /ws/signal/{room_id}` | WebRTC signaling | JWT (query param) |
| `WS /ws/notifications` | Глобальные уведомления | JWT (query param) |
| `WS /ws/fed/{virtual_id}` | Федеративный relay | JWT (query param) |

#### Служебные

| Метод | Путь | Описание |
|-------|------|----------|
| `GET` | `/` | Главная страница (SPA) |
| `GET` | `/health` | Проверка здоровья узла |
| `GET` | `/service-worker.js` | Service Worker для PWA |
| `GET` | `/manifest.json` | PWA Manifest |
| `GET` | `/api/docs` | Swagger UI документация |

---

## :shield: Безопасность и модель угроз

### Механизмы защиты

| Механизм | Описание | Реализация |
|----------|----------|------------|
| **E2E шифрование** | Все сообщения зашифрованы AES-256-GCM, ключ известен только участникам | `app/security/crypto.py`, `rust_utils/src/messages/crypt.rs` |
| **ECIES key distribution** | Ключ комнаты шифруется индивидуально X25519+HKDF+AES для каждого участника | `app/security/key_exchange.py` |
| **Argon2id** | Пароли хешируются memory-hard алгоритмом | `rust_utils/src/auth/passwords.rs`, `argon2-cffi` |
| **JWT + Refresh Token** | Короткоживущий access (60 мин) + долгоживущий refresh (30 дней) | `app/security/auth_jwt.py` |
| **CSRF Double-Submit** | CSRF-токен в cookie + заголовке | `app/security/middleware.py` |
| **WAF** | SQLi, XSS, Path Traversal detection + rate limiting | `app/security/waf.py` |
| **Security Headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options | `app/security/middleware.py` |
| **Rate Limiting** | Token Bucket (20 burst, 5/sec) per WebSocket | `app/peer/connection_manager.py` |
| **File Validation** | MIME-type check, extension blacklist, anomaly detection | `app/security/secure_upload.py` |
| **Constant-time comparison** | SHA-256 хеширование токенов с constant-time сравнением | `rust_utils/src/auth/tokens.rs` |
| **Deduplication** | LRU кэш seen_ids для предотвращения replay-атак | `app/peer/connection_manager.py` |
| **TLS** | Все соединения через HTTPS (SSL/TLS) | `uvicorn --ssl-*` |
| **Обфускация трафика** | Паддинг, jitter, cover headers для обхода DPI | `app/transport/obfuscation.py` |
| **Cover traffic** | Фейковый сайт для plausible deniability | `app/transport/cover_traffic.py` |
| **Phone masking** | Маскирование номера телефона в ответах API | `app/chats/contacts.py`, `app/chats/search.py` |

### Матрица угроз

| Угроза | Уровень риска | Защита | Статус |
|--------|---------------|--------|--------|
| Перехват сообщений на сервере | Критический | E2E шифрование (сервер хранит только шифротекст) | Защищено |
| Кража приватного ключа с устройства | Критический | Ключ зашифрован паролем в localStorage/IndexedDB | Частично (зависит от клиента) |
| Brute-force паролей | Высокий | Argon2id + rate limiting | Защищено |
| SQL-инъекции | Высокий | WAF + SQLAlchemy ORM (parametrized queries) | Защищено |
| XSS-атаки | Высокий | WAF + CSP headers + input sanitization | Защищено |
| CSRF | Высокий | Double-submit cookie + CSRF middleware | Защищено |
| Path Traversal | Высокий | WAF + secure filename generation | Защищено |
| Replay-атаки (сообщения) | Средний | Dedup cache (LRU 10000) + BLAKE3 content hash | Защищено |
| DDoS | Средний | Rate limiting (Token Bucket) + WAF block | Частично |
| Traffic analysis (DPI) | Средний | Обфускация (паддинг, jitter, cover headers) | Защищено (global mode) |
| Active probing | Средний | Cover website (fake CloudSync) | Защищено (global mode) |
| Metadata analysis | Низкий | P2P — нет центрального сервера с метаданными | Защищено |
| Компрометация bootstrap-пира | Низкий | Gossip-протокол не зависит от одного пира | Защищено |
| Сертификат MITM | Низкий | mkcert (локальный CA) или certificate pinning | Частично |

### Известные ограничения

| Ограничение | Описание | Возможное решение |
|-------------|----------|-------------------|
| Forward Secrecy | Ключ комнаты не ротируется автоматически | Реализация Double Ratchet для DM |
| Key Verification | Нет визуальной верификации ключей (QR, emoji) | Safety numbers как в Signal |
| Metadata на узле | Локальный узел видит кто и когда подключился | Onion routing (Tor integration) |
| Device Linking | Нет протокола связывания нескольких устройств | Multi-device protocol |
| Message Deletion | Удаление не гарантировано на всех узлах | Ephemeral messages с TTL |
| Group Size | Максимум 200 участников | Sender Keys protocol для масштабирования |

---

## :anchor: Надёжность

### WebSocket reconnect

При разрыве WebSocket-соединения клиент автоматически переподключается:

| Параметр | Значение |
|----------|----------|
| Начальная задержка | 1 секунда |
| Максимальная задержка | 30 секунд |
| Стратегия | Exponential backoff с jitter |
| Максимум попыток | Бесконечно |
| При переподключении | Загрузка пропущенных сообщений из истории |

### Очередь сообщений

При временном разрыве соединения сообщения буферизируются на клиенте:

| Параметр | Значение |
|----------|----------|
| Размер буфера | 100 сообщений |
| При переполнении | Старые сообщения отбрасываются |
| При переподключении | Буфер отправляется серверу |
| Порядок | FIFO (First In, First Out) |

### Ping/Keepalive

WebSocket-соединения поддерживаются через ping/pong:

| Параметр | Значение |
|----------|----------|
| Ping интервал | 20 секунд |
| Pong таймаут | 10 секунд |
| При таймауте | Закрытие соединения и reconnect |

### Дедупликация (dedup)

Глобальный кэш `seen_ids` предотвращает повторную обработку сообщений:

| Параметр | Значение |
|----------|----------|
| Тип кэша | LRU (Least Recently Used) |
| Размер | 10 000 записей |
| Ключ | message_id или content_hash |
| При дубликате | Сообщение отбрасывается |

### TTL сообщений

Для федеративных сообщений используется TTL (Time To Live):

| Параметр | Значение |
|----------|----------|
| Начальный TTL | 5 хопов |
| При каждом хопе | TTL -= 1 |
| При TTL = 0 | Сообщение отбрасывается |
| Назначение | Предотвращение бесконечных петель |

### Graceful Degradation

| Сценарий | Поведение |
|----------|-----------|
| Rust не скомпилирован | Python fallback (медленнее, но работает) |
| SSL-сертификаты отсутствуют | HTTP-режим (без WebRTC звонков) |
| UDP broadcast не работает | Ручное добавление пиров по IP |
| Bootstrap-пиры недоступны | Загрузка из `global_peers.json` |
| WebSocket разрыв | Автоматический reconnect |
| БД повреждена | Ошибка при старте (требует ручного восстановления) |

---

## :iphone: PWA

VORTEX — Progressive Web App, который может быть установлен как приложение на любой платформе.

### Поддержка платформ

| Платформа | Установка | Уведомления | Offline |
|-----------|-----------|-------------|---------|
| **Chrome (Desktop)** | Да (иконка в адресной строке) | Да | Частично |
| **Chrome (Android)** | Да (Add to Home Screen) | Да | Частично |
| **Safari (iOS)** | Да (Share → Add to Home Screen) | Ограничено | Частично |
| **Firefox (Desktop)** | Нет (не поддерживает PWA install) | Да | Частично |
| **Edge (Desktop)** | Да | Да | Частично |
| **Samsung Internet** | Да | Да | Частично |
| **Brave (Desktop/Android)** | Да (Chromium-based, иконка в адресной строке) | Да (требует разрешение) | Частично |
| **Tor Browser** | Нет (PWA отключён для анонимности) | Нет (заблокировано) | Нет (Service Worker ограничен) |
| **Яндекс Браузер (Desktop/Android)** | Да (Chromium-based) | Да | Частично |
| **Atom (Desktop)** | Да (Chromium-based) | Да | Частично |

### Что даёт PWA

| Возможность | Описание |
|-------------|----------|
| **Установка** | Иконка на рабочем столе, запуск как отдельное приложение |
| **Offline** | Кэширование статических ресурсов через Service Worker |
| **Push** | Уведомления о новых сообщениях (через WebSocket) |
| **Fullscreen** | Запуск без адресной строки браузера |
| **Auto-update** | Service Worker обновляется при изменении ресурсов |

### Стратегия кэширования

| Тип ресурса | Стратегия | Описание |
|-------------|-----------|----------|
| HTML | Network First | Сначала сеть, затем кэш |
| CSS | Cache First | Сначала кэш, обновление в фоне |
| JS | Cache First | Сначала кэш, обновление в фоне |
| Изображения | Cache First | Кэш с длительным сроком |
| API | Network Only | Всегда из сети |
| WebSocket | Network Only | Всегда из сети |

### Файловая структура PWA

| Файл | Описание |
|------|----------|
| `static/manifest.json` | PWA Manifest (имя, иконки, цвета, display mode) |
| `static/js/service-worker.js` | Service Worker (кэширование, push-уведомления) |
| `static/js/pwa.js` | PWA регистрация и управление |
| `templates/index.html` | SPA entry point |

---

## :bar_chart: Метрики и производительность

### Крипто-бенчмарки

| Операция | Rust (vortex_chat) | Python (cryptography) | Ускорение |
|----------|--------------------|-----------------------|-----------|
| AES-256-GCM шифрование (1 KB) | ~2 мкс | ~15 мкс | 7.5x |
| AES-256-GCM расшифровка (1 KB) | ~2 мкс | ~15 мкс | 7.5x |
| BLAKE3 хеширование (1 KB) | ~0.5 мкс | ~3 мкс | 6x |
| Argon2id (пароль) | ~50 мс | ~80 мс | 1.6x |
| SHA-256 (constant-time) | ~1 мкс | ~5 мкс | 5x |
| X25519 DH | ~50 мкс | ~150 мкс | 3x |
| X25519 keygen | ~50 мкс | ~120 мкс | 2.4x |

### Rust vs Python сравнение

| Аспект | Rust (vortex_chat) | Python fallback |
|--------|--------------------|--------------------|
| AES-256-GCM | `aes-gcm` crate | `cryptography.hazmat` |
| BLAKE3 | `blake3` crate | `blake3` PyPI |
| Argon2id | `argon2` crate | `argon2-cffi` |
| X25519 | `x25519-dalek` | `cryptography` |
| SHA-256 | `sha2` + `subtle` (CT) | `hashlib` |
| Компиляция | `maturin develop --release` | — |
| LTO | Включено (`lto = true`) | — |
| Codegen units | 1 (максимальная оптимизация) | — |

### WebRTC метрики

| Метрика | Описание | Источник |
|---------|----------|----------|
| `currentRoundTripTime` | RTT текущий (секунды) | `RTCIceCandidatePairStats` |
| `jitter` | Вариация задержки (секунды) | `RTCInboundRtpStreamStats` |
| `packetsLost` | Потерянные пакеты | `RTCInboundRtpStreamStats` |
| `packetsReceived` | Полученные пакеты | `RTCInboundRtpStreamStats` |
| `bytesReceived` | Принятые байты | `RTCInboundRtpStreamStats` |
| `bytesSent` | Отправленные байты | `RTCOutboundRtpStreamStats` |
| `frameWidth` / `frameHeight` | Разрешение видео | `RTCInboundRtpStreamStats` |
| `framesPerSecond` | FPS видео | `RTCInboundRtpStreamStats` |

---

## :test_tube: Тестирование

### Запуск тестов

```bash
# Запуск всех тестов
pytest

# Запуск с подробным выводом
pytest -v

# Запуск конкретного файла
pytest app/tests/tests.py

# Запуск с покрытием
pytest --cov=app --cov-report=html

# Rust тесты
cd rust_utils
cargo test
cd ..
```

### Тестовое покрытие

| Модуль | Файл тестов | Что тестируется |
|--------|-------------|-----------------|
| Аутентификация | `app/tests/tests.py` | Регистрация, логин, JWT, challenge-response |
| Комнаты | `app/tests/tests.py` | Создание, вступление, выход, ключи |
| Шифрование | `app/tests/tests.py` | AES-GCM, BLAKE3, Argon2, X25519 |
| WAF | `app/tests/tests.py` | SQLi detection, XSS detection, rate limiting |
| Файлы | `app/tests/tests.py` | Upload, download, resumable, validation |
| WebSocket | `app/tests/tests.py` | Подключение, сообщения, ключи |
| Rust модуль | `rust_utils/tests/messages_tests.rs` | encrypt/decrypt, hash, keygen |

### Бенчмарки

```bash
# Запуск крипто-бенчмарков
python app/benchmarks/run_benchmarks.py
```

---

## :file_folder: Структура проекта

```
Vortex/
├── run.py                              # Точка входа: wizard + launcher
├── conftest.py                         # Pytest конфигурация
├── requirements.txt                    # Python зависимости
├── generate_icons.py                   # Генерация PWA-иконок
├── .env                                # Конфигурация узла (авто-генерируется)
│
├── app/                                # Основной Python-пакет
│   ├── __init__.py
│   ├── main.py                         # FastAPI приложение, lifespan, middleware
│   ├── config.py                       # Конфигурация (.env reader, Config class)
│   ├── base.py                         # SQLAlchemy Base
│   ├── database.py                     # Инициализация БД, SessionLocal, get_db
│   ├── models.py                       # User, RefreshToken, Pydantic схемы
│   ├── models_rooms.py                 # Room, RoomMember, Message, EncryptedRoomKey, PendingKeyRequest, FileTransfer
│   ├── models_contacts.py             # Contact (список контактов)
│   ├── results.json                    # Результаты бенчмарков
│   │
│   ├── authentication/                 # Аутентификация
│   │   ├── __init__.py
│   │   └── auth.py                     # Регистрация, логин, challenge-response, JWT
│   │
│   ├── chats/                          # Чаты и сообщения
│   │   ├── __init__.py
│   │   ├── chat.py                     # WebSocket чат, файлы, signaling, notifications
│   │   ├── rooms.py                    # CRUD комнат, key distribution
│   │   ├── dm.py                       # Личные сообщения (DM)
│   │   ├── contacts.py                 # Управление контактами
│   │   └── search.py                   # Поиск пользователей
│   │
│   ├── security/                       # Безопасность
│   │   ├── __init__.py
│   │   ├── crypto.py                   # Крипто-модуль (Rust/Python dual backend)
│   │   ├── key_exchange.py             # ECIES, валидация ECIES payload
│   │   ├── auth_jwt.py                 # JWT генерация/валидация, get_current_user
│   │   ├── middleware.py               # SecurityHeaders, Logging, CSRF, TokenRefresh
│   │   ├── waf.py                      # WAF (SQLi, XSS, Path Traversal, Rate Limit)
│   │   ├── secure_upload.py            # Валидация файлов, MIME, anomaly detection
│   │   └── security_validate.py        # Дополнительные проверки
│   │
│   ├── peer/                           # P2P обнаружение и управление
│   │   ├── __init__.py
│   │   ├── peer_registry.py            # UDP discovery, PeerInfo, PeerRegistry
│   │   └── connection_manager.py       # WebSocket менеджер, деdup, rate limiter
│   │
│   ├── federation/                     # Федерация
│   │   ├── __init__.py
│   │   └── federation.py               # Guest login, virtual rooms, WS relay
│   │
│   ├── transport/                      # Транспортные протоколы
│   │   ├── __init__.py
│   │   ├── transport_manager.py        # Управление приоритетами транспортов
│   │   ├── nat_traversal.py            # STUN + UDP Hole Punching
│   │   ├── wifi_direct.py              # Wi-Fi Direct P2P
│   │   ├── ble_transport.py            # Bluetooth Low Energy
│   │   ├── global_transport.py         # Gossip-протокол, GlobalTransport
│   │   ├── global_routes.py            # API-эндпоинты глобального режима
│   │   ├── obfuscation.py              # Обфускация трафика (padding, jitter, headers)
│   │   ├── cover_traffic.py            # Фейковый сайт (CloudSync Solutions)
│   │   └── routes.py                   # Дополнительные маршруты транспорта
│   │
│   ├── files/                          # Работа с файлами
│   │   ├── __init__.py
│   │   └── resumable.py                # Протокол возобновляемой загрузки
│   │
│   ├── keys/                           # Управление ключами
│   │   ├── __init__.py
│   │   └── keys.py                     # Публичные ключи узла и пользователей
│   │
│   ├── routes/                         # Дополнительные маршруты
│   │   ├── __init__.py
│   │   ├── web.py                      # Веб-маршруты
│   │   └── websocket.py               # WebSocket маршруты
│   │
│   ├── services/                       # Сервисный слой
│   │   ├── __init__.py
│   │   └── chat_service.py            # Бизнес-логика чата
│   │
│   ├── utilites/                       # Утилиты
│   │   ├── __init__.py
│   │   └── utils.py                    # Вспомогательные функции (invite codes и др.)
│   │
│   ├── benchmarks/                     # Бенчмарки
│   │   ├── __init__.py
│   │   └── run_benchmarks.py           # Крипто-бенчмарки (Rust vs Python)
│   │
│   └── tests/                          # Тесты
│       ├── __init__.py
│       └── tests.py                    # Основные тесты
│
├── rust_utils/                         # Rust крипто-ядро
│   ├── Cargo.toml                      # Cargo конфигурация (pyo3, aes-gcm, blake3...)
│   ├── src/
│   │   ├── lib.rs                      # PyO3 модуль: экспорт функций в Python
│   │   ├── messages.rs                 # Модуль сообщений (mod declaration)
│   │   ├── messages/
│   │   │   ├── crypt.rs                # AES-256-GCM encrypt/decrypt
│   │   │   └── hash.rs                 # BLAKE3 хеширование + generate_key
│   │   ├── auth.rs                     # Модуль аутентификации (mod declaration)
│   │   ├── auth/
│   │   │   ├── passwords.rs            # Argon2id hash/verify
│   │   │   └── tokens.rs              # SHA-256 constant-time hash/verify
│   │   ├── crypto.rs                   # Модуль крипто (mod declaration)
│   │   ├── crypto/
│   │   │   └── handshake.rs            # X25519 keygen + HKDF derive_session_key
│   │   ├── udp_broadcast.rs            # Модуль UDP (mod declaration)
│   │   └── udp_broadcast/
│   │       └── discovery.rs            # UDP broadcast P2P discovery
│   └── tests/
│       └── messages_tests.rs           # Тесты шифрования
│
├── node_setup/                         # Мастер настройки (wizard)
│   ├── __init__.py
│   ├── wizard.py                       # FastAPI wizard-приложение
│   ├── models.py                       # Pydantic схемы wizard
│   ├── ssl_manager.py                  # Генерация SSL-сертификатов
│   ├── static/
│   │   ├── css/
│   │   │   └── setup.css               # Стили мастера настройки
│   │   └── js/
│   │       └── setup.js                # Логика мастера настройки
│   └── templates/
│       └── setup.html                  # HTML мастера настройки
│
├── static/                             # Статические файлы (frontend)
│   ├── manifest.json                   # PWA Manifest
│   ├── css/
│   │   ├── main.css                    # Основные стили (glassmorphism)
│   │   ├── menu.css                    # Стили меню
│   │   └── setup.css                   # Стили настройки
│   └── js/
│       ├── main.js                     # Точка входа фронтенда
│       ├── auth.js                     # Аутентификация (login/register)
│       ├── crypto.js                   # Web Crypto API (X25519, AES-GCM, ECIES)
│       ├── rooms.js                    # Управление комнатами
│       ├── contacts.js                 # Управление контактами
│       ├── notifications.js            # Уведомления (WebSocket)
│       ├── peers.js                    # Список пиров
│       ├── ui.js                       # UI компоненты
│       ├── utils.js                    # Утилиты
│       ├── pwa.js                      # PWA регистрация
│       ├── setup.js                    # Настройка
│       ├── webrtc.js                   # WebRTC звонки (voice + video)
│       ├── voice_recorder.js           # Запись голосовых сообщений
│       ├── photo_editor.js             # Встроенный фото-редактор
│       ├── update_viewer.js            # Просмотр обновлений
│       ├── service-worker.js           # Service Worker (кэширование, push)
│       └── chat/
│           ├── chat.js                 # Основная логика чата
│           ├── messages.js             # Рендеринг сообщений
│           ├── file-upload.js          # Загрузка файлов
│           ├── image-viewer.js         # Просмотр изображений
│           └── liquid-glass.js         # Liquid glass анимации
│
├── templates/                          # HTML шаблоны
│   └── index.html                      # SPA entry point
│
├── uploads/                            # Загруженные файлы (зашифрованные)
│   └── ...
│
├── certs/                              # SSL-сертификаты (генерируются)
│   ├── vortex.crt                      # TLS-сертификат
│   └── vortex.key                      # Приватный ключ
│
├── keys/                               # X25519 ключевые пары узла
│   └── ...
│
└── global_peers.json                   # Сохранённые глобальные пиры
```

---

## :floppy_disk: Схема базы данных

VORTEX использует SQLite через SQLAlchemy ORM. Ниже приведена полная схема всех таблиц.

### Таблица `users`

| Столбец | Тип | Ограничения | Описание |
|---------|-----|-------------|----------|
| `id` | INTEGER | PRIMARY KEY, INDEX | Уникальный идентификатор пользователя |
| `phone` | VARCHAR(20) | UNIQUE, NOT NULL, INDEX | Номер телефона (для регистрации и поиска) |
| `username` | VARCHAR(50) | UNIQUE, NOT NULL, INDEX | Имя пользователя (3-30 символов, a-z, 0-9, _) |
| `password_hash` | VARCHAR(512) | NOT NULL | Argon2id хеш пароля |
| `display_name` | VARCHAR(100) | NULLABLE | Отображаемое имя |
| `avatar_emoji` | VARCHAR(10) | DEFAULT '👤' | Аватар-эмодзи |
| `x25519_public_key` | VARCHAR(64) | NULLABLE, INDEX | X25519 публичный ключ (hex, 32 bytes) |
| `email` | VARCHAR(255) | UNIQUE, NULLABLE, INDEX | Email для поиска |
| `last_ip` | VARCHAR(45) | NULLABLE | Последний IP-адрес подключения |
| `network_mode` | VARCHAR(10) | DEFAULT 'local' | Режим сети: local или global |
| `is_active` | BOOLEAN | DEFAULT TRUE | Активен ли аккаунт |
| `created_at` | DATETIME | DEFAULT utcnow | Дата регистрации |
| `last_seen` | DATETIME | DEFAULT utcnow, ON UPDATE | Последняя активность |

### Таблица `rooms`

| Столбец | Тип | Ограничения | Описание |
|---------|-----|-------------|----------|
| `id` | INTEGER | PRIMARY KEY, INDEX | Уникальный ID комнаты |
| `name` | VARCHAR(100) | NOT NULL | Название комнаты |
| `description` | VARCHAR(500) | DEFAULT '' | Описание |
| `creator_id` | INTEGER | FK → users.id, NULLABLE | Создатель комнаты |
| `is_private` | BOOLEAN | DEFAULT FALSE | Приватная ли комната |
| `invite_code` | VARCHAR(16) | UNIQUE, NOT NULL, INDEX | Код приглашения |
| `max_members` | INTEGER | DEFAULT 200 | Максимум участников |
| `is_dm` | BOOLEAN | DEFAULT FALSE | Является ли DM-комнатой |
| `created_at` | DATETIME | DEFAULT utcnow | Дата создания |
| `updated_at` | DATETIME | DEFAULT utcnow, ON UPDATE | Дата обновления |

### Таблица `room_members`

| Столбец | Тип | Ограничения | Описание |
|---------|-----|-------------|----------|
| `id` | INTEGER | PRIMARY KEY | ID записи |
| `room_id` | INTEGER | FK → rooms.id, NOT NULL | Комната |
| `user_id` | INTEGER | FK → users.id, NOT NULL | Пользователь |
| `role` | ENUM | DEFAULT 'member' | Роль: owner / admin / member |
| `joined_at` | DATETIME | DEFAULT utcnow | Дата вступления |
| `is_muted` | BOOLEAN | DEFAULT FALSE | Заглушен ли |
| `is_banned` | BOOLEAN | DEFAULT FALSE | Заблокирован ли |

Уникальное ограничение: `(room_id, user_id)` — пользователь может быть участником комнаты только один раз.

### Таблица `messages`

| Столбец | Тип | Ограничения | Описание |
|---------|-----|-------------|----------|
| `id` | INTEGER | PRIMARY KEY | ID сообщения |
| `room_id` | INTEGER | FK → rooms.id, NOT NULL, INDEX | Комната |
| `sender_id` | INTEGER | FK → users.id, NULLABLE | Отправитель |
| `msg_type` | ENUM | DEFAULT 'text' | Тип: text / file / image / voice / system |
| `content_encrypted` | BLOB | NOT NULL | Зашифрованный контент (nonce + AES-GCM + tag) |
| `content_hash` | BLOB(32) | NULLABLE | BLAKE3 хеш зашифрованного контента |
| `file_name` | VARCHAR(255) | NULLABLE | Имя файла (если тип file/image/voice) |
| `file_size` | INTEGER | NULLABLE | Размер файла |
| `reply_to_id` | INTEGER | FK → messages.id, NULLABLE | ID цитируемого сообщения |
| `is_edited` | BOOLEAN | DEFAULT FALSE | Было ли отредактировано |
| `created_at` | DATETIME | DEFAULT utcnow, INDEX | Дата создания |

Составной индекс: `(room_id, created_at)` — для быстрой загрузки истории.

### Таблица `encrypted_room_keys`

| Столбец | Тип | Ограничения | Описание |
|---------|-----|-------------|----------|
| `id` | INTEGER | PRIMARY KEY | ID записи |
| `room_id` | INTEGER | FK → rooms.id, NOT NULL, INDEX | Комната |
| `user_id` | INTEGER | FK → users.id, NOT NULL, INDEX | Пользователь |
| `ephemeral_pub` | VARCHAR(64) | NOT NULL | Эфемерный X25519 публичный ключ (hex) |
| `ciphertext` | VARCHAR(120) | NOT NULL | nonce(12) + AES-GCM(room_key) + tag(16) в hex |
| `recipient_pub` | VARCHAR(64) | NULLABLE | X25519 pubkey получателя (для верификации) |
| `created_at` | DATETIME | DEFAULT utcnow | Дата создания |
| `updated_at` | DATETIME | ON UPDATE utcnow | Дата обновления |

Уникальное ограничение: `(room_id, user_id)`.

### Таблица `pending_key_requests`

| Столбец | Тип | Ограничения | Описание |
|---------|-----|-------------|----------|
| `id` | INTEGER | PRIMARY KEY | ID записи |
| `room_id` | INTEGER | FK → rooms.id, NOT NULL, INDEX | Комната |
| `user_id` | INTEGER | FK → users.id, NOT NULL, INDEX | Ожидающий пользователь |
| `pubkey_hex` | VARCHAR(64) | NOT NULL | X25519 pubkey ожидающего (hex) |
| `created_at` | DATETIME | DEFAULT utcnow | Дата создания |
| `expires_at` | DATETIME | NOT NULL | Срок действия (48 часов) |

TTL: 48 часов. Если ключ не был доставлен — запрос создаётся заново при следующем подключении.

### Таблица `contacts`

| Столбец | Тип | Ограничения | Описание |
|---------|-----|-------------|----------|
| `id` | INTEGER | PRIMARY KEY | ID контакта |
| `owner_id` | INTEGER | FK → users.id, NOT NULL, INDEX | Владелец контакта |
| `contact_id` | INTEGER | FK → users.id, NOT NULL, INDEX | Контактный пользователь |
| `nickname` | VARCHAR(100) | NULLABLE | Кастомный никнейм |
| `created_at` | DATETIME | DEFAULT utcnow | Дата добавления |

Уникальное ограничение: `(owner_id, contact_id)`.

### Таблица `file_transfers`

| Столбец | Тип | Ограничения | Описание |
|---------|-----|-------------|----------|
| `id` | INTEGER | PRIMARY KEY | ID файла |
| `room_id` | INTEGER | FK → rooms.id, NOT NULL | Комната |
| `uploader_id` | INTEGER | FK → users.id, NULLABLE | Загрузивший |
| `original_name` | VARCHAR(255) | NOT NULL | Оригинальное имя файла |
| `stored_name` | VARCHAR(255) | NOT NULL | Имя файла на диске (случайное) |
| `mime_type` | VARCHAR(128) | NULLABLE | MIME-тип |
| `size_bytes` | INTEGER | NOT NULL | Размер в байтах |
| `file_hash` | VARCHAR(64) | NOT NULL | SHA-256 хеш файла |
| `is_available` | BOOLEAN | DEFAULT TRUE | Доступен ли файл |
| `download_count` | INTEGER | DEFAULT 0 | Счётчик скачиваний |
| `created_at` | DATETIME | DEFAULT utcnow | Дата загрузки |

### Таблица `refresh_tokens`

| Столбец | Тип | Ограничения | Описание |
|---------|-----|-------------|----------|
| `id` | INTEGER | PRIMARY KEY | ID токена |
| `user_id` | INTEGER | NOT NULL, INDEX | Пользователь |
| `token_hash` | VARCHAR(64) | UNIQUE, NOT NULL | SHA-256 хеш токена |
| `expires_at` | DATETIME | NOT NULL | Срок действия |
| `revoked_at` | DATETIME | NULLABLE | Дата отзыва |
| `created_at` | DATETIME | DEFAULT utcnow | Дата создания |
| `ip_address` | VARCHAR(45) | NULLABLE | IP-адрес создания |
| `user_agent` | VARCHAR(512) | NULLABLE | User-Agent браузера |

---

## :busts_in_silhouette: Разработчики

### Борис Мальцев — Основной разработчик

| Область | Вклад |
|---------|-------|
| **Архитектура** | Проектирование P2P mesh-архитектуры, модульная структура, двойной режим работы |
| **Криптография** | E2E шифрование (X25519 + AES-256-GCM), ECIES key distribution, Argon2id, BLAKE3 |
| **Rust крипто-ядро** | Реализация `vortex_chat` через PyO3 (aes-gcm, blake3, argon2, x25519-dalek) |
| **Бэкенд** | FastAPI, WebSocket чат, аутентификация (JWT + challenge-response), WAF |
| **Фронтенд** | SPA на Vanilla JS, Web Crypto API, WebRTC, PWA, glassmorphism UI |
| **Протоколы** | UDP discovery, gossip-протокол, federation relay, обфускация трафика |
| **Инфраструктура** | SSL/TLS, NAT traversal, Wi-Fi Direct, BLE, resumable file uploads |

### Андрей Караваев — Разработчик

| Область | Вклад |
|---------|-------|
| **Тестирование** | Unit-тесты, интеграционные тесты, тестирование E2E сценариев |
| **Дизайн** | UI/UX дизайн, glassmorphism-стиль, анимации, liquid glass эффекты |
| **Документация** | Техническая документация, README, комментарии в коде |
| **Разработка** | Контакты, поиск пользователей, уведомления, фото-редактор |

---

## :page_facing_up: Лицензия

```
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```

Copyright 2024-2026 VORTEX Project Contributors.

---

<p align="center">
  <b>VORTEX</b> — 100% децентрализованный P2P мессенджер
</p>
<p align="center">
  Создано с вниманием к безопасности и приватности
</p>
<p align="center">
  <b>Борис Мальцев</b> &mdash; основной разработчик, архитектура, криптография, бэкенд, фронтенд
  <br>
  <b>Андрей Караваев</b> &mdash; разработчик, тестирование, дизайн, документация
</p>
<p align="center">
  <i>v4.0.0</i>
</p>
