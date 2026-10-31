<div align="center">

<img src="assets/skyproject-logo.png" alt="Sky Project" width="340" />

# SKY PROJECT

### МОДИФИЦИРОВАННЫЙ КЛИЕНТ И СЕРВЕР MULTI THEFT AUTO: SAN ANDREAS

[![MTA:SA](https://img.shields.io/badge/MTA%3ASA-1.6.0-3B82F6?style=for-the-badge)](https://github.com/multitheftauto/mtasa-blue)
![C++](https://img.shields.io/badge/C%2B%2B-Native-2563EB?style=for-the-badge&logo=cplusplus&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-Client-374151?style=for-the-badge&logo=windows&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Server-374151?style=for-the-badge&logo=linux&logoColor=white)

**[English](README.md) · [Русский](README_RU.md) · [Українська](README_UA.md)**

---

**Независимый проект на основе официальных исходников MTA:SA 1.6.0.**

</div>

## ✦ О проекте

**Sky Project** — проект разработки собственного клиента и сервера **Multi Theft Auto: San Andreas**. Репозиторий создан на базе оригинального исходного кода **MTA:SA 1.6.0** и предназначен для дальнейших модификаций Sky Project.

> **Статус:** начальная версия исходников. Собственные функции и оформление будут добавляться постепенно.

## ⚙️ Технологии

| Компонент | Описание |
|:--|:--|
| Основа | Multi Theft Auto: San Andreas 1.6.0 |
| Основной язык | C++ |
| Скрипты игры | Lua |
| IDE для Windows | Visual Studio 2022 |
| Клиент | Windows |
| Сервер | Windows / Linux |
| Генерация проектов | Premake 5 |

## 🛠️ Сборка из исходников

### Windows

Потребуются Visual Studio 2022 с компонентами разработки на C++, Git и зависимости оригинальной системы сборки MTA (в том числе компоненты старого DirectX SDK, если они требуются).

```powershell
git clone https://github.com/n1cec0derrr/skyproject-mtasa.git
cd skyproject-mtasa
.\win-create-projects.bat
```

Откройте созданное решение в Visual Studio и выберите нужную конфигурацию. Дополнительные зависимости и инструкции смотрите в документации оригинального MTA.

### Linux

Для сборки сервера Linux используется система сборки оригинального MTA. Актуальные требования к инструментам и зависимостям указаны в скриптах репозитория и документации оригинального проекта.

## 📁 Структура проекта

```text
skyproject-mtasa/
├── Client/       # Клиент игры
├── Server/       # Выделенный сервер
├── Shared/       # Общий код и SDK
├── vendor/       # Сторонние зависимости
├── utils/        # Инструменты разработки
└── assets/       # Оформление Sky Project
```

## 🔗 Ссылки

- [Репозиторий Sky Project](https://github.com/n1cec0derrr/skyproject-mtasa)
- [Оригинальные исходники MTA:SA](https://github.com/multitheftauto/mtasa-blue)
- [Официальный сайт Multi Theft Auto](https://multitheftauto.com/)

## 📜 Лицензии и авторство

Проект основан на **Multi Theft Auto: San Andreas**, разработанном командой MTA и участниками сообщества. Sky Project — независимая модификация, **не являющаяся официальным проектом MTA**.

Все применимые лицензии, уведомления об авторских правах и условия использования сторонних компонентов сохраняют силу. См. файлы лицензий в исходном коде.

<div align="center">

---

<sub>SKY PROJECT · НА ОСНОВЕ MTA:SA 1.6.0</sub>

</div>
