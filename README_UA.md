<div align="center">

<img src="assets/skyproject-logo.png" alt="Sky Project" width="340" />

# SKY PROJECT

### МОДИФІКОВАНИЙ КЛІЄНТ І СЕРВЕР MULTI THEFT AUTO: SAN ANDREAS

[![MTA:SA](https://img.shields.io/badge/MTA%3ASA-1.6.0-3B82F6?style=for-the-badge)](https://github.com/multitheftauto/mtasa-blue)
![C++](https://img.shields.io/badge/C%2B%2B-Native-2563EB?style=for-the-badge&logo=cplusplus&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-Client-374151?style=for-the-badge&logo=windows&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Server-374151?style=for-the-badge&logo=linux&logoColor=white)

**[English](README.md) · [Русский](README_RU.md) · [Українська](README_UA.md)**

---

**Незалежний проєкт на основі офіційного вихідного коду MTA:SA 1.6.0.**

</div>

## ✦ Про проєкт

**Sky Project** — проєкт розробки власного клієнта та сервера **Multi Theft Auto: San Andreas**. Репозиторій створено на основі офіційного вихідного коду **MTA:SA 1.6.0** для подальших модифікацій Sky Project.

> **Стан розробки:** початкова версія вихідного коду. Власні функції та оформлення додаватимуться поступово.

## ⚙️ Технології

| Компонент | Опис |
|:--|:--|
| Основа | Multi Theft Auto: San Andreas 1.6.0 |
| Основна мова | C++ |
| Ігрові скрипти | Lua |
| IDE для Windows | Visual Studio 2022 |
| Клієнт | Windows |
| Сервер | Windows / Linux |
| Генерація проєктів | Premake 5 |

## 🛠️ Збирання з вихідного коду

### Windows

Потрібні Visual Studio 2022 із засобами розробки C++, Git і залежності оригінальної системи збирання MTA (зокрема компоненти застарілого DirectX SDK, якщо вони необхідні).

```powershell
git clone https://github.com/n1cec0derrr/skyproject-mtasa.git
cd skyproject-mtasa
.\win-create-projects.bat
```

Відкрийте створене рішення у Visual Studio та виберіть потрібну конфігурацію. Додаткові вимоги дивіться в документації оригінального MTA.

### Linux

Для збирання сервера Linux використовується система збирання оригінального MTA. Вимоги до інструментів і залежностей наведені у скриптах репозиторію та документації оригінального проєкту.

## 📁 Структура репозиторію

```text
skyproject-mtasa/
├── Client/       # Клієнт гри
├── Server/       # Виділений сервер
├── Shared/       # Спільний код та SDK
├── vendor/       # Сторонні залежності
├── utils/        # Інструменти розробки
└── assets/       # Оформлення Sky Project
```

## 🔗 Посилання

- [Репозиторій Sky Project](https://github.com/n1cec0derrr/skyproject-mtasa)
- [Оригінальний код MTA:SA](https://github.com/multitheftauto/mtasa-blue)
- [Офіційний сайт Multi Theft Auto](https://multitheftauto.com/)

## 📜 Ліцензії та авторство

Проєкт заснований на **Multi Theft Auto: San Andreas**, розробленому командою MTA та учасниками спільноти. Sky Project — незалежна модифікація, що **не є офіційним проєктом MTA**.

Усі чинні ліцензії, повідомлення про авторські права та умови використання сторонніх компонентів залишаються в силі. Дивіться файли ліцензій у вихідному коді.

<div align="center">

---

<sub>SKY PROJECT · НА ОСНОВІ MTA:SA 1.6.0</sub>

</div>
