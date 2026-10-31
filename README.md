<div align="center">

<img src="assets/skyproject-logo.png" alt="Sky Project" width="340" />

# SKY PROJECT

### CUSTOM MULTI THEFT AUTO: SAN ANDREAS CLIENT & SERVER

[![MTA:SA](https://img.shields.io/badge/MTA%3ASA-1.6.0-3B82F6?style=for-the-badge)](https://github.com/multitheftauto/mtasa-blue)
![C++](https://img.shields.io/badge/C%2B%2B-Native-2563EB?style=for-the-badge&logo=cplusplus&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-Client-374151?style=for-the-badge&logo=windows&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Server-374151?style=for-the-badge&logo=linux&logoColor=white)

**[English](README.md) · [Русский](README_RU.md) · [Українська](README_UA.md)**

---

**An independent customization project built on the official MTA:SA 1.6.0 source code.**

</div>

## ✦ About

**Sky Project** is a custom client and server development project for **Multi Theft Auto: San Andreas**. This repository starts from the official **MTA:SA 1.6.0** source code and serves as the foundation for future Sky Project modifications.

> **Development status:** Initial source baseline. Custom features and branding will be implemented progressively.

## ⚙️ Technology

| Component | Details |
|:--|:--|
| Base | Multi Theft Auto: San Andreas 1.6.0 |
| Primary language | C++ |
| Game scripting | Lua |
| Windows IDE | Visual Studio 2022 |
| Client platform | Windows |
| Server platforms | Windows / Linux |
| Project generator | Premake 5 |

## 🛠️ Build from source

### Windows

**Prerequisites:** Visual Studio 2022 with C++ desktop development tools, Git, and the dependencies required by the upstream MTA build system (including legacy DirectX SDK components where needed).

```powershell
git clone https://github.com/n1cec0derrr/skyproject-mtasa.git
cd skyproject-mtasa
.\win-create-projects.bat
```

Open the generated Visual Studio solution and select the appropriate configuration. Refer to the upstream build documentation for additional dependencies and build instructions.

### Linux server

Linux server builds use the upstream MTA build system. Consult the repository's build scripts and upstream documentation for supported toolchains and dependencies.

## 📁 Repository structure

```text
skyproject-mtasa/
├── Client/       # Game client
├── Server/       # Dedicated server
├── Shared/       # Shared code and SDK
├── vendor/       # Third-party dependencies
├── utils/        # Build and development tools
└── assets/       # Sky Project branding
```

## 🔗 Links

- [Sky Project repository](https://github.com/n1cec0derrr/skyproject-mtasa)
- [Original MTA:SA source code](https://github.com/multitheftauto/mtasa-blue)
- [Multi Theft Auto](https://multitheftauto.com/)

## 📜 License & attribution

This project is based on **Multi Theft Auto: San Andreas**, developed by the MTA team and its contributors. Sky Project is an independent modification and is **not an official MTA project**.

The original licenses, copyright notices, and applicable third-party license terms remain in effect. See the license files distributed with the source code. Original authorship and attribution are retained.

<div align="center">

---

<sub>SKY PROJECT · BASED ON MTA:SA 1.6.0</sub>

</div>
