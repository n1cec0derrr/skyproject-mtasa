# Сборка клиента Sky Project

Клиент собирается из этого репозитория в папку `Bin`. Карта, машины и данные Sky Project
приходят из зашифрованного пакета `Bin\dlc\sky_project.skydlc`, `.img` на диске не нужны.
Что раздаёт лаунчер и как выпускать обновления — в `LAUNCHER_RU.md`.

## Что нужно

- Windows, Visual Studio 2026 с компонентом «Разработка классических приложений на C++» (набор v145).
  Подойдёт и Visual Studio 2022 (набор v143), см. ниже.
- DirectX SDK (June 2010). После установки должна быть задана переменная окружения
  `DXSDK_DIR` = `C:\Program Files (x86)\Microsoft DirectX SDK (June 2010)\`
  (без неё не найдётся `d3dx9.h`).
- Интернет при первой генерации проектов: premake скачивает CEF, Unifont, discord-rpc и `netc.dll`.
- **Мастер-ключ DLC** `Client\core\DLC\SkyDLCKey.local.h`. Его нет в репозитории и не должно быть:
  с ним любой расшифрует пакеты. Владелец передаёт файл лично. Без него клиент соберётся, но DLC
  не прочитает (в `MTA\logs\logfile.txt` будет `SkyDLC: no master key in this build`).

## Сборка

```
win-create-projects.bat
```

Затем собрать `Build\MTASA.sln`, конфигурация **Release**, платформа **Win32**:

```
"%ProgramFiles%\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" Build\MTASA.sln -p:Configuration=Release -p:Platform=Win32 -maxCpuCount
```

С Visual Studio 2022 добавить `-p:PlatformToolset=v143` и взять её MSBuild
(`%ProgramFiles%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe`).

Файлы данных MTA и `netc.dll`:

```
utils\premake5.exe install_data
```

## Раскладка готового клиента

```
Bin\
    Sky Project.exe            запуск
    MTA\ ...                   модули и данные MTA (из сборки и install_data)
    dlc\sky_project.skydlc     пакет Sky Project (собирается Tools\SkyDLCStudio)
    runtime\GTA San Andreas\   GTA SA 1.0, без .img
        gta_sa.exe, eax.dll, ogg.dll, vorbis*.dll, stream.ini, anim\, data\, models\, text\   из GTA SA
        audio\                                звук Sky Project (урезанный, ~130 МБ, со своим audio\config)
        $Fla92.dll, DllTricks.dll, MinHook.x86.dll, MinHook.x64.dll, zlib1.dll,
        fastman92limitAdjuster_GTASA.ini      лимит-аджастер Sky Project
```

- Папку `audio` берите целиком из клиента Sky Project, вместе с `audio\config`: файлы
  `banklkup.dat` и `traklkup.dat` описывают именно эти звуковые банки, с полным звуком GTA они не совпадают.

- Папку `runtime\GTA San Andreas` клиент использует всегда, путь из реестра не нужен.
- Лимит-аджастер `$Fla92.dll` загружает `core.dll` при старте игры. Без него карта и машины
  Sky Project не помещаются в лимиты GTA, игра падает при загрузке IDE.
- `.asi` в папке игры класть не надо: загрузчик MTA предупреждает о них (CL28).
- Всё, что Sky Project меняет в файлах игры (`handling.cfg`, `vehicles.ide`, `water.dat`, `hud.txd`,
  пути, карта и т. д.), лежит в пакете и перекрывает файлы с диска.

## Пакет DLC

`Tools\SkyDLCStudio` — программа для сборки `.skydlc`, описание в `Tools\SkyDLCStudio\README_RU.md`.
Ей нужен тот же `SkyDLCKey.local.h`, с которым собран клиент: отпечаток ключа в окне студии
должен совпадать у всех, кто собирает пакеты.

## Отличия от обычного MTA 1.6 ради скриптов Sky Project

- Есть функции старого клиента Sky: `engineStreamingGetMaxMemory`, `engineRestreamModel`,
  `engineRestreamMap` (её вызывает `nrp_memory_sa`). `engineRestreamMap` не перезагружает карту целиком,
  а освобождает память так же, как сама игра: выгружает давно не видимое, что на экране — остаётся.
- Модели в `resources/<ресурс>/...` внутри пакетов DLC подхватывают `engineLoadDFF/TXD/COL/IFP`.
- Архив `.img` из патча `zz_*.skydlc` клиент при запуске сам дописывает в `gta.dat` перед остальными
  архивами: модели из патча заменяют модели основного пакета (машины в `data\Paths\skyproject_vehs.img`)
  без ресурсов и скриптов. В логе: `SkyDLC: patch archive added to gta.dat: ...`.
- Замена модели маркера (1316, 1317, 1559) не меняет вид маркеров, как в старом клиенте.
  Иначе ресурс `ofis_int` (офис на 1559) превращал каждый маркер-стрелку в городе в офис.

## Проверка

`Bin\Sky Project.exe mtasa://<адрес сервера>`. В `Bin\MTA\logs\logfile.txt` должно быть:

```
Sky: load $Fla92.dll: ok
SkyDLC: loaded package: sky_project.skydlc, files=...
SkyDLC: initialized=1, hooked=1, packages=1, files=...
Sky: camera collision hook skipped, the code at 0x41AB8E is patched by a limit adjuster
```
