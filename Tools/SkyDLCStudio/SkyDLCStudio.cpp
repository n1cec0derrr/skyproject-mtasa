// Sky DLC Studio: window for building the encrypted .skydlc packages of Sky Project.

#include "SkyDLCCore.h"

#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>

#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

using namespace sky;

namespace
{
    enum : int
    {
        ID_CONTENT = 100,
        ID_CONTENT_BROWSE,
        ID_GAME,
        ID_GAME_BROWSE,
        ID_DLC,
        ID_DLC_BROWSE,
        ID_KEY,
        ID_KEY_BROWSE,
        ID_FINGERPRINT,
        ID_LIST,
        ID_REFRESH,
        ID_IMPORT,
        ID_BUILD_CHANGED,
        ID_BUILD_ALL,
        ID_BUILD_PATCH,
        ID_VERIFY,
        ID_FOLDER_PATCH,
        ID_CANCEL,
        ID_HINT,
        ID_SINGLE,
        ID_PROGRESS,
        ID_STATUS,
        ID_LOG,
    };

    constexpr UINT WM_APP_LOG = WM_APP + 1;
    constexpr UINT WM_APP_PROGRESS = WM_APP + 2;
    constexpr UINT WM_APP_DONE = WM_APP + 3;

    struct ProgressMessage
    {
        std::wstring stage;
        uint64_t     done = 0;
        uint64_t     total = 0;
    };

    struct Field
    {
        int          labelId, editId, browseId;
        const wchar_t* label;
        const wchar_t* iniKey;
        bool         folder;
    };

    const Field FIELDS[] = {
        {0, ID_CONTENT, ID_CONTENT_BROWSE, L"Папка контента:", L"Content", true},
        {0, ID_GAME, ID_GAME_BROWSE, L"Папка игры (gta_sa.exe):", L"Game", true},
        {0, ID_DLC, ID_DLC_BROWSE, L"Папка dlc клиента:", L"Dlc", true},
        {0, ID_KEY, ID_KEY_BROWSE, L"Мастер-ключ:", L"Key", false},
    };

    HWND              g_window = nullptr;
    HWND              g_list = nullptr;
    HWND              g_log = nullptr;
    HWND              g_progress = nullptr;
    HWND              g_status = nullptr;
    HFONT             g_font = nullptr;
    HWND              g_labels[4] = {};
    std::thread       g_worker;
    std::atomic<bool> g_cancel{false};
    bool              g_busy = false;
    UINT              g_dpi = 96;
    fs::path          g_ini;

    int Scale(int value) { return MulDiv(value, static_cast<int>(g_dpi), 96); }

    // ------------------------------------------------------------ worker → window

    class WindowReporter : public Reporter
    {
    public:
        void Log(const std::wstring& text) override { PostMessageW(g_window, WM_APP_LOG, 0, reinterpret_cast<LPARAM>(new std::wstring(text))); }

        void Progress(const std::wstring& stage, uint64_t done, uint64_t total) override
        {
            const auto now = std::chrono::steady_clock::now();
            if (stage == m_stage && now - m_last < std::chrono::milliseconds(80))
                return;
            m_stage = stage;
            m_last = now;
            PostMessageW(g_window, WM_APP_PROGRESS, 0, reinterpret_cast<LPARAM>(new ProgressMessage{stage, done, total}));
        }

        bool IsCancelled() override { return g_cancel.load(); }

    private:
        std::wstring                          m_stage;
        std::chrono::steady_clock::time_point m_last{};
    };

    // ------------------------------------------------------------ settings

    std::wstring GetText(int id)
    {
        HWND         control = GetDlgItem(g_window, id);
        std::wstring text(static_cast<size_t>(GetWindowTextLengthW(control)) + 1, L'\0');
        GetWindowTextW(control, text.data(), static_cast<int>(text.size()));
        text.resize(wcslen(text.c_str()));
        while (!text.empty() && (text.back() == L' ' || text.back() == L'\\' || text.back() == L'"'))
            text.pop_back();
        while (!text.empty() && (text.front() == L' ' || text.front() == L'"'))
            text.erase(text.begin());
        return text;
    }

    void SetText(int id, const std::wstring& text) { SetWindowTextW(GetDlgItem(g_window, id), text.c_str()); }

    Settings ReadSettings()
    {
        Settings settings;
        settings.content = GetText(ID_CONTENT);
        settings.game = GetText(ID_GAME);
        settings.dlc = GetText(ID_DLC);
        settings.key = GetText(ID_KEY);
        settings.single = SendMessageW(GetDlgItem(g_window, ID_SINGLE), BM_GETCHECK, 0, 0) == BST_CHECKED;
        return settings;
    }

    void SaveSettings()
    {
        for (const Field& field : FIELDS)
            WritePrivateProfileStringW(L"Studio", field.iniKey, GetText(field.editId).c_str(), g_ini.c_str());
        WritePrivateProfileStringW(L"Studio", L"Single", ReadSettings().single ? L"1" : L"0", g_ini.c_str());
    }

    fs::path FindKeyFile(const fs::path& start)
    {
        for (fs::path dir = start; !dir.empty(); dir = dir.parent_path())
        {
            const fs::path candidate = dir / L"Client" / L"core" / L"DLC" / L"SkyDLCKey.local.h";
            if (fs::is_regular_file(candidate))
                return candidate;
            if (dir == dir.parent_path())
                break;
        }

        return {};
    }

    // The repository the studio was built in: the first folder above the exe with Client\core
    fs::path FindRepository(const fs::path& start)
    {
        for (fs::path dir = start; !dir.empty(); dir = dir.parent_path())
        {
            if (fs::is_directory(dir / L"Client" / L"core"))
                return dir;
            if (dir == dir.parent_path())
                break;
        }
        return {};
    }

    void LoadSettings(const fs::path& exeDir)
    {
        auto read = [](const wchar_t* key) {
            wchar_t buffer[1024] = {};
            GetPrivateProfileStringW(L"Studio", key, L"", buffer, 1024, g_ini.c_str());
            return std::wstring(buffer);
        };

        std::wstring content = read(L"Content"), game = read(L"Game"), dlc = read(L"Dlc"), key = read(L"Key");

        // Defaults: the client built from this repository, Bin\runtime\GTA San Andreas and Bin\dlc
        const fs::path repository = FindRepository(exeDir);
        if (game.empty() && !repository.empty())
        {
            const fs::path runtime = repository / L"Bin" / L"runtime" / L"GTA San Andreas";
            if (fs::is_regular_file(runtime / L"gta_sa.exe"))
                game = runtime.wstring();
        }
        if (dlc.empty() && !repository.empty())
            dlc = (repository / L"Bin" / L"dlc").wstring();
        if (content.empty())
            content = (exeDir.root_path() / L"SkyDLCContent").wstring();
        if (key.empty())
            key = FindKeyFile(exeDir).wstring();

        SetText(ID_CONTENT, content);
        SetText(ID_GAME, game);
        SetText(ID_DLC, dlc);
        SetText(ID_KEY, key);
        SendMessageW(GetDlgItem(g_window, ID_SINGLE), BM_SETCHECK, GetPrivateProfileIntW(L"Studio", L"Single", 1, g_ini.c_str()) ? BST_CHECKED : BST_UNCHECKED, 0);
    }

    void UpdateFingerprint()
    {
        std::wstring text;
        try
        {
            text = L"отпечаток " + KeyFingerprint(LoadMasterKey(GetText(ID_KEY)));
        }
        catch (const Error&)
        {
            text = L"ключ не прочитан";
        }
        SetText(ID_FINGERPRINT, text);
    }

    // ------------------------------------------------------------ ui helpers

    void AppendLog(const std::wstring& text)
    {
        SYSTEMTIME time;
        GetLocalTime(&time);
        wchar_t stamp[16];
        swprintf(stamp, 16, L"%02d:%02d:%02d  ", time.wHour, time.wMinute, time.wSecond);

        const std::wstring line = stamp + text + L"\r\n";
        const int          length = GetWindowTextLengthW(g_log);
        SendMessageW(g_log, EM_SETSEL, length, length);
        SendMessageW(g_log, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(line.c_str()));
    }

    void SetBusy(bool busy)
    {
        g_busy = busy;
        for (int id : {ID_SINGLE, ID_REFRESH, ID_IMPORT, ID_BUILD_CHANGED, ID_BUILD_ALL, ID_BUILD_PATCH, ID_FOLDER_PATCH, ID_VERIFY, ID_CONTENT_BROWSE, ID_GAME_BROWSE, ID_DLC_BROWSE,
                       ID_KEY_BROWSE})
            EnableWindow(GetDlgItem(g_window, id), !busy);
        for (const Field& field : FIELDS)
            SendMessageW(GetDlgItem(g_window, field.editId), EM_SETREADONLY, busy, 0);
        EnableWindow(GetDlgItem(g_window, ID_CANCEL), busy);
        SendMessageW(g_progress, PBM_SETPOS, 0, 0);
        if (!busy)
            SetWindowTextW(g_status, L"");
    }

    void ShowScan(const ScanResult& scan)
    {
        ListView_DeleteAllItems(g_list);

        int row = 0;
        for (const PackageView& view : scan.packages)
        {
            LVITEMW item{};
            item.mask = LVIF_TEXT | LVIF_PARAM;
            item.iItem = row;
            item.pszText = const_cast<wchar_t*>(view.fileName.c_str());
            item.lParam = view.upToDate ? 1 : 0;
            ListView_InsertItem(g_list, &item);

            const std::wstring count = view.fileCount ? std::to_wstring(view.fileCount) : L"";
            const std::wstring size = view.size ? FormatSize(view.size) : L"";
            ListView_SetItemText(g_list, row, 1, const_cast<wchar_t*>(view.source.c_str()));
            ListView_SetItemText(g_list, row, 2, const_cast<wchar_t*>(count.c_str()));
            ListView_SetItemText(g_list, row, 3, const_cast<wchar_t*>(size.c_str()));
            ListView_SetItemText(g_list, row, 4, const_cast<wchar_t*>(view.status.c_str()));
            row++;
        }

        AppendLog(scan.summary);
    }

    // Runs a job off the window thread, rescans the content after it
    void RunJob(const std::wstring& title, std::function<void(const Settings&, Reporter&)> job, bool rescan = true)
    {
        if (g_busy)
            return;

        if (g_worker.joinable())
            g_worker.join();

        SaveSettings();
        UpdateFingerprint();
        const Settings settings = ReadSettings();

        g_cancel = false;
        SetBusy(true);
        AppendLog(L"── " + title);

        g_worker = std::thread([settings, job, rescan]() {
            WindowReporter reporter;
            bool           success = false;

            try
            {
                job(settings, reporter);
                success = true;
            }
            catch (const Cancelled&)
            {
                reporter.Log(L"Отменено. Готовые пакеты на месте, недоделанный не записан.");
            }
            catch (const Error& e)
            {
                reporter.Log(L"ОШИБКА: " + e.text);
            }
            catch (const std::exception& e)
            {
                reporter.Log(L"ОШИБКА: " + Widen(e.what()));
            }

            ScanResult* scan = nullptr;
            if (rescan && !g_cancel)
            {
                try
                {
                    scan = new ScanResult(Scan(settings, reporter));
                }
                catch (const Error& e)
                {
                    reporter.Log(e.text);
                }
                catch (const std::exception& e)
                {
                    reporter.Log(Widen(e.what()));
                }
            }

            PostMessageW(g_window, WM_APP_DONE, success, reinterpret_cast<LPARAM>(scan));
        });
    }

    bool Confirm(const std::wstring& text) { return MessageBoxW(g_window, text.c_str(), L"Sky DLC Studio", MB_OKCANCEL | MB_ICONQUESTION) == IDOK; }

    void Browse(const Field& field)
    {
        IFileOpenDialog* dialog = nullptr;
        if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog))))
            return;

        DWORD options = 0;
        dialog->GetOptions(&options);
        dialog->SetOptions(options | FOS_FORCEFILESYSTEM | (field.folder ? FOS_PICKFOLDERS : FOS_FILEMUSTEXIST));
        dialog->SetTitle(field.label);

        if (!field.folder)
        {
            const COMDLG_FILTERSPEC filters[] = {{L"Ключ (SkyDLCKey.local.h)", L"*.h"}, {L"Все файлы", L"*.*"}};
            dialog->SetFileTypes(2, filters);
        }

        const fs::path current = GetText(field.editId);
        IShellItem*    folder = nullptr;
        const fs::path start = field.folder ? current : current.parent_path();
        if (!start.empty() && fs::is_directory(start) && SUCCEEDED(SHCreateItemFromParsingName(start.c_str(), nullptr, IID_PPV_ARGS(&folder))))
        {
            dialog->SetFolder(folder);
            folder->Release();
        }

        if (SUCCEEDED(dialog->Show(g_window)))
        {
            IShellItem* result = nullptr;
            if (SUCCEEDED(dialog->GetResult(&result)))
            {
                PWSTR path = nullptr;
                if (SUCCEEDED(result->GetDisplayName(SIGDN_FILESYSPATH, &path)))
                {
                    SetText(field.editId, path);
                    CoTaskMemFree(path);

                    // The dlc folder follows the game folder unless chosen by hand
                    if (field.editId == ID_GAME && GetText(ID_DLC).empty())
                        SetText(ID_DLC, (fs::path(GetText(ID_GAME)) / L"dlc").wstring());
                }
                result->Release();
            }
        }
        dialog->Release();

        SaveSettings();
        if (field.editId == ID_KEY)
            UpdateFingerprint();
    }

    void OpenInExplorer(int row)
    {
        wchar_t name[MAX_PATH] = {}, source[MAX_PATH] = {};
        ListView_GetItemText(g_list, row, 0, name, MAX_PATH);
        ListView_GetItemText(g_list, row, 1, source, MAX_PATH);

        fs::path target = fs::path(GetText(ID_DLC)) / name;
        if (!fs::exists(target))
            target = fs::path(GetText(ID_CONTENT)) / source;

        if (fs::exists(target))
        {
            const std::wstring arguments = L"/select,\"" + target.wstring() + L"\"";
            ShellExecuteW(g_window, nullptr, L"explorer.exe", arguments.c_str(), nullptr, SW_SHOWNORMAL);
        }
    }

    // ------------------------------------------------------------ commands

    void OnImport()
    {
        const Settings settings = ReadSettings();
        const auto     images = FindGameImages(settings.game);

        if (images.empty())
        {
            MessageBoxW(g_window, (L"В папке игры не найдено .img:\n" + settings.game.wstring()).c_str(), L"Импорт", MB_ICONWARNING);
            return;
        }

        std::wstring text = L"Разложить архивы игры по папкам в\n" + settings.content.wstring() + L"\n\n";
        uint64_t     total = 0;
        for (const auto& [path, size] : images)
        {
            text += L"   " + path.wstring() + L"   " + FormatSize(size) + L"\n";
            total += size;
        }
        text += L"\nНужно места: около " + FormatSize(total) +
                L".\nУже разложенные архивы пропускаются, файлы игры не меняются.\n"
                L"Ещё копируются data\\gta.dat, default.dat, *.ide и *.ipl, если их нет в контенте.";

        if (Confirm(text))
            RunJob(L"Импорт из игры", [](const Settings& s, Reporter& r) { Import(s, r); });
    }

    // Any folder -> its own small package, independent of the content folder
    void OnFolderPatch()
    {
        IFileOpenDialog* dialog = nullptr;
        if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog))))
            return;

        DWORD options = 0;
        dialog->GetOptions(&options);
        dialog->SetOptions(options | FOS_FORCEFILESYSTEM | FOS_PICKFOLDERS);
        dialog->SetTitle(L"Папка патча (внутри: resources\\<ресурс>\\models\\..., data\\..., *.img\\...)");

        std::wstring folder;
        if (SUCCEEDED(dialog->Show(g_window)))
        {
            IShellItem* result = nullptr;
            if (SUCCEEDED(dialog->GetResult(&result)))
            {
                PWSTR path = nullptr;
                if (SUCCEEDED(result->GetDisplayName(SIGDN_FILESYSPATH, &path)))
                {
                    folder = path;
                    CoTaskMemFree(path);
                }
                result->Release();
            }
        }
        dialog->Release();

        if (!folder.empty())
            RunJob(L"Патч из папки " + folder, [folder](const Settings& s, Reporter& r) { BuildFolderPatch(s, folder, r); });
    }

    void OnCommand(int id)
    {
        switch (id)
        {
            case ID_REFRESH:
                RunJob(L"Обновление", [](const Settings&, Reporter&) {});
                break;

            case ID_IMPORT:
                OnImport();
                break;

            case ID_BUILD_CHANGED:
                RunJob(L"Сборка изменённых архивов", [](const Settings& s, Reporter& r) { Build(s, BuildMode::Changed, r); });
                break;

            case ID_BUILD_ALL:
                if (Confirm(L"Пересобрать все пакеты целиком, даже актуальные?\nПатч при этом убирается: всё уходит в основные архивы."))
                    RunJob(L"Полная пересборка", [](const Settings& s, Reporter& r) { Build(s, BuildMode::All, r); });
                break;

            case ID_BUILD_PATCH:
                RunJob(L"Сборка патча", [](const Settings& s, Reporter& r) { Build(s, BuildMode::Patch, r); });
                break;

            case ID_FOLDER_PATCH:
                OnFolderPatch();
                break;

            case ID_VERIFY:
                RunJob(L"Проверка пакетов в папке dlc", [](const Settings& s, Reporter& r) { VerifyAll(s, r); }, false);
                break;

            case ID_CANCEL:
                g_cancel = true;
                SetWindowTextW(g_status, L"Отмена…");
                break;

            default:
                for (const Field& field : FIELDS)
                    if (field.browseId == id && !g_busy)
                        Browse(field);
                break;
        }
    }

    // ------------------------------------------------------------ window

    HWND Create(const wchar_t* type, const wchar_t* text, DWORD style, int id, DWORD exStyle = 0)
    {
        HWND control = CreateWindowExW(exStyle, type, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10, g_window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                                       GetModuleHandleW(nullptr), nullptr);
        SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(g_font), TRUE);
        return control;
    }

    void MakeFont()
    {
        if (g_font)
            DeleteObject(g_font);

        NONCLIENTMETRICSW metrics{sizeof(metrics)};
        SystemParametersInfoForDpi(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0, g_dpi);
        g_font = CreateFontIndirectW(&metrics.lfMessageFont);
    }

    void CreateControls()
    {
        for (size_t i = 0; i < 4; i++)
        {
            const Field& field = FIELDS[i];
            g_labels[i] = Create(L"STATIC", field.label, SS_LEFT | SS_CENTERIMAGE, -1);
            Create(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL, field.editId, WS_EX_CLIENTEDGE);
            Create(L"BUTTON", L"…", WS_TABSTOP | BS_PUSHBUTTON, field.browseId);
        }
        Create(L"STATIC", L"", SS_LEFT | SS_CENTERIMAGE, ID_FINGERPRINT);
        Create(L"BUTTON", L"Один общий файл sky_project.skydlc (иначе — отдельный пакет на каждый архив)", WS_TABSTOP | BS_AUTOCHECKBOX, ID_SINGLE);

        Create(L"BUTTON", L"Обновить", WS_TABSTOP | BS_PUSHBUTTON, ID_REFRESH);
        Create(L"BUTTON", L"Импорт из игры", WS_TABSTOP | BS_PUSHBUTTON, ID_IMPORT);
        Create(L"BUTTON", L"Собрать изменённые", WS_TABSTOP | BS_DEFPUSHBUTTON, ID_BUILD_CHANGED);
        Create(L"BUTTON", L"Собрать патч", WS_TABSTOP | BS_PUSHBUTTON, ID_BUILD_PATCH);
        Create(L"BUTTON", L"Пересобрать всё", WS_TABSTOP | BS_PUSHBUTTON, ID_BUILD_ALL);
        Create(L"BUTTON", L"Проверить пакеты", WS_TABSTOP | BS_PUSHBUTTON, ID_VERIFY);
        Create(L"BUTTON", L"Патч из папки…", WS_TABSTOP | BS_PUSHBUTTON, ID_FOLDER_PATCH);
        Create(L"BUTTON", L"Отмена", WS_TABSTOP | BS_PUSHBUTTON, ID_CANCEL);

        Create(L"STATIC",
               L"«Собрать изменённые» — изменения уходят в основной пакет (общий файл пересобирается целиком), патч убирается.\r\n"
               L"«Собрать патч» — новые и изменённые модели и файлы данных уходят в маленький zz_patch.skydlc, основной пакет не трогается.",
               SS_LEFT, ID_HINT);

        g_list = Create(WC_LISTVIEWW, L"", WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL, ID_LIST, WS_EX_CLIENTEDGE);
        ListView_SetExtendedListViewStyle(g_list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);

        const struct
        {
            const wchar_t* title;
            int            width;
            int            format;
        } columns[] = {{L"Пакет", 220, LVCFMT_LEFT}, {L"Источник", 260, LVCFMT_LEFT}, {L"Файлов", 70, LVCFMT_RIGHT}, {L"Размер", 90, LVCFMT_RIGHT},
                       {L"Состояние", 420, LVCFMT_LEFT}};

        for (int i = 0; i < 5; i++)
        {
            LVCOLUMNW column{};
            column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
            column.pszText = const_cast<wchar_t*>(columns[i].title);
            column.cx = Scale(columns[i].width);
            column.fmt = columns[i].format;
            ListView_InsertColumn(g_list, i, &column);
        }

        g_progress = Create(PROGRESS_CLASSW, L"", PBS_SMOOTH, ID_PROGRESS);
        SendMessageW(g_progress, PBM_SETRANGE32, 0, 1000);
        g_status = Create(L"STATIC", L"", SS_LEFT | SS_CENTERIMAGE | SS_ENDELLIPSIS, ID_STATUS);

        g_log = Create(L"EDIT", L"", ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL | WS_TABSTOP, ID_LOG, WS_EX_CLIENTEDGE);
        SendMessageW(g_log, EM_SETLIMITTEXT, 0, 0);

        EnableWindow(GetDlgItem(g_window, ID_CANCEL), FALSE);
    }

    void Layout()
    {
        RECT client;
        GetClientRect(g_window, &client);

        const int margin = Scale(10), gap = Scale(6), row = Scale(24), labelWidth = Scale(170), browseWidth = Scale(32);
        const int width = client.right - 2 * margin;
        int       y = margin;

        auto move = [](int id, int x, int y, int w, int h) { MoveWindow(GetDlgItem(g_window, id), x, y, std::max(w, 0), std::max(h, 0), TRUE); };

        for (size_t i = 0; i < 4; i++)
        {
            const Field& field = FIELDS[i];
            const bool   key = field.editId == ID_KEY;
            const int    fingerprint = key ? Scale(230) : 0;
            const int    editWidth = width - labelWidth - browseWidth - 2 * gap - fingerprint;

            MoveWindow(g_labels[i], margin, y, labelWidth, row, TRUE);
            move(field.editId, margin + labelWidth, y, editWidth, row);
            move(field.browseId, margin + labelWidth + editWidth + gap, y, browseWidth, row);
            if (key)
                move(ID_FINGERPRINT, margin + labelWidth + editWidth + browseWidth + 2 * gap, y, fingerprint - gap, row);
            y += row + gap;
        }

        move(ID_SINGLE, margin + labelWidth, y, width - labelWidth, row);
        y += row + gap;
        const int buttons[] = {ID_REFRESH, ID_IMPORT, ID_BUILD_CHANGED, ID_BUILD_PATCH, ID_BUILD_ALL, ID_FOLDER_PATCH, ID_VERIFY, ID_CANCEL};
        const int extra[] = {0, 0, Scale(16), 0, 0, Scale(16), Scale(16), Scale(16)};
        const int count = 8;
        const int buttonWidth = std::min(Scale(150), (width - Scale(64) - gap * (count - 1)) / count);
        const int buttonHeight = Scale(30);
        int       x = margin;
        for (int i = 0; i < count; i++)
        {
            x += extra[i];
            move(buttons[i], x, y, buttonWidth, buttonHeight);
            x += buttonWidth + gap;
        }
        y += buttonHeight + gap;

        move(ID_HINT, margin, y, width, Scale(34));
        y += Scale(34) + gap;

        const int bottom = client.bottom - margin;
        const int rest = bottom - y;
        const int listHeight = std::max(Scale(120), rest * 45 / 100);
        move(ID_LIST, margin, y, width, listHeight);
        y += listHeight + gap;

        move(ID_PROGRESS, margin, y, Scale(260), Scale(18));
        move(ID_STATUS, margin + Scale(260) + gap, y, width - Scale(260) - gap, Scale(18));
        y += Scale(18) + gap;

        move(ID_LOG, margin, y, width, bottom - y);
    }

    LRESULT OnCustomDraw(NMLVCUSTOMDRAW* draw)
    {
        switch (draw->nmcd.dwDrawStage)
        {
            case CDDS_PREPAINT:
                return CDRF_NOTIFYITEMDRAW;
            case CDDS_ITEMPREPAINT:
                // Packages that need work stand out
                draw->clrText = draw->nmcd.lItemlParam ? RGB(0, 110, 40) : RGB(170, 70, 0);
                return CDRF_DODEFAULT;
        }
        return CDRF_DODEFAULT;
    }

    LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
    {
        switch (message)
        {
            case WM_CREATE:
                g_window = window;
                g_dpi = GetDpiForWindow(window);
                MakeFont();
                CreateControls();
                return 0;

            case WM_SIZE:
                Layout();
                return 0;

            case WM_CTLCOLORSTATIC:
                // The read-only log stays white like a normal text field
                if (reinterpret_cast<HWND>(lParam) == g_log)
                {
                    SetBkColor(reinterpret_cast<HDC>(wParam), GetSysColor(COLOR_WINDOW));
                    SetTextColor(reinterpret_cast<HDC>(wParam), GetSysColor(COLOR_WINDOWTEXT));
                    return reinterpret_cast<LRESULT>(GetSysColorBrush(COLOR_WINDOW));
                }
                break;

            case WM_GETMINMAXINFO:
            {
                auto* info = reinterpret_cast<MINMAXINFO*>(lParam);
                info->ptMinTrackSize = {Scale(900), Scale(560)};
                return 0;
            }

            case WM_DPICHANGED:
            {
                g_dpi = HIWORD(wParam);
                MakeFont();
                EnumChildWindows(
                    window, [](HWND child, LPARAM) { SendMessageW(child, WM_SETFONT, reinterpret_cast<WPARAM>(g_font), TRUE); return TRUE; }, 0);
                const RECT* suggested = reinterpret_cast<RECT*>(lParam);
                SetWindowPos(window, nullptr, suggested->left, suggested->top, suggested->right - suggested->left, suggested->bottom - suggested->top,
                             SWP_NOZORDER | SWP_NOACTIVATE);
                return 0;
            }

            case WM_COMMAND:
                if (LOWORD(wParam) == ID_SINGLE && HIWORD(wParam) == BN_CLICKED)
                {
                    SaveSettings();
                    OnCommand(ID_REFRESH);
                }
                else if (HIWORD(wParam) == BN_CLICKED)
                    OnCommand(LOWORD(wParam));
                else if (LOWORD(wParam) == ID_KEY && HIWORD(wParam) == EN_KILLFOCUS)
                    UpdateFingerprint();
                return 0;

            case WM_NOTIFY:
            {
                auto* header = reinterpret_cast<NMHDR*>(lParam);
                if (header->idFrom == ID_LIST && header->code == NM_CUSTOMDRAW)
                    return OnCustomDraw(reinterpret_cast<NMLVCUSTOMDRAW*>(lParam));
                if (header->idFrom == ID_LIST && header->code == NM_DBLCLK)
                {
                    const int row = reinterpret_cast<NMITEMACTIVATE*>(lParam)->iItem;
                    if (row >= 0)
                        OpenInExplorer(row);
                }
                return 0;
            }

            case WM_APP_LOG:
            {
                std::unique_ptr<std::wstring> text(reinterpret_cast<std::wstring*>(lParam));
                AppendLog(*text);
                return 0;
            }

            case WM_APP_PROGRESS:
            {
                std::unique_ptr<ProgressMessage> progress(reinterpret_cast<ProgressMessage*>(lParam));
                const int position = progress->total ? static_cast<int>(progress->done * 1000 / progress->total) : 0;
                SendMessageW(g_progress, PBM_SETPOS, position, 0);

                std::wstring text = progress->stage;
                if (progress->total)
                    text += L"   " + FormatSize(progress->done) + L" / " + FormatSize(progress->total);
                SetWindowTextW(g_status, text.c_str());
                return 0;
            }

            case WM_APP_DONE:
            {
                std::unique_ptr<ScanResult> scan(reinterpret_cast<ScanResult*>(lParam));
                if (g_worker.joinable())
                    g_worker.join();
                SetBusy(false);
                if (scan)
                    ShowScan(*scan);
                if (!wParam)
                    MessageBeep(MB_ICONWARNING);
                return 0;
            }

            case WM_CLOSE:
                if (g_busy)
                {
                    if (MessageBoxW(window, L"Идёт работа. Прервать и выйти?\nНедоделанный пакет не будет записан, готовые останутся.", L"Sky DLC Studio",
                                    MB_OKCANCEL | MB_ICONWARNING) != IDOK)
                        return 0;
                    g_cancel = true;
                    if (g_worker.joinable())
                        g_worker.join();
                }
                SaveSettings();
                DestroyWindow(window);
                return 0;

            case WM_DESTROY:
                PostQuitMessage(0);
                return 0;
        }

        return DefWindowProcW(window, message, wParam, lParam);
    }
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show)
{
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&controls);

    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    const fs::path exeDir = fs::path(exePath).parent_path();
    g_ini = exeDir / L"SkyDLCStudio.ini";

    WNDCLASSEXW windowClass{sizeof(windowClass)};
    windowClass.lpfnWndProc = WindowProc;
    windowClass.hInstance = instance;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    windowClass.lpszClassName = L"SkyDLCStudio";
    windowClass.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(1));
    if (!windowClass.hIcon)
        windowClass.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    RegisterClassExW(&windowClass);

    const UINT systemDpi = GetDpiForSystem();
    HWND       window = CreateWindowExW(0, windowClass.lpszClassName, L"Sky DLC Studio — пакеты .skydlc для Sky Project", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,
                                        CW_USEDEFAULT, MulDiv(1180, systemDpi, 96), MulDiv(780, systemDpi, 96), nullptr, nullptr, instance, nullptr);
    if (!window)
        return 1;

    LoadSettings(exeDir);
    UpdateFingerprint();
    Layout();
    ShowWindow(window, show);
    UpdateWindow(window);

    AppendLog(L"Sky DLC Studio. Пакеты собираются форматом SKYDLC3, пути внутри — от папки gta_sa.exe.");
    if (fs::is_directory(GetText(ID_CONTENT)))
        RunJob(L"Обновление", [](const Settings&, Reporter&) {});
    else
        AppendLog(L"Папки контента ещё нет. Нажмите «Импорт из игры», чтобы разложить .img по папкам.");

    MSG message;
    while (GetMessageW(&message, nullptr, 0, 0))
    {
        if (!IsDialogMessageW(window, &message))
        {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }

    CoUninitialize();
    return static_cast<int>(message.wParam);
}
