/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        Client/core/Core.cpp
 *  PURPOSE:     Core library entry point
 *
 *  Multi Theft Auto is available from https://multitheftauto.com/
 *
 *****************************************************************************/

#include "StdInc.h"
#include <filesystem>
#define DECLARE_PROFILER_SECTION_Core
#include "profiler/SharedUtil.Profiler.h"
#define UTF8_FILE_HOOKS_PERSONALITY_Core
#include "SharedUtil.Win32Utf8FileHooks.hpp"
#include "SharedUtil.Memory.h"

#define CORE_API extern "C" __declspec(dllexport)

namespace fs = std::filesystem;

CCore*         g_pCore = NULL;
CGraphics*     g_pGraphics = NULL;
CLocalization* g_pLocalization = NULL;

HINSTANCE g_hModule = NULL;

fs::path g_gtaDirectory;
fs::path g_mtaDirectory;

BOOL WINAPI DllMain(HINSTANCE dll, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        g_hModule = dll;
        DisableThreadLibraryCalls(dll);
        AddUtf8FileHooks();
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        RemoveUtf8FileHooks();

        if (IsGTAProcess())
        {
            // For now, ExitProcess if any destruction is attempted (or we'll crash)
            ExitProcess(0);

            if (g_pCore)
            {
                AddReportLog(7102, "Core - PROCESS_DETACH");

                delete g_pCore;
                g_pCore = nullptr;
            }
        }
    }

    return TRUE;
}

CORE_API void SetMTADirectory(const wchar_t* path, size_t length)
{
    if (!g_mtaDirectory.empty() || !path || !path[0] || !length)
        return;

    g_mtaDirectory.assign(std::wstring_view{path, length});
}

CORE_API void SetGTADirectory(const wchar_t* path, size_t length)
{
    if (!g_gtaDirectory.empty() || !path || !path[0] || !length)
        return;

    g_gtaDirectory.assign(std::wstring_view{path, length});
}

CORE_API int InitializeCore()
{
    if (g_pCore)
        return 1;

    if (!IsGTAProcess())
        return 2;

    if (g_mtaDirectory.empty())
        return 3;

    if (g_gtaDirectory.empty())
        return 4;

    // Group our processes and windows under a single taskbar button
    SetCurrentProcessExplicitAppUserModelID(L"Multi Theft Auto");

    WriteDebugEvent(SString("ModuleFileName: %s", *GetLaunchPathFilename()));

    // Sky Project: the fastman92 limit adjuster and the streaming memory fix from the game folder.
    // They patch gta_sa.exe, so they load before anything else runs, the way the old Sky client did.
    // Without the limit adjuster the game cannot take our archives and model counts.
    for (const wchar_t* name : {L"$Fla92.dll", L"StreamMemFix.asi"})
    {
        const fs::path module = g_gtaDirectory / name;
        std::error_code error;

        if (!fs::is_regular_file(module, error))
        {
            WriteDebugEvent(SString("Sky: %s not found in the game folder", *ToUTF8(name)));
            continue;
        }

        const HMODULE handle = LoadLibraryW(module.c_str());
        WriteDebugEvent(SString("Sky: load %s: %s (error %u)", *ToUTF8(name), handle ? "ok" : "failed", handle ? 0u : GetLastError()));
    }

    SetMemoryAllocationFailureHandler();

    g_pCore = new CCore();
    return 0;
}
