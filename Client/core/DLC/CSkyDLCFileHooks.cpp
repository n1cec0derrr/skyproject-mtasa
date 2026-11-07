#include "StdInc.h"
#include "CSkyDLCManager.h"

#include <atomic>
#include <shared_mutex>
#include <SharedUtil.Detours.h>
#include <unordered_map>

// The game reads .img archives through its streaming thread and data files through
// its CRT, both end up in these kernel32 calls. A file found in a package is opened
// as a handle to the .skydlc itself, reads on that handle return decrypted data.
namespace SkyDLC
{
    namespace
    {
        struct SVirtualHandle
        {
            const DLCFile* file;
            uint64_t       position;
        };

        std::shared_mutex                          g_handleLock;
        std::unordered_map<HANDLE, SVirtualHandle> g_handles;
        std::atomic<size_t>                        g_handleCount{0};

        decltype(&CreateFileA)      Real_CreateFileA = nullptr;
        decltype(&CreateFileW)      Real_CreateFileW = nullptr;
        decltype(&ReadFile)         Real_ReadFile = nullptr;
        decltype(&SetFilePointer)   Real_SetFilePointer = nullptr;
        decltype(&SetFilePointerEx) Real_SetFilePointerEx = nullptr;
        decltype(&GetFileSize)      Real_GetFileSize = nullptr;
        decltype(&GetFileSizeEx)    Real_GetFileSizeEx = nullptr;
        decltype(&CloseHandle)      Real_CloseHandle = nullptr;

        bool GetHandle(HANDLE handle, SVirtualHandle& state)
        {
            if (g_handleCount.load(std::memory_order_relaxed) == 0)
                return false;

            std::shared_lock lock(g_handleLock);

            const auto it = g_handles.find(handle);

            if (it == g_handles.end())
                return false;

            state = it->second;
            return true;
        }

        void SetPosition(HANDLE handle, uint64_t position)
        {
            std::unique_lock lock(g_handleLock);

            const auto it = g_handles.find(handle);

            if (it != g_handles.end())
                it->second.position = position;
        }

        bool GetRelativePath(const wchar_t* path, const std::wstring& root, std::wstring& relative)
        {
            if (root.empty() || _wcsnicmp(path, root.c_str(), root.size()) != 0)
                return false;

            relative = path + root.size();
            return true;
        }

        std::wstring GetRootWithSlash(std::wstring root)
        {
            if (!root.empty() && root.back() != L'\\')
                root += L'\\';

            return root;
        }

        // Paths are matched against the current directory (the real GTA folder) and the executable's folder
        const DLCFile* FindGameFile(const wchar_t* path)
        {
            if (!path || GetDLCManager().GetFileCount() == 0)
                return nullptr;

            wchar_t     fullPath[MAX_PATH];
            const DWORD fullLength = GetFullPathNameW(path, MAX_PATH, fullPath, nullptr);

            if (fullLength == 0 || fullLength >= MAX_PATH)
                return nullptr;

            wchar_t currentDirectory[MAX_PATH] = {};
            GetCurrentDirectoryW(MAX_PATH, currentDirectory);

            static const std::wstring executableDirectory = [] {
                wchar_t executable[MAX_PATH] = {};
                GetModuleFileNameW(nullptr, executable, MAX_PATH);
                return GetRootWithSlash(std::filesystem::path(executable).parent_path().wstring());
            }();

            std::wstring relative;

            if (!GetRelativePath(fullPath, GetRootWithSlash(currentDirectory), relative) && !GetRelativePath(fullPath, executableDirectory, relative))
                return nullptr;

            return GetDLCManager().FindFile(ToUTF8(relative.c_str()));
        }

        HANDLE OpenVirtualFile(const DLCFile& file)
        {
            HANDLE handle = Real_CreateFileW(GetDLCManager().GetPackagePath(file).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                             FILE_ATTRIBUTE_NORMAL, nullptr);

            if (handle != INVALID_HANDLE_VALUE)
            {
                std::unique_lock lock(g_handleLock);
                g_handles[handle] = {&file, 0};
                g_handleCount.store(g_handles.size(), std::memory_order_relaxed);
            }

            return handle;
        }

        const DLCFile* FindForOpen(const wchar_t* path, DWORD desiredAccess, DWORD creationDisposition)
        {
            if ((desiredAccess & ~(GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE)) != 0 || creationDisposition != OPEN_EXISTING)
                return nullptr;

            return FindGameFile(path);
        }

        HANDLE WINAPI Hook_CreateFileW(LPCWSTR fileName, DWORD desiredAccess, DWORD shareMode, LPSECURITY_ATTRIBUTES security, DWORD creationDisposition,
                                       DWORD flags, HANDLE templateFile)
        {
            if (const DLCFile* file = FindForOpen(fileName, desiredAccess, creationDisposition))
                return OpenVirtualFile(*file);

            return Real_CreateFileW(fileName, desiredAccess, shareMode, security, creationDisposition, flags, templateFile);
        }

        HANDLE WINAPI Hook_CreateFileA(LPCSTR fileName, DWORD desiredAccess, DWORD shareMode, LPSECURITY_ATTRIBUTES security, DWORD creationDisposition,
                                       DWORD flags, HANDLE templateFile)
        {
            if (fileName && GetDLCManager().GetFileCount() > 0)
            {
                wchar_t wideName[MAX_PATH];

                if (MultiByteToWideChar(CP_ACP, 0, fileName, -1, wideName, MAX_PATH) > 0)
                {
                    if (const DLCFile* file = FindForOpen(wideName, desiredAccess, creationDisposition))
                        return OpenVirtualFile(*file);
                }
            }

            return Real_CreateFileA(fileName, desiredAccess, shareMode, security, creationDisposition, flags, templateFile);
        }

        BOOL WINAPI Hook_ReadFile(HANDLE handle, LPVOID buffer, DWORD bytesToRead, LPDWORD bytesRead, LPOVERLAPPED overlapped)
        {
            SVirtualHandle state;

            if (!GetHandle(handle, state))
                return Real_ReadFile(handle, buffer, bytesToRead, bytesRead, overlapped);

            const uint64_t offset = overlapped ? (static_cast<uint64_t>(overlapped->OffsetHigh) << 32) | overlapped->Offset : state.position;

            uint32_t read = 0;

            if (!GetDLCManager().Read(*state.file, offset, buffer, bytesToRead, read))
            {
                if (bytesRead)
                    *bytesRead = 0;

                SetLastError(ERROR_CRC);
                return FALSE;
            }

            if (bytesRead)
                *bytesRead = read;

            // Reads finish before returning, the streaming thread sees a completed overlapped request
            if (overlapped)
            {
                overlapped->Internal = 0;
                overlapped->InternalHigh = read;

                if (read == 0 && bytesToRead > 0)
                {
                    overlapped->Internal = static_cast<ULONG_PTR>(0xC0000011L);  // STATUS_END_OF_FILE
                    SetLastError(ERROR_HANDLE_EOF);
                    return FALSE;
                }

                if (overlapped->hEvent)
                    SetEvent(overlapped->hEvent);
            }
            else
            {
                SetPosition(handle, offset + read);
            }

            return TRUE;
        }

        bool MovePosition(HANDLE handle, const SVirtualHandle& state, int64_t distance, DWORD method, uint64_t& position)
        {
            int64_t base = 0;

            if (method == FILE_CURRENT)
                base = static_cast<int64_t>(state.position);
            else if (method == FILE_END)
                base = static_cast<int64_t>(state.file->size);
            else if (method != FILE_BEGIN)
                return false;

            if (base + distance < 0)
                return false;

            position = static_cast<uint64_t>(base + distance);
            SetPosition(handle, position);
            return true;
        }

        DWORD WINAPI Hook_SetFilePointer(HANDLE handle, LONG distance, PLONG distanceHigh, DWORD method)
        {
            SVirtualHandle state;

            if (!GetHandle(handle, state))
                return Real_SetFilePointer(handle, distance, distanceHigh, method);

            const int64_t fullDistance =
                distanceHigh ? static_cast<int64_t>((static_cast<uint64_t>(static_cast<uint32_t>(*distanceHigh)) << 32) | static_cast<uint32_t>(distance)) : distance;

            uint64_t position = 0;

            if (!MovePosition(handle, state, fullDistance, method, position))
            {
                SetLastError(ERROR_NEGATIVE_SEEK);
                return INVALID_SET_FILE_POINTER;
            }

            if (distanceHigh)
                *distanceHigh = static_cast<LONG>(position >> 32);

            SetLastError(NO_ERROR);
            return static_cast<DWORD>(position);
        }

        BOOL WINAPI Hook_SetFilePointerEx(HANDLE handle, LARGE_INTEGER distance, PLARGE_INTEGER newPosition, DWORD method)
        {
            SVirtualHandle state;

            if (!GetHandle(handle, state))
                return Real_SetFilePointerEx(handle, distance, newPosition, method);

            uint64_t position = 0;

            if (!MovePosition(handle, state, distance.QuadPart, method, position))
            {
                SetLastError(ERROR_NEGATIVE_SEEK);
                return FALSE;
            }

            if (newPosition)
                newPosition->QuadPart = static_cast<LONGLONG>(position);

            return TRUE;
        }

        DWORD WINAPI Hook_GetFileSize(HANDLE handle, LPDWORD sizeHigh)
        {
            SVirtualHandle state;

            if (!GetHandle(handle, state))
                return Real_GetFileSize(handle, sizeHigh);

            if (sizeHigh)
                *sizeHigh = static_cast<DWORD>(state.file->size >> 32);

            SetLastError(NO_ERROR);
            return static_cast<DWORD>(state.file->size);
        }

        BOOL WINAPI Hook_GetFileSizeEx(HANDLE handle, PLARGE_INTEGER size)
        {
            SVirtualHandle state;

            if (!GetHandle(handle, state))
                return Real_GetFileSizeEx(handle, size);

            size->QuadPart = static_cast<LONGLONG>(state.file->size);
            return TRUE;
        }

        BOOL WINAPI Hook_CloseHandle(HANDLE handle)
        {
            if (g_handleCount.load(std::memory_order_relaxed) != 0)
            {
                std::unique_lock lock(g_handleLock);

                g_handles.erase(handle);
                g_handleCount.store(g_handles.size(), std::memory_order_relaxed);
            }

            return Real_CloseHandle(handle);
        }
    }

    bool InstallFileHooks()
    {
        using SharedUtil::DetourLibraryFunction;

        // CreateFile goes last, no virtual handle can exist before the other hooks are in place
        return DetourLibraryFunction("kernel32.dll", "ReadFile", Real_ReadFile, Hook_ReadFile) &&
               DetourLibraryFunction("kernel32.dll", "SetFilePointer", Real_SetFilePointer, Hook_SetFilePointer) &&
               DetourLibraryFunction("kernel32.dll", "SetFilePointerEx", Real_SetFilePointerEx, Hook_SetFilePointerEx) &&
               DetourLibraryFunction("kernel32.dll", "GetFileSize", Real_GetFileSize, Hook_GetFileSize) &&
               DetourLibraryFunction("kernel32.dll", "GetFileSizeEx", Real_GetFileSizeEx, Hook_GetFileSizeEx) &&
               DetourLibraryFunction("kernel32.dll", "CloseHandle", Real_CloseHandle, Hook_CloseHandle) &&
               DetourLibraryFunction("kernel32.dll", "CreateFileW", Real_CreateFileW, Hook_CreateFileW) &&
               DetourLibraryFunction("kernel32.dll", "CreateFileA", Real_CreateFileA, Hook_CreateFileA);
    }
}
