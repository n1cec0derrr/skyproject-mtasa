// Sky DLC Studio: everything except the window.
//
// The content folder mirrors the game folder (the one with gta_sa.exe):
//   models\gta3.img\        a folder named *.img is an IMG archive, its files (.dff/.txd/.col/...) are the entries
//   data\gta.dat, *.ide ... any other file goes into the game as is
//
// Two layouts:
//   single: everything (every IMG built on the fly + the other files) in one sky_project.skydlc
//   split:  a package per *.img folder (<path>.skydlc) and files.skydlc for the other files
// A patch (zz_patch.skydlc) holds models\sky_patch.img with only the models changed since their archive
// was last built, so small additions do not rebuild a whole archive. In the single layout it also holds
// the changed data files (gta.dat, .ide, .ipl): it loads after sky_project.skydlc and overrides them.

#pragma once

#define NOMINMAX
#include <windows.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace sky
{
    namespace fs = std::filesystem;

    using Bytes = std::vector<uint8_t>;
    using Key = std::array<uint8_t, 32>;
    using Hash = std::array<uint8_t, 16>;

    struct Error : std::runtime_error
    {
        explicit Error(const std::wstring& message);
        std::wstring text;
    };

    struct Cancelled : std::runtime_error
    {
        Cancelled() : std::runtime_error("cancelled") {}
    };

    class Reporter
    {
    public:
        virtual ~Reporter() = default;
        virtual void Log(const std::wstring& text) = 0;
        virtual void Progress(const std::wstring& stage, uint64_t done, uint64_t total) = 0;
        virtual bool IsCancelled() = 0;

        void Check()
        {
            if (IsCancelled())
                throw Cancelled();
        }
    };

    struct Settings
    {
        fs::path content;  // folder with models\gta3.img\ etc.
        fs::path game;     // folder with gta_sa.exe
        fs::path dlc;      // where the client looks for .skydlc
        fs::path key;      // SkyDLCKey.local.h
        bool     single = true;  // everything in one sky_project.skydlc instead of a package per archive
    };

    enum class BuildMode
    {
        Changed,  // rebuild the archives that changed, whole
        All,      // rebuild every package
        Patch     // put changed models into the small patch package, leave the archives as they are
    };

    struct PackageView
    {
        std::wstring fileName;  // models_gta3.skydlc
        std::wstring source;    // models\gta3.img
        size_t       fileCount = 0;
        uint64_t     size = 0;
        std::wstring status;
        bool         upToDate = false;
    };

    struct ScanResult
    {
        std::vector<PackageView> packages;
        std::wstring             summary;
    };

    // Strings
    std::wstring Widen(const std::string& utf8);
    std::string  Narrow(const std::wstring& text);
    std::wstring FormatSize(uint64_t size);

    // Master key
    Key          LoadMasterKey(const fs::path& path);
    std::wstring KeyFingerprint(const Key& master);

    // Operations, all run on a worker thread
    ScanResult Scan(const Settings& settings, Reporter& reporter);
    void       Build(const Settings& settings, BuildMode mode, Reporter& reporter);
    void       Import(const Settings& settings, Reporter& reporter);
    void       VerifyAll(const Settings& settings, Reporter& reporter);

    // Packs one folder into its own package zz_<folder name>.skydlc, whatever the content folder holds.
    // The folder mirrors the game folder: resources\<resource>\models\car.dff, data\..., models\x.img\ ...
    void BuildFolderPatch(const Settings& settings, const fs::path& folder, Reporter& reporter);

    // .img files found in the game folder (relative paths), for the import prompt
    std::vector<std::pair<fs::path, uint64_t>> FindGameImages(const fs::path& game);
}
