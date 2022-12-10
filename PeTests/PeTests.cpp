#include <Windows.h>

#include <Pe/Pe.hpp>
#include <Pdb/Pdb.h>
#include <Pdb/SymLoader.h>

#include <cstdio>
#include <cassert>

#include <winternl.h>
#include <DbgHelp.h>

#include <vector>

namespace tr
{

template <typename... Args>
constexpr void unused(const Args&...)
{
}

} // namespace tr



template <typename PeObject>
void parsePe(const PeObject& pe)
{
    assert(pe.valid());

    printf("#Begin\n\n");

    {
        printf("Sections:\n");
        for (const auto& sec : pe.sections())
        {
            printf("    %.8s\n", sec.Name);
        }
    }

    printf("\n");

    {
        printf("Imports:\n");
        for (const auto& impLib : pe.imports())
        {
            printf("  Lib: %s\n", impLib.libName());
            for (const auto& fn : impLib)
            {
                switch (fn.type())
                {
                case Pe::ImportType::name:
                {
                    printf("    Name: %s\n", fn.name()->Name);
                    break;
                }
                case Pe::ImportType::ordinal:
                {
                    printf("    Ordinal: %u\n", static_cast<unsigned int>(fn.ordinal()));
                    break;
                }
                }
            }
        }
    }

    printf("\n");

    {
        const auto exports = pe.exports();
        printf("Exports count %u (0x%X):\n", exports.count(), exports.count());
        for (const auto& exp : exports)
        {
            switch (exp.type())
            {
            case Pe::ExportType::exact:
            {
                printf("[%u]  %s at %p\n", exp.ordinal(), exp.name(), exp.address());
                break;
            }
            case Pe::ExportType::forwarder:
            {
                printf("[%u] Forwarder: %s\n", exp.ordinal(), exp.forwarder());
                break;
            }
            }

            if (exp.hasName())
            {
                const auto byName = exports.find(exp.name());
                assert(byName.type() == exp.type());
                assert(byName.ordinal() == exp.ordinal());
                switch (byName.type())
                {
                case Pe::ExportType::exact:
                {
                    assert(byName.address() == exp.address());
                    break;
                }
                case Pe::ExportType::forwarder:
                {
                    assert(byName.forwarder() == exp.forwarder());
                    break;
                }
                }

                const auto byOrdinal = exports.find(exp.ordinal());
                assert(byName.address() == byOrdinal.address());
                assert(byName.ordinal() == byOrdinal.ordinal());
                assert(byName.type() == byOrdinal.type());
            }
            else
            {
                const auto t = exp.type(); t;
                const auto byOrdinal = exports.find(exp.ordinal());
                if (exp.type() == Pe::ExportType::exact)
                {
                    assert(byOrdinal.address() == exp.address());
                }
                assert(byOrdinal.ordinal() == exp.ordinal());
                assert(byOrdinal.type() == exp.type());
            }
        }
    }

    printf("\n");

    {
        printf("Relocs:\n");
        for (const auto& relocEntry : pe.relocs())
        {
            printf("  Page 0x%X:\n", relocEntry.descriptor()->VirtualAddress);
            for (const auto& reloc : relocEntry)
            {
                switch (reloc.reloc()->type())
                {
                case Pe::RelocType::absolute:
                {
                    printf("    ABS: %p (Offset in page: 0x%X)\n", reloc.addr(), reloc.reloc()->offsetInPage);
                    break;
                }
                case Pe::RelocType::dir64:
                {
                    printf("    DIR64: %p (Offset in page: 0x%X)\n", reloc.addr(), reloc.reloc()->offsetInPage);
                    break;
                }
                case Pe::RelocType::high:
                {
                    printf("    HIGH: %p (Offset in page: 0x%X)\n", reloc.addr(), reloc.reloc()->offsetInPage);
                    break;
                }
                case Pe::RelocType::highadj:
                {
                    printf("    HIGHADJ: %p (Offset in page: 0x%X)\n", reloc.addr(), reloc.reloc()->offsetInPage);
                    break;
                }
                case Pe::RelocType::highlow:
                {
                    printf("    HIGHLOW: %p (Offset in page: 0x%X)\n", reloc.addr(), reloc.reloc()->offsetInPage);
                    break;
                }
                case Pe::RelocType::low:
                {
                    printf("    LOW: %p (Offset in page: 0x%X)\n", reloc.addr(), reloc.reloc()->offsetInPage);
                    break;
                }
                case Pe::RelocType::unknown:
                {
                    printf("    UNKNOWN: %p (Offset in page: 0x%X)\n", reloc.addr(), reloc.reloc()->offsetInPage);
                    break;
                }
                }
            }
        }
    }

    printf("\n");

    {
        printf("Exceptions:\n");
        for (const auto& exception : pe.exceptions())
        {
            printf("    0x%X..0x%X\n", exception.runtimeFunction()->BeginAddress, exception.runtimeFunction()->EndAddress);
        }
    }

    printf("\n");

    {
        printf("TLS:\n");
        for (const auto& tls : pe.tls())
        {
            printf("    Callback: %p\n", tls.callback());
        }
    }

    printf("\n");

    {
        printf("Debug:\n");
        for (const auto& debug : pe.debug())
        {
            printf("    Entry: %p\n", debug.debugEntry());
            if (debug.debugEntry()->Type == IMAGE_DEBUG_TYPE_CODEVIEW)
            {
                const auto* const codeView = pe.byRva<Pe::CodeView::DebugInfo>(debug.debugEntry()->AddressOfRawData);
                switch (codeView->magic)
                {
                    case Pe::CodeView::CodeViewMagic::pdb20:
                    {
                        const auto& pdb = codeView->pdb20;
                        printf("        CodeView PDB 2.0 path: '%s\\%08X%X\\%s'\n",
                            pdb.pdbName,
                            pdb.signature,
                            pdb.age,
                            pdb.pdbName);
                        break;
                    }
                    case Pe::CodeView::CodeViewMagic::pdb70:
                    {
                        const auto& pdb = codeView->pdb70;
                        printf("        CodeView PDB 7.0 path: '%s\\%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X\\%s'\n",
                            pdb.pdbName,
                            pdb.guid.Data1, pdb.guid.Data2, pdb.guid.Data3,
                            pdb.guid.Data4[0], pdb.guid.Data4[1], pdb.guid.Data4[2], pdb.guid.Data4[3], pdb.guid.Data4[4], pdb.guid.Data4[5], pdb.guid.Data4[6], pdb.guid.Data4[7],
                            pdb.age,
                            pdb.pdbName);
                        break;
                    }
                }
            }
        }
    }

    printf("\n#End\n");
}


void testPe()
{
    const HMODULE hModule = GetModuleHandleW(L"ntdll.dll");

    printf("Module:\n");

    const auto modPe = Pe::PeNative::fromModule(hModule);
    parsePe(modPe);
    

    printf("\n\nFile:\n");

    wchar_t path[MAX_PATH]{};
    const auto nameLength = GetModuleFileNameW(hModule, path, static_cast<unsigned int>(std::size(path)));
    if (!nameLength)
    {
        printf("Unable to get the current binary name\n");
        return;
    }

    const auto hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("Unable to open the file %ws\n", path);
        return;
    }
    
    const auto fileSize = GetFileSize(hFile, nullptr);
    if (!fileSize)
    {
        printf("Unable to size of the file %ws\n", path);
        CloseHandle(hFile);
        return;
    }

    std::vector<unsigned char> fileBuf(fileSize);
    unsigned long readBytes = 0;
    const bool readStatus = !!ReadFile(hFile, &fileBuf[0], fileSize, &readBytes, nullptr);
    if (!readStatus)
    {
        printf("Unable to read the file %ws\n", path);
        CloseHandle(hFile);
        return;
    }

    CloseHandle(hFile);

    const auto filePe = Pe::PeNative::fromFile(&fileBuf[0]);
    parsePe(filePe);
}


class SymDownloader : public Pdb::WinInetFileDownloader
{
private:
    using Super = Pdb::WinInetFileDownloader;

private:
    size_t m_totalSize{ 0 };
    size_t m_downloaded{ 0 };

private:
    static std::pair<float, const char*> formatSize(size_t size) noexcept
    {
        const char* sizeSuffix = nullptr;
        float formattedSize = 0.0f;
        if (size > 1048576)
        {
            sizeSuffix = "Mb";
            formattedSize = static_cast<float>(size) / 1048576;
        }
        else if (size > 1024)
        {
            sizeSuffix = "Kb";
            formattedSize = static_cast<float>(size) / 1024;
        }
        else
        {
            sizeSuffix = "Bytes";
            formattedSize = static_cast<float>(size);
        }

        return std::make_pair(formattedSize, sizeSuffix);
    }

protected:

    virtual void onError(const unsigned int httpCode) override
    {
        Super::onError(httpCode);
        printf("HTTP Error: %u\n", httpCode);
    }

    virtual void onStart(const wchar_t* const url, const size_t fileSize) noexcept override
    {
        const auto formattedSize = formatSize(fileSize);

        printf("Downloading:\n  * '%ws'\n  * %.2f %s\n", url, formattedSize.first, formattedSize.second);
        m_totalSize = fileSize;
    }

    virtual Super::Action onReceive(const void* buf, const size_t size) override
    {
        const auto action = Super::onReceive(buf, size);
        if (action == Super::Action::cancel)
        {
            printf("Cancelled\n");
            return action;
        }

        m_downloaded += size;

        const auto formattedDownloaded = formatSize(m_downloaded);
        const auto formattedTotal = formatSize(m_totalSize);

        printf("Downloaded %u%% (%.2f %s from %.2f %s)\n",
            static_cast<unsigned int>(m_downloaded * 100 / m_totalSize),
            formattedDownloaded.first, formattedDownloaded.second,
            formattedTotal.first, formattedTotal.second
            );

        return Super::Action::proceed;
    }

public:
    using Super::Super;
};

void testPdb()
{
    const auto exePath = std::wstring(L"C:\\Windows\\System32\\ntoskrnl.exe");
    try
    {
        Pdb::Prov prov;

        const auto pdbInfo = prov.getPdbInfo(exePath.c_str());
        printf("CodeView PDB Path: '%ws'\n", pdbInfo.pdbPath().c_str());

        const auto url = std::wstring(Pdb::Prov::k_microsoftSymbolServerSecure) + L"/" + pdbInfo.pdbUrl();
        const std::wstring symFolder = L"C:\\Symbols\\";
        
        SymDownloader loader((symFolder + pdbInfo.pdbPath()).c_str());
        const bool downloadStatus = Pdb::SymLoader::download(url.c_str(), loader);
        if (!downloadStatus)
        {
            printf("Unable to download the symbols");
            return;
        }

        prov.setSymPath(symFolder.c_str());

        const Pdb::Mod mod(exePath.c_str());
        const auto sym = mod.find(L"_EPROCESS").cast<Pdb::SymTypeStruct>();
        for (const auto child : sym.children())
        {
            const auto symTag = child.tag();
            tr::unused(symTag);

            if (child.equals<Pdb::SymTypeBaseClass>())
            {
                const auto base = child.cast<Pdb::SymTypeBaseClass>();
                const auto tag = base.tag();
                const auto type = base.type();
                const auto typeTag = type.tag();
                const auto typeName = type.name();
                const auto name = base.name();
                tr::unused(base, tag, type, typeTag, typeName, name);
            }
            else if (child.equals<Pdb::SymStaticMember>())
            {
                const auto field = child.cast<Pdb::SymStaticMember>();
                printf("static %ws %ws;\n", field.type().name().c_str(), field.name().c_str());
            }
            else if (child.equals<Pdb::SymDynamicMember>())
            {
                const auto field = child.cast<Pdb::SymDynamicMember>();
                const auto name = field.name();
                const auto tag = field.tag();
                const auto typeTag = field.type().tag();
                const auto bf = field.bitfield();
                tr::unused(tag, typeTag);
                printf("%u:%u pos, %u %ws %ws\n", bf.present, bf.pos, field.offset(), field.type().name().c_str(), name.c_str());
            }
            else if (child.equals<Pdb::SymFunc>())
            {
                const auto func = child.cast<Pdb::SymFunc>();

                const auto funcType = func.type();
                const auto funcTypeTag = funcType.tag();
                const auto conv = funcType.convention();
                tr::unused(funcTypeTag, conv);

                auto name = func.name().append(L"(");
                bool firstArg = true;

                for (const auto funcArg : func.children())
                {
                    if (!funcArg.equals<Pdb::SymFuncArg>())
                    {
                        continue;
                    }

                    const auto arg = funcArg.cast<Pdb::SymFuncArg>();

                    const auto argName = arg.name();
                    const auto argType = arg.type();
                    const auto argTypeTag = argType.tag();
                    const auto typeName = argType.name();

                    tr::unused(argTypeTag);

                    if (!firstArg) name.append(L", ");
                    name.append(typeName).append(L" ").append(argName);

                    firstArg = false;
                }

                name.append(L")");

                printf("0x%I64X %ws;\n", func.address(), name.c_str());
            }
        }
    }
    catch (const Pdb::BadCast& e)
    {
        printf("%ws\n", e.reason().c_str());
    }
    catch (const Pdb::NotInitialized& e)
    {
        printf("%ws\n", e.reason().c_str());
    }
    catch (const Pdb::DbgHelpFailure& e)
    {
        printf("%ws Error: 0x%X\n", e.reason().c_str(), e.error());
    }
    catch (const Pdb::SymNotFound& e)
    {
        printf("%ws\n", e.reason().c_str());
    }
}

int main()
{
    testPe();
    testPdb();
    return 0;
}
