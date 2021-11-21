#include <Windows.h>

#include <Pe/Pe.hpp>
#include <Pdb/Pdb.h>

#include <cstdio>
#include <cassert>

extern "C" __declspec(dllexport) unsigned int PeExportedTestValue = 0x1ee7c0de;

void testPe()
{
    const auto pe = Pe::Pe::fromModule(GetModuleHandleW(L"ntdll.dll"));
    assert(pe.valid());

    printf("Imports:\n");
    for (const auto& impLib : pe.imports())
    {
        printf("  Lib: %s", impLib.libName());
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

    printf("Exports:\n");
    for (const auto& exp : pe.exports())
    {
        switch (exp.type())
        {
        case Pe::ExportType::exact:
        {
            printf("  %s at %p\n", exp.name(), exp.address());
            break;
        }
        case Pe::ExportType::forwarder:
        {
            printf("  Forwarder: %s\n", exp.forwarder());
            break;
        }
        }
    }

    printf("Relocs:\n");
    for (const auto& relocEntry : pe.relocs())
    {
        for (const auto& reloc : relocEntry)
        {
            switch (reloc.reloc()->type())
            {
            case Pe::RelocType::absolute:
            {
                printf("  ABS: %p\n", reloc.addr());
                break;
            }
            case Pe::RelocType::dir64:
            {
                printf("  DIR64: %p\n", reloc.addr());
                break;
            }
            case Pe::RelocType::high:
            {
                printf("  HIGH: %p\n", reloc.addr());
                break;
            }
            case Pe::RelocType::highadj:
            {
                printf("  HIGHADJ: %p\n", reloc.addr());
                break;
            }
            case Pe::RelocType::highlow:
            {
                printf("  HIGHLOW: %p\n", reloc.addr());
                break;
            }
            case Pe::RelocType::low:
            {
                printf("  LOW: %p\n", reloc.addr());
                break;
            }
            case Pe::RelocType::unknown:
            {
                printf("  UNKNOWN: %p\n", reloc.addr());
                break;
            }
            }
        }
    }
}

void testPdb()
{
    const auto exePath = std::wstring(L"C:\\Windows\\System32\\ntoskrnl.exe");
    try
    {
        Pdb::Prov prov;

        const Pdb::Mod mod(exePath.c_str());

        const auto sym = mod.find(L"_EPROCESS").cast<Pdb::SymTypeStruct>();
        const auto k = sym.kind();
        for (const auto child : sym.children())
        {
            const auto tag = child.tag();

            if (child.equals<Pdb::SymTypeBaseClass>())
            {
                const auto base = child.cast<Pdb::SymTypeBaseClass>();
                const auto tag = base.tag();
                const auto type = base.type();
                const auto typeTag = type.tag();
                const auto typeName = type.name();
                const auto name = base.name();
            }
            else if (child.equals<Pdb::SymStaticMember>())
            {
                const auto field = child.cast<Pdb::SymStaticMember>();
                const auto chtype = field.type();
                printf("static %ws %ws;\n", field.type().name().c_str(), field.name().c_str());
            }
            else if (child.equals<Pdb::SymDynamicMember>())
            {
                const auto field = child.cast<Pdb::SymDynamicMember>();
                const auto name = field.name();
                const auto tag = field.tag();
                const auto typeTag = field.type().tag();
                const auto bf = field.bitfield();
                printf("%u:%u pos, %u %ws %ws\n", bf.present, bf.pos, field.offset(), field.type().name().c_str(), field.name().c_str());
            }
            else if (child.equals<Pdb::SymFunc>())
            {
                const auto func = child.cast<Pdb::SymFunc>();

                const auto funcType = func.type();
                const auto funcTypeTag = funcType.tag();

                const auto conv = funcType.convention();

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
