# ♟️ format**PE**
## A bunch of PE and PDB parsers written in C++
## **Pe++**
This header-only library provides a convinient way to represent a PE-file as an enumerable object.  
#### The library supports enumeration of:
* Sections
* Imports
* Exports
* Relocations
* Exceptions
* Bound- and delayed-imports

#### Features:
* Zero-alloc
* Support for both x32 and x64 files regardless of the bitness of your process
* Support for raw PE files from disk and already deployed (loaded) files in memory
* Kernelmode support
* Extremely fast and lightweight
* Only one header file
* Simplicity in usage
* Provides additional information and access to raw PE structures if you need more!

#### Usage:
Just include the **Pe/Pe.hpp** to your project!
```cpp
#include <Windows.h>
#include <cstdio>

#include <Pe/Pe.hpp>

int main()
{
    const auto hNtdll = GetModuleHandleW(L"ntdll.dll");

    const auto pe = Pe::Pe::fromModule(hNtdll);

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

    return 0;
}
```

## **Pdb++**
This library provides a typed and convinient way to parse PDB files using the DbgHelp library.  
It distinguishes raw information from DbgHelp by tags and classifies them by predefined types.  
In other words, you always know which type you deal with - so, you can't parse a struct as a function or something like that.  
#### It supports:
* Base types (int, uint, int64, uint64, int128, uint128, float, double)
* User-defined types (UDT)
* Structs
* Classes and their parent classes
* Unions
* Interfaces
* Pointers
* Arrays
* Function types, exact functions and their arguments
* Enums
* Bitfields
* Constants
* Static and dynamic members of classes and structs

#### Usage:  
Include the **Pdb/Pdb.cpp** and the **Pdb/Pdb.h** to your project and (**important!**) put **dbghelp.dll** and **symsrv.dll** to the folder with your executable: it's necessary to download symbols from a symbol servers.  
You can find these libraries in the folder of your SDK (e.g. "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000\\[x32 or x64]").
```cpp
#include <Pdb/Pdb.hpp>

int main()
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
            if (child.equals<Pdb::SymDynamicMember>())
            {
                const auto field = child.cast<Pdb::SymDynamicMember>();
                const auto name = field.name();
                const auto tag = field.tag();
                const auto typeTag = field.type().tag();
                const auto bf = field.bitfield();
                const wchar_t* const typeName = field.type().name().c_str();
                const wchar_t* const fieldName = field.name().c_str();
                printf("%u:%u pos, %u %ws %ws\n", bf.present, bf.pos, field.offset(), typeName, fieldName);
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

    return 0;
}
```
