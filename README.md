# <p align="center">♟️ format<b>PE</b>²</p>  
### <p align="center">A bunch of <b>PE</b> and <b>PDB</b> parsers written in C++</p>
### 💾 Pe:
This header-only library provides a convinient way to represent a PE-file as an enumerable object.  
#### The library supports enumeration of:
* Sections
* Imports
* Exports
* Relocations
* Exceptions
* Bound- and delayed-imports
* TLS-callbacks
* Debug directory with support for CodeView PDB information

#### Features:
* Zero-alloc
* Support for both x32 and x64 files regardless of the bitness of your process
* Support for raw PE files from disk and for loaded images in memory
* Kernelmode support
* Extremely fast and lightweight
* Only one header file
* Simplicity in usage
* Support for C++14 and above
* Provides additional information and access to raw PE structures if you need more!

#### Usage:
Just include the **Pe/Pe.hpp** to your project!  
For the complete example of usage look at the [PeTests.cpp](https://github.com/HoShiMin/formatPE/blob/main/PeTests/PeTests.cpp).
```cpp
#include <Windows.h>
#include <cstdio>

#include <Pe/Pe.hpp>

int main()
{
    const auto hNtdll = GetModuleHandleW(L"ntdll.dll");

    //
    // Usage:
    //   Pe::Pe[32|64|Native]::fromFile(fileContent)
    //   Pe::Pe[32|64|Native]::fromModule(hModule)
    //
    // Pe::PeNative is an alias for Pe::Pe32 or Pe::Pe64
    // depending on the current process bitness.
    //

    const auto pe = Pe::PeNative::fromModule(hNtdll);

    // Iterating over exports:
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

    // Find an exported function by name:
    const auto fn = pe.exports().find("NtCreateSection");
    const void* const addr = fn.address();

    return 0;
}
```
---

### 🗜️ Pdb:
This library provides a typed and convinient way to download and parse PDB files using the DbgHelp library.  
It distinguishes raw information from DbgHelp by tags and classifies it by predefined types.  
In other words, you always know which type you deal with - so, you can't parse a struct as a function or something like that.  
#### It supports:
* Downloading PDBs without **symsrv.dll**
* Works with the **dbghelp.dll** supplied with the system in `C:\Windows\System32\dbghelp.dll`
* Does **not** require distribution of **dbghelp.dll** and **symsrv.dll** next to the application
* Base types (`int`, `uint`, `int64`, `uint64`, `int128`, `uint128`, `float`, `double`)
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
* Support for C++14 and above

#### Usage:  
Include the **Pdb/Pdb.cpp** and the **Pdb/Pdb.h** to your project and (optionally) **SymLoader.cpp** and **SymLoader.h** if you want to download PDBs manually.<br>
> ### Important!  
> You **must** have **dbghelp.dll** and **symsrv.dll** in the folder of your application  
> if you plan to download symbols automatically using the symbol path like:  
> `srv*C:\Symbols*http://msdl.microsoft.com/download/symbols`<br><br>
You can find these libraries in the folder of your SDK, for example:  
`C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000\\[x32|x64]\`<br><br>
**But** there is a way to download PDBs **manually** using the **SymLoader** class.  
In this case you **don't need** to distribute **dbghelp.dll** and **symsrv.dll** with the library.

For the complete example of usage look at the [PeTests.cpp](https://github.com/HoShiMin/formatPE/blob/main/PeTests/PeTests.cpp).
```cpp
#include <Pdb/Pdb.hpp>
#include <Pdb/SymLoader.h> // To download PDBs manually

int main()
{
    const std::wstring exePath = L"C:\\Windows\\System32\\ntoskrnl.exe";
    try
    {
        // Create the provider first: it initializes the DbgHelp engine:
        Pdb::Prov prov;

        // Obtain the PDB info associated with the binary:
        const auto pdbInfo = prov.getPdbInfo(exePath.c_str());

        // Use this PDB info to build a link to the file on a symbol server:
        const auto url = std::wstring(Pdb::Prov::k_microsoftSymbolServerSecure)
            + L"/" + pdbInfo.pdbUrl();

        // Select the destination where to place downloaded PDB,
        // the path will be created with all subfolders:
        const std::wstring symFolder = L"C:\\Symbols\\";

        // You can get more control over downloading:
        // derivate from the Pdb::WinInetFileDownloader or from its superclass
        // and override onStart, onReceive, onCancel, onError or onFinish -
        // and you can get HTTP codes and data size.
        Pdb::WinInetFileDownloader downloader((symFolder + pdbInfo.pdbPath()).c_str());
        const bool downloadStatus = Pdb::SymLoader::download(url.c_str(), downloader);
        if (!downloadStatus)
        {
            printf("Unable to download the PDB");
            return;
        }

        // The file was downloaded, set the search path to it for the dbghelp.dll:
        prov.setSymPath(symFolder.c_str());

        // Or you can skip all previous steps if you have
        // both dbghelp.dll and symsrv.dll in the folder of your app.
        // In this case dbghelp.dll will download symbols automatically.

        // Now we can load the image and parse its data:
        const Pdb::Mod mod(exePath.c_str());

        // Let's dump _EPROCESS with all its fields:
        const auto sym = mod.find(L"_EPROCESS").cast<Pdb::SymTypeStruct>();
        for (const auto child : sym.children())
        {
            if (child.equals<Pdb::SymDynamicMember>())
            {
                const auto field = child.cast<Pdb::SymDynamicMember>();
                const auto name = field.name();
                const auto type = field.type();
                const auto bitfield = field.bitfield();
                printf("[%u:%u], %u %ws %ws\n",
                    bitfield.present, bitfield.pos,
                    field.offset(),
                    type.name().c_str(),
                    name.c_str()
                );
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

#### Cmake:

```cmake
# Copy repositories directory to your project directory as a subdirectory. Then:

add_executable("your-project-exe"
"xxx.cpp" #your project cpps
"xxx.cpp"
"xxx.cpp"
)

add_subdirectory("./formatPE/")
target_link_libraries("your-project-exe" PRIVATE 
formatPE::Pe
formatPE::Pdb
formatPE::SymLoader
)

```
