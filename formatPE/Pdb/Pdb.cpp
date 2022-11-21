#include "Pdb.h"

#define _NO_CVCONST_H

#include <DbgHelp.h>
#pragma comment(lib, "dbghelp.lib")

#include <sstream>
#include <iomanip>

namespace Pdb
{

const wchar_t* Prov::k_microsoftSymbolServer = L"http://msdl.microsoft.com/download/symbols";
const wchar_t* Prov::k_microsoftSymbolServerSecure = L"https://msdl.microsoft.com/download/symbols";
const wchar_t* Prov::k_defaultSymPath = L"srv*C:\\Symbols*http://msdl.microsoft.com/download/symbols";
const uint32_t Prov::k_defaultOptions = SYMOPT_UNDNAME | SYMOPT_DEBUG | SYMOPT_LOAD_ANYTHING;

size_t Prov::s_initCount = 0;

InstUid Prov::uid()
{
    if (!s_initCount)
    {
        throw NotInitialized(__FUNCTIONW__ L": A symbols provider isn't created yet. Create the Pdb::Prov instance before the call.");
    }
    return &s_initCount;
}




const wchar_t* PdbInfo::extractFileName(const wchar_t* const path, const size_t length) noexcept
{
    if (!length)
    {
        return path;
    }

    const wchar_t* name = &path[length - 1];
    while ((name != path) && (*name != L'\\') && (*name != L'/'))
    {
        --name;
    }

    return name;
}

PdbInfo PdbInfo::get(const wchar_t* const path) noexcept(false)
{
    SYMSRV_INDEX_INFOW info{};
    info.sizeofstruct = sizeof(info);
    const bool status = !!SymSrvGetFileIndexInfoW(path, &info, 0);
    if (!status)
    {
        const auto lastError = GetLastError();
        throw DbgHelpFailure(__FUNCTIONW__ L": Unable to get a file index info.", lastError);
    }

    PdbInfo pdbInfo;
    pdbInfo.m_info.timestamp = info.timestamp;
    pdbInfo.m_info.imageFileSize = info.size;
    pdbInfo.m_info.age = info.age;
    pdbInfo.m_info.guid = info.guid;
    wcscpy_s(pdbInfo.m_info.file, info.file);
    wcscpy_s(pdbInfo.m_info.dbgFile, info.dbgfile);
    wcscpy_s(pdbInfo.m_info.pdbFile, info.pdbfile);
    pdbInfo.m_info.stripped = info.stripped;
    pdbInfo.m_type = ((info.sig == info.guid.Data1) && (info.guid.Data2 == 0) && (info.guid.Data3 == 0) && (*reinterpret_cast<const uint64_t*>(info.guid.Data4) == 0))
        ? Type::pdb20
        : Type::pdb70;

    return pdbInfo;
}

PdbInfo::Type PdbInfo::type() const noexcept
{
    return m_type;
}

const PdbInfo::IndexInfo& PdbInfo::info() const noexcept
{
    return m_info;
}

std::wstring PdbInfo::makeFullPath(const wchar_t delimiter) const
{
    const size_t pathLength = wcslen(m_info.pdbFile);
    if (!pathLength)
    {
        return {};
    }

    const wchar_t* const pdbPath = m_info.pdbFile;
    const wchar_t* const pdbName = extractFileName(pdbPath, pathLength);
    const unsigned int age = m_info.age;

    switch (m_type)
    {
    case Type::pdb70:
    {
        const auto& guid = m_info.guid;

        std::wstringstream stream;
        stream << std::uppercase << std::hex << std::setfill(L'0')
            << pdbName
            << delimiter
            << std::setw(8) << guid.Data1
            << std::setw(4) << guid.Data2
            << std::setw(4) << guid.Data3
            << std::setw(2) << guid.Data4[0]
            << std::setw(2) << guid.Data4[1]
            << std::setw(2) << guid.Data4[2]
            << std::setw(2) << guid.Data4[3]
            << std::setw(2) << guid.Data4[4]
            << std::setw(2) << guid.Data4[5]
            << std::setw(2) << guid.Data4[6]
            << std::setw(2) << guid.Data4[7]
            << std::setw(1) << age
            << delimiter
            << pdbPath;

        return stream.str();
    }
    case Type::pdb20:
    {
        const auto sig = m_info.signature;

        std::wstringstream stream;
        stream << std::uppercase << std::hex << std::setfill(L'0')
            << pdbName
            << delimiter
            << std::setw(8) << sig
            << std::setw(1) << age
            << delimiter
            << pdbPath;

        return stream.str();
    }
    default:
    {
        break;
    }
    }

    return {};
}

std::wstring PdbInfo::pdbSig() const
{
    const unsigned int age = m_info.age;

    switch (m_type)
    {
    case Type::pdb70:
    {
        const auto& guid = m_info.guid;

        std::wstringstream stream;
        stream << std::uppercase << std::hex << std::setfill(L'0')
            << std::setw(8) << guid.Data1
            << std::setw(4) << guid.Data2
            << std::setw(4) << guid.Data3
            << std::setw(2) << guid.Data4[0]
            << std::setw(2) << guid.Data4[1]
            << std::setw(2) << guid.Data4[2]
            << std::setw(2) << guid.Data4[3]
            << std::setw(2) << guid.Data4[4]
            << std::setw(2) << guid.Data4[5]
            << std::setw(2) << guid.Data4[6]
            << std::setw(2) << guid.Data4[7]
            << std::setw(1) << age;

        return stream.str();
    }
    case Type::pdb20:
    {
        const auto sig = m_info.signature;

        std::wstringstream stream;
        stream << std::uppercase << std::hex << std::setfill(L'0')
            << std::setw(8) << sig
            << std::setw(1) << age;

        return stream.str();
    }
    default:
    {
        break;
    }
    }

    return {};
}

std::wstring PdbInfo::pdbPath() const
{
    return makeFullPath('\\');
}

std::wstring PdbInfo::pdbUrl() const
{
    return makeFullPath('/');
}



Prov::Prov() noexcept(false) : Prov(k_defaultSymPath)
{
}

Prov::Prov(const wchar_t* symPath) noexcept(false)
{
    if (!s_initCount)
    {
        const bool status = !!SymInitializeW(&s_initCount, symPath, false);
        if (!status)
        {
            const auto lastError = GetLastError();
            throw DbgHelpFailure(__FUNCTIONW__ L": Unable to create the Prov instance: 'SymInitializeW' failure.", lastError);
        }

        const auto options = getOptions();
        setOptions(options | k_defaultOptions);
    }
    ++s_initCount;
}

Prov::~Prov()
{
    --s_initCount;
    if (!s_initCount)
    {
        SymCleanup(&s_initCount);
    }
}

uint32_t Prov::getOptions() const noexcept
{
    return SymGetOptions();
}

void Prov::setOptions(uint32_t options) noexcept
{
    SymSetOptions(options);
}

std::wstring Prov::getSymPath() const noexcept(false)
{
    constexpr auto k_sizeStep = 384u;
    std::wstring buf(k_sizeStep, L'\0');
    while (true)
    {
        const bool status = !!SymGetSearchPathW(uid(), &buf[0], static_cast<uint32_t>(buf.size()));
        if (status)
        {
            buf.resize(wcslen(buf.c_str()));
            return buf;
        }

        const auto lastError = GetLastError();
        if (lastError != ERROR_INSUFFICIENT_BUFFER)
        {
            throw DbgHelpFailure(__FUNCTIONW__ L": Unable to obtain a symbol path: 'SymGetSearchPathW' failure.", lastError);
        }

        buf.resize(buf.size() + k_sizeStep);
    }
}

void Prov::setSymPath(const wchar_t* symPath) noexcept(false)
{
    const bool status = !!SymSetSearchPathW(uid(), symPath);
    if (!status)
    {
        const auto lastError = GetLastError();
        throw DbgHelpFailure(__FUNCTIONW__ L": Unable to set a symbol path: 'SymSetSearchPathW' failure.", lastError);
    }
}

PdbInfo Prov::getPdbInfo(const wchar_t* const filePath) noexcept(false)
{
    return PdbInfo::get(filePath);
}



template <>
const wchar_t* const TypeHolder<SymTag>::s_names[]
{
    L"(SymTagNull)",
    L"Executable (Global)",
    L"Compiland",
    L"CompilandDetails",
    L"CompilandEnv",
    L"Function",
    L"Block",
    L"Data",
    L"Annotation",
    L"Label",
    L"PublicSymbol",
    L"UserDefinedType",
    L"Enum",
    L"FunctionType",
    L"PointerType",
    L"ArrayType",
    L"BaseType",
    L"Typedef",
    L"BaseClass",
    L"Friend",
    L"FunctionArgType",
    L"FuncDebugStart",
    L"FuncDebugEnd",
    L"UsingNamespace",
    L"VTableShape",
    L"VTable",
    L"Custom",
    L"Thunk",
    L"CustomType",
    L"ManagedType",
    L"Dimension",
    L"CallSite",
    L"InlineSite",
    L"BaseInterface",
    L"VectorType",
    L"MatrixType",
    L"HLSLType",
    L"Caller",
    L"Callee",
    L"Export",
    L"HeapAllocationSite",
    L"CoffGroup",
    L"Inlinee"
};

template <>
const wchar_t* const TypeHolder<BaseType>::s_names[]
{
    L"<NoType>",
    L"void",
    L"char",
    L"wchar_t",
    L"signed char",
    L"unsigned char",
    L"int",
    L"unsigned int",
    L"float",
    L"<BCD>",
    L"bool",
    L"short",
    L"unsigned short",
    L"long",
    L"unsigned long",
    L"__int8",
    L"__int16",
    L"__int32",
    L"__int64",
    L"__int128",
    L"unsigned __int8",
    L"unsigned __int16",
    L"unsigned __int32",
    L"unsigned __int64",
    L"unsigned __int128",
    L"<currency>",
    L"<date>",
    L"VARIANT",
    L"<complex>",
    L"<bit>",
    L"BSTR",
    L"HRESULT",
    L"char16_t",
    L"char32_t",
    L"char8_t"
};

template <>
const wchar_t* const TypeHolder<DataKind>::s_names[]
{
    L"Unknown",
    L"Local",
    L"Static Local",
    L"Param",
    L"Object Ptr",
    L"File Static",
    L"Global",
    L"Member",
    L"Static Member",
    L"Constant"
};

template <>
const wchar_t* const TypeHolder<UdtKind>::s_names[]
{
    L"struct",
    L"class",
    L"union",
    L"interface"
};



Children::ChildrenList* Children::makeList(uint32_t count) noexcept
{
    const auto size = sizeof(ChildrenList) + count * sizeof(*ChildrenList::id);
    auto* const buf = reinterpret_cast<ChildrenList*>(new (std::nothrow) uint8_t[size]);
    if (buf)
    {
        memset(buf, 0, size);
        buf->count = count;
    }
    return buf;
}

Children::Children(const Mod& mod, ChildrenList* children)
    : m_mod(mod)
    , m_children(children)
{
}

Children::Children(const Children& children)
    : m_mod(children.m_mod)
    , m_children(nullptr)
{
    copy(children.m_children);
}

Children::Children(Children&& children) noexcept
    : m_mod(children.m_mod)
    , m_children(std::exchange(children.m_children, nullptr))
{
}

Children::~Children()
{
    reset();
}

void Children::copy(const ChildrenList* children)
{
    reset();
    if (children)
    {
        m_children = makeList(children->count);
        *m_children = *children;
        memcpy(m_children->id, children->id, children->count * sizeof(*ChildrenList::id));
    }
}

bool Children::valid() const
{
    return m_children != nullptr;
}

void Children::reset()
{
    if (valid())
    {
        delete[] reinterpret_cast<uint8_t*>(m_children);
        m_children = nullptr;
    }
}

uint32_t Children::count() const noexcept
{
    if (!m_children)
    {
        return 0;
    }

    return m_children->count;
}

Sym Children::find(const wchar_t* name) const noexcept(false)
{
    if (!name)
    {
        throw SymNotFound(__FUNCTIONW__ L": Name is NULL.", L"<null>");
    }

    for (const auto sym : *this)
    {
        const auto symName = sym.name();
        if (wcscmp(symName.c_str(), name) == 0)
        {
            return sym;
        }
    }

    throw SymNotFound(std::wstring(__FUNCTIONW__ ": Symbol '").append(name).append(L"' not found."), name);
}

Children::Iterator Children::begin() const
{
    return (count() > 0) ? Iterator(this) : end();
}

Children::Iterator Children::end() const
{
    return Iterator(nullptr);
}

Children::operator bool() const
{
    return valid();
}

Children::Iterator::Iterator(const Children* children)
    : m_children(children)
    , m_counter(children ? children->m_children->start : 0)
{
}

Sym Children::Iterator::operator * () const
{
    return Sym(m_children->m_mod, m_children->m_children->id[m_counter]);
}

Children::Iterator& Children::Iterator::operator ++ ()
{
    if (!m_children || !m_children->m_children)
    {
        return *this;
    }

    ++m_counter;

    if (m_counter == m_children->m_children->count)
    {
        m_counter = 0;
        m_children = nullptr;
    }

    return *this;
}

Children::Iterator Children::Iterator::operator ++ (int)
{
    auto it = *this;
    ++(*this);
    return it;
}

bool Children::Iterator::operator == (const Iterator& it) const
{
    return (m_counter == it.m_counter) && (m_children == it.m_children);
}

bool Children::Iterator::operator != (const Iterator& it) const
{
    return !operator == (it);
}


Sym::Sym(const Mod& mod, TypeId index) : m_mod(mod), m_typeId(index)
{
}

const Mod& Sym::mod() const noexcept
{
    return m_mod;
}

TypeId Sym::id() const noexcept
{
    return m_typeId;
}

bool Sym::queryNoexcept(SymInfo info, void* buf) const noexcept
{
    return !!SymGetTypeInfo(
        Prov::uid(),
        m_mod.base(),
        m_typeId,
        static_cast<IMAGEHLP_SYMBOL_TYPE_INFO>(info),
        buf
    );
}

void Sym::query(SymInfo info, void* buf) const noexcept(false)
{
    const bool status = queryNoexcept(info, buf);
    if (!status)
    {
        //VARIANT var;
        const auto lastError = GetLastError();
        throw DbgHelpFailure(__FUNCTIONW__ L": Unable to query a symbol info: 'SymGetTypeInfo' failure.", lastError);
    }
}

std::wstring Sym::name() const noexcept(false)
{
    wchar_t* const buf = query<SymInfo::GetSymName>();
    if (buf)
    {
        const std::wstring result(buf);
        LocalFree(buf);
        return result;
    }
    return {};
}

SymTag Sym::tag() const noexcept(false)
{
    return query<SymInfo::GetSymTag>();
}

DataKind Sym::dataKind() const noexcept(false)
{
    return query<SymInfo::GetDataKind>();
}

UdtKind Sym::udtKind() const noexcept(false)
{
    return query<SymInfo::GetUdtKind>();
}

BaseType Sym::baseType() const noexcept(false)
{
    return query<SymInfo::GetBaseType>();
}

Sym Sym::type() const noexcept(false)
{
    return Sym(m_mod, query<SymInfo::GetType>());
}

Sym Sym::typeId() const noexcept(false)
{
    return Sym(m_mod, query<SymInfo::GetTypeId>());
}

Sym Sym::arrayIndexTypeId() const noexcept(false)
{
    return Sym(m_mod, query<SymInfo::GetArrayIndexTypeId>());
}

Sym Sym::symIndex() const noexcept(false)
{
    return Sym(m_mod, query<SymInfo::GetSymIndex>());
}

uint64_t Sym::address() const noexcept(false)
{
    return query<SymInfo::GetAddress>();
}

uint32_t Sym::addressOffset() const noexcept(false)
{
    return query<SymInfo::GetAddressOffset>();
}

uint32_t Sym::offset() const noexcept(false)
{
    return query<SymInfo::GetOffset>();
}

uint64_t Sym::size() const noexcept(false)
{
    return query<SymInfo::GetLength>();
}

uint32_t Sym::count() const noexcept(false)
{
    return query<SymInfo::GetCount>();
}

Variant Sym::value() const noexcept(false)
{
    return query<SymInfo::GetValue>();
}

uint32_t Sym::bitpos() const noexcept(false)
{
    return query<SymInfo::GetBitPosition>();
}

Convention Sym::convention() const noexcept(false)
{
    return query<SymInfo::GetCallingConvention>();
}

uint32_t Sym::childrenCount() const noexcept(false)
{
    return query<SymInfo::GetChildrenCount>();
}

Children Sym::children() const noexcept(false)
{
    const auto count = childrenCount();
    if (!count)
    {
        return Children(m_mod, nullptr);
    }

    auto* const buf = Children::makeList(count);
    query(SymInfo::FindChildren, buf);
    return Children(m_mod, buf);
}




std::wstring SymType::name() const noexcept(false)
{
    const auto tag = SymType::tag();
    switch (tag)
    {
    case SymTag::BaseType:
    {
        return cast<SymTypeBase>().name();
    }
    case SymTag::UDT:
    {
        return cast<SymTypeUdtGeneric>().name();
    }
    case SymTag::PointerType:
    {
        return cast<SymTypePtr>().name();
    }
    case SymTag::ArrayType:
    {
        return cast<SymTypeArray>().name();
    }
    default:
    {
        return Sym::name();
    }
    }
}





Mod::Mod(const wchar_t* path) noexcept(false)
    : Mod(path, nullptr, 0, 0)
{
}

Mod::Mod(const wchar_t* path, const wchar_t* synonym) noexcept(false)
    : Mod(path, synonym, 0, 0)
{
}

Mod::Mod(const wchar_t* path, uint64_t imageBase, uint32_t imageSize) noexcept(false)
    : Mod(path, nullptr, imageBase, imageSize)
{
}

Mod::Mod(const wchar_t* path, const wchar_t* synonym, uint64_t imageBase, uint32_t imageSize) noexcept(false)
{
    m_base = SymLoadModuleExW(Prov::uid(), nullptr, path, synonym, imageBase, imageSize, nullptr, 0);
    if (!m_base)
    {
        const auto lastError = GetLastError();
        throw DbgHelpFailure(__FUNCTIONW__ L": Unable to load module: 'SymLoadModuleExW' failure.", lastError);
    }
}

Mod::Mod(Mod&& mod) noexcept : m_base(std::exchange(mod.m_base, 0))
{
}

Mod::~Mod()
{
    if (m_base)
    {
        SymUnloadModule64(Prov::uid(), m_base);
    }
}

Mod& Mod::operator = (Mod&& mod) noexcept
{
    if (&mod == this)
    {
        return *this;
    }

    m_base = std::exchange(mod.m_base, 0);
    return *this;
}

uint64_t Mod::base() const
{
    return m_base;
}

Sym Mod::find(const wchar_t* name) const noexcept(false)
{
    if (!name)
    {
        throw SymNotFound(__FUNCTIONW__ L": Name is NULL.", L"<null>");
    }

    constexpr auto k_size = sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(wchar_t);
    unsigned char buf[k_size]{};
    auto* const info = reinterpret_cast<SYMBOL_INFOW*>(buf);
    info->SizeOfStruct = k_size;
    info->MaxNameLen = MAX_SYM_NAME;
    const bool status = !!SymGetTypeFromNameW(Prov::uid(), base(), name, info);
    if (!status)
    {
        const auto lastError = GetLastError();

        switch (lastError)
        {
        case ERROR_INVALID_FUNCTION:
        {
            throw SymNotFound(std::wstring(__FUNCTIONW__ ": Symbol '").append(name).append(L"' not found."), name);
        }
        case ERROR_INVALID_PARAMETER:
        {
            throw DbgHelpFailure(
                __FUNCTIONW__ L": Unable to get type from name: 'SymGetTypeFromNameW' failure. "
                "Ensure that 'symsrv.dll' and 'dbghelp.dll' are present in the folder of this program or "
                "that symbols are present in the symbols folder.",
                lastError
            );
        }
        default:
        {
            throw DbgHelpFailure(__FUNCTIONW__ L": Unable to get type from name: 'SymGetTypeFromNameW' failure.", lastError);
        }
        }
    }

    return Sym(*this, info->TypeIndex);
}

} // namespace Pdb