#pragma once

#include <Windows.h>

#include <string>
#include <array>


namespace Pdb
{

using InstUid = void*;
using TypeId = uint32_t;

using WinError = uint32_t;

class Exception
{
private:
    const std::wstring m_reason;

public:
    explicit Exception(const std::wstring& reason) : m_reason(reason)
    {
    }

    virtual ~Exception() = default;

    const std::wstring& reason() const
    {
        return m_reason;
    }
};

class NotInitialized : public Exception
{
public:
    using Exception::Exception;
};

class DbgHelpFailure : public Exception
{
private:
    WinError m_error;

public:
    explicit DbgHelpFailure(const std::wstring& reason, WinError error)
        : Exception(reason)
        , m_error(error)
    {
    }

    WinError error() const
    {
        return m_error;
    }
};

class SymNotFound : public Exception
{
private:
    const std::wstring m_sym;

public:
    SymNotFound(const std::wstring& reason, const std::wstring& sym)
        : Exception(reason)
        , m_sym(sym)
    {
    }

    const std::wstring& sym() const
    {
        return m_sym;
    }
};

class BadCast : public Exception
{
public:
    explicit BadCast(const std::wstring& reason) : Exception(reason)
    {
    }
};



class Prov;

class PdbInfo
{
    friend Prov;

public:
    enum class Type
    {
        unknown,
        pdb20,
        pdb70
    };

    struct IndexInfo
    {
        unsigned int timestamp;
        unsigned int imageFileSize;
        unsigned int age;
        union
        {
            unsigned int signature;
            GUID guid;
        };
        wchar_t file[MAX_PATH + 1];
        wchar_t dbgFile[MAX_PATH + 1];
        wchar_t pdbFile[MAX_PATH + 1];
        bool stripped;
    };

private:
    static const wchar_t* extractFileName(const wchar_t* path, size_t length) noexcept;

private:
    IndexInfo m_info{};
    Type m_type{ Type::unknown };

private:
    PdbInfo() = default;
    std::wstring makeFullPath(wchar_t delimiter) const;

private:
    static PdbInfo get(const wchar_t* path) noexcept(false);

public:
    PdbInfo(const PdbInfo&) = default;
    PdbInfo(PdbInfo&&) = default;
    PdbInfo& operator = (const PdbInfo&) = default;
    PdbInfo& operator = (PdbInfo&&) = default;

    Type type() const noexcept;
    const IndexInfo& info() const noexcept;

    std::wstring pdbSig() const; // XXXX..XXX

    std::wstring pdbPath() const; // file.pdb\XXXX..XXX\path\to\file.pdb
    std::wstring pdbUrl() const;  // file.pdb/XXXX..XXX/path/to/file.pdb
};



class Prov
{
public:
    static const wchar_t* k_microsoftSymbolServer;
    static const wchar_t* k_microsoftSymbolServerSecure;
    static const wchar_t* k_defaultSymPath;
    static const uint32_t k_defaultOptions;

private:
    static size_t s_initCount;

public:
    static InstUid uid();

    Prov() noexcept(false);
    Prov(const wchar_t* symPath) noexcept(false);
    Prov(const Prov&) = delete;
    Prov(Prov&&) noexcept = default;
    ~Prov();

    Prov& operator = (const Prov&) = delete;
    Prov& operator = (Prov&&) noexcept = default;

    uint32_t getOptions() const noexcept;
    void setOptions(uint32_t options) noexcept;

    std::wstring getSymPath() const noexcept(false);
    void setSymPath(const wchar_t* symPath) noexcept(false);

    PdbInfo getPdbInfo(const wchar_t* filePath) noexcept(false);
};

struct Variant
{
    enum class Type : unsigned short
    {
        Empty = 0,
        Null = 1,
        Short = 2,
        Int = 3,
        Float = 4,
        Double = 5,
        Currency = 6,
        Date = 7,
        Bstr = 8,
        Dispatch = 9, // IDispatch*
        SCode = 10,
        Bool = 11, // True = -1, False = 0
        Variant = 12, // VARIANT*
        Unknown = 13, // IUnknown*
        Decimal = 14, // 16 byte fixed point
        Char = 16,
        UChar = 17,
        UShort = 18,
        UInt = 19,
        Int64 = 20,
        UInt64 = 21,
        ArchInt = 22, // Machine signed int
        ArchUInt = 23, // Machine unsigne int
        Void = 24, // C-style void
        Hresult = 25,
        Ptr = 26,
        SafeArray = 27,
        CStyleArray = 28,
        UserDefined = 29,
        String = 30, // Null-terminated string
        WideString = 31, // Null-terminated wide string
        Record = 36, // User-defined type
        SizeType = 37,
        UnsignedSizeType = 38,
        FileTime = 64,
        Blob = 65, // Length prefixed bytes
        Stream = 66, // Name of the stream follows
        Storage = 67, // Name of the storage follows
        StreamedObject = 68, // Stream contains an object
        StoredObject = 69, // Storage contains an object
        BlobObject = 70, // Blob contains an object
        ClipboardFormat = 71,
        Clsid = 72,
        VersionedStream = 73, // Stream with a GUID version
        BstrBlob = 0xfff, // Reserved for system use
    };

    enum class TypeSpec
    {
        Vector = 0x1000, // Simple counted array
        Array = 0x2000, // SAFEARRAY*
        ByRef = 0x4000, // void* for local use
        Reserved = 0x8000,
        Illegal = 0xffff,
        IllegalMasked = 0xfff,
        TypeMask = 0xfff
    };

    union TypeFields
    {
        unsigned short raw;
        struct
        {
            Type type : 12;
            unsigned short vector : 1;
            unsigned short array : 1;
            unsigned short ptr : 1;
            unsigned short reserved : 1;
        } fields;
    };
    static_assert(sizeof(TypeFields) == sizeof(unsigned short), "Invalid size of TypeFields");

    template <Type type>
    struct ValueType;

    template <>
    struct ValueType<Type::Short>
    {
        using Type = short;
    };

    template <>
    struct ValueType<Type::Int>
    {
        using Type = int;
    };

    template <>
    struct ValueType<Type::Float>
    {
        using Type = float;
    };

    template <>
    struct ValueType<Type::Double>
    {
        using Type = double;
    };

    template <>
    struct ValueType<Type::Char>
    {
        using Type = char;
    };

    template <>
    struct ValueType<Type::UChar>
    {
        using Type = unsigned char;
    };

    template <>
    struct ValueType<Type::UShort>
    {
        using Type = unsigned short;
    };

    template <>
    struct ValueType<Type::UInt>
    {
        using Type = unsigned int;
    };

    template <>
    struct ValueType<Type::Int64>
    {
        using Type = long long;
    };

    template <>
    struct ValueType<Type::UInt64>
    {
        using Type = unsigned long long;
    };

    template <>
    struct ValueType<Type::ArchInt>
    {
        using Type = intptr_t;
    };

    template <>
    struct ValueType<Type::ArchUInt>
    {
        using Type = size_t;
    };

    template <>
    struct ValueType<Type::Void>
    {
        using Type = void;
    };

    template <>
    struct ValueType<Type::String>
    {
        using Type = char;
    };

    template <>
    struct ValueType<Type::WideString>
    {
        using Type = wchar_t;
    };

    template <Type type, TypeSpec... spec>
    struct TypeDeductor;

    template <Type type>
    struct TypeDeductor<type>
    {
        using Type = typename ValueType<type>::Type;
    };

    template <Type type>
    struct TypeDeductor<type, TypeSpec::ByRef>
    {
        using Type = typename ValueType<type>::Type*;
    };

    struct Layout
    {
        TypeFields type;
        unsigned short reserved1;
        unsigned short reserved2;
        unsigned short reserved3;
        union
        {
            unsigned char buf[sizeof(void*) * 2];
            char i8;
            unsigned char u8;
            short i16;
            unsigned short u16;
            int i32;
            unsigned int u32;
            long long i64;
            unsigned long long u64;
            char str[1];
            wchar_t wstr[1];
            float flt;
            double dbl;
            size_t native;
            void* ptr;
            void* __ptr32 ptr32;
            void* __ptr64 ptr64;
        } views;
    };
    static_assert(sizeof(Layout) == (2 * sizeof(void*) + sizeof(unsigned long long)), "Invalid size of Layout");

    unsigned char buf[sizeof(Layout)]{};

    const Layout* layout() const
    {
        return reinterpret_cast<const Layout*>(buf);
    }

    Layout* layout()
    {
        return reinterpret_cast<Layout*>(buf);
    }

    TypeFields type() const
    {
        return layout()->type;
    }

    template <Type type>
    typename TypeDeductor<type>::Type as() const
    {
        if (layout()->type.fields.type != type)
        {
            throw BadCast(__FUNCTIONW__ L": Invalid type cast: types mismatch.");
        }

        return *reinterpret_cast<const typename TypeDeductor<type>::Type*>(&layout()->views);
    }

    template <Type type, TypeSpec spec>
    typename TypeDeductor<type, spec>::Type as() const
    {
        const auto variantType = layout()->type;

        if /*constexpr*/ (spec == TypeSpec::ByRef)
        {
            if (!variantType.fields.ptr)
            {
                throw BadCast(__FUNCTIONW__ L": Invalid type cast of variant type: TypeSpec::ByRef was specified, but the type isn't a pointer.");
            }
        }

        return as<type>();
    }

    template <typename ValType>
    ValType as() const
    {
        return *reinterpret_cast<const ValType*>(&layout()->views);
    }
};

enum class Bool : unsigned int
{
    False,
    True
};

// Based on cvconst.h:
enum class UdtKind : unsigned int
{
    Struct,
    Class,
    Union,
    Interface
};

// Based on cvconst.h:
enum class Convention : unsigned int
{
    NearC       = 0x00, // Near right to left push, caller pops stack
    FarC        = 0x01, // Far right to left push, caller pops stack
    NearPascal  = 0x02, // Near left to right push, callee pops stack
    FarPascal   = 0x03, // Far left to right push, callee pops stack
    NearFast    = 0x04, // Near left to right push with regs, callee pops stack
    FarFast     = 0x05, // Far left to right push with regs, callee pops stack
    Skipped     = 0x06, // Skipped (unused) call index
    NearStd     = 0x07, // Near standard call
    FarStd      = 0x08, // Far standard call
    NearSys     = 0x09, // Near sys call
    FarSys      = 0x0a, // Far sys call
    Thiscall    = 0x0b, // this call (this passed in register)
    MipsCall    = 0x0c, // Mips call
    Generic     = 0x0d, // Generic call sequence
    AlphaCall   = 0x0e, // Alpha call
    PPCCall     = 0x0f, // PPC call
    SHCall      = 0x10, // Hitachi SuperH call
    ARMCall     = 0x11, // ARM call
    AM33Call    = 0x12, // AM33 call
    TriCall     = 0x13, // TriCore Call
    SH5Call     = 0x14, // Hitachi SuperH-5 call
    M32RCall    = 0x15, // M32R Call
    CLRCall     = 0x16, // CLR call
    Inline      = 0x17, // Marker for routines always inlined and thus lacking a convention
    NearVector  = 0x18, // Near left to right push with regs, callee pops stack
    Reserved    = 0x19  // First unused call enumeration
};

// Based on cvconst.h:
enum class SymTag : unsigned int
{
    Null,
    Exe,
    Compiland,
    CompilandDetails,
    CompilandEnv,
    Function,
    Block,
    Data,
    Annotation,
    Label,
    PublicSymbol,
    UDT,
    Enum,
    FunctionType,
    PointerType,
    ArrayType,
    BaseType,
    Typedef,
    BaseClass,
    Friend,
    FunctionArgType,
    FuncDebugStart,
    FuncDebugEnd,
    UsingNamespace,
    VTableShape,
    VTable,
    Custom,
    Thunk,
    CustomType,
    ManagedType,
    Dimension,
    CallSite,
    InlineSite,
    BaseInterface,
    VectorType,
    MatrixType,
    HLSLType,
    Caller,
    Callee,
    Export,
    HeapAllocationSite,
    CoffGroup,
    Inlinee,
    Max
};

// Based on cvconst.h:
enum class Location : unsigned int
{
    Null,
    Static,
    TLS,
    RegRel,
    ThisRel,
    Enregistered,
    BitField,
    Slot,
    IlRel,
    MetaData,
    Constant,
    Max
};

// Based on cvconst.h:
enum class DataKind : unsigned int
{
    Unknown,
    Local,
    StaticLocal,
    Param,
    ObjectPtr,
    FileStatic,
    Global,
    Member,
    StaticMember,
    Constant
};

// Based on cvconst.h:
enum class BaseType : unsigned int
{
    NoType,
    Void,
    Char,
    WChar,
    SignedChar,
    UChar,
    Int,
    UInt,
    Float,
    BCD,
    Bool,
    Short,
    UShort,
    Long,
    ULong,
    Int8,
    Int16,
    Int32,
    Int64,
    Int128,
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    UInt128,
    Currency,
    Date,
    Variant,
    Complex,
    Bit,
    BSTR,
    Hresult,
    Char16,
    Char32,
    Char8
};

template <typename SymType>
class TypeHolder
{
private:
    static const wchar_t* const s_names[];

private:
    SymType m_type;

public:
    explicit TypeHolder(SymType type) : m_type(type)
    {
    }

    const wchar_t* name() const
    {
        return s_names[static_cast<unsigned int>(m_type)];
    }

    SymType type() const
    {
        return m_type;
    }

    operator const wchar_t* () const
    {
        return name();
    }

    operator SymType() const
    {
        return type();
    }
};

enum class SymInfo
{
    GetSymTag,
    GetSymName,
    GetLength,
    GetType,
    GetTypeId,
    GetBaseType,
    GetArrayIndexTypeId,
    FindChildren,
    GetDataKind,
    GetAddressOffset,
    GetOffset,
    GetValue,
    GetCount,
    GetChildrenCount,
    GetBitPosition,
    GetVirtualBaseClass,
    GetVirtualTableShapeId,
    GetVirtualBasePointerOffset,
    GetClassParentId,
    GetNested,
    GetSymIndex,
    GetLexicalParent,
    GetAddress,
    GetThisAdjust,
    GetUdtKind,
    IsEquivTo,
    GetCallingConvention,
    IsCloseEquivTo,
    GtiexReqsValid,
    GetVirtualBaseOffset,
    GetVirtualBaseDispIndex,
    IsReference,
    GetIndirectVirtualBaseClass,
    GetVirtualBaseTableType,
    Max
};

template <SymInfo info>
struct SymInfoType;

template <>
struct SymInfoType<SymInfo::GetSymTag>
{
    using Type = SymTag;
};

template <>
struct SymInfoType<SymInfo::GetSymName>
{
    using Type = wchar_t*;
};

template <>
struct SymInfoType<SymInfo::GetLength>
{
    using Type = unsigned long long;
};

template <>
struct SymInfoType<SymInfo::GetType>
{
    using Type = TypeId;
};

template <>
struct SymInfoType<SymInfo::GetTypeId>
{
    using Type = TypeId;
};

template <>
struct SymInfoType<SymInfo::GetBaseType>
{
    using Type = BaseType;
};

template <>
struct SymInfoType<SymInfo::GetArrayIndexTypeId>
{
    using Type = TypeId;
};

template <>
struct SymInfoType<SymInfo::FindChildren>
{
    using Type = struct
    {
        unsigned int count;
        unsigned int start;
        unsigned int childId[1];
    };
};

template <>
struct SymInfoType<SymInfo::GetDataKind>
{
    using Type = DataKind;
};

template <>
struct SymInfoType<SymInfo::GetAddressOffset>
{
    using Type = unsigned int;
};

template <>
struct SymInfoType<SymInfo::GetOffset>
{
    using Type = unsigned int;
};

template <>
struct SymInfoType<SymInfo::GetValue>
{
    using Type = Variant;
};

template <>
struct SymInfoType<SymInfo::GetCount>
{
    using Type = unsigned int;
};

template <>
struct SymInfoType<SymInfo::GetChildrenCount>
{
    using Type = unsigned int;
};

template <>
struct SymInfoType<SymInfo::GetBitPosition>
{
    using Type = unsigned int;
};

template <>
struct SymInfoType<SymInfo::GetVirtualBaseClass>
{
    using Type = Bool;
};

template <>
struct SymInfoType<SymInfo::GetVirtualTableShapeId>
{
    using Type = unsigned int;
};

template <>
struct SymInfoType<SymInfo::GetVirtualBasePointerOffset>
{
    using Type = unsigned int;
};

template <>
struct SymInfoType<SymInfo::GetClassParentId>
{
    using Type = unsigned int;
};

template <>
struct SymInfoType<SymInfo::GetNested>
{
    using Type = Bool;
};

template <>
struct SymInfoType<SymInfo::GetSymIndex>
{
    using Type = unsigned int;
};

template <>
struct SymInfoType<SymInfo::GetLexicalParent>
{
    using Type = unsigned int;
};

template <>
struct SymInfoType<SymInfo::GetAddress>
{
    using Type = unsigned long long;
};

template <>
struct SymInfoType<SymInfo::GetThisAdjust>
{
    using Type = unsigned int;
};

template <>
struct SymInfoType<SymInfo::GetUdtKind>
{
    using Type = UdtKind;
};

template <>
struct SymInfoType<SymInfo::IsEquivTo>
{
    using Type = unsigned int;
};

template <>
struct SymInfoType<SymInfo::GetCallingConvention>
{
    using Type = Convention;
};

template <>
struct SymInfoType<SymInfo::IsCloseEquivTo>
{
    using Type = Bool;
};

template <>
struct SymInfoType<SymInfo::GtiexReqsValid>
{
    using Type = unsigned long long;
};

template <>
struct SymInfoType<SymInfo::GetVirtualBaseOffset>
{
    using Type = unsigned int;
};

template <>
struct SymInfoType<SymInfo::GetVirtualBaseDispIndex>
{
    using Type = unsigned int;
};

template <>
struct SymInfoType<SymInfo::IsReference>
{
    using Type = bool;
};

template <>
struct SymInfoType<SymInfo::GetIndirectVirtualBaseClass>
{
    using Type = unsigned int;
};

template <>
struct SymInfoType<SymInfo::GetVirtualBaseTableType>
{
    using Type = unsigned int;
};

class Sym;
class Mod;

class Children
{
private:
    struct ChildrenList
    {
        uint32_t count;
        uint32_t start;
        uint32_t id[1];
    };

public:
    class Iterator
    {
    private:
        const Children* m_children;
        uint32_t m_counter;

    public:
        explicit Iterator(const Children* children);

        Sym operator * () const;

        Iterator& operator ++ ();
        Iterator operator ++ (int);

        bool operator == (const Iterator& it) const;
        bool operator != (const Iterator& it) const;
    };

private:
    const Mod& m_mod;
    ChildrenList* m_children;

private:
    void copy(const ChildrenList* children);

public:
    static ChildrenList* makeList(uint32_t count) noexcept;

    explicit Children(const Mod& mod, ChildrenList* children);
    Children(const Children& children);
    Children(Children&& children) noexcept;
    ~Children();

    Children& operator = (const Children& children) = delete;
    Children& operator = (Children&& children) = delete;

    bool valid() const;

    void reset();

    uint32_t count() const noexcept;

    Sym find(const wchar_t* name) const noexcept(false);

    Iterator begin() const;
    Iterator end() const;

    explicit operator bool() const;
};


class Sym
{
private:
    const Mod& m_mod;
    TypeId m_typeId;

public:
    SymTag tag() const noexcept(false);
    std::wstring name() const noexcept(false);

protected:
    DataKind dataKind() const noexcept(false);
    UdtKind udtKind() const noexcept(false);
    BaseType baseType() const noexcept(false);
    Sym type() const noexcept(false);
    Sym typeId() const noexcept(false);
    Sym arrayIndexTypeId() const noexcept(false);
    Sym symIndex() const noexcept(false);
    uint64_t address() const noexcept(false);
    uint32_t addressOffset() const noexcept(false);
    uint32_t offset() const noexcept(false);
    uint64_t size() const noexcept(false);
    uint32_t count() const noexcept(false);
    Variant value() const noexcept(false);
    uint32_t bitpos() const noexcept(false);
    Convention convention() const noexcept(false);
    uint32_t childrenCount() const noexcept(false);
    Children children() const noexcept(false);

public:
    Sym(const Mod& mod, TypeId index);
    Sym(const Sym&) = default;
    Sym(Sym&&) = default;
    Sym& operator = (const Sym&) = delete;
    Sym& operator = (Sym&&) = delete;
    ~Sym() = default;

    const Mod& mod() const noexcept;
    TypeId id() const noexcept;

    bool queryNoexcept(SymInfo info, void* buf) const noexcept;
    void query(SymInfo info, void* buf) const noexcept(false);

    template <SymInfo info>
    typename SymInfoType<info>::Type queryNoexcept() const noexcept(false)
    {
        typename SymInfoType<info>::Type buf{};
        queryNoexcept(info, &buf);
        return buf;
    }

    template <SymInfo info>
    typename SymInfoType<info>::Type query() const noexcept(false)
    {
        typename SymInfoType<info>::Type buf{};
        query(info, &buf);
        return buf;
    }

    template <typename Type>
    Type cast() const
    {
        if (!equals<Type>())
        {
            throw BadCast(__FUNCTIONW__ L": Invalid type cast.");
        }
        return Type(mod(), id());
    }

    template <typename Type>
    bool equals() const
    {
        return Type::typeof(*this);
    }
};



template <SymTag tag>
class TagClassificator
{
public:
    static constexpr auto k_tag = tag;

    static bool typeof(const Sym& sym) noexcept(false)
    {
        return sym.tag() == k_tag;
    }
};

template <DataKind kind>
class DataClassificator
{
private:
    class DataKindExposer : public Sym
    {
    public:
        using Sym::Sym;
        using Sym::dataKind;
    };

public:
    static constexpr auto k_tag = SymTag::Data;
    static constexpr auto k_kind = kind;

    static bool typeof(const Sym& sym) noexcept(false)
    {
        return (sym.tag() == k_tag) && (DataKindExposer(sym.mod(), sym.id()).dataKind() == k_kind);
    }
};

template <UdtKind kind>
class UdtClassificator
{
private:
    class UdtKindExposer : public Sym
    {
    public:
        using Sym::Sym;
        using Sym::udtKind;
    };

public:
    static constexpr auto k_tag = SymTag::UDT;
    static constexpr auto k_kind = kind;

    static bool typeof(const Sym& sym) noexcept(false)
    {
        return (sym.tag() == k_tag) && (UdtKindExposer(sym.mod(), sym.id()).udtKind() == k_kind);
    }
};




class SymType : public Sym
{
public:
    using Sym::Sym;
    using Sym::size;

    std::wstring name() const noexcept(false);
};

class SymTypeBase : public SymType, public TagClassificator<SymTag::BaseType>
{
public:
    using SymType::SymType;
    using Sym::baseType;

    std::wstring name() const noexcept(false)
    {
        const auto type = baseType();
        const auto len = size();

        if (len == 8)
        {
            switch (type)
            {
            case BaseType::Int:
            {
                return TypeHolder<BaseType>(BaseType::Int64).name();
            }
            case BaseType::UInt:
            {
                return TypeHolder<BaseType>(BaseType::UInt64).name();
            }
            case BaseType::Long:
            {
                return TypeHolder<BaseType>(BaseType::Int64).name();
            }
            case BaseType::ULong:
            {
                return TypeHolder<BaseType>(BaseType::UInt64).name();
            }
            case BaseType::Float:
            {
                return L"double";
            }
            }
        }
        else if (len == 16)
        {
            switch (type)
            {
            case BaseType::Int:
            {
                return TypeHolder<BaseType>(BaseType::Int128).name();
            }
            case BaseType::UInt:
            {
                return TypeHolder<BaseType>(BaseType::UInt128).name();
            }
            case BaseType::Long:
            {
                return TypeHolder<BaseType>(BaseType::Int128).name();
            }
            case BaseType::ULong:
            {
                return TypeHolder<BaseType>(BaseType::UInt128).name();
            }
            }
        }

        return TypeHolder<BaseType>(type).name();
    }
};

class SymTypeUdt : public SymType
{
public:
    using SymType::SymType;
    using Sym::name;
    using Sym::childrenCount;
    using Sym::children;

    UdtKind kind() const noexcept(false)
    {
        return udtKind();
    }
};

class SymTypeUdtGeneric : public SymTypeUdt, public TagClassificator<SymTag::UDT>
{
public:
    using SymTypeUdt::SymTypeUdt;
};

class SymTypeStruct : public SymTypeUdt, public UdtClassificator<UdtKind::Struct>
{
public:
    using SymTypeUdt::SymTypeUdt;
};

class SymTypeClass : public SymTypeUdt, public UdtClassificator<UdtKind::Class>
{
public:
    using SymTypeUdt::SymTypeUdt;
};

class SymTypeUnion : public SymTypeUdt, public UdtClassificator<UdtKind::Union>
{
public:
    using SymTypeUdt::SymTypeUdt;
};

class SymTypeInterface : public SymTypeUdt, public UdtClassificator<UdtKind::Interface>
{
public:
    using SymTypeUdt::SymTypeUdt;
};

class SymTypePtr : public SymType, public TagClassificator<SymTag::PointerType>
{
public:
    using SymType::SymType;

    SymType pointsTo() const noexcept(false)
    {
        const auto type = Sym::type();
        return SymType(type.mod(), type.id());
    }

    std::wstring name() const noexcept(false)
    {
        return pointsTo().name().append(1, L'*');
    }
};

class SymTypeArray : public SymType, public TagClassificator<SymTag::ArrayType>
{
public:
    using SymType::SymType;
    using Sym::count;
    using Sym::childrenCount;
    using Sym::children;

    SymType type() const noexcept(false)
    {
        const auto type = arrayIndexTypeId();
        return SymType(type.mod(), type.id());
    }

    std::wstring name() const noexcept(false)
    {
        return type().name().append(1, L'[').append(std::to_wstring(count())).append(1, L']');
    }
};

class SymTypeFunc : public SymType, public TagClassificator<SymTag::FunctionType>
{
public:
    using SymType::SymType;
    using Sym::convention;
};

class SymTypeEnum : public SymType, public TagClassificator<SymTag::Enum>
{
public:
    using SymType::SymType;
    using Sym::children;
};

class SymTypeBaseClass : public SymType, public TagClassificator<SymTag::BaseClass>
{
public:
    using SymType::SymType;
    using Sym::type;
};

class SymData : public Sym
{
public:
    using Sym::Sym;
    using Sym::name;
    using Sym::bitpos;
    
    struct Bit
    {
        uint32_t pos : 31;
        uint32_t present : 1;
    };
    static_assert(sizeof(Bit) == sizeof(uint32_t), "Invalid size of Bit");

    Bit bitfield() const noexcept
    {
        try
        {
            const auto pos = query<SymInfo::GetBitPosition>();
            Bit bit{};
            bit.pos = pos;
            bit.present = true;
            return bit;
        }
        catch (const DbgHelpFailure&)
        {
            return {};
        }
    }

    SymType type() const noexcept(false)
    {
        const auto dataType = Sym::type();
        return SymType(dataType.mod(), dataType.id());
    }

    DataKind kind() const noexcept(false)
    {
        return dataKind();
    }
};

class SymDataGeneric : public SymData, public TagClassificator<SymTag::Data>
{
public:
    using SymData::SymData;
};

class SymConst : public SymData, public DataClassificator<DataKind::Constant>
{
public:
    using SymData::SymData;
    using Sym::value;
};


class SymStaticMember : public SymData, public DataClassificator<DataKind::StaticMember>
{
public:
    using SymData::SymData;
};

class SymDynamicMember : public SymData, public DataClassificator<DataKind::Member>
{
public:
    using SymData::SymData;
    using Sym::offset;
};



class SymFunc : public SymData, public TagClassificator<SymTag::Function>
{
public:
    using SymData::SymData;

    uint64_t address() const noexcept
    {
        return queryNoexcept<SymInfo::GetAddress>();
    }

    SymTypeFunc type() const noexcept(false)
    {
        const auto type = Sym::type();
        return SymTypeFunc(type.mod(), type.id());
    }

    using Sym::childrenCount;
    using Sym::children;
};

class SymFuncArg : public SymData, public TagClassificator<SymTag::Data>
{
public:
    using SymData::SymData;
};



class SymPublicSymbol : public Sym, public TagClassificator<SymTag::PublicSymbol>
{
public:
    using Sym::Sym;

    using Sym::name;
    using Sym::address;
    using Sym::size;
};


class Mod
{
private:
    uint64_t m_base;

public:
    explicit Mod(const wchar_t* path) noexcept(false);
    Mod(const wchar_t* path, const wchar_t* synonym) noexcept(false);
    Mod(const wchar_t* path, uint64_t imageBase, uint32_t imageSize) noexcept(false);
    Mod(const wchar_t* path, const wchar_t* synonym, uint64_t imageBase, uint32_t imageSize) noexcept(false);
    Mod(const Mod&) = delete;
    Mod(Mod&&) noexcept;
    ~Mod();

    Mod& operator = (const Mod&) = delete;
    Mod& operator = (Mod&&) noexcept;

    uint64_t base() const;

    Sym find(const wchar_t* name) const noexcept(false);
};

} // namespace Pdb