#pragma once

#include "Pdb.h"

namespace Pdb
{



class DownloaderInterface
{
public:
    virtual ~DownloaderInterface() = default;
    virtual bool valid() const noexcept = 0;
    virtual bool download(const wchar_t* url) = 0;
};

class WinInetAbstractDownloader : public DownloaderInterface
{
protected:
    enum class Action
    {
        cancel,
        proceed
    };

protected:
    virtual void onStart(const wchar_t* url, size_t contentLength) = 0;
    virtual Action onReceive(const void* buf, size_t size) = 0;
    virtual void onFinish() = 0;
    virtual void onError(unsigned int httpCode) = 0;
    virtual void onCancel() = 0;

public:
    virtual bool download(const wchar_t* url) noexcept override;
};

class WinInetFileDownloader : public WinInetAbstractDownloader
{
private:
    HANDLE m_hFile;

protected:
    static HANDLE createFileWithHierarchy(const wchar_t* filePath, unsigned long access, unsigned long share) noexcept;

protected:
    virtual void onStart(const wchar_t* url, size_t contentLength) override;
    virtual Action onReceive(const void* buf, size_t size);
    virtual void onFinish() override;
    virtual void onError(unsigned int httpCode) override;
    virtual void onCancel() override;

protected:
    void closeFile() noexcept;

public:
    WinInetFileDownloader(const wchar_t* filePath) noexcept;
    ~WinInetFileDownloader() noexcept;

    virtual bool valid() const noexcept override;
};

struct SymLoader
{
    static bool download(const wchar_t* url, DownloaderInterface& downloader);
};



} // namespace Pdb