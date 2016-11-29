/**
 * @file memfs-dokany.cpp
 *
 * @copyright 2015-2016 Bill Zissimopoulos
 */
/*
 * This file is derived from MEMFS which is a part of WinFsp.
 *
 * This file comes under no license. This means that you MAY NOT
 * use it for any purpose other than as a reference.
 *
 * http://choosealicense.com/no-license/
 */

#include "memfs-dokany.h"
#include <map>
#include <cassert>

#define NT_SUCCESS(Status)              (((NTSTATUS)(Status)) >= 0)

/*
 * Define the MEMFS_NAMED_STREAMS macro to include named streams support.
 *
 * NOTE: INCOMPLETE FOR MEMFS-DOKANY.
 */
//#define MEMFS_NAMED_STREAMS

#define MEMFS_SECTOR_SIZE               512
#define MEMFS_SECTORS_PER_ALLOCATION_UNIT 1

/* Path Support */
VOID FspPathPrefix(PWSTR Path, PWSTR *PPrefix, PWSTR *PRemain, PWSTR Root)
{
    PWSTR Pointer;

    for (Pointer = Path; *Pointer; Pointer++)
        if (L'\\' == *Pointer)
        {
            if (0 != Root && Path == Pointer)
                Path = Root;
            *Pointer++ = L'\0';
            for (; L'\\' == *Pointer; Pointer++)
                ;
            break;
        }

    *PPrefix = Path;
    *PRemain = Pointer;
}

VOID FspPathSuffix(PWSTR Path, PWSTR *PRemain, PWSTR *PSuffix, PWSTR Root)
{
    PWSTR Pointer, RemainEnd = 0, Suffix = 0;

    for (Pointer = Path; *Pointer;)
        if (L'\\' == *Pointer)
        {
            RemainEnd = Pointer++;
            for (; L'\\' == *Pointer; Pointer++)
                ;
            Suffix = Pointer;
        }
        else
            Pointer++;

    *PRemain = Path;
    if (Path < Suffix)
    {
        if (0 != Root && Path == RemainEnd && L'\\' == *Path)
            *PRemain = Root;
        *RemainEnd = L'\0';
        *PSuffix = Suffix;
    }
    else
        *PSuffix = Pointer;
}

VOID FspPathCombine(PWSTR Prefix, PWSTR Suffix)
{
    for (; Prefix < Suffix; Prefix++)
        if (L'\0' == *Prefix)
            *Prefix = L'\\';
}

/* Large Heap Support */
typedef struct
{
    DWORD Options;
    SIZE_T InitialSize;
    SIZE_T MaximumSize;
    SIZE_T Alignment;
} LARGE_HEAP_INITIALIZE_PARAMS;
static INIT_ONCE LargeHeapInitOnce = INIT_ONCE_STATIC_INIT;
static HANDLE LargeHeap;
static SIZE_T LargeHeapAlignment;
static BOOL WINAPI LargeHeapInitOnceF(
    PINIT_ONCE InitOnce, PVOID Parameter, PVOID *Context)
{
    LARGE_HEAP_INITIALIZE_PARAMS *Params = (LARGE_HEAP_INITIALIZE_PARAMS *)Parameter;
    LargeHeap = HeapCreate(Params->Options, Params->InitialSize, Params->MaximumSize);
    LargeHeapAlignment = 0 != Params->Alignment ?
        FSP_FSCTL_ALIGN_UP(Params->Alignment, 4096) :
        16 * 4096;
    return TRUE;
}
static inline
BOOLEAN LargeHeapInitialize(
    DWORD Options,
    SIZE_T InitialSize,
    SIZE_T MaximumSize,
    SIZE_T Alignment)
{
    LARGE_HEAP_INITIALIZE_PARAMS Params;
    Params.Options = Options;
    Params.InitialSize = InitialSize;
    Params.MaximumSize = MaximumSize;
    Params.Alignment = Alignment;
    InitOnceExecuteOnce(&LargeHeapInitOnce, LargeHeapInitOnceF, &Params, 0);
    return 0 != LargeHeap;
}
static inline
PVOID LargeHeapAlloc(SIZE_T Size)
{
    return HeapAlloc(LargeHeap, 0, FSP_FSCTL_ALIGN_UP(Size, LargeHeapAlignment));
}
static inline
PVOID LargeHeapRealloc(PVOID Pointer, SIZE_T Size)
{
    if (0 != Pointer)
    {
        if (0 != Size)
            return HeapReAlloc(LargeHeap, 0, Pointer, FSP_FSCTL_ALIGN_UP(Size, LargeHeapAlignment));
        else
            return HeapFree(LargeHeap, 0, Pointer), 0;
    }
    else
    {
        if (0 != Size)
            return HeapAlloc(LargeHeap, 0, FSP_FSCTL_ALIGN_UP(Size, LargeHeapAlignment));
        else
            return 0;
    }
}
static inline
VOID LargeHeapFree(PVOID Pointer)
{
    if (0 != Pointer)
        HeapFree(LargeHeap, 0, Pointer);
}

static inline
FILETIME MemfsGetSystemTime(VOID)
{
    FILETIME FileTime;
    GetSystemTimeAsFileTime(&FileTime);
    return FileTime;
}

static inline
int MemfsCompareString(PWSTR a, int alen, PWSTR b, int blen, BOOLEAN CaseInsensitive)
{
    int len, res;

    if (-1 == alen)
        alen = (int)wcslen(a);
    if (-1 == blen)
        blen = (int)wcslen(b);

    len = alen < blen ? alen : blen;

    /* we should still be in the C locale */
    if (CaseInsensitive)
        res = _wcsnicmp(a, b, len);
    else
        res = wcsncmp(a, b, len);

    if (0 == res)
        res = alen - blen;

    return res;
}

static inline
int MemfsFileNameCompare(PWSTR a, PWSTR b, BOOLEAN CaseInsensitive)
{
    return MemfsCompareString(a, -1, b, -1, CaseInsensitive);
}

static inline
BOOLEAN MemfsFileNameHasPrefix(PWSTR a, PWSTR b, BOOLEAN CaseInsensitive)
{
    int alen = (int)wcslen(a);
    int blen = (int)wcslen(b);

    return alen >= blen && 0 == MemfsCompareString(a, blen, b, blen, CaseInsensitive) &&
        (alen == blen || (1 == blen && L'\\' == b[0]) ||
#if defined(MEMFS_NAMED_STREAMS)
            (L'\\' == a[blen] || L':' == a[blen]));
#else
            (L'\\' == a[blen]));
#endif
}

typedef struct _MEMFS_FILE_NODE
{
    WCHAR FileName[MAX_PATH];
    BY_HANDLE_FILE_INFORMATION FileInfo;
    SIZE_T FileSecuritySize;
    PVOID FileSecurity;
    PVOID FileData;
    ULONG RefCount;
#if defined(MEMFS_NAMED_STREAMS)
    struct _MEMFS_FILE_NODE *MainFileNode;
#endif
} MEMFS_FILE_NODE;

struct MEMFS_FILE_NODE_LESS
{
    MEMFS_FILE_NODE_LESS(BOOLEAN CaseInsensitive) : CaseInsensitive(CaseInsensitive)
    {
    }
    bool operator()(PWSTR a, PWSTR b) const
    {
        return 0 > MemfsFileNameCompare(a, b, CaseInsensitive);
    }
    BOOLEAN CaseInsensitive;
};
typedef std::map<PWSTR, MEMFS_FILE_NODE *, MEMFS_FILE_NODE_LESS> MEMFS_FILE_NODE_MAP;

typedef struct _MEMFS
{
    //FSP_FILE_SYSTEM *FileSystem;
    MEMFS_FILE_NODE_MAP *FileNodeMap;
    ULONG MaxFileNodes;
    ULONG MaxFileSize;
} MEMFS;

static inline
NTSTATUS MemfsFileNodeCreate(PWSTR FileName, MEMFS_FILE_NODE **PFileNode)
{
    static UINT64 IndexNumber = 1;
    MEMFS_FILE_NODE *FileNode;
    LARGE_INTEGER FileIndexNumber;

    *PFileNode = 0;

    if (MAX_PATH <= wcslen(FileName))
        return STATUS_OBJECT_NAME_INVALID;

    FileNode = (MEMFS_FILE_NODE *)malloc(sizeof *FileNode);
    if (0 == FileNode)
        return STATUS_INSUFFICIENT_RESOURCES;

    FileIndexNumber.QuadPart = IndexNumber++;
    memset(FileNode, 0, sizeof *FileNode);
    wcscpy_s(FileNode->FileName, sizeof FileNode->FileName / sizeof(WCHAR), FileName);
    FileNode->FileInfo.ftCreationTime =
    FileNode->FileInfo.ftLastAccessTime =
    FileNode->FileInfo.ftLastWriteTime = MemfsGetSystemTime();
    FileNode->FileInfo.nNumberOfLinks = 1;
    FileNode->FileInfo.nFileIndexLow = FileIndexNumber.LowPart;
    FileNode->FileInfo.nFileIndexHigh = FileIndexNumber.HighPart;

    *PFileNode = FileNode;

    return STATUS_SUCCESS;
}

static inline
VOID MemfsFileNodeDelete(MEMFS_FILE_NODE *FileNode)
{
    LargeHeapFree(FileNode->FileData);
    free(FileNode->FileSecurity);
    free(FileNode);
}

static inline
VOID MemfsFileNodeGetFileInfo(MEMFS_FILE_NODE *FileNode, BY_HANDLE_FILE_INFORMATION *FileInfo)
{
#if defined(MEMFS_NAMED_STREAMS)
    if (0 == FileNode->MainFileNode)
        *FileInfo = FileNode->FileInfo;
    else
    {
        *FileInfo = FileNode->MainFileNode->FileInfo;
        FileInfo->dwFileAttributes &= ~FILE_ATTRIBUTE_DIRECTORY;
            /* named streams cannot be directories */
        FileInfo->nFileSizeHigh = FileNode->FileInfo.nFileSizeHigh;
        FileInfo->nFileSizeLow = FileNode->FileInfo.nFileSizeLow;
    }
#else
    *FileInfo = FileNode->FileInfo;
#endif
}

static inline
BOOLEAN MemfsFileNodeMapIsCaseInsensitive(MEMFS_FILE_NODE_MAP *FileNodeMap)
{
    return FileNodeMap->key_comp().CaseInsensitive;
}

static inline
NTSTATUS MemfsFileNodeMapCreate(BOOLEAN CaseInsensitive, MEMFS_FILE_NODE_MAP **PFileNodeMap)
{
    *PFileNodeMap = 0;
    try
    {
        *PFileNodeMap = new MEMFS_FILE_NODE_MAP(MEMFS_FILE_NODE_LESS(CaseInsensitive));
        return STATUS_SUCCESS;
    }
    catch (...)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
}

static inline
VOID MemfsFileNodeMapDelete(MEMFS_FILE_NODE_MAP *FileNodeMap)
{
    for (MEMFS_FILE_NODE_MAP::iterator p = FileNodeMap->begin(), q = FileNodeMap->end(); p != q; ++p)
        MemfsFileNodeDelete(p->second);

    delete FileNodeMap;
}

static inline
SIZE_T MemfsFileNodeMapCount(MEMFS_FILE_NODE_MAP *FileNodeMap)
{
    return FileNodeMap->size();
}

static inline
MEMFS_FILE_NODE *MemfsFileNodeMapGet(MEMFS_FILE_NODE_MAP *FileNodeMap, PWSTR FileName)
{
    MEMFS_FILE_NODE_MAP::iterator iter = FileNodeMap->find(FileName);
    if (iter == FileNodeMap->end())
        return 0;
    return iter->second;
}

#if defined(MEMFS_NAMED_STREAMS)
static inline
MEMFS_FILE_NODE *MemfsFileNodeMapGetMain(MEMFS_FILE_NODE_MAP *FileNodeMap, PWSTR FileName0)
{
    WCHAR FileName[MAX_PATH];
    wcscpy_s(FileName, sizeof FileName / sizeof(WCHAR), FileName0);
    PWSTR StreamName = wcschr(FileName, L':');
    if (0 == StreamName)
        return 0;
    StreamName[0] = L'\0';
    MEMFS_FILE_NODE_MAP::iterator iter = FileNodeMap->find(FileName);
    if (iter == FileNodeMap->end())
        return 0;
    return iter->second;
}
#endif

static inline
MEMFS_FILE_NODE *MemfsFileNodeMapGetParent(MEMFS_FILE_NODE_MAP *FileNodeMap, PWSTR FileName0,
    PNTSTATUS PResult)
{
    WCHAR Root[2] = L"\\";
    PWSTR Remain, Suffix;
    WCHAR FileName[MAX_PATH];
    wcscpy_s(FileName, sizeof FileName / sizeof(WCHAR), FileName0);
    FspPathSuffix(FileName, &Remain, &Suffix, Root);
    MEMFS_FILE_NODE_MAP::iterator iter = FileNodeMap->find(Remain);
    FspPathCombine(FileName, Suffix);
    if (iter == FileNodeMap->end())
    {
        *PResult = STATUS_OBJECT_PATH_NOT_FOUND;
        return 0;
    }
    if (0 == (iter->second->FileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
    {
        *PResult = STATUS_NOT_A_DIRECTORY;
        return 0;
    }
    return iter->second;
}

static inline
NTSTATUS MemfsFileNodeMapInsert(MEMFS_FILE_NODE_MAP *FileNodeMap, MEMFS_FILE_NODE *FileNode,
    PBOOLEAN PInserted)
{
    *PInserted = 0;
    try
    {
        *PInserted = FileNodeMap->insert(MEMFS_FILE_NODE_MAP::value_type(FileNode->FileName, FileNode)).second;
        if (*PInserted)
            FileNode->RefCount++;
        return STATUS_SUCCESS;
    }
    catch (...)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
}

static inline
VOID MemfsFileNodeMapRemove(MEMFS_FILE_NODE_MAP *FileNodeMap, MEMFS_FILE_NODE *FileNode)
{
    if (FileNodeMap->erase(FileNode->FileName))
        --FileNode->RefCount;
}

static inline
BOOLEAN MemfsFileNodeMapHasChild(MEMFS_FILE_NODE_MAP *FileNodeMap, MEMFS_FILE_NODE *FileNode)
{
    BOOLEAN Result = FALSE;
    WCHAR Root[2] = L"\\";
    PWSTR Remain, Suffix;
    MEMFS_FILE_NODE_MAP::iterator iter = FileNodeMap->upper_bound(FileNode->FileName);
    for (; FileNodeMap->end() != iter; ++iter)
    {
#if defined(MEMFS_NAMED_STREAMS)
        if (0 != wcschr(iter->second->FileName, L':'))
            continue;
#endif
        FspPathSuffix(iter->second->FileName, &Remain, &Suffix, Root);
        Result = 0 == MemfsFileNameCompare(Remain, FileNode->FileName,
            MemfsFileNodeMapIsCaseInsensitive(FileNodeMap));
        FspPathCombine(iter->second->FileName, Suffix);
        break;
    }
    return Result;
}

static inline
BOOLEAN MemfsFileNodeMapEnumerateChildren(MEMFS_FILE_NODE_MAP *FileNodeMap, MEMFS_FILE_NODE *FileNode,
    BOOLEAN (*EnumFn)(MEMFS_FILE_NODE *, PVOID), PVOID Context)
{
    WCHAR Root[2] = L"\\";
    PWSTR Remain, Suffix;
    MEMFS_FILE_NODE_MAP::iterator iter = FileNodeMap->upper_bound(FileNode->FileName);
    BOOLEAN IsDirectoryChild;
    for (; FileNodeMap->end() != iter; ++iter)
    {
        if (!MemfsFileNameHasPrefix(iter->second->FileName, FileNode->FileName,
            MemfsFileNodeMapIsCaseInsensitive(FileNodeMap)))
            break;
        FspPathSuffix(iter->second->FileName, &Remain, &Suffix, Root);
        IsDirectoryChild = 0 == MemfsFileNameCompare(Remain, FileNode->FileName,
            MemfsFileNodeMapIsCaseInsensitive(FileNodeMap));
#if defined(MEMFS_NAMED_STREAMS)
        IsDirectoryChild = IsDirectoryChild && 0 == wcschr(Suffix, L':');
#endif
        FspPathCombine(iter->second->FileName, Suffix);
        if (IsDirectoryChild)
        {
            if (!EnumFn(iter->second, Context))
                return FALSE;
        }
    }
    return TRUE;
}

#if defined(MEMFS_NAMED_STREAMS)
static inline
BOOLEAN MemfsFileNodeMapEnumerateNamedStreams(MEMFS_FILE_NODE_MAP *FileNodeMap, MEMFS_FILE_NODE *FileNode,
    BOOLEAN (*EnumFn)(MEMFS_FILE_NODE *, PVOID), PVOID Context)
{
    MEMFS_FILE_NODE_MAP::iterator iter = FileNodeMap->upper_bound(FileNode->FileName);
    for (; FileNodeMap->end() != iter; ++iter)
    {
        if (!MemfsFileNameHasPrefix(iter->second->FileName, FileNode->FileName,
            MemfsFileNodeMapIsCaseInsensitive(FileNodeMap)))
            break;
        if (L':' != iter->second->FileName[wcslen(FileNode->FileName)])
            break;
        if (!EnumFn(iter->second, Context))
            return FALSE;
    }
    return TRUE;
}
#endif

static inline
BOOLEAN MemfsFileNodeMapEnumerateDescendants(MEMFS_FILE_NODE_MAP *FileNodeMap, MEMFS_FILE_NODE *FileNode,
    BOOLEAN (*EnumFn)(MEMFS_FILE_NODE *, PVOID), PVOID Context)
{
    WCHAR Root[2] = L"\\";
    MEMFS_FILE_NODE_MAP::iterator iter = FileNodeMap->lower_bound(FileNode->FileName);
    for (; FileNodeMap->end() != iter; ++iter)
    {
        if (!MemfsFileNameHasPrefix(iter->second->FileName, FileNode->FileName,
            MemfsFileNodeMapIsCaseInsensitive(FileNodeMap)))
            break;
        if (!EnumFn(iter->second, Context))
            return FALSE;
    }
    return TRUE;
}

/*
 * DOKAN_OPERATIONS
 */

NTSTATUS DOKAN_CALLBACK MySetEndOfFile(LPCWSTR FileName,
    LONGLONG NewSize,
    PDOKAN_FILE_INFO DokanFileInfo);
NTSTATUS DOKAN_CALLBACK MySetAllocationSize(LPCWSTR FileName,
    LONGLONG NewSize,
    PDOKAN_FILE_INFO DokanFileInfo);

NTSTATUS DOKAN_CALLBACK MyGetDiskFreeSpace(PULONGLONG FreeBytesAvailable,
    PULONGLONG TotalNumberOfBytes,
    PULONGLONG TotalNumberOfFreeBytes,
    PDOKAN_FILE_INFO DokanFileInfo)
{
    MEMFS *Memfs = (MEMFS *)(UINT_PTR)DokanFileInfo->DokanOptions->GlobalContext;

    *TotalNumberOfBytes = Memfs->MaxFileNodes * (UINT64)Memfs->MaxFileSize;
    *FreeBytesAvailable = *TotalNumberOfFreeBytes =
        (Memfs->MaxFileNodes - MemfsFileNodeMapCount(Memfs->FileNodeMap)) * (UINT64)Memfs->MaxFileSize;

    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK MyGetVolumeInformation(LPWSTR VolumeNameBuffer,
    DWORD VolumeNameSize,
    LPDWORD VolumeSerialNumber,
    LPDWORD MaximumComponentLength,
    LPDWORD FileSystemFlags,
    LPWSTR FileSystemNameBuffer,
    DWORD FileSystemNameSize,
    PDOKAN_FILE_INFO DokanFileInfo)
{
    MEMFS *Memfs = (MEMFS *)(UINT_PTR)DokanFileInfo->DokanOptions->GlobalContext;

    VolumeNameBuffer[0] = L'\0';
    *VolumeSerialNumber = 0;
    *MaximumComponentLength = 255;
    *FileSystemFlags =
        (MemfsFileNodeMapIsCaseInsensitive(Memfs->FileNodeMap) ? FILE_CASE_SENSITIVE_SEARCH : 0) |
        FILE_CASE_PRESERVED_NAMES |
        FILE_UNICODE_ON_DISK;
    FileSystemNameBuffer[0] = L'\0';

    return STATUS_SUCCESS;
}

static NTSTATUS Create(PDOKAN_FILE_INFO DokanFileInfo,
    PWSTR FileName, UINT32 CreateOptions, UINT32 GrantedAccess,
    UINT32 FileAttributes, PSECURITY_DESCRIPTOR SecurityDescriptor, UINT64 AllocationSize,
    PVOID *PFileNode, BY_HANDLE_FILE_INFORMATION *FileInfo)
{
    MEMFS *Memfs = (MEMFS *)(UINT_PTR)DokanFileInfo->DokanOptions->GlobalContext;
#if defined(MEMFS_NAME_NORMALIZATION)
    WCHAR FileNameBuf[MAX_PATH];
#endif
    MEMFS_FILE_NODE *FileNode;
    MEMFS_FILE_NODE *ParentNode;
    NTSTATUS Result;
    BOOLEAN Inserted;

    if (CreateOptions & FILE_DIRECTORY_FILE)
        AllocationSize = 0;

    FileNode = MemfsFileNodeMapGet(Memfs->FileNodeMap, FileName);
    if (0 != FileNode)
        return STATUS_OBJECT_NAME_COLLISION;

    ParentNode = MemfsFileNodeMapGetParent(Memfs->FileNodeMap, FileName, &Result);
    if (0 == ParentNode)
        return Result;

    if (MemfsFileNodeMapCount(Memfs->FileNodeMap) >= Memfs->MaxFileNodes)
        return STATUS_CANNOT_MAKE;

    if (AllocationSize > Memfs->MaxFileSize)
        return STATUS_DISK_FULL;

#if defined(MEMFS_NAME_NORMALIZATION)
    if (MemfsFileNodeMapIsCaseInsensitive(Memfs->FileNodeMap))
    {
        WCHAR Root[2] = L"\\";
        PWSTR Remain, Suffix;
        size_t RemainLength, BSlashLength, SuffixLength;

        FspPathSuffix(FileName, &Remain, &Suffix, Root);
        assert(0 == MemfsCompareString(Remain, -1, ParentNode->FileName, -1, TRUE));
        FspPathCombine(FileName, Suffix);

        RemainLength = wcslen(ParentNode->FileName);
        BSlashLength = 1 < RemainLength;
        SuffixLength = wcslen(Suffix);
        if (MAX_PATH <= RemainLength + BSlashLength + SuffixLength)
            return STATUS_OBJECT_NAME_INVALID;

        memcpy(FileNameBuf, ParentNode->FileName, RemainLength * sizeof(WCHAR));
        memcpy(FileNameBuf + RemainLength, L"\\", BSlashLength * sizeof(WCHAR));
        memcpy(FileNameBuf + RemainLength + BSlashLength, Suffix, (SuffixLength + 1) * sizeof(WCHAR));

        FileName = FileNameBuf;
    }
#endif

    Result = MemfsFileNodeCreate(FileName, &FileNode);
    if (!NT_SUCCESS(Result))
        return Result;

#if defined(MEMFS_NAMED_STREAMS)
    FileNode->MainFileNode = MemfsFileNodeMapGetMain(Memfs->FileNodeMap, FileName);
#endif

    FileNode->FileInfo.dwFileAttributes = (FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ?
        FileAttributes : FileAttributes | FILE_ATTRIBUTE_ARCHIVE;

    if (0 != SecurityDescriptor)
    {
        FileNode->FileSecuritySize = GetSecurityDescriptorLength(SecurityDescriptor);
        FileNode->FileSecurity = (PSECURITY_DESCRIPTOR)malloc(FileNode->FileSecuritySize);
        if (0 == FileNode->FileSecurity)
        {
            MemfsFileNodeDelete(FileNode);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        memcpy(FileNode->FileSecurity, SecurityDescriptor, FileNode->FileSecuritySize);
    }

#if 0
    FileNode->FileInfo.AllocationSize = AllocationSize;
    if (0 != FileNode->FileInfo.AllocationSize)
    {
        FileNode->FileData = LargeHeapAlloc((size_t)FileNode->FileInfo.AllocationSize);
        if (0 == FileNode->FileData)
        {
            MemfsFileNodeDelete(FileNode);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
#endif

    Result = MemfsFileNodeMapInsert(Memfs->FileNodeMap, FileNode, &Inserted);
    if (!NT_SUCCESS(Result) || !Inserted)
    {
        MemfsFileNodeDelete(FileNode);
        if (NT_SUCCESS(Result))
            Result = STATUS_OBJECT_NAME_COLLISION; /* should not happen! */
        return Result;
    }

    FileNode->RefCount++;
    *PFileNode = FileNode;
    MemfsFileNodeGetFileInfo(FileNode, FileInfo);

#if defined(MEMFS_NAME_NORMALIZATION)
    if (MemfsFileNodeMapIsCaseInsensitive(Memfs->FileNodeMap))
    {
        FSP_FSCTL_OPEN_FILE_INFO *OpenFileInfo = FspFileSystemGetOpenFileInfo(FileInfo);

        wcscpy_s(OpenFileInfo->NormalizedName, OpenFileInfo->NormalizedNameSize / sizeof(WCHAR),
            FileNode->FileName);
        OpenFileInfo->NormalizedNameSize = (UINT16)(wcslen(FileNode->FileName) * sizeof(WCHAR));
    }
#endif

    return STATUS_SUCCESS;
}

static NTSTATUS Open(PDOKAN_FILE_INFO DokanFileInfo,
    PWSTR FileName, UINT32 CreateOptions, UINT32 GrantedAccess,
    PVOID *PFileNode, BY_HANDLE_FILE_INFORMATION *FileInfo)
{
    MEMFS *Memfs = (MEMFS *)(UINT_PTR)DokanFileInfo->DokanOptions->GlobalContext;
    MEMFS_FILE_NODE *FileNode;
    NTSTATUS Result;

    FileNode = MemfsFileNodeMapGet(Memfs->FileNodeMap, FileName);
    if (0 == FileNode)
    {
        Result = STATUS_OBJECT_NAME_NOT_FOUND;
        MemfsFileNodeMapGetParent(Memfs->FileNodeMap, FileName, &Result);
        return Result;
    }

    /*
     * NTFS and FastFat do this at Cleanup time, but we are going to cheat.
     *
     * To properly implement this we should maintain some state of whether
     * we modified the file or not. Alternatively we could have the driver
     * report to us at Cleanup time whether the file was modified. [The
     * FSD does maintain the FO_FILE_MODIFIED bit, but does not send it
     * to us.]
     *
     * TBD.
     */
    if (0 == (FileNode->FileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
        (GrantedAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA)))
        FileNode->FileInfo.dwFileAttributes |= FILE_ATTRIBUTE_ARCHIVE;

    FileNode->RefCount++;
    *PFileNode = FileNode;
    MemfsFileNodeGetFileInfo(FileNode, FileInfo);

#if defined(MEMFS_NAME_NORMALIZATION)
    if (MemfsFileNodeMapIsCaseInsensitive(Memfs->FileNodeMap))
    {
        FSP_FSCTL_OPEN_FILE_INFO *OpenFileInfo = FspFileSystemGetOpenFileInfo(FileInfo);

        wcscpy_s(OpenFileInfo->NormalizedName, OpenFileInfo->NormalizedNameSize / sizeof(WCHAR),
            FileNode->FileName);
        OpenFileInfo->NormalizedNameSize = (UINT16)(wcslen(FileNode->FileName) * sizeof(WCHAR));
    }
#endif

    return STATUS_SUCCESS;
}

static NTSTATUS Overwrite(PDOKAN_FILE_INFO DokanFileInfo,
    PVOID FileNode0, UINT32 FileAttributes, BOOLEAN ReplaceFileAttributes,
    BY_HANDLE_FILE_INFORMATION *FileInfo)
{
    MEMFS *Memfs = (MEMFS *)(UINT_PTR)DokanFileInfo->DokanOptions->GlobalContext;
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)FileNode0;

    if (ReplaceFileAttributes)
        FileNode->FileInfo.dwFileAttributes = FileAttributes | FILE_ATTRIBUTE_ARCHIVE;
    else
        FileNode->FileInfo.dwFileAttributes |= FileAttributes | FILE_ATTRIBUTE_ARCHIVE;

    FileNode->FileInfo.nFileSizeHigh =
    FileNode->FileInfo.nFileSizeLow = 0;
    FileNode->FileInfo.ftLastWriteTime =
    FileNode->FileInfo.ftLastAccessTime = MemfsGetSystemTime();

    MemfsFileNodeGetFileInfo(FileNode, FileInfo);

    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK MyCreateFile(LPCWSTR FileName0,
    PDOKAN_IO_SECURITY_CONTEXT SecurityContext,
    ACCESS_MASK DesiredAccess,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PDOKAN_FILE_INFO DokanFileInfo)
{
    NTSTATUS Result;
    WCHAR FileName[MAX_PATH];
    PVOID FileNode;
    BY_HANDLE_FILE_INFORMATION FileInfo;

    wcscpy_s(FileName, sizeof FileName / sizeof(WCHAR), FileName0);

    switch (CreateDisposition)
    {
    case FILE_CREATE:
        Result = Create(DokanFileInfo,
            FileName, CreateOptions, DesiredAccess, FileAttributes, 0, 0, &FileNode, &FileInfo);
        break;
    case FILE_OPEN:
        Result = Open(DokanFileInfo,
            FileName, CreateOptions, DesiredAccess, &FileNode, &FileInfo);
        break;
    case FILE_OPEN_IF:
        Result = Open(DokanFileInfo,
            FileName, CreateOptions, DesiredAccess, &FileNode, &FileInfo);
        if (STATUS_OBJECT_NAME_NOT_FOUND == Result)
            Result = Create(DokanFileInfo,
                FileName, CreateOptions, DesiredAccess, FileAttributes, 0, 0, &FileNode, &FileInfo);
        break;
    case FILE_OVERWRITE:
    case FILE_SUPERSEDE:
        Result = Open(DokanFileInfo,
            FileName, CreateOptions, DesiredAccess, &FileNode, &FileInfo);
        if (NT_SUCCESS(Result))
            Result = Overwrite(DokanFileInfo, FileNode, FileAttributes,
                FILE_SUPERSEDE == CreateDisposition, &FileInfo);
        break;
    case FILE_OVERWRITE_IF:
        Result = Open(DokanFileInfo,
            FileName, CreateOptions, DesiredAccess, &FileNode, &FileInfo);
        if (NT_SUCCESS(Result))
            Result = Overwrite(DokanFileInfo, FileNode, FileAttributes,
                FILE_SUPERSEDE == CreateDisposition, &FileInfo);
        else if (STATUS_OBJECT_NAME_NOT_FOUND == Result)
            Result = Create(DokanFileInfo,
                FileName, CreateOptions, DesiredAccess, FileAttributes, 0, 0, &FileNode, &FileInfo);
        break;
    default:
        Result = STATUS_INVALID_PARAMETER;
        break;
    }

    if (NT_SUCCESS(Result))
        DokanFileInfo->Context = (UINT_PTR)FileNode;

    return Result;
}

#if defined(MEMFS_NAMED_STREAMS)
typedef struct _MEMFS_CLEANUP_CONTEXT
{
    MEMFS_FILE_NODE **FileNodes;
    ULONG Count;
} MEMFS_CLEANUP_CONTEXT;

static BOOLEAN CleanupEnumFn(MEMFS_FILE_NODE *FileNode, PVOID Context0)
{
    MEMFS_CLEANUP_CONTEXT *Context = (MEMFS_CLEANUP_CONTEXT *)Context0;

    Context->FileNodes[Context->Count++] = FileNode;

    return TRUE;
}
#endif

void DOKAN_CALLBACK MyCleanup(LPCWSTR FileName,
    PDOKAN_FILE_INFO DokanFileInfo)
{
    MEMFS *Memfs = (MEMFS *)(UINT_PTR)DokanFileInfo->DokanOptions->GlobalContext;
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)(UINT_PTR)DokanFileInfo->Context;

    if (DokanFileInfo->DeleteOnClose && !MemfsFileNodeMapHasChild(Memfs->FileNodeMap, FileNode))
    {
#if defined(MEMFS_NAMED_STREAMS)
        MEMFS_CLEANUP_CONTEXT Context = { 0 };
        ULONG Index;

        Context.FileNodes = (MEMFS_FILE_NODE **)malloc(Memfs->MaxFileNodes * sizeof Context.FileNodes[0]);
        if (0 != Context.FileNodes)
        {
            MemfsFileNodeMapEnumerateNamedStreams(Memfs->FileNodeMap, FileNode, CleanupEnumFn, &Context);
            for (Index = 0; Context.Count > Index; Index++)
                MemfsFileNodeMapRemove(Memfs->FileNodeMap, Context.FileNodes[Index]);
            free(Context.FileNodes);
        }
#endif

        MemfsFileNodeMapRemove(Memfs->FileNodeMap, FileNode);
    }
}

void DOKAN_CALLBACK MyCloseFile(LPCWSTR FileName,
    PDOKAN_FILE_INFO DokanFileInfo)
{
    MEMFS *Memfs = (MEMFS *)(UINT_PTR)DokanFileInfo->DokanOptions->GlobalContext;
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)(UINT_PTR)DokanFileInfo->Context;

    if (0 == --FileNode->RefCount)
        MemfsFileNodeDelete(FileNode);
}

NTSTATUS DOKAN_CALLBACK MyReadFile(LPCWSTR FileName,
    LPVOID Buffer,
    DWORD Length,
    LPDWORD PBytesTransferred,
    LONGLONG Offset,
    PDOKAN_FILE_INFO DokanFileInfo)
{
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)(UINT_PTR)DokanFileInfo->Context;
    UINT64 EndOffset;

    if (Offset >= FileNode->FileInfo.nFileSizeLow)
        return STATUS_END_OF_FILE;

    EndOffset = Offset + Length;
    if (EndOffset > FileNode->FileInfo.nFileSizeLow)
        EndOffset = FileNode->FileInfo.nFileSizeLow;

    memcpy(Buffer, (PUINT8)FileNode->FileData + Offset, (size_t)(EndOffset - Offset));

    *PBytesTransferred = (ULONG)(EndOffset - Offset);

    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK MyWriteFile(LPCWSTR FileName,
    LPCVOID Buffer,
    DWORD Length,
    LPDWORD PBytesTransferred,
    LONGLONG Offset,
    PDOKAN_FILE_INFO DokanFileInfo)
{
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)(UINT_PTR)DokanFileInfo->Context;
    UINT64 EndOffset;

    if (DokanFileInfo->PagingIo)
    {
        if (Offset >= FileNode->FileInfo.nFileSizeLow)
            return STATUS_SUCCESS;
        EndOffset = Offset + Length;
        if (EndOffset > FileNode->FileInfo.nFileSizeLow)
            EndOffset = FileNode->FileInfo.nFileSizeLow;
    }
    else
    {
        if (DokanFileInfo->WriteToEndOfFile)
            Offset = FileNode->FileInfo.nFileSizeLow;
        EndOffset = Offset + Length;
        if (EndOffset > FileNode->FileInfo.nFileSizeLow)
            MySetEndOfFile(FileName, EndOffset, DokanFileInfo);
    }

    memcpy((PUINT8)FileNode->FileData + Offset, Buffer, (size_t)(EndOffset - Offset));

    *PBytesTransferred = (ULONG)(EndOffset - Offset);

    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK MyFlushFileBuffers(LPCWSTR FileName,
    PDOKAN_FILE_INFO DokanFileInfo)
{
    /* nothing to do, since we do not cache anything */
    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK MyGetFileInformation(LPCWSTR FileName,
    LPBY_HANDLE_FILE_INFORMATION FileInfo,
    PDOKAN_FILE_INFO DokanFileInfo)
{
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)(UINT_PTR)DokanFileInfo->Context;

    MemfsFileNodeGetFileInfo(FileNode, FileInfo);

    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK MySetFileAttributes(LPCWSTR FileName,
    DWORD FileAttributes,
    PDOKAN_FILE_INFO DokanFileInfo)
{
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)(UINT_PTR)DokanFileInfo->Context;

#if defined(MEMFS_NAMED_STREAMS)
    if (0 != FileNode->MainFileNode)
        FileNode = FileNode->MainFileNode;
#endif

    if (INVALID_FILE_ATTRIBUTES != FileAttributes)
        FileNode->FileInfo.dwFileAttributes = FileAttributes;

    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK MySetFileTime(LPCWSTR FileName,
    CONST FILETIME *CreationTime,
    CONST FILETIME *LastAccessTime,
    CONST FILETIME *LastWriteTime,
    PDOKAN_FILE_INFO DokanFileInfo)
{
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)(UINT_PTR)DokanFileInfo->Context;

#if defined(MEMFS_NAMED_STREAMS)
    if (0 != FileNode->MainFileNode)
        FileNode = FileNode->MainFileNode;
#endif

    if (0 != CreationTime)
        FileNode->FileInfo.ftCreationTime = *CreationTime;
    if (0 != LastAccessTime)
        FileNode->FileInfo.ftLastAccessTime = *LastAccessTime;
    if (0 != LastWriteTime)
        FileNode->FileInfo.ftLastWriteTime = *LastWriteTime;

    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK MySetEndOfFile(LPCWSTR FileName,
    LONGLONG NewSize,
    PDOKAN_FILE_INFO DokanFileInfo)
{
    MEMFS *Memfs = (MEMFS *)(UINT_PTR)DokanFileInfo->DokanOptions->GlobalContext;
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)(UINT_PTR)DokanFileInfo->Context;
    UINT64 AllocationUnit = MEMFS_SECTOR_SIZE * MEMFS_SECTORS_PER_ALLOCATION_UNIT;
    LONGLONG AllocationSize = (FileNode->FileInfo.nFileSizeLow + AllocationUnit - 1) /
        AllocationUnit * AllocationUnit;

    if (FileNode->FileInfo.nFileSizeLow != NewSize)
    {
        if (AllocationSize < NewSize)
        {
            AllocationSize = (NewSize + AllocationUnit - 1) / AllocationUnit * AllocationUnit;

            NTSTATUS Result = MySetAllocationSize(FileName, NewSize, DokanFileInfo);
            if (!NT_SUCCESS(Result))
                return Result;
        }

        if (FileNode->FileInfo.nFileSizeLow < NewSize)
            memset((PUINT8)FileNode->FileData + FileNode->FileInfo.nFileSizeLow, 0,
                (size_t)(NewSize - FileNode->FileInfo.nFileSizeLow));
        FileNode->FileInfo.nFileSizeLow = (DWORD)NewSize;
    }

    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK MySetAllocationSize(LPCWSTR FileName,
    LONGLONG NewSize,
    PDOKAN_FILE_INFO DokanFileInfo)
{
    MEMFS *Memfs = (MEMFS *)(UINT_PTR)DokanFileInfo->DokanOptions->GlobalContext;
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)(UINT_PTR)DokanFileInfo->Context;
    UINT64 AllocationUnit = MEMFS_SECTOR_SIZE * MEMFS_SECTORS_PER_ALLOCATION_UNIT;
    LONGLONG AllocationSize = (FileNode->FileInfo.nFileSizeLow + AllocationUnit - 1) /
        AllocationUnit * AllocationUnit;

    if (AllocationSize != NewSize)
    {
        if (NewSize > Memfs->MaxFileSize)
            return STATUS_DISK_FULL;

        PVOID FileData = LargeHeapRealloc(FileNode->FileData, (size_t)NewSize);
        if (0 == FileData && 0 != NewSize)
            return STATUS_INSUFFICIENT_RESOURCES;

        FileNode->FileData = FileData;

        if (FileNode->FileInfo.nFileSizeLow > NewSize)
            FileNode->FileInfo.nFileSizeLow = (DWORD)NewSize;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS CanDelete(PDOKAN_FILE_INFO DokanFileInfo,
    PVOID FileNode0, PWSTR FileName)
{
    MEMFS *Memfs = (MEMFS *)(UINT_PTR)DokanFileInfo->DokanOptions->GlobalContext;
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)FileNode0;

    if (MemfsFileNodeMapHasChild(Memfs->FileNodeMap, FileNode))
        return STATUS_DIRECTORY_NOT_EMPTY;

    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK MyDeleteFile(LPCWSTR FileName0,
    PDOKAN_FILE_INFO DokanFileInfo)
{
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)(UINT_PTR)DokanFileInfo->Context;
    WCHAR FileName[MAX_PATH];

    wcscpy_s(FileName, sizeof FileName / sizeof(WCHAR), FileName0);

    return CanDelete(DokanFileInfo, FileNode, FileName);
}

NTSTATUS DOKAN_CALLBACK MyDeleteDirectory(LPCWSTR FileName0,
    PDOKAN_FILE_INFO DokanFileInfo)
{
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)(UINT_PTR)DokanFileInfo->Context;
    WCHAR FileName[MAX_PATH];

    wcscpy_s(FileName, sizeof FileName / sizeof(WCHAR), FileName0);

    return CanDelete(DokanFileInfo, FileNode, FileName);
}

typedef struct _MEMFS_RENAME_CONTEXT
{
    MEMFS_FILE_NODE **FileNodes;
    ULONG Count;
} MEMFS_RENAME_CONTEXT;

static BOOLEAN RenameEnumFn(MEMFS_FILE_NODE *FileNode, PVOID Context0)
{
    MEMFS_RENAME_CONTEXT *Context = (MEMFS_RENAME_CONTEXT *)Context0;

    Context->FileNodes[Context->Count++] = FileNode;
    FileNode->RefCount++;

    return TRUE;
}

NTSTATUS DOKAN_CALLBACK MyMoveFile(LPCWSTR FileName,
    LPCWSTR NewFileName0,
    BOOL ReplaceIfExists,
    PDOKAN_FILE_INFO DokanFileInfo)
{
    MEMFS *Memfs = (MEMFS *)(UINT_PTR)DokanFileInfo->DokanOptions->GlobalContext;
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)(UINT_PTR)DokanFileInfo->Context;
    MEMFS_FILE_NODE *NewFileNode, *DescendantFileNode;
    MEMFS_RENAME_CONTEXT Context = { 0 };
    ULONG Index, FileNameLen, NewFileNameLen;
    BOOLEAN Inserted;
    NTSTATUS Result;
    WCHAR NewFileName[MAX_PATH];

    wcscpy_s(NewFileName, sizeof NewFileName / sizeof(WCHAR), NewFileName0);

    NewFileNode = MemfsFileNodeMapGet(Memfs->FileNodeMap, NewFileName);
    if (0 != NewFileNode && FileNode != NewFileNode)
    {
        if (!ReplaceIfExists)
        {
            Result = STATUS_OBJECT_NAME_COLLISION;
            goto exit;
        }

        if (NewFileNode->FileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            Result = STATUS_ACCESS_DENIED;
            goto exit;
        }
    }

    Context.FileNodes = (MEMFS_FILE_NODE **)malloc(Memfs->MaxFileNodes * sizeof Context.FileNodes[0]);
    if (0 == Context.FileNodes)
    {
        Result = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }

    MemfsFileNodeMapEnumerateDescendants(Memfs->FileNodeMap, FileNode, RenameEnumFn, &Context);

    FileNameLen = (ULONG)wcslen(FileNode->FileName);
    NewFileNameLen = (ULONG)wcslen(NewFileName);
    for (Index = 0; Context.Count > Index; Index++)
    {
        DescendantFileNode = Context.FileNodes[Index];
        if (MAX_PATH <= wcslen(DescendantFileNode->FileName) - FileNameLen + NewFileNameLen)
        {
            Result = STATUS_OBJECT_NAME_INVALID;
            goto exit;
        }
    }

    if (0 != NewFileNode)
    {
        NewFileNode->RefCount++;
        MemfsFileNodeMapRemove(Memfs->FileNodeMap, NewFileNode);
        if (0 == --NewFileNode->RefCount)
            MemfsFileNodeDelete(NewFileNode);
    }

    for (Index = 0; Context.Count > Index; Index++)
    {
        DescendantFileNode = Context.FileNodes[Index];
        MemfsFileNodeMapRemove(Memfs->FileNodeMap, DescendantFileNode);
        memmove(DescendantFileNode->FileName + NewFileNameLen,
            DescendantFileNode->FileName + FileNameLen,
            (wcslen(DescendantFileNode->FileName) + 1 - FileNameLen) * sizeof(WCHAR));
        memcpy(DescendantFileNode->FileName, NewFileName, NewFileNameLen * sizeof(WCHAR));
        Result = MemfsFileNodeMapInsert(Memfs->FileNodeMap, DescendantFileNode, &Inserted);
        if (!NT_SUCCESS(Result))
        {
            OutputDebugStringA(__FUNCTION__ ": cannot insert into FileNodeMap; aborting\n");
            abort();
        }
        assert(Inserted);
    }

    Result = STATUS_SUCCESS;

exit:
    for (Index = 0; Context.Count > Index; Index++)
    {
        DescendantFileNode = Context.FileNodes[Index];
        DescendantFileNode->RefCount--;
    }
    free(Context.FileNodes);

    return Result;
}

typedef struct _MEMFS_READ_DIRECTORY_CONTEXT
{
    PFillFindData FillFindData;
    PDOKAN_FILE_INFO DokanFileInfo;
} MEMFS_READ_DIRECTORY_CONTEXT;

static BOOLEAN AddDirInfo(MEMFS_FILE_NODE *FileNode, PWSTR FileName,
    PFillFindData FillFindData,
    PDOKAN_FILE_INFO DokanFileInfo)
{
    WIN32_FIND_DATAW DirInfo;
    WCHAR Root[2] = L"\\";
    PWSTR Remain, Suffix;

    if (0 == FileName)
    {
        FspPathSuffix(FileNode->FileName, &Remain, &Suffix, Root);
        FileName = Suffix;
        FspPathCombine(FileNode->FileName, Suffix);
    }

    memset(&DirInfo, 0, sizeof DirInfo);
    DirInfo.dwFileAttributes = FileNode->FileInfo.dwFileAttributes;
    DirInfo.ftCreationTime = FileNode->FileInfo.ftCreationTime;
    DirInfo.ftLastAccessTime = FileNode->FileInfo.ftLastAccessTime;
    DirInfo.ftLastWriteTime = FileNode->FileInfo.ftLastWriteTime;
    DirInfo.nFileSizeHigh = FileNode->FileInfo.nFileSizeHigh;
    DirInfo.nFileSizeLow = FileNode->FileInfo.nFileSizeLow;
    wcscpy_s(DirInfo.cFileName, sizeof DirInfo.cFileName / sizeof(WCHAR), FileName);
    DirInfo.cAlternateFileName[0] = L'\0';

    return 0 == FillFindData(&DirInfo, DokanFileInfo);
}

static BOOLEAN ReadDirectoryEnumFn(MEMFS_FILE_NODE *FileNode, PVOID Context0)
{
    MEMFS_READ_DIRECTORY_CONTEXT *Context = (MEMFS_READ_DIRECTORY_CONTEXT *)Context0;

    return AddDirInfo(FileNode, 0, Context->FillFindData, Context->DokanFileInfo);
}

NTSTATUS DOKAN_CALLBACK MyFindFiles(LPCWSTR FileName,
    PFillFindData FillFindData,
    PDOKAN_FILE_INFO DokanFileInfo)
{
    MEMFS *Memfs = (MEMFS *)(UINT_PTR)DokanFileInfo->DokanOptions->GlobalContext;
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)(UINT_PTR)DokanFileInfo->Context;
    MEMFS_FILE_NODE *ParentNode;
    MEMFS_READ_DIRECTORY_CONTEXT Context;
    NTSTATUS Result;

    ParentNode = MemfsFileNodeMapGetParent(Memfs->FileNodeMap, FileNode->FileName, &Result);
    if (0 == ParentNode)
        return Result;

    Context.FillFindData = FillFindData;
    Context.DokanFileInfo = DokanFileInfo;

    if (L'\0' != FileNode->FileName[1])
    {
        if (!AddDirInfo(FileNode, L".", FillFindData, DokanFileInfo))
            return STATUS_SUCCESS;
        if (!AddDirInfo(ParentNode, L"..", FillFindData, DokanFileInfo))
            return STATUS_SUCCESS;
    }

    MemfsFileNodeMapEnumerateChildren(Memfs->FileNodeMap, FileNode, ReadDirectoryEnumFn, &Context);

    return STATUS_SUCCESS;
}

#if 0
NTSTATUS DOKAN_CALLBACK MyFindFilesWithPattern(LPCWSTR PathName,
    LPCWSTR SearchPattern,
    PFillFindData FillFindData,
    PDOKAN_FILE_INFO DokanFileInfo)
{
    return STATUS_INVALID_DEVICE_REQUEST;
}
#endif

#if 0
NTSTATUS DOKAN_CALLBACK MyLockFile(LPCWSTR FileName,
    LONGLONG ByteOffset,
    LONGLONG Length,
    PDOKAN_FILE_INFO DokanFileInfo)
{
    return STATUS_INVALID_DEVICE_REQUEST;
}
#endif

#if 0
NTSTATUS DOKAN_CALLBACK MyUnlockFile(LPCWSTR FileName,
    LONGLONG ByteOffset,
    LONGLONG Length,
    PDOKAN_FILE_INFO DokanFileInfo)
{
    return STATUS_INVALID_DEVICE_REQUEST;
}
#endif

#if 0
NTSTATUS DOKAN_CALLBACK MyMounted(PDOKAN_FILE_INFO DokanFileInfo)
{
    return STATUS_INVALID_DEVICE_REQUEST;
}
#endif

#if 0
NTSTATUS DOKAN_CALLBACK MyUnmounted(PDOKAN_FILE_INFO DokanFileInfo)
{
    return STATUS_INVALID_DEVICE_REQUEST;
}
#endif

#if 0
NTSTATUS DOKAN_CALLBACK MyGetFileSecurity(LPCWSTR FileName,
    PSECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    ULONG BufferLength,
    PULONG LengthNeeded,
    PDOKAN_FILE_INFO DokanFileInfo)
{
    return STATUS_INVALID_DEVICE_REQUEST;
}
#endif

#if 0
NTSTATUS DOKAN_CALLBACK MySetFileSecurity(LPCWSTR FileName,
    PSECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    ULONG BufferLength,
    PDOKAN_FILE_INFO DokanFileInfo)
{
    return STATUS_INVALID_DEVICE_REQUEST;
}
#endif

#if 0
NTSTATUS DOKAN_CALLBACK MyFindStreams(LPCWSTR FileName,
    PFillFindStreamData FillFindStreamData,
    PDOKAN_FILE_INFO DokanFileInfo)
{
    return STATUS_INVALID_DEVICE_REQUEST;
}
#endif

static DOKAN_OPERATIONS MyOperations =
{
    MyCreateFile,
    MyCleanup,
    MyCloseFile,
    MyReadFile,
    MyWriteFile,
    MyFlushFileBuffers,
    MyGetFileInformation,
    MyFindFiles,
    0, //MyFindFilesWithPattern,
    MySetFileAttributes,
    MySetFileTime,
    MyDeleteFile,
    MyDeleteDirectory,
    MyMoveFile,
    MySetEndOfFile,
    MySetAllocationSize,
    0,//MyLockFile,
    0,//MyUnlockFile,
    MyGetDiskFreeSpace,
    MyGetVolumeInformation,
    0,//MyMounted,
    0,//MyUnmounted,
    0,//MyGetFileSecurity,
    0,//MySetFileSecurity,
#if defined(MEMFS_NAMED_STREAMS)
    0,//MyFindStreams,
#else
    0,
#endif
};

NTSTATUS MemfsCreate(
    ULONG Flags,
    ULONG MaxFileNodes,
    ULONG MaxFileSize,
    MEMFS **PMemfs)
{
    NTSTATUS Result;
    BOOLEAN CaseInsensitive = !!(Flags & MemfsCaseInsensitive);
    UINT64 AllocationUnit;
    MEMFS *Memfs;
    MEMFS_FILE_NODE *RootNode;
    BOOLEAN Inserted;

    *PMemfs = 0;

    Result = MemfsHeapConfigure(0, 0, 0);
    if (!NT_SUCCESS(Result))
        return Result;

    Memfs = (MEMFS *)malloc(sizeof *Memfs);
    if (0 == Memfs)
        return STATUS_INSUFFICIENT_RESOURCES;

    memset(Memfs, 0, sizeof *Memfs);
    Memfs->MaxFileNodes = MaxFileNodes;
    AllocationUnit = MEMFS_SECTOR_SIZE * MEMFS_SECTORS_PER_ALLOCATION_UNIT;
    Memfs->MaxFileSize = (ULONG)((MaxFileSize + AllocationUnit - 1) / AllocationUnit * AllocationUnit);

    Result = MemfsFileNodeMapCreate(CaseInsensitive, &Memfs->FileNodeMap);
    if (!NT_SUCCESS(Result))
    {
        free(Memfs);
        return Result;
    }

    /*
     * Create root directory.
     */

    Result = MemfsFileNodeCreate(L"\\", &RootNode);
    if (!NT_SUCCESS(Result))
    {
        MemfsDelete(Memfs);
        return Result;
    }

    RootNode->FileInfo.dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;

    Result = MemfsFileNodeMapInsert(Memfs->FileNodeMap, RootNode, &Inserted);
    if (!NT_SUCCESS(Result))
    {
        MemfsFileNodeDelete(RootNode);
        MemfsDelete(Memfs);
        return Result;
    }

    return STATUS_SUCCESS;
}

VOID MemfsDelete(MEMFS *Memfs)
{
    MemfsFileNodeMapDelete(Memfs->FileNodeMap);

    free(Memfs);
}

NTSTATUS MemfsRun(MEMFS *Memfs, PWSTR Mountpoint, PWSTR UncName)
{
    DWORD_PTR ProcessMask, SystemMask;
    DOKAN_OPTIONS Options;
    NTSTATUS Result;
    int MainResult;

    if (!GetProcessAffinityMask(GetCurrentProcess(), &ProcessMask, &SystemMask))
    {
        Result = STATUS_UNSUCCESSFUL;
        goto exit;
    }

    memset(&Options, 0, sizeof Options);
    Options.Version = DOKAN_VERSION;
    for (Options.ThreadCount = 0; 0 != ProcessMask; ProcessMask >>= 1)
        Options.ThreadCount += ProcessMask & 1;
    if (Options.ThreadCount < 2)
        Options.ThreadCount = 2;
    Options.GlobalContext = (UINT_PTR)Memfs;
    Options.MountPoint = Mountpoint;
    Options.UNCName = UncName;
    Options.Timeout = 60000;
    Options.AllocationUnitSize = MEMFS_SECTOR_SIZE * MEMFS_SECTORS_PER_ALLOCATION_UNIT;
    Options.SectorSize = MEMFS_SECTOR_SIZE;

    MainResult = DokanMain(&Options, &MyOperations);
    switch (MainResult)
    {
    case DOKAN_SUCCESS:
        Result = STATUS_SUCCESS;
        break;
    case DOKAN_ERROR:
    case DOKAN_DRIVE_LETTER_ERROR:
    case DOKAN_DRIVER_INSTALL_ERROR:
    case DOKAN_START_ERROR:
    case DOKAN_MOUNT_ERROR:
    case DOKAN_MOUNT_POINT_ERROR:
    case DOKAN_VERSION_ERROR:
        Result = 0xe0000000 | (-MainResult);
        break;
    default:
        Result = STATUS_UNSUCCESSFUL;
        break;
    }

exit:
    return Result;
}

NTSTATUS MemfsHeapConfigure(SIZE_T InitialSize, SIZE_T MaximumSize, SIZE_T Alignment)
{
    return LargeHeapInitialize(0, InitialSize, MaximumSize, LargeHeapAlignment) ?
        STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}
