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

#if 0
#undef _DEBUG
#include "memfs.h"
#include <sddl.h>
#include <map>
#include <cassert>
#include <VersionHelpers.h>

/*
 * Define the MEMFS_NAMED_STREAMS macro to include named streams support.
 */
#define MEMFS_NAMED_STREAMS

/*
 * Define the MEMFS_NAME_NORMALIZATION macro to include name normalization support.
 */
#define MEMFS_NAME_NORMALIZATION

/*
 * Define the DEBUG_BUFFER_CHECK macro on Windows 8 or above. This includes
 * a check for the Write buffer to ensure that it is read-only.
 */
#if !defined(NDEBUG)
#define DEBUG_BUFFER_CHECK
#endif

#define MEMFS_SECTOR_SIZE               512
#define MEMFS_SECTORS_PER_ALLOCATION_UNIT 1

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
UINT64 MemfsGetSystemTime(VOID)
{
    FILETIME FileTime;
    GetSystemTimeAsFileTime(&FileTime);
    return ((PLARGE_INTEGER)&FileTime)->QuadPart;
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
    FSP_FSCTL_FILE_INFO FileInfo;
    SIZE_T FileSecuritySize;
    PVOID FileSecurity;
    PVOID FileData;
    SIZE_T ReparseDataSize;
    PVOID ReparseData;
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
    FSP_FILE_SYSTEM *FileSystem;
    MEMFS_FILE_NODE_MAP *FileNodeMap;
    ULONG MaxFileNodes;
    ULONG MaxFileSize;
    UINT16 VolumeLabelLength;
    WCHAR VolumeLabel[32];
} MEMFS;

static inline
NTSTATUS MemfsFileNodeCreate(PWSTR FileName, MEMFS_FILE_NODE **PFileNode)
{
    static UINT64 IndexNumber = 1;
    MEMFS_FILE_NODE *FileNode;

    *PFileNode = 0;

    if (MAX_PATH <= wcslen(FileName))
        return STATUS_OBJECT_NAME_INVALID;

    FileNode = (MEMFS_FILE_NODE *)malloc(sizeof *FileNode);
    if (0 == FileNode)
        return STATUS_INSUFFICIENT_RESOURCES;

    memset(FileNode, 0, sizeof *FileNode);
    wcscpy_s(FileNode->FileName, sizeof FileNode->FileName / sizeof(WCHAR), FileName);
    FileNode->FileInfo.CreationTime =
    FileNode->FileInfo.LastAccessTime =
    FileNode->FileInfo.LastWriteTime =
    FileNode->FileInfo.ChangeTime = MemfsGetSystemTime();
    FileNode->FileInfo.IndexNumber = IndexNumber++;

    *PFileNode = FileNode;

    return STATUS_SUCCESS;
}

static inline
VOID MemfsFileNodeDelete(MEMFS_FILE_NODE *FileNode)
{
    free(FileNode->ReparseData);
    LargeHeapFree(FileNode->FileData);
    free(FileNode->FileSecurity);
    free(FileNode);
}

static inline
VOID MemfsFileNodeGetFileInfo(MEMFS_FILE_NODE *FileNode, FSP_FSCTL_FILE_INFO *FileInfo)
{
#if defined(MEMFS_NAMED_STREAMS)
    if (0 == FileNode->MainFileNode)
        *FileInfo = FileNode->FileInfo;
    else
    {
        *FileInfo = FileNode->MainFileNode->FileInfo;
        FileInfo->FileAttributes &= ~FILE_ATTRIBUTE_DIRECTORY;
            /* named streams cannot be directories */
        FileInfo->AllocationSize = FileNode->FileInfo.AllocationSize;
        FileInfo->FileSize = FileNode->FileInfo.FileSize;
    }
#else
    *FileInfo = FileNode->FileInfo;
#endif
}

static inline
VOID MemfsFileNodeMapDump(MEMFS_FILE_NODE_MAP *FileNodeMap)
{
    for (MEMFS_FILE_NODE_MAP::iterator p = FileNodeMap->begin(), q = FileNodeMap->end(); p != q; ++p)
        FspDebugLog("%c %04lx %6lu %S\n",
            FILE_ATTRIBUTE_DIRECTORY & p->second->FileInfo.FileAttributes ? 'd' : 'f',
            (ULONG)p->second->FileInfo.FileAttributes,
            (ULONG)p->second->FileInfo.FileSize,
            p->second->FileName);
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
    if (0 == (iter->second->FileInfo.FileAttributes & FILE_ATTRIBUTE_DIRECTORY))
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

static NTSTATUS GetReparsePointByName(
    FSP_FILE_SYSTEM *FileSystem, PVOID Context,
    PWSTR FileName, BOOLEAN IsDirectory, PVOID Buffer, PSIZE_T PSize);

static NTSTATUS SetFileSize(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileNode0, UINT64 NewSize, BOOLEAN SetAllocationSize,
    FSP_FSCTL_FILE_INFO *FileInfo);

static NTSTATUS GetVolumeInfo(FSP_FILE_SYSTEM *FileSystem,
    FSP_FSCTL_VOLUME_INFO *VolumeInfo)
{
    MEMFS *Memfs = (MEMFS *)FileSystem->UserContext;

    VolumeInfo->TotalSize = Memfs->MaxFileNodes * (UINT64)Memfs->MaxFileSize;
    VolumeInfo->FreeSize = (Memfs->MaxFileNodes - MemfsFileNodeMapCount(Memfs->FileNodeMap)) *
        (UINT64)Memfs->MaxFileSize;
    VolumeInfo->VolumeLabelLength = Memfs->VolumeLabelLength;
    memcpy(VolumeInfo->VolumeLabel, Memfs->VolumeLabel, Memfs->VolumeLabelLength);

    return STATUS_SUCCESS;
}

static NTSTATUS SetVolumeLabel(FSP_FILE_SYSTEM *FileSystem,
    PWSTR VolumeLabel,
    FSP_FSCTL_VOLUME_INFO *VolumeInfo)
{
    MEMFS *Memfs = (MEMFS *)FileSystem->UserContext;

    Memfs->VolumeLabelLength = (UINT16)(wcslen(VolumeLabel) * sizeof(WCHAR));
    if (Memfs->VolumeLabelLength > sizeof Memfs->VolumeLabel)
        Memfs->VolumeLabelLength = sizeof Memfs->VolumeLabel;
    memcpy(Memfs->VolumeLabel, VolumeLabel, Memfs->VolumeLabelLength);

    VolumeInfo->TotalSize = Memfs->MaxFileNodes * Memfs->MaxFileSize;
    VolumeInfo->FreeSize =
        (Memfs->MaxFileNodes - MemfsFileNodeMapCount(Memfs->FileNodeMap)) * Memfs->MaxFileSize;
    VolumeInfo->VolumeLabelLength = Memfs->VolumeLabelLength;
    memcpy(VolumeInfo->VolumeLabel, Memfs->VolumeLabel, Memfs->VolumeLabelLength);

    return STATUS_SUCCESS;
}

static NTSTATUS GetSecurityByName(FSP_FILE_SYSTEM *FileSystem,
    PWSTR FileName, PUINT32 PFileAttributes,
    PSECURITY_DESCRIPTOR SecurityDescriptor, SIZE_T *PSecurityDescriptorSize)
{
    MEMFS *Memfs = (MEMFS *)FileSystem->UserContext;
    MEMFS_FILE_NODE *FileNode;
    NTSTATUS Result;

    FileNode = MemfsFileNodeMapGet(Memfs->FileNodeMap, FileName);
    if (0 == FileNode)
    {
        Result = STATUS_OBJECT_NAME_NOT_FOUND;

        if (FspFileSystemFindReparsePoint(FileSystem, GetReparsePointByName, 0,
            FileName, PFileAttributes))
            Result = STATUS_REPARSE;
        else
            MemfsFileNodeMapGetParent(Memfs->FileNodeMap, FileName, &Result);

        return Result;
    }

#if defined(MEMFS_NAMED_STREAMS)
    UINT32 FileAttributesMask = ~(UINT32)0;
    if (0 != FileNode->MainFileNode)
    {
        FileAttributesMask = ~(UINT32)FILE_ATTRIBUTE_DIRECTORY;
        FileNode = FileNode->MainFileNode;
    }

    if (0 != PFileAttributes)
        *PFileAttributes = FileNode->FileInfo.FileAttributes & FileAttributesMask;
#else
    if (0 != PFileAttributes)
        *PFileAttributes = FileNode->FileInfo.FileAttributes;
#endif

    if (0 != PSecurityDescriptorSize)
    {
        if (FileNode->FileSecuritySize > *PSecurityDescriptorSize)
        {
            *PSecurityDescriptorSize = FileNode->FileSecuritySize;
            return STATUS_BUFFER_OVERFLOW;
        }

        *PSecurityDescriptorSize = FileNode->FileSecuritySize;
        if (0 != SecurityDescriptor)
            memcpy(SecurityDescriptor, FileNode->FileSecurity, FileNode->FileSecuritySize);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS Create(FSP_FILE_SYSTEM *FileSystem,
    PWSTR FileName, UINT32 CreateOptions, UINT32 GrantedAccess,
    UINT32 FileAttributes, PSECURITY_DESCRIPTOR SecurityDescriptor, UINT64 AllocationSize,
    PVOID *PFileNode, FSP_FSCTL_FILE_INFO *FileInfo)
{
    MEMFS *Memfs = (MEMFS *)FileSystem->UserContext;
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

    FileNode->FileInfo.FileAttributes = (FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ?
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

static NTSTATUS Open(FSP_FILE_SYSTEM *FileSystem,
    PWSTR FileName, UINT32 CreateOptions, UINT32 GrantedAccess,
    PVOID *PFileNode, FSP_FSCTL_FILE_INFO *FileInfo)
{
    MEMFS *Memfs = (MEMFS *)FileSystem->UserContext;
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
    if (0 == (FileNode->FileInfo.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
        (GrantedAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA)))
        FileNode->FileInfo.FileAttributes |= FILE_ATTRIBUTE_ARCHIVE;

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

NTSTATUS Overwrite(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileNode0, UINT32 FileAttributes, BOOLEAN ReplaceFileAttributes,
    FSP_FSCTL_FILE_INFO *FileInfo)
{
    MEMFS *Memfs = (MEMFS *)FileSystem->UserContext;
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)FileNode0;

    if (ReplaceFileAttributes)
        FileNode->FileInfo.FileAttributes = FileAttributes | FILE_ATTRIBUTE_ARCHIVE;
    else
        FileNode->FileInfo.FileAttributes |= FileAttributes | FILE_ATTRIBUTE_ARCHIVE;

    FileNode->FileInfo.FileSize = 0;
    FileNode->FileInfo.LastWriteTime =
    FileNode->FileInfo.LastAccessTime = MemfsGetSystemTime();

    MemfsFileNodeGetFileInfo(FileNode, FileInfo);

    return STATUS_SUCCESS;
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

static VOID Cleanup(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileNode0, PWSTR FileName, BOOLEAN Delete)
{
    MEMFS *Memfs = (MEMFS *)FileSystem->UserContext;
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)FileNode0;

    assert(Delete); /* the new FSP_FSCTL_VOLUME_PARAMS::PostCleanupOnDeleteOnly ensures this */

    if (Delete && !MemfsFileNodeMapHasChild(Memfs->FileNodeMap, FileNode))
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

static VOID Close(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileNode0)
{
    MEMFS *Memfs = (MEMFS *)FileSystem->UserContext;
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)FileNode0;

    if (0 == --FileNode->RefCount)
        MemfsFileNodeDelete(FileNode);
}

static NTSTATUS Read(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileNode0, PVOID Buffer, UINT64 Offset, ULONG Length,
    PULONG PBytesTransferred)
{
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)FileNode0;
    UINT64 EndOffset;

    if (Offset >= FileNode->FileInfo.FileSize)
        return STATUS_END_OF_FILE;

    EndOffset = Offset + Length;
    if (EndOffset > FileNode->FileInfo.FileSize)
        EndOffset = FileNode->FileInfo.FileSize;

    memcpy(Buffer, (PUINT8)FileNode->FileData + Offset, (size_t)(EndOffset - Offset));

    *PBytesTransferred = (ULONG)(EndOffset - Offset);

    return STATUS_SUCCESS;
}

static NTSTATUS Write(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileNode0, PVOID Buffer, UINT64 Offset, ULONG Length,
    BOOLEAN WriteToEndOfFile, BOOLEAN ConstrainedIo,
    PULONG PBytesTransferred, FSP_FSCTL_FILE_INFO *FileInfo)
{
#if defined(DEBUG_BUFFER_CHECK)
    SYSTEM_INFO SystemInfo;
    GetSystemInfo(&SystemInfo);
    for (PUINT8 P = (PUINT8)Buffer, EndP = P + Length; EndP > P; P += SystemInfo.dwPageSize)
        __try
        {
            *P = *P | 0;
            assert(!IsWindows8OrGreater());
                /* only on Windows 8 we can make the buffer read-only! */
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            /* ignore! */
        }
#endif

    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)FileNode0;
    UINT64 EndOffset;

    if (ConstrainedIo)
    {
        if (Offset >= FileNode->FileInfo.FileSize)
            return STATUS_SUCCESS;
        EndOffset = Offset + Length;
        if (EndOffset > FileNode->FileInfo.FileSize)
            EndOffset = FileNode->FileInfo.FileSize;
    }
    else
    {
        if (WriteToEndOfFile)
            Offset = FileNode->FileInfo.FileSize;
        EndOffset = Offset + Length;
        if (EndOffset > FileNode->FileInfo.FileSize)
            SetFileSize(FileSystem, FileNode, EndOffset, FALSE, FileInfo);
    }

    memcpy((PUINT8)FileNode->FileData + Offset, Buffer, (size_t)(EndOffset - Offset));

    *PBytesTransferred = (ULONG)(EndOffset - Offset);
    MemfsFileNodeGetFileInfo(FileNode, FileInfo);

    return STATUS_SUCCESS;
}

NTSTATUS Flush(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileNode)
{
    /* nothing to do, since we do not cache anything */
    return STATUS_SUCCESS;
}

static NTSTATUS GetFileInfo(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileNode0,
    FSP_FSCTL_FILE_INFO *FileInfo)
{
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)FileNode0;

    MemfsFileNodeGetFileInfo(FileNode, FileInfo);

    return STATUS_SUCCESS;
}

static NTSTATUS SetBasicInfo(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileNode0, UINT32 FileAttributes,
    UINT64 CreationTime, UINT64 LastAccessTime, UINT64 LastWriteTime,
    FSP_FSCTL_FILE_INFO *FileInfo)
{
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)FileNode0;

#if defined(MEMFS_NAMED_STREAMS)
    if (0 != FileNode->MainFileNode)
        FileNode = FileNode->MainFileNode;
#endif

    if (INVALID_FILE_ATTRIBUTES != FileAttributes)
        FileNode->FileInfo.FileAttributes = FileAttributes;
    if (0 != CreationTime)
        FileNode->FileInfo.CreationTime = CreationTime;
    if (0 != LastAccessTime)
        FileNode->FileInfo.LastAccessTime = LastAccessTime;
    if (0 != LastWriteTime)
        FileNode->FileInfo.LastWriteTime = LastWriteTime;

    MemfsFileNodeGetFileInfo(FileNode, FileInfo);

    return STATUS_SUCCESS;
}

static NTSTATUS SetFileSize(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileNode0, UINT64 NewSize, BOOLEAN SetAllocationSize,
    FSP_FSCTL_FILE_INFO *FileInfo)
{
    MEMFS *Memfs = (MEMFS *)FileSystem->UserContext;
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)FileNode0;

    if (SetAllocationSize)
    {
        if (FileNode->FileInfo.AllocationSize != NewSize)
        {
            if (NewSize > Memfs->MaxFileSize)
                return STATUS_DISK_FULL;

            PVOID FileData = LargeHeapRealloc(FileNode->FileData, (size_t)NewSize);
            if (0 == FileData && 0 != NewSize)
                return STATUS_INSUFFICIENT_RESOURCES;

            FileNode->FileData = FileData;

            FileNode->FileInfo.AllocationSize = NewSize;
            if (FileNode->FileInfo.FileSize > NewSize)
                FileNode->FileInfo.FileSize = NewSize;
        }
    }
    else
    {
        if (FileNode->FileInfo.FileSize != NewSize)
        {
            if (FileNode->FileInfo.AllocationSize < NewSize)
            {
                UINT64 AllocationUnit = MEMFS_SECTOR_SIZE * MEMFS_SECTORS_PER_ALLOCATION_UNIT;
                UINT64 AllocationSize = (NewSize + AllocationUnit - 1) / AllocationUnit * AllocationUnit;

                NTSTATUS Result = SetFileSize(FileSystem, FileNode, AllocationSize, TRUE,
                    FileInfo);
                if (!NT_SUCCESS(Result))
                    return Result;
            }

            if (FileNode->FileInfo.FileSize < NewSize)
                memset((PUINT8)FileNode->FileData + FileNode->FileInfo.FileSize, 0,
                    (size_t)(NewSize - FileNode->FileInfo.FileSize));
            FileNode->FileInfo.FileSize = NewSize;
        }
    }

    MemfsFileNodeGetFileInfo(FileNode, FileInfo);

    return STATUS_SUCCESS;
}

static NTSTATUS CanDelete(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileNode0, PWSTR FileName)
{
    MEMFS *Memfs = (MEMFS *)FileSystem->UserContext;
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)FileNode0;

    if (MemfsFileNodeMapHasChild(Memfs->FileNodeMap, FileNode))
        return STATUS_DIRECTORY_NOT_EMPTY;

    return STATUS_SUCCESS;
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

static NTSTATUS Rename(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileNode0,
    PWSTR FileName, PWSTR NewFileName, BOOLEAN ReplaceIfExists)
{
    MEMFS *Memfs = (MEMFS *)FileSystem->UserContext;
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)FileNode0;
    MEMFS_FILE_NODE *NewFileNode, *DescendantFileNode;
    MEMFS_RENAME_CONTEXT Context = { 0 };
    ULONG Index, FileNameLen, NewFileNameLen;
    BOOLEAN Inserted;
    NTSTATUS Result;

    NewFileNode = MemfsFileNodeMapGet(Memfs->FileNodeMap, NewFileName);
    if (0 != NewFileNode && FileNode != NewFileNode)
    {
        if (!ReplaceIfExists)
        {
            Result = STATUS_OBJECT_NAME_COLLISION;
            goto exit;
        }

        if (NewFileNode->FileInfo.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
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
            FspDebugLog(__FUNCTION__ ": cannot insert into FileNodeMap; aborting\n");
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

static NTSTATUS GetSecurity(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileNode0,
    PSECURITY_DESCRIPTOR SecurityDescriptor, SIZE_T *PSecurityDescriptorSize)
{
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)FileNode0;

#if defined(MEMFS_NAMED_STREAMS)
    if (0 != FileNode->MainFileNode)
        FileNode = FileNode->MainFileNode;
#endif

    if (FileNode->FileSecuritySize > *PSecurityDescriptorSize)
    {
        *PSecurityDescriptorSize = FileNode->FileSecuritySize;
        return STATUS_BUFFER_OVERFLOW;
    }

    *PSecurityDescriptorSize = FileNode->FileSecuritySize;
    if (0 != SecurityDescriptor)
        memcpy(SecurityDescriptor, FileNode->FileSecurity, FileNode->FileSecuritySize);

    return STATUS_SUCCESS;
}

static NTSTATUS SetSecurity(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileNode0,
    SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR ModificationDescriptor,
    HANDLE AccessToken)
{
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)FileNode0;
    PSECURITY_DESCRIPTOR NewSecurityDescriptor, FileSecurity;
    SIZE_T FileSecuritySize;
    NTSTATUS Result;

#if defined(MEMFS_NAMED_STREAMS)
    if (0 != FileNode->MainFileNode)
        FileNode = FileNode->MainFileNode;
#endif

    Result = FspSetSecurityDescriptor(
        FileNode->FileSecurity,
        SecurityInformation,
        ModificationDescriptor,
        AccessToken,
        &NewSecurityDescriptor);
    if (!NT_SUCCESS(Result))
        return Result;

    FileSecuritySize = GetSecurityDescriptorLength(NewSecurityDescriptor);
    FileSecurity = (PSECURITY_DESCRIPTOR)malloc(FileSecuritySize);
    if (0 == FileSecurity)
    {
        FspDeleteSecurityDescriptor(NewSecurityDescriptor, (NTSTATUS (*)())FspSetSecurityDescriptor);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memcpy(FileSecurity, NewSecurityDescriptor, FileSecuritySize);
    FspDeleteSecurityDescriptor(NewSecurityDescriptor, (NTSTATUS (*)())FspSetSecurityDescriptor);

    free(FileNode->FileSecurity);
    FileNode->FileSecuritySize = FileSecuritySize;
    FileNode->FileSecurity = FileSecurity;

    return STATUS_SUCCESS;
}

typedef struct _MEMFS_READ_DIRECTORY_CONTEXT
{
    PVOID Buffer;
    UINT64 Offset;
    ULONG Length;
    PULONG PBytesTransferred;
    BOOLEAN OffsetFound;
} MEMFS_READ_DIRECTORY_CONTEXT;

static BOOLEAN AddDirInfo(MEMFS_FILE_NODE *FileNode, PWSTR FileName,
    PVOID Buffer, ULONG Length, PULONG PBytesTransferred)
{
    UINT8 DirInfoBuf[sizeof(FSP_FSCTL_DIR_INFO) + sizeof FileNode->FileName];
    FSP_FSCTL_DIR_INFO *DirInfo = (FSP_FSCTL_DIR_INFO *)DirInfoBuf;
    WCHAR Root[2] = L"\\";
    PWSTR Remain, Suffix;

    if (0 == FileName)
    {
        FspPathSuffix(FileNode->FileName, &Remain, &Suffix, Root);
        FileName = Suffix;
        FspPathCombine(FileNode->FileName, Suffix);
    }

    memset(DirInfo->Padding, 0, sizeof DirInfo->Padding);
    DirInfo->Size = (UINT16)(sizeof(FSP_FSCTL_DIR_INFO) + wcslen(FileName) * sizeof(WCHAR));
    DirInfo->FileInfo = FileNode->FileInfo;
    DirInfo->NextOffset = FileNode->FileInfo.IndexNumber;
    memcpy(DirInfo->FileNameBuf, FileName, DirInfo->Size - sizeof(FSP_FSCTL_DIR_INFO));

    return FspFileSystemAddDirInfo(DirInfo, Buffer, Length, PBytesTransferred);
}

static BOOLEAN ReadDirectoryEnumFn(MEMFS_FILE_NODE *FileNode, PVOID Context0)
{
    MEMFS_READ_DIRECTORY_CONTEXT *Context = (MEMFS_READ_DIRECTORY_CONTEXT *)Context0;

    if (0 != Context->Offset && !Context->OffsetFound)
    {
        Context->OffsetFound = FileNode->FileInfo.IndexNumber == Context->Offset;
        return TRUE;
    }

    return AddDirInfo(FileNode, 0,
        Context->Buffer, Context->Length, Context->PBytesTransferred);
}

static NTSTATUS ReadDirectory(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileNode0, PVOID Buffer, UINT64 Offset, ULONG Length,
    PWSTR Pattern,
    PULONG PBytesTransferred)
{
    MEMFS *Memfs = (MEMFS *)FileSystem->UserContext;
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)FileNode0;
    MEMFS_FILE_NODE *ParentNode;
    MEMFS_READ_DIRECTORY_CONTEXT Context;
    NTSTATUS Result;

    ParentNode = MemfsFileNodeMapGetParent(Memfs->FileNodeMap, FileNode->FileName, &Result);
    if (0 == ParentNode)
        return Result;

    Context.Buffer = Buffer;
    Context.Offset = Offset;
    Context.Length = Length;
    Context.PBytesTransferred = PBytesTransferred;
    Context.OffsetFound = FALSE;

    if (L'\0' != FileNode->FileName[1])
    {
        /* if this is not the root directory add the dot entries */

        if (0 == Offset)
            if (!AddDirInfo(FileNode, L".", Buffer, Length, PBytesTransferred))
                return STATUS_SUCCESS;
        if (0 == Offset || FileNode->FileInfo.IndexNumber == Offset)
        {
            Context.OffsetFound = FileNode->FileInfo.IndexNumber == Context.Offset;

            if (!AddDirInfo(ParentNode, L"..", Buffer, Length, PBytesTransferred))
                return STATUS_SUCCESS;
        }
    }

    if (MemfsFileNodeMapEnumerateChildren(Memfs->FileNodeMap, FileNode, ReadDirectoryEnumFn, &Context))
        FspFileSystemAddDirInfo(0, Buffer, Length, PBytesTransferred);

    return STATUS_SUCCESS;
}

static NTSTATUS ResolveReparsePoints(FSP_FILE_SYSTEM *FileSystem,
    PWSTR FileName, UINT32 ReparsePointIndex, BOOLEAN ResolveLastPathComponent,
    PIO_STATUS_BLOCK PIoStatus, PVOID Buffer, PSIZE_T PSize)
{
    return FspFileSystemResolveReparsePoints(FileSystem, GetReparsePointByName, 0,
        FileName, ReparsePointIndex, ResolveLastPathComponent,
        PIoStatus, Buffer, PSize);
}

static NTSTATUS GetReparsePointByName(
    FSP_FILE_SYSTEM *FileSystem, PVOID Context,
    PWSTR FileName, BOOLEAN IsDirectory, PVOID Buffer, PSIZE_T PSize)
{
    MEMFS *Memfs = (MEMFS *)FileSystem->UserContext;
    MEMFS_FILE_NODE *FileNode;

#if defined(MEMFS_NAMED_STREAMS)
    /* GetReparsePointByName will never receive a named stream */
    assert(0 == wcschr(FileName, L':'));
#endif

    FileNode = MemfsFileNodeMapGet(Memfs->FileNodeMap, FileName);
    if (0 == FileNode)
        return STATUS_OBJECT_NAME_NOT_FOUND;

    if (0 == (FileNode->FileInfo.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        return STATUS_NOT_A_REPARSE_POINT;

    if (0 != Buffer)
    {
        if (FileNode->ReparseDataSize > *PSize)
            return STATUS_BUFFER_TOO_SMALL;

        *PSize = FileNode->ReparseDataSize;
        memcpy(Buffer, FileNode->ReparseData, FileNode->ReparseDataSize);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS GetReparsePoint(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileNode0,
    PWSTR FileName, PVOID Buffer, PSIZE_T PSize)
{
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)FileNode0;

#if defined(MEMFS_NAMED_STREAMS)
    if (0 != FileNode->MainFileNode)
        FileNode = FileNode->MainFileNode;
#endif

    if (0 == (FileNode->FileInfo.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        return STATUS_NOT_A_REPARSE_POINT;

    if (FileNode->ReparseDataSize > *PSize)
        return STATUS_BUFFER_TOO_SMALL;

    *PSize = FileNode->ReparseDataSize;
    memcpy(Buffer, FileNode->ReparseData, FileNode->ReparseDataSize);

    return STATUS_SUCCESS;
}

static NTSTATUS SetReparsePoint(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileNode0,
    PWSTR FileName, PVOID Buffer, SIZE_T Size)
{
    MEMFS *Memfs = (MEMFS *)FileSystem->UserContext;
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)FileNode0;
    PVOID ReparseData;
    NTSTATUS Result;

#if defined(MEMFS_NAMED_STREAMS)
    if (0 != FileNode->MainFileNode)
        FileNode = FileNode->MainFileNode;
#endif

    if (MemfsFileNodeMapHasChild(Memfs->FileNodeMap, FileNode))
        return STATUS_DIRECTORY_NOT_EMPTY;

    if (0 != FileNode->ReparseData)
    {
        Result = FspFileSystemCanReplaceReparsePoint(
            FileNode->ReparseData, FileNode->ReparseDataSize,
            Buffer, Size);
        if (!NT_SUCCESS(Result))
            return Result;
    }

    ReparseData = realloc(FileNode->ReparseData, Size);
    if (0 == ReparseData && 0 != Size)
        return STATUS_INSUFFICIENT_RESOURCES;

    FileNode->FileInfo.FileAttributes |= FILE_ATTRIBUTE_REPARSE_POINT;
    FileNode->FileInfo.ReparseTag = *(PULONG)Buffer;
        /* the first field in a reparse buffer is the reparse tag */
    FileNode->ReparseDataSize = Size;
    FileNode->ReparseData = ReparseData;
    memcpy(FileNode->ReparseData, Buffer, Size);

    return STATUS_SUCCESS;
}

static NTSTATUS DeleteReparsePoint(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileNode0,
    PWSTR FileName, PVOID Buffer, SIZE_T Size)
{
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)FileNode0;
    NTSTATUS Result;

#if defined(MEMFS_NAMED_STREAMS)
    if (0 != FileNode->MainFileNode)
        FileNode = FileNode->MainFileNode;
#endif

    if (0 != FileNode->ReparseData)
    {
        Result = FspFileSystemCanReplaceReparsePoint(
            FileNode->ReparseData, FileNode->ReparseDataSize,
            Buffer, Size);
        if (!NT_SUCCESS(Result))
            return Result;
    }
    else
        return STATUS_NOT_A_REPARSE_POINT;

    free(FileNode->ReparseData);

    FileNode->FileInfo.FileAttributes &= ~FILE_ATTRIBUTE_REPARSE_POINT;
    FileNode->FileInfo.ReparseTag = 0;
    FileNode->ReparseDataSize = 0;
    FileNode->ReparseData = 0;

    return STATUS_SUCCESS;
}

#if defined(MEMFS_NAMED_STREAMS)
typedef struct _MEMFS_GET_STREAM_INFO_CONTEXT
{
    PVOID Buffer;
    ULONG Length;
    PULONG PBytesTransferred;
} MEMFS_GET_STREAM_INFO_CONTEXT;

static BOOLEAN AddStreamInfo(MEMFS_FILE_NODE *FileNode,
    PVOID Buffer, ULONG Length, PULONG PBytesTransferred)
{
    UINT8 StreamInfoBuf[sizeof(FSP_FSCTL_STREAM_INFO) + sizeof FileNode->FileName];
    FSP_FSCTL_STREAM_INFO *StreamInfo = (FSP_FSCTL_STREAM_INFO *)StreamInfoBuf;
    PWSTR StreamName;

    StreamName = wcschr(FileNode->FileName, L':');
    if (0 != StreamName)
        StreamName++;
    else
        StreamName = L"";

    StreamInfo->Size = (UINT16)(sizeof(FSP_FSCTL_STREAM_INFO) + wcslen(StreamName) * sizeof(WCHAR));
    StreamInfo->StreamSize = FileNode->FileInfo.FileSize;
    StreamInfo->StreamAllocationSize = FileNode->FileInfo.AllocationSize;
    memcpy(StreamInfo->StreamNameBuf, StreamName, StreamInfo->Size - sizeof(FSP_FSCTL_STREAM_INFO));

    return FspFileSystemAddStreamInfo(StreamInfo, Buffer, Length, PBytesTransferred);
}

static BOOLEAN GetStreamInfoEnumFn(MEMFS_FILE_NODE *FileNode, PVOID Context0)
{
    MEMFS_GET_STREAM_INFO_CONTEXT *Context = (MEMFS_GET_STREAM_INFO_CONTEXT *)Context0;

    return AddStreamInfo(FileNode,
        Context->Buffer, Context->Length, Context->PBytesTransferred);
}

static NTSTATUS GetStreamInfo(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileNode0, PVOID Buffer, ULONG Length,
    PULONG PBytesTransferred)
{
    MEMFS *Memfs = (MEMFS *)FileSystem->UserContext;
    MEMFS_FILE_NODE *FileNode = (MEMFS_FILE_NODE *)FileNode0;
    MEMFS_GET_STREAM_INFO_CONTEXT Context;

    if (0 != FileNode->MainFileNode)
        FileNode = FileNode->MainFileNode;

    Context.Buffer = Buffer;
    Context.Length = Length;
    Context.PBytesTransferred = PBytesTransferred;

    if (0 == (FileNode->FileInfo.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
        !AddStreamInfo(FileNode, Buffer, Length, PBytesTransferred))
        return STATUS_SUCCESS;

    if (MemfsFileNodeMapEnumerateNamedStreams(Memfs->FileNodeMap, FileNode, GetStreamInfoEnumFn, &Context))
        FspFileSystemAddStreamInfo(0, Buffer, Length, PBytesTransferred);

    /* ???: how to handle out of response buffer condition? */

    return STATUS_SUCCESS;
}
#endif

static FSP_FILE_SYSTEM_INTERFACE MemfsInterface =
{
    GetVolumeInfo,
    SetVolumeLabel,
    GetSecurityByName,
    Create,
    Open,
    Overwrite,
    Cleanup,
    Close,
    Read,
    Write,
    Flush,
    GetFileInfo,
    SetBasicInfo,
    SetFileSize,
    CanDelete,
    Rename,
    GetSecurity,
    SetSecurity,
    ReadDirectory,
    ResolveReparsePoints,
    GetReparsePoint,
    SetReparsePoint,
    DeleteReparsePoint,
#if defined(MEMFS_NAMED_STREAMS)
    GetStreamInfo,
#else
    0,
#endif
};

NTSTATUS MemfsCreate(
    ULONG Flags,
    ULONG FileInfoTimeout,
    ULONG MaxFileNodes,
    ULONG MaxFileSize,
    PWSTR VolumePrefix,
    PWSTR RootSddl,
    MEMFS **PMemfs)
{
    NTSTATUS Result;
    FSP_FSCTL_VOLUME_PARAMS VolumeParams;
    BOOLEAN CaseInsensitive = !!(Flags & MemfsCaseInsensitive);
    PWSTR DevicePath = (Flags & MemfsNet) ?
        L"" FSP_FSCTL_NET_DEVICE_NAME : L"" FSP_FSCTL_DISK_DEVICE_NAME;
    UINT64 AllocationUnit;
    MEMFS *Memfs;
    MEMFS_FILE_NODE *RootNode;
    PSECURITY_DESCRIPTOR RootSecurity;
    ULONG RootSecuritySize;
    BOOLEAN Inserted;

    *PMemfs = 0;

    Result = MemfsHeapConfigure(0, 0, 0);
    if (!NT_SUCCESS(Result))
        return Result;

    if (0 == RootSddl)
        RootSddl = L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)";
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(RootSddl, SDDL_REVISION_1,
        &RootSecurity, &RootSecuritySize))
        return FspNtStatusFromWin32(GetLastError());

    Memfs = (MEMFS *)malloc(sizeof *Memfs);
    if (0 == Memfs)
    {
        LocalFree(RootSecurity);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    memset(Memfs, 0, sizeof *Memfs);
    Memfs->MaxFileNodes = MaxFileNodes;
    AllocationUnit = MEMFS_SECTOR_SIZE * MEMFS_SECTORS_PER_ALLOCATION_UNIT;
    Memfs->MaxFileSize = (ULONG)((MaxFileSize + AllocationUnit - 1) / AllocationUnit * AllocationUnit);

    Result = MemfsFileNodeMapCreate(CaseInsensitive, &Memfs->FileNodeMap);
    if (!NT_SUCCESS(Result))
    {
        free(Memfs);
        LocalFree(RootSecurity);
        return Result;
    }

    memset(&VolumeParams, 0, sizeof VolumeParams);
    VolumeParams.SectorSize = MEMFS_SECTOR_SIZE;
    VolumeParams.SectorsPerAllocationUnit = MEMFS_SECTORS_PER_ALLOCATION_UNIT;
    VolumeParams.VolumeCreationTime = MemfsGetSystemTime();
    VolumeParams.VolumeSerialNumber = (UINT32)(MemfsGetSystemTime() / (10000 * 1000));
    VolumeParams.FileInfoTimeout = FileInfoTimeout;
    VolumeParams.CaseSensitiveSearch = !CaseInsensitive;
    VolumeParams.CasePreservedNames = 1;
    VolumeParams.UnicodeOnDisk = 1;
    VolumeParams.PersistentAcls = 1;
    VolumeParams.ReparsePoints = 1;
    VolumeParams.ReparsePointsAccessCheck = 0;
#if defined(MEMFS_NAMED_STREAMS)
    VolumeParams.NamedStreams = 1;
#endif
    VolumeParams.PostCleanupOnDeleteOnly = 1;
    if (0 != VolumePrefix)
        wcscpy_s(VolumeParams.Prefix, sizeof VolumeParams.Prefix / sizeof(WCHAR), VolumePrefix);
    wcscpy_s(VolumeParams.FileSystemName, sizeof VolumeParams.FileSystemName / sizeof(WCHAR), L"MEMFS");

    Result = FspFileSystemCreate(DevicePath, &VolumeParams, &MemfsInterface, &Memfs->FileSystem);
    if (!NT_SUCCESS(Result))
    {
        MemfsFileNodeMapDelete(Memfs->FileNodeMap);
        free(Memfs);
        LocalFree(RootSecurity);
        return Result;
    }

    Memfs->FileSystem->UserContext = Memfs;
    Memfs->VolumeLabelLength = sizeof L"MEMFS" - sizeof(WCHAR);
    memcpy(Memfs->VolumeLabel, L"MEMFS", Memfs->VolumeLabelLength);

#if 0
    FspFileSystemSetOperationGuardStrategy(Memfs->FileSystem,
        FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_COARSE);
#endif

    /*
     * Create root directory.
     */

    Result = MemfsFileNodeCreate(L"\\", &RootNode);
    if (!NT_SUCCESS(Result))
    {
        MemfsDelete(Memfs);
        LocalFree(RootSecurity);
        return Result;
    }

    RootNode->FileInfo.FileAttributes = FILE_ATTRIBUTE_DIRECTORY;

    RootNode->FileSecurity = malloc(RootSecuritySize);
    if (0 == RootNode->FileSecurity)
    {
        MemfsFileNodeDelete(RootNode);
        MemfsDelete(Memfs);
        LocalFree(RootSecurity);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RootNode->FileSecuritySize = RootSecuritySize;
    memcpy(RootNode->FileSecurity, RootSecurity, RootSecuritySize);

    Result = MemfsFileNodeMapInsert(Memfs->FileNodeMap, RootNode, &Inserted);
    if (!NT_SUCCESS(Result))
    {
        MemfsFileNodeDelete(RootNode);
        MemfsDelete(Memfs);
        LocalFree(RootSecurity);
        return Result;
    }

    LocalFree(RootSecurity);

    *PMemfs = Memfs;

    return STATUS_SUCCESS;
}

VOID MemfsDelete(MEMFS *Memfs)
{
    FspFileSystemDelete(Memfs->FileSystem);

    MemfsFileNodeMapDelete(Memfs->FileNodeMap);

    free(Memfs);
}

NTSTATUS MemfsStart(MEMFS *Memfs)
{
    return FspFileSystemStartDispatcher(Memfs->FileSystem, 0);
}

VOID MemfsStop(MEMFS *Memfs)
{
    FspFileSystemStopDispatcher(Memfs->FileSystem);
}

FSP_FILE_SYSTEM *MemfsFileSystem(MEMFS *Memfs)
{
    return Memfs->FileSystem;
}

NTSTATUS MemfsHeapConfigure(SIZE_T InitialSize, SIZE_T MaximumSize, SIZE_T Alignment)
{
    return LargeHeapInitialize(0, InitialSize, MaximumSize, LargeHeapAlignment) ?
        STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}
#endif
