/**
 * @file memfs-dokany.h
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

#ifndef MEMFS_DOKANY_H_INCLUDED
#define MEMFS_DOKANY_H_INCLUDED

#if 0
#include <winfsp/winfsp.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _MEMFS MEMFS;

enum
{
    MemfsDisk                           = 0x00,
    MemfsNet                            = 0x01,
    MemfsCaseInsensitive                = 0x80,
};

NTSTATUS MemfsCreate(
    ULONG Flags,
    ULONG FileInfoTimeout,
    ULONG MaxFileNodes,
    ULONG MaxFileSize,
    PWSTR VolumePrefix,
    PWSTR RootSddl,
    MEMFS **PMemfs);
VOID MemfsDelete(MEMFS *Memfs);
NTSTATUS MemfsStart(MEMFS *Memfs);
VOID MemfsStop(MEMFS *Memfs);
FSP_FILE_SYSTEM *MemfsFileSystem(MEMFS *Memfs);

NTSTATUS MemfsHeapConfigure(SIZE_T InitialSize, SIZE_T MaximumSize, SIZE_T Alignment);

#ifdef __cplusplus
}
#endif

#endif //#if 0

#endif
