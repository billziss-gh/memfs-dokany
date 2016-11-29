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

#include <dokan/dokan.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FSP_FSCTL_ALIGN_UP(x, s)        (((x) + ((s) - 1L)) & ~((s) - 1L))

typedef struct _MEMFS MEMFS;

enum
{
    MemfsCaseInsensitive                = 0x80,
};

NTSTATUS MemfsCreate(
    ULONG Flags,
    ULONG MaxFileNodes,
    ULONG MaxFileSize,
    MEMFS **PMemfs);
VOID MemfsDelete(MEMFS *Memfs);
NTSTATUS MemfsRun(MEMFS *Memfs, PWSTR Mountpoint, PWSTR UncName);

NTSTATUS MemfsHeapConfigure(SIZE_T InitialSize, SIZE_T MaximumSize, SIZE_T Alignment);

#ifdef __cplusplus
}
#endif

#endif
