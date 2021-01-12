
/*--------------------------------------------------------------------*/
/*--- DYLD Cache                                      dyld_cache.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (c) 2020 Louis Brunner <louis.brunner.fr@gmail.com>

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.

   The GNU General Public License is contained in the file COPYING.
*/

// While dyld_caching as existed for longer than that
// we have used DYLD_SHARED_REGION=avoid in the past
//
// Starting with macOS 11 (Big Sur), it isn't an option anymore
// as some dylib are not provided in file format anymore
#if defined(VGO_darwin) &&  DARWIN_VERS >= DARWIN_11_00

#include "pub_core_aspacemgr.h"             // VG_(am_mmap_named_file_fixed_client_flags)
#include "pub_core_debuginfo.h"             // VG_(di_notify_mmap)
#include "pub_core_debuglog.h"              // VG_(debugLog)
#include "pub_core_mach.h"                  // VG_(dyld_cache_*)
#include "pub_core_syscall.h"               // VG_(do_syscall1)
#include "pub_core_libcassert.h"            // vg_assert
#include "pub_core_threadstate.h"           // ThreadState
#include "pub_tool_libcbase.h"              // VG_(strncmp)
#include "pub_tool_libcprint.h"             // VG_(dmsg)
#include "pub_tool_libcfile.h"              // VG_(stat)
#include "vki/vki-scnums-darwin.h"          // __NR_shared_region_check_np
#include "priv_dyld_internals.h"            // CACHE_MAGIC_*, dyld_cache_header

// FIXME: probably shouldn't include this directly?
#include "m_syswrap/priv_syswrap-generic.h" // ML_(notify_core_and_tool_of_mmap)

#include <mach-o/loader.h>

// Only supported on macOS 11 onwards which is 64bit only
# define MACH_HEADER mach_header_64
# define LC_SEGMENT_CMD LC_SEGMENT_64
# define SEGMENT_COMMAND segment_command_64

typedef struct {
  const dyld_cache_header* header;
  Addr slide;
  const dyld_cache_mapping_info* mappings;
  int has_image_array;
  const dyld_cache_image_info* images_old;
  const DyldImageArray* images_new;
} DYLDCache;

static DYLDCache dyld_cache = {
  .header = NULL,
  .slide = 0,
  .mappings = NULL,
  .has_image_array = 0,
};

// This file is inspired by Apple's dyld sources:
//  * `findInSharedCacheImage`/`reuseExistingCache` in `dyld-*/dyld3/SharedCacheRuntime.cpp`
//  * `hasImagePath` in `dyld-*/dyld3/shared-cache/DyldSharedCache.cpp`
//  * `ImageArray`/`Image`/`TypedBytes` in `dyld-*/dyld3/Closure.cpp`
//  * `cacheablePath` in `dyld-*/src/dyld.cpp`

static int try_to_init(void) {
  Addr cache_address;
  const dyld_cache_header* header;

  if (sr_Res(VG_(do_syscall1)(__NR_shared_region_check_np, (UWord)&cache_address)) != 0) {
    VG_(debugLog)(2, "dyld_cache", "ERROR: could not get shared dyld cache address\n");
    return 0;
  }
  header = (const dyld_cache_header *) cache_address;

  if (VG_(strcmp)(header->magic, CACHE_MAGIC_x86_64) != 0
    && VG_(strcmp)(header->magic, CACHE_MAGIC_x86_64_HASWELL) != 0) {
    VG_(debugLog)(2, "dyld_cache", "ERROR: incompatible shared dyld cache (%s)\n", header->magic);
    return 0;
  }

  dyld_cache.header = header;
  VG_(debugLog)(2, "dyld_cache", "shared dyld cache found: %#lx\n", (Addr) dyld_cache.header);
  VG_(debugLog)(2, "dyld_cache", "shared dyld cache format: %d\n", dyld_cache.header->formatVersion);

  // Mark the header itself
  ML_(notify_core_and_tool_of_mmap)(
    cache_address, sizeof(*dyld_cache.header),
    VKI_PROT_READ, VKI_MAP_ANON, -1, 0
  );

  // Mark the mappings
  // FIXME: not aligned
  // ML_(notify_core_and_tool_of_mmap)(
  //   cache_address + dyld_cache.header->mappingOffset,
  //   sizeof(dyld_cache_mapping_info) * dyld_cache.header->mappingCount,
  //   VKI_PROT_READ, VKI_MAP_ANON, -1, 0
  // );

  vg_assert(dyld_cache.header->mappingCount == 3);

  dyld_cache.mappings = (const dyld_cache_mapping_info*)(cache_address + dyld_cache.header->mappingOffset);
  dyld_cache.slide = cache_address - (Addr)dyld_cache.mappings[0].address;

  // FIXME: too big
  // ML_(notify_core_and_tool_of_mmap)(
  //   dyld_cache.mappings[0].address, dyld_cache.mappings[0].size,
  //   VKI_PROT_READ | VKI_PROT_EXEC, VKI_MAP_ANON, -1, 0
  // );

  // FIXME: why not?
  // ML_(notify_core_and_tool_of_mmap)(
  //   dyld_cache.mappings[1].address, dyld_cache.mappings[1].size,
  //   VKI_PROT_READ | VKI_PROT_WRITE, VKI_MAP_ANON, -1, 0
  // );

  // FIXME: too big
  // ML_(notify_core_and_tool_of_mmap)(
  //   dyld_cache.mappings[2].address, dyld_cache.mappings[2].size,
  //   VKI_PROT_READ, VKI_MAP_ANON, -1, 0
  // );

  // Mark the images
  // FIXME: not aligned
  // ML_(notify_core_and_tool_of_mmap)(
  //   cache_address + dyld_cache.header->imagesOffset,
  //   sizeof(dyld_cache_image_info) * dyld_cache.header->imagesCount,
  //   VKI_PROT_READ, VKI_MAP_ANON, -1, 0
  // );

  dyld_cache.has_image_array = dyld_cache.header->mappingOffset >= 0x100 && dyld_cache.header->dylibsImageArrayAddr != 0;
  dyld_cache.images_old = (const dyld_cache_image_info*)(cache_address + dyld_cache.header->imagesOffset);
  if (dyld_cache.has_image_array) {
    dyld_cache.images_new = (const DyldImageArray*)(cache_address + (dyld_cache.header->dylibsImageArrayAddr - dyld_cache.mappings[0].address));

    // FIXME: why not?
    // ML_(notify_core_and_tool_of_mmap)(
    //   (Addr)dyld_cache.images_new,
    //   sizeof(DyldTypedBytes) + dyld_cache.images_new->payloadLength,
    //   VKI_PROT_READ, VKI_MAP_ANON, -1, 0
    // );

    if (dyld_cache.mappings[0].fileOffset == 0 && dyld_cache.header->mappingOffset >= 0x118) {
      // FIXME: not aligned
      // ML_(notify_core_and_tool_of_mmap)(
      //   (Addr)dyld_cache.header->dylibsTrieAddr + dyld_cache.slide,
      //   dyld_cache.header->dylibsTrieSize,
      //   VKI_PROT_READ, VKI_MAP_ANON, -1, 0
      // );
    }
  }

  // TODO: mark the rest of the structure as accessible?

  return 1;
}

void VG_(dyld_cache_init)(void) {
  if (!try_to_init()) {
    VG_(dmsg)("WARNING: could not initialize dyld cache, this will probably fail\n");
    return;
  }
}

int VG_(dyld_cache_might_be_in)(const HChar* path) {
  // If not init'd, there is no point
  if (dyld_cache.header == NULL) {
    return 0;
  }

  if (VG_(strncmp)(path, "/usr/lib/", 9) == 0) {
		return 1;
  }
	if (VG_(strncmp)(path, "/System/Library/", 16) == 0) {
    return 1;
  }
  // FIXME: more flexible heuristics around extensions?
  return 0;
}

static const char* get_dylib_path(const dyld_cache_image_info* info) {
  vg_assert(dyld_cache.header != NULL);
  // TODO: place where the paths are stored might not be tracked yet!
  return (const char*)dyld_cache.header + info->pathFileOffset;
}

static const void * typed_bytes_payload(const DyldTypedBytes* typed_bytes) {
  return (const uint8_t*)typed_bytes + sizeof(DyldTypedBytes);
}

static const DyldTypedBytes* typed_bytes_next(const DyldTypedBytes* current) {
  vg_assert((current->payloadLength & 0x3) == 0);
  return (const DyldTypedBytes*)((const uint8_t*)typed_bytes_payload(current) + current->payloadLength);
}

static const DyldImage* get_image_for_index(uint32_t image_index) {
  vg_assert(dyld_cache.header != NULL);
  vg_assert(dyld_cache.has_image_array);

  VG_(debugLog)(3, "dyld_cache", "looking up image n=%u\n", image_index);

  if (dyld_cache.images_new->firstImageNum > image_index) {
    VG_(debugLog)(3, "dyld_cache", "failed, first=%u\n", dyld_cache.images_new->firstImageNum);
    return NULL;
  }

  uint32_t index = image_index - dyld_cache.images_new->firstImageNum;
  if (index >= dyld_cache.images_new->count) {
    VG_(debugLog)(3, "dyld_cache", "failed, first=%u count=%u\n", dyld_cache.images_new->firstImageNum, dyld_cache.images_new->count);
    return NULL;
  }

  const void* payload = typed_bytes_payload((const DyldTypedBytes*)dyld_cache.images_new);
  const uint8_t* image_addr = (const uint8_t*)payload + dyld_cache.images_new->offsets[index];
  VG_(debugLog)(3, "dyld_cache", "found, image=%p\n", image_addr);
  return (const DyldImage*)(image_addr);
}

static ULong read_uleb128(const uint8_t* p, const uint8_t* end, int* error) {
  ULong result = 0;
  UChar shift = 0;
  *error = 0;
  do {
    // FIXME: should assert but we might be reading junk...
    // vg_assert(p == end);
    // vg_assert(shift > 63);
    if (p == end || shift > 63) {
      *error = 1;
      return 0;
    }
    result |= (*p & 0x7f) << shift;
    shift += 7;
  } while (*p++ & 0x80);
  return result;
}

#define DYLD_TRIE_MAX_OFFSETS 128
// This function is lifted as-is from `dyld::MachOLoaded::trieWalk`
static const uint8_t* dyld_trie_walk(const uint8_t* start, const uint8_t* end, const HChar* path) {
  uint32_t visitedNodeOffsets[DYLD_TRIE_MAX_OFFSETS];
  int visitedNodeOffsetCount = 0;
  const uint8_t* p = start;
  int error = 0;
  const int trieDebug = 0;

  visitedNodeOffsets[visitedNodeOffsetCount++] = 0;
  while (p < end) {
    uint64_t terminalSize = *p++;
    if (trieDebug) VG_(debugLog)(4, "dyld_cache", "[TRIE] LOOP p=%p end=%p tsize=%llu\n", p, end, terminalSize);

    if (terminalSize > 127) {
      // except for re-export-with-rename, all terminal sizes fit in one byte
      --p;
      terminalSize = read_uleb128(p, end, &error);
      if (error) {
        if (trieDebug) VG_(debugLog)(4, "dyld_cache", "[TRIE] ULEB FAILED\n");
        return NULL;
      }
      if (trieDebug) VG_(debugLog)(4, "dyld_cache", "[TRIE] REREAD ULEB tsize=%llu\n", terminalSize);
    }

    if (trieDebug) VG_(debugLog)(4, "dyld_cache", "[TRIE] STATE path=%s\n", path);
    if ((*path == '\0') && (terminalSize != 0)) {
      if (trieDebug) VG_(debugLog)(4, "dyld_cache", "[TRIE] FOUND p=%p\n", p);
      return p;
    }

    const uint8_t* children = p + terminalSize;
    if (children > end) {
      if (trieDebug) VG_(debugLog)(4, "dyld_cache", "[TRIE] CHILDREN, TOO FAR\n");
      return NULL;
    }

    uint8_t childrenRemaining = *children++;
    uint64_t nodeOffset = 0;

    p = children;
    for (; childrenRemaining > 0; --childrenRemaining) {
      if (trieDebug) VG_(debugLog)(4, "dyld_cache", "[TRIE] CHILDREN LOOP children=%p remaining=%d\n", p, childrenRemaining);
      const char* ss = path;
      int wrongEdge = 0;

      // scan whole edge to get to next edge
      // if edge is longer than target symbol name, don't read past end of symbol name
      char c = *p;
      while (c != '\0') {
        if (trieDebug) VG_(debugLog)(4, "dyld_cache", "[TRIE] CHAR LOOP c=%c ss=%c wrong=%d\n", c, *ss, wrongEdge);
        if (!wrongEdge) {
          if (c != *ss) {
            wrongEdge = 1;
          }
          ++ss;
        }
        ++p;
        c = *p;
      }

      if (wrongEdge) {
        if (trieDebug) VG_(debugLog)(4, "dyld_cache", "[TRIE] WRONG EDGE, SKIP\n");
        // advance to next child
        ++p; // skip over zero terminator
        // skip over uleb128 until last byte is found
        while ((*p & 0x80) != 0) {
          ++p;
        }
        ++p; // skip over last byte of uleb128
        if (p > end) {
          if (trieDebug) VG_(debugLog)(4, "dyld_cache", "[TRIE] WRONG EDGE, TOO FAR\n");
          return NULL;
        }
      } else {
        if (trieDebug) VG_(debugLog)(4, "dyld_cache", "[TRIE] MATCHING\n");
        // the symbol so far matches this edge (child)
        // so advance to the child's node
        ++p;
        nodeOffset = read_uleb128(p, end, &error);
        if (error) {
          if (trieDebug) VG_(debugLog)(4, "dyld_cache", "[TRIE] ULEB2 FAILED\n");
          return NULL;
        }
        if (trieDebug) VG_(debugLog)(4, "dyld_cache", "[TRIE] READ ULEB2 nodeOffset=%llu\n", nodeOffset);
        if ((nodeOffset == 0) || ( &start[nodeOffset] > end)) {
          if (trieDebug) VG_(debugLog)(4, "dyld_cache", "[TRIE] WRONG OFFSET\n");
          return NULL;
        }
        path = ss;
        if (trieDebug) VG_(debugLog)(4, "dyld_cache", "[TRIE] NEW PATH path=%s\n", path);
        break;
      }
    }

    if (nodeOffset != 0) {
      if (nodeOffset > (uint64_t)(end - start)) {
        if (trieDebug) VG_(debugLog)(4, "dyld_cache", "[TRIE] OFFSET TOO FAR\n");
        return NULL;
      }
      for (int i = 0; i < visitedNodeOffsetCount; ++i) {
        if (visitedNodeOffsets[i] == nodeOffset) {
          if (trieDebug) VG_(debugLog)(4, "dyld_cache", "[TRIE] ALREADY VISITED OFFSET\n");
          return NULL;
        }
      }
      if (trieDebug) VG_(debugLog)(4, "dyld_cache", "[TRIE] MARKING OFFSET nodeOffset=%llu\n", nodeOffset);
      visitedNodeOffsets[visitedNodeOffsetCount++] = (uint32_t)nodeOffset;
      if (trieDebug) VG_(debugLog)(4, "dyld_cache", "[TRIE] NOW USING OFFSETS count=%d\n", visitedNodeOffsetCount);
      if (visitedNodeOffsetCount >= DYLD_TRIE_MAX_OFFSETS) {
        if (trieDebug) VG_(debugLog)(4, "dyld_cache", "[TRIE] TOO MANY OFFSETS\n");
        return NULL;
      }
      p = &start[nodeOffset];
      if (trieDebug) VG_(debugLog)(4, "dyld_cache", "[TRIE] JUMPING WITH OFFSET p=%p\n", p);
    } else {
      return NULL;
    }
  }
  return NULL;
}

static const DyldImage* get_image_for_path(const HChar* path) {
  vg_assert(dyld_cache.header != NULL);

  if (dyld_cache.mappings[0].fileOffset != 0) {
    VG_(debugLog)(2, "dyld_cache", "aborting get_image_for_path\n");
    return NULL;
  }

  if (dyld_cache.header->mappingOffset >= 0x118) {
    VG_(debugLog)(2, "dyld_cache", "preparing for trie walk\n");
    const uint8_t* trie_start = (uint8_t*)(dyld_cache.header->dylibsTrieAddr + dyld_cache.slide);
    const uint8_t* trie_end = trie_start + dyld_cache.header->dylibsTrieSize;

    const uint8_t* node = dyld_trie_walk(trie_start, trie_end, path);
    if (node != NULL) {
      int error;
      return get_image_for_index(read_uleb128(node, trie_end, &error) + 1);
    }
    return NULL;
  }

  VG_(debugLog)(2, "dyld_cache", "browsing images...\n");
  const dyld_cache_image_info* info;
  const char * found;
  for (uint32_t i = 0; i < dyld_cache.header->imagesCount; ++i) {
    info = &dyld_cache.images_old[i];
    found = get_dylib_path(info);
    VG_(debugLog)(3, "dyld_cache", "found: %s\n", found);
    if (VG_(strcmp)(found, path) == 0) {
      return get_image_for_index(i + 1);
    }
  }
  return NULL;
}

static const void* get_image_attribute(const DyldImage* image, DyldImageTypeAttribute attribute, uint32_t* size) {
  vg_assert(((Addr)image & 0x3) == 0);
  vg_assert(size != NULL);
  *size = 0;
  const DyldTypedBytes* start = (const DyldTypedBytes*) typed_bytes_payload((const DyldTypedBytes*)image);
  const DyldTypedBytes* end = typed_bytes_next((const DyldTypedBytes*)image);
  for (const DyldTypedBytes* p = start; p < end; p = typed_bytes_next(p)) {
    if (p->type == attribute) {
      *size = p->payloadLength;
      return typed_bytes_payload(p);
    }
  }
  return NULL;
}

static void track_macho_file(const HChar * path, Addr addr) {
  VG_(debugLog)(2, "dyld_cache", "found an image (%s) at %#lx\n", path, addr);
  const struct MACH_HEADER* hdr = (const struct MACH_HEADER *) addr;
  const vki_uint8_t * hdrbuf = (const vki_uint8_t *) addr;
  const struct load_command *lc, *lcend;
  const struct SEGMENT_COMMAND *segcmd;
  Addr seg_addr = 0;
  SizeT seg_size;
  SysRes res;

  // FIXME: would prefer to actually have the filename set on the created aspace segment
  // However we don't have an associated fd...
  ML_(notify_core_and_tool_of_mmap)(
    addr, sizeof(struct MACH_HEADER),
    VKI_PROT_READ | VKI_PROT_EXEC, VKI_MAP_ANON, -1, 0
  );

  VG_(debugLog)(3, "dyld_cache", "looking up __TEXT, __DATA and LC_UUID...\n");
  lcend = (const struct load_command *)(hdrbuf + hdr->sizeofcmds + sizeof(struct MACH_HEADER));
  for (lc = (const struct load_command *)(hdrbuf + sizeof(struct MACH_HEADER));
        lc < lcend;
        lc = (const struct load_command *)(lc->cmdsize + (const vki_uint8_t *)lc))
    {
      if ((const vki_uint8_t *)lc < hdrbuf  ||
          lc->cmdsize+(const vki_uint8_t *)lc > (const vki_uint8_t *)lcend) {
          VG_(dmsg)("bad executable (invalid load commands): %s\n", path);
          return;
      }

      switch (lc->cmd) {
      case LC_SEGMENT_CMD:
        if (lc->cmdsize < sizeof(struct SEGMENT_COMMAND)) {
          VG_(dmsg)("bad executable (invalid load commands): %s\n", path);
          return;
        }
        segcmd = (const struct SEGMENT_COMMAND *)lc;
        seg_addr = segcmd->vmaddr + dyld_cache.slide;
        seg_size = segcmd->vmsize;

        if (0 == VG_(strcmp)(segcmd->segname, SEG_TEXT)) {
          VG_(debugLog)(3, "dyld_cache", "tracking __TEXT (%#lx, %#lx)\n", seg_addr, seg_size);
          // ML_(notify_core_and_tool_of_mmap)(
          //   seg_addr, seg_size,
          //   VKI_PROT_READ | VKI_PROT_EXEC, VKI_MAP_ANON, -1, 0
          // );

          res = VG_(am_mmap_named_file_fixed_client_flags)(
            seg_addr, seg_size,
            VKI_PROT_READ | VKI_PROT_EXEC,
            VKI_MAP_FIXED | VKI_MAP_PRIVATE | VKI_MAP_ANONYMOUS,
            0, segcmd->fileoff, path
          );
          if (sr_isError(res)) {
            VG_(printf)("valgrind: mmap-FIXED(0x%llx, %lld) failed in dyld cache (__TEXT) "
                        "with error %lu (%s).\n",
                        (ULong)seg_addr, (Long)seg_size,
                        sr_Err(res), VG_(strerror)(sr_Err(res)) );
            VG_(exit)(1);
          }

          VG_(di_notify_mmap_in_memory)(path, addr, seg_addr, seg_size);
        } else if (0 == VG_(strcmp)(segcmd->segname, SEG_DATA)) {
          VG_(debugLog)(3, "dyld_cache", "tracking __DATA (%#lx, %#lx)\n", seg_addr, seg_size);

          if (!VG_IS_PAGE_ALIGNED(seg_addr)) {
            VG_(dmsg)("__DATA segment for %s is not page-aligned (%#lx)\n", path, seg_addr);
          } else {
            // TODO: redo like __TEXT?
            ML_(notify_core_and_tool_of_mmap)(
              seg_addr, seg_size,
              VKI_PROT_READ | VKI_PROT_WRITE, VKI_MAP_ANON, -1, 0
            );

            VG_(di_notify_mmap_in_memory)(path, addr, seg_addr, seg_size);
          }
        }

        break;
      case LC_UUID: {
        const struct uuid_command* uuidcmd = (const struct uuid_command *)lc;
        const UChar* uuid = uuidcmd->uuid;
        VG_(debugLog)(3, "dyld_cache", "found UUID: %02X%02X%02X%02X"
        "-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
        (UInt)uuid[0], (UInt)uuid[1], (UInt)uuid[2], (UInt)uuid[3],
        (UInt)uuid[4], (UInt)uuid[5], (UInt)uuid[6], (UInt)uuid[7],
        (UInt)uuid[8], (UInt)uuid[9], (UInt)uuid[10],
        (UInt)uuid[11], (UInt)uuid[12], (UInt)uuid[13],
        (UInt)uuid[14], (UInt)uuid[15]
        );
        break;
      }
    }
  }
}

int VG_(dyld_cache_check_and_register)(const HChar* path) {
  // If not init'd, there is no point trying
  if (dyld_cache.header == NULL) {
    return 0;
  }

  // Sanity check
  if (!VG_(dyld_cache_might_be_in)(path)) {
    return 0;
  }

  VG_(debugLog)(2, "dyld_cache", "potential dylib to check in the cache: %s\n", path);

  if (dyld_cache.header->formatVersion < DYLD_MINIMUM_FORMAT) {
    // Support for older cache format
    VG_(debugLog)(2, "dyld_cache", "using older file format\n");
    const dyld_cache_image_info* const start = dyld_cache.images_old;
    const dyld_cache_image_info* const end = &start[dyld_cache.header->imagesCount];
    const char * found;

    for (const dyld_cache_image_info* p = start; p != end; ++p) {
      found = get_dylib_path(p);
      VG_(debugLog)(3, "dyld_cache", "found: %s\n", found);
      if (VG_(strcmp)(found, path) == 0) {
        track_macho_file(path, (Addr)p->address + dyld_cache.slide);
        return 1;
      }
    }
    VG_(debugLog)(2, "dyld_cache", "no image found\n");
    return 0;
  }

  // check for older cache (again?)
  if (!dyld_cache.has_image_array) {
    VG_(debugLog)(2, "dyld_cache", "WARNING: missing image array with current format\n");
    return 0;
  }

  const DyldImage* image = get_image_for_path(path);
  if (image == NULL) {
    VG_(debugLog)(2, "dyld_cache", "not found, looking for potential symlinks...\n");
    // the path might be a symlink, try different approaches
    if (dyld_cache.header->dylibsExpectedOnDisk) {
      VG_(debugLog)(2, "dyld_cache", "...through inode/mtime\n");
      struct vg_stat buf;
      if (!sr_isError(VG_(stat)(path, &buf))) {
        const dyld_cache_image_info* const start = dyld_cache.images_old;
        const dyld_cache_image_info* const end = &start[dyld_cache.header->imagesCount];
        for (const dyld_cache_image_info* p = start; p != end; ++p) {
          // check if we have a matching inode and mtime in the cache
          if ((p->inode == buf.ino) && (p->modTime == buf.mtime)) {
            image = get_image_for_index(p - start);
            break;
          }
        }
      } else {
        VG_(debugLog)(2, "dyld_cache", "could not find dylib on disk\n");
      }
    } else {
      VG_(debugLog)(2, "dyld_cache", "...through realpath (unimplemented)\n");
      // TODO: redo get_image_for_path with the result of `realpath(path, ...)`, but I don't think that's possible?
    }
  }

  if (image == NULL) {
    VG_(debugLog)(2, "dyld_cache", "no image found\n");
    return 0;
  }

  uint32_t size;
  const DyldCacheSegment* segments = (const DyldCacheSegment*)get_image_attribute(image, imagetype_cacheSegment, &size);
  vg_assert(segments != NULL);
  vg_assert((size % sizeof(DyldCacheSegment)) == 0);
  track_macho_file(path, (Addr)dyld_cache.header + segments[0].cacheOffset);
  return 1;
}

#endif
