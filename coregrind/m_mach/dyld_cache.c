
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
#include "pub_tool_mallocfree.h"            // VG_(malloc)(), VG_(free)()
#include "pub_core_transtab.h"              // VG_(discard_translations)
#include "pub_core_tooliface.h"             // VG_TRACK
#include "vki/vki-scnums-darwin.h"          // __NR_shared_region_check_np
#include "priv_dyld_internals.h"            // CACHE_MAGIC_*, dyld_cache_header

// FIXME: probably shouldn't include this directly?
#include "m_aspacemgr/priv_aspacemgr.h" // ML_(am_do_munmap_NO_NOTIFY)
#include "m_syswrap/priv_syswrap-generic.h" // ML_(notify_core_and_tool_of_mmap)

#include <mach-o/loader.h>
#include <mach-o/nlist.h>

// Only supported on macOS 11 onwards which is 64bit only
# define MACH_HEADER mach_header_64
# define LC_SEGMENT_CMD LC_SEGMENT_64
# define SEGMENT_COMMAND segment_command_64
# define SECTION section_64
# define NLIST nlist_64

typedef struct {
  const dyld_cache_header* header;
  Addr slide;
  const dyld_cache_mapping_info* mappings;
  int has_image_array;
  const dyld_cache_image_info* images_old;
  const DyldImageArray* images_new;
  const dyld_cache_local_symbols_info* local_syms_info;
  const dyld_cache_local_symbols_entry* local_syms_entries;
  const struct NLIST* local_nlists;
  const char* local_strings;
} DYLDCache;

static DYLDCache dyld_cache = {
  .header = NULL,
  .slide = 0,
  .mappings = NULL,
  .has_image_array = 0,
  .images_old = NULL,
  .images_new = NULL,
  .local_syms_info = NULL,
  .local_syms_entries = NULL,
  .local_nlists = NULL,
  .local_strings = NULL,
};

// This file is inspired by Apple's dyld sources:
//  * `findInSharedCacheImage`/`reuseExistingCache` in `dyld-*/dyld3/SharedCacheRuntime.cpp`
//  * `hasImagePath` in `dyld-*/dyld3/shared-cache/DyldSharedCache.cpp`
//  * `ImageArray`/`Image`/`TypedBytes` in `dyld-*/dyld3/Closure.cpp`
//  * `cacheablePath` in `dyld-*/src/dyld.cpp`

// Sometimes we need to trigger the same behavior has mmap on non-mmap'd regions
// e.g. the trie inside the dyld cache which we want to mark as readable to avoid warnings
// Technically only does `notify_tool_of_mmap` at the moment
static void lenient_notify_core_and_tool_of_mmap(
  Addr a, SizeT len, UInt prot,
  UInt flags, Int fd, Off64T offset
) {
  Bool rr, ww, xx;

  len = VG_PGROUNDUP(len);

  rr = toBool(prot & VKI_PROT_READ);
  ww = toBool(prot & VKI_PROT_WRITE);
  xx = toBool(prot & VKI_PROT_EXEC);
  VG_TRACK( new_mem_mmap, a, len, rr, ww, xx, 0 );
}

static void output_debug_info() {
  VG_(debugLog)(4, "dyld_cache",
    "shared dyld content: {\n"
    "  .magic: %s,\n"
    "  .mappingOffset: %#x,\n"
    "  .mappingCount: %u,\n"
    "  .imagesOffset: %#x,\n"
    "  .imagesCount: %u,\n"
    "  .dyldBaseAddress: %#llx,\n"
    "  .codeSignatureOffset: %#llx,\n"
    "  .codeSignatureSize: %llu,\n"
    "  .slideInfoOffset: %#llx,\n"
    "  .slideInfoSize: %llu,\n"
    "  .localSymbolsOffset: %#llx,\n"
    "  .localSymbolsSize: %llu,\n"
    "  .cacheType: %llu,\n"
    "  .branchPoolsOffset: %#x,\n"
    "  .branchPoolsCount: %u,\n"
    "  .accelerateInfoAddr: %#llx,\n"
    "  .accelerateInfoSize: %llu,\n"
    "  .imagesTextOffset: %#llx,\n"
    "  .imagesTextCount: %llu,\n"
    "  .dylibsImageGroupAddr: %#llx,\n"
    "  .dylibsImageGroupSize: %llu,\n"
    "  .otherImageGroupAddr: %#llx,\n"
    "  .otherImageGroupSize: %llu,\n"
    "  .progClosuresAddr: %#llx,\n"
    "  .progClosuresSize: %llu,\n"
    "  .progClosuresTrieAddr: %#llx,\n"
    "  .progClosuresTrieSize: %llu,\n"
    "  .platform: %u,\n"
    "  .formatVersion: %d,\n"
    "  .dylibsExpectedOnDisk: %d,\n"
    "  .simulator: %d,\n"
    "  .locallyBuiltCache: %d,\n"
    "  .padding: %d,\n"
    "  .sharedRegionStart: %#llx,\n"
    "  .sharedRegionSize: %llu,\n"
    "  .maxSlide: %#llx,\n"
    "  .dylibsImageArrayAddr: %#llx,\n"
    "  .dylibsImageArraySize: %llu,\n"
    "  .dylibsTrieAddr: %#llx,\n"
    "  .dylibsTrieSize: %llu,\n"
    "  .otherImageArrayAddr: %#llx,\n"
    "  .otherImageArraySize: %llu,\n"
    "  .otherTrieAddr: %#llx,\n"
    "  .otherTrieSize: %llu,\n"
    "}\n",
    dyld_cache.header->magic,
    dyld_cache.header->mappingOffset,
    dyld_cache.header->mappingCount,
    dyld_cache.header->imagesOffset,
    dyld_cache.header->imagesCount,
    dyld_cache.header->dyldBaseAddress,
    dyld_cache.header->codeSignatureOffset,
    dyld_cache.header->codeSignatureSize,
    dyld_cache.header->slideInfoOffset,
    dyld_cache.header->slideInfoSize,
    dyld_cache.header->localSymbolsOffset,
    dyld_cache.header->localSymbolsSize,
    dyld_cache.header->cacheType,
    dyld_cache.header->branchPoolsOffset,
    dyld_cache.header->branchPoolsCount,
    dyld_cache.header->accelerateInfoAddr,
    dyld_cache.header->accelerateInfoSize,
    dyld_cache.header->imagesTextOffset,
    dyld_cache.header->imagesTextCount,
    dyld_cache.header->dylibsImageGroupAddr,
    dyld_cache.header->dylibsImageGroupSize,
    dyld_cache.header->otherImageGroupAddr,
    dyld_cache.header->otherImageGroupSize,
    dyld_cache.header->progClosuresAddr,
    dyld_cache.header->progClosuresSize,
    dyld_cache.header->progClosuresTrieAddr,
    dyld_cache.header->progClosuresTrieSize,
    dyld_cache.header->platform,
    dyld_cache.header->formatVersion,
    dyld_cache.header->dylibsExpectedOnDisk,
    dyld_cache.header->simulator,
    dyld_cache.header->locallyBuiltCache,
    dyld_cache.header->padding,
    dyld_cache.header->sharedRegionStart,
    dyld_cache.header->sharedRegionSize,
    dyld_cache.header->maxSlide,
    dyld_cache.header->dylibsImageArrayAddr,
    dyld_cache.header->dylibsImageArraySize,
    dyld_cache.header->dylibsTrieAddr,
    dyld_cache.header->dylibsTrieSize,
    dyld_cache.header->otherImageArrayAddr,
    dyld_cache.header->otherImageArraySize,
    dyld_cache.header->otherTrieAddr,
    dyld_cache.header->otherTrieSize
  );
}

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
  output_debug_info();

  // Mark the header itself
  ML_(notify_core_and_tool_of_mmap)(
    cache_address, sizeof(*dyld_cache.header),
    VKI_PROT_READ, VKI_MAP_ANON, -1, 0
  );

  // Mark the mappings
  // not aligned
  lenient_notify_core_and_tool_of_mmap(
    cache_address + dyld_cache.header->mappingOffset,
    sizeof(dyld_cache_mapping_info) * dyld_cache.header->mappingCount,
    VKI_PROT_READ, VKI_MAP_ANON, -1, 0
  );

  vg_assert(dyld_cache.header->mappingCount == 3);

  dyld_cache.mappings = (const dyld_cache_mapping_info*)(cache_address + dyld_cache.header->mappingOffset);
  dyld_cache.slide = cache_address - (Addr)dyld_cache.mappings[0].address;

  for (int i = 0; i < dyld_cache.header->mappingCount; ++i) {
    VG_(debugLog)(4, "dyld_cache",
      "mapping[%d]{"
      "  .address: %#llx,\n"
      "  .size: %llu,\n"
      "  .fileOffset: %#llx,\n"
      "  .maxProt: %#x,\n"
      "  .initProt: %#x,\n"
      "}\n",
      i,
      dyld_cache.mappings[i].address,
      dyld_cache.mappings[i].size,
      dyld_cache.mappings[i].fileOffset,
      dyld_cache.mappings[i].maxProt,
      dyld_cache.mappings[i].initProt
    );
  }

  // FIXME: too big
  // lenient_notify_core_and_tool_of_mmap(
  //   dyld_cache.mappings[0].address, dyld_cache.mappings[0].size,
  //   VKI_PROT_READ | VKI_PROT_EXEC, VKI_MAP_ANON, -1, 0
  // );
  lenient_notify_core_and_tool_of_mmap(
    dyld_cache.mappings[1].address, dyld_cache.mappings[1].size,
    VKI_PROT_READ | VKI_PROT_WRITE, VKI_MAP_ANON, -1, 0
  );
  // lenient_notify_core_and_tool_of_mmap(
  //   dyld_cache.mappings[2].address, dyld_cache.mappings[2].size,
  //   VKI_PROT_READ, VKI_MAP_ANON, -1, 0
  // );

  // Mark the images
  // not aligned
  lenient_notify_core_and_tool_of_mmap(
    cache_address + dyld_cache.header->imagesOffset,
    sizeof(dyld_cache_image_info) * dyld_cache.header->imagesCount,
    VKI_PROT_READ, VKI_MAP_ANON, -1, 0
  );

  //0x7fff800320ac

  dyld_cache.has_image_array = dyld_cache.header->mappingOffset >= 0x100 && dyld_cache.header->dylibsImageArrayAddr != 0;
  dyld_cache.images_old = (const dyld_cache_image_info*)(cache_address + dyld_cache.header->imagesOffset);
  if (dyld_cache.has_image_array) {
    dyld_cache.images_new = (const DyldImageArray*)(cache_address + (dyld_cache.header->dylibsImageArrayAddr - dyld_cache.mappings[0].address));

    // not aligned
    lenient_notify_core_and_tool_of_mmap(
      (Addr)dyld_cache.images_new,
      sizeof(DyldTypedBytes) + dyld_cache.images_new->payloadLength,
      VKI_PROT_READ, VKI_MAP_ANON, -1, 0
    );

    if (dyld_cache.mappings[0].fileOffset == 0 && dyld_cache.header->mappingOffset >= 0x118) {
      // not aligned
      lenient_notify_core_and_tool_of_mmap(
        (Addr)dyld_cache.header->dylibsTrieAddr + dyld_cache.slide,
        dyld_cache.header->dylibsTrieSize,
        VKI_PROT_READ, VKI_MAP_ANON, -1, 0
      );
    }
  }

  if (dyld_cache.header->localSymbolsOffset != 0 && dyld_cache.header->mappingOffset > offsetof(dyld_cache_header, localSymbolsSize)) {
    dyld_cache.local_syms_info = (const dyld_cache_local_symbols_info*) ((Addr) dyld_cache.header + dyld_cache.header->localSymbolsOffset);
    dyld_cache.local_syms_entries = (const dyld_cache_local_symbols_entry*) ((Addr) dyld_cache.local_syms_info + dyld_cache.local_syms_info->entriesOffset);
    dyld_cache.local_nlists = (const struct NLIST*) ((Addr) dyld_cache.local_syms_info + dyld_cache.local_syms_info->nlistOffset);
    dyld_cache.local_strings = (const char*) ((Addr) dyld_cache.local_syms_info + dyld_cache.local_syms_info->stringsOffset);

    lenient_notify_core_and_tool_of_mmap(
      (Addr)dyld_cache.local_syms_info,
      dyld_cache.header->localSymbolsSize,
      VKI_PROT_READ, VKI_MAP_ANON, -1, 0
    );
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
  int i = 0, j = 0;

  {
    const struct MACH_HEADER* hdr = (const struct MACH_HEADER *) addr;

    VG_(debugLog)(2, "dyld_cache", "found an image (%s) at %#lx\n", path, addr);
    // FIXME: would prefer to actually have the filename set on the created aspace segment
    // However we don't have an associated fd...
    ML_(notify_core_and_tool_of_mmap)(
      addr, sizeof(struct MACH_HEADER) + hdr->sizeofcmds,
      VKI_PROT_READ, VKI_MAP_ANON, -1, 0
    );
  }

  Addr linkEditBase = 0;
  const struct NLIST* local_nlists = NULL;
  SizeT local_nlists_size = 0;
  SizeT size = 0, le_size = 0, syms_count = 0, strpool_size = 0;
  {
    const struct load_command * lc = (const struct load_command *) (addr + sizeof(struct MACH_HEADER));

    VG_(debugLog)(3, "dyld_cache", "calculating copy's size...\n");
    for (i = 0; i < ((const struct MACH_HEADER *) addr)->ncmds; ++i) {
      switch (lc->cmd) {
      case LC_SEGMENT_CMD:
        if (lc->cmdsize < sizeof(struct SEGMENT_COMMAND)) {
          VG_(dmsg)("bad executable (invalid load commands): %s\n", path);
          return;
        }
        const struct SEGMENT_COMMAND *segcmd = (const struct SEGMENT_COMMAND *) lc;
        if (0 != VG_(strcmp)(segcmd->segname, "__LINKEDIT")) {
          size += segcmd->filesize;
        } else {
          linkEditBase = segcmd->vmaddr + dyld_cache.slide - segcmd->fileoff;
        }
        if (0 == VG_(strcmp)(segcmd->segname, "__TEXT")) {
          if (dyld_cache.local_syms_info != NULL) {
            for (j = 0; j < dyld_cache.local_syms_info->entriesCount; ++j) {
              const dyld_cache_local_symbols_entry* entry = &dyld_cache.local_syms_entries[i];
              if (entry->dylibOffset == segcmd->fileoff) {
                local_nlists = &dyld_cache.local_nlists[entry->nlistStartIndex];
                local_nlists_size = entry->nlistCount;
                break;
              }
            }
          }
        }
        break;

      case LC_DATA_IN_CODE:
      case LC_FUNCTION_STARTS:
        if (lc->cmdsize < sizeof(struct linkedit_data_command)) {
          VG_(dmsg)("bad executable (invalid load commands): %s\n", path);
          return;
        }
        const struct linkedit_data_command * le = (const struct linkedit_data_command *) lc;
        le_size += le->datasize;
        le_size = VG_ROUNDUP(le_size, sizeof(uint_t));
        break;

      case LC_SYMTAB:
        if (lc->cmdsize < sizeof(struct symtab_command)) {
          VG_(dmsg)("bad executable (invalid load commands): %s\n", path);
          return;
        }
        const struct symtab_command *symtab = (const struct symtab_command *) lc;
        const struct NLIST* s = NULL;
        const struct NLIST* syms_start = (struct NLIST*) ((Addr) dyld_cache.header + symtab->symoff);
        const struct NLIST* syms_end = &syms_start[symtab->nsyms];
        syms_count = symtab->nsyms;
        if (local_nlists_size != 0) {
          syms_count = local_nlists_size;
          for (s = syms_start; s != syms_end; ++s) {
            if ((s->n_type & (N_TYPE|N_EXT)) == N_SECT) {
              continue;
            }
            ++syms_count;
          }
        }
        // FIXME: extremely hacky but allows to avoid iterating over all symbols twice, might break catastrophically later
        strpool_size = syms_count * 255 + 1;
        strpool_size = VG_ROUNDUP(strpool_size, sizeof(uint_t));
        le_size += syms_count * sizeof(struct NLIST) + strpool_size;
        break;

      case LC_DYSYMTAB:
        if (lc->cmdsize < sizeof(struct dysymtab_command)) {
          VG_(dmsg)("bad executable (invalid load commands): %s\n", path);
          return;
        }
        const struct dysymtab_command *dysymtab = (const struct dysymtab_command *) lc;
        le_size += dysymtab->nindirectsyms;

      case LC_REEXPORT_DYLIB:
        // FIXME: finish exports symbols
        // exports_size += 1;
        break;

      case LC_UUID: {
        if (lc->cmdsize < sizeof(struct uuid_command)) {
          VG_(dmsg)("bad executable (invalid command): %s\n", path);
          return;
        }
        const struct uuid_command* uuidcmd = (const struct uuid_command *) lc;
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
      lc = (const struct load_command *) ((Addr) lc + lc->cmdsize);
    }

    size += le_size;
  }

  // Make a copy of the image in memory...
  Addr macho_map;
  {
    Addr offset = 0;
    SysRes res;
    const struct load_command * lc = (const struct load_command *) (addr + sizeof(struct MACH_HEADER));

    size = VG_PGROUNDUP(size);
    VG_(debugLog)(3, "dyld_cache", "making copy (%lu bytes)...\n", size);
    res = VG_(am_do_mmap_NO_NOTIFY)(0, size, VKI_PROT_READ | VKI_PROT_WRITE, VKI_MAP_ANON, -1, 0);
    if (sr_isError(res)) {
      VG_(printf)("valgrind: mmap(%lu) failed in dyld cache (Mach-O) "
                  "with error %lu (%s).\n",
                  size,
                  sr_Err(res), VG_(strerror)(sr_Err(res)));
      VG_(exit)(1);
    }
    macho_map = sr_Res(res);

    // From dyld-*/launch-cache/dsc_extractor.cpp
    // Copy all segments but __LINKEDIT, which is handled separately
    VG_(debugLog)(3, "dyld_cache", "copying segments...\n");
    for (i = 0; i < ((const struct MACH_HEADER *) addr)->ncmds; ++i) {
      switch (lc->cmd) {
      case LC_SEGMENT_CMD:
        if (lc->cmdsize < sizeof(struct SEGMENT_COMMAND)) {
          VG_(dmsg)("bad executable (invalid load commands): %s\n", path);
          return;
        }
        const struct SEGMENT_COMMAND *segcmd = (const struct SEGMENT_COMMAND *) lc;

        if (0 == VG_(strcmp)(segcmd->segname, "__LINKEDIT")) {
          continue;
        }

        // Faulting address: 0x7FFF7FFD5F40
        // Faulting address: 0x7FFF7FFD42A0
        if ((Addr) dyld_cache.header + segcmd->fileoff + segcmd->filesize > 0x7FFF7FFD0000) {
          VG_(dmsg)("WHY ISN'T IT WORKING??: %s\n", path);
          return;
        }

        VG_(memcpy)((void*) (macho_map + offset), (const void*) ((Addr) dyld_cache.header + segcmd->fileoff), segcmd->filesize);
        VG_(debugLog)(4, "dyld_cache", "copying SEGMENT_CMD to %lx (%llu bytes)\n", offset, segcmd->filesize);
        offset += segcmd->filesize;
        break;
      }
      lc = (const struct load_command *) ((Addr) lc + lc->cmdsize);
    }
  }

  // ... then fix it up so that it looks like it was actually loaded from file
  // Also copy the linkedit data
  const struct SEGMENT_COMMAND *seg_text, *seg_data;
  struct SEGMENT_COMMAND *seg_edit;
  {
    struct MACH_HEADER* mh = (struct MACH_HEADER*) macho_map;
    Addr le_offset = 0;
    SizeT cumulative_size = 0;
    SizeT remaining_bytes = mh->sizeofcmds;
    SizeT removed_commands = 0;

    // FIXME: finish exports symbols
    // SizeT dep_index = 0;
    // SizeT exports_index = 0;
    // Addr exports_trie_off = 0;
    // SizeT exports_trie_size = 0;
    // // FIXME: might leak
    // SizeT* exports = VG_(malloc) ("dyld_cache.tmf.exp", sizeof(SizeT) * exports_size);

    struct load_command * lc = (struct load_command *) ((Addr) mh + sizeof(*mh));

    mh->flags &= 0x7FFFFFFF;

    VG_(debugLog)(3, "dyld_cache", "fixing up copy\n");
    // From dyld-*/launch-cache/dsc_extractor.cpp
    for (i = 0; i < mh->ncmds; ++i) {
      int remove = 0;

      switch (lc->cmd) {
      case LC_SEGMENT_CMD:
        if (lc->cmdsize < sizeof(struct SEGMENT_COMMAND)) {
          VG_(dmsg)("bad executable (invalid load commands): %s\n", path);
          return;
        }
        struct SEGMENT_COMMAND *segcmd = (struct SEGMENT_COMMAND *) lc;

        segcmd->fileoff = cumulative_size;
        segcmd->filesize = segcmd->vmsize;

        struct SECTION *section = (struct SECTION *) ((Addr) segcmd + sizeof(*segcmd));
        struct SECTION *end = &section[segcmd->nsects];
        for (; section < end; ++section) {
          if (section->offset != 0) {
            section->offset = cumulative_size + section->addr - segcmd->vmaddr;
          }
        }

        if (0 == VG_(strcmp)(segcmd->segname, "__LINKEDIT")) {
          VG_(debugLog)(3, "dyld_cache", "found __LINKEDIT\n");
          seg_edit = segcmd;
        } else if (0 == VG_(strcmp)(segcmd->segname, "__TEXT")) {
          VG_(debugLog)(3, "dyld_cache", "found __TEXT\n");
          seg_text = segcmd;
        } else if (0 == VG_(strcmp)(segcmd->segname, "__DATA")) {
          VG_(debugLog)(3, "dyld_cache", "found __DATA\n");
          seg_data = segcmd;
        }

        cumulative_size += segcmd->filesize;
      break;

      case LC_DYLD_INFO_ONLY:
        if (lc->cmdsize < sizeof(struct dyld_info_command)) {
          VG_(dmsg)("bad executable (invalid load commands): %s\n", path);
          return;
        }
        struct dyld_info_command *dyldcmd = (struct dyld_info_command *) lc;
        // FIXME: finish exports symbols
        // exports_trie_off = dyldcmd->export_off;
        // exports_trie_size = dyldcmd->export_size;
        dyldcmd->rebase_off = 0;
        dyldcmd->rebase_size = 0;
        dyldcmd->bind_off = 0;
        dyldcmd->bind_size = 0;
        dyldcmd->weak_bind_off = 0;
        dyldcmd->weak_bind_size = 0;
        dyldcmd->lazy_bind_off = 0;
        dyldcmd->lazy_bind_size = 0;
        dyldcmd->export_off = 0;
        dyldcmd->export_size = 0;
        break;

      case LC_DYLD_EXPORTS_TRIE: {
        if (lc->cmdsize < sizeof(struct linkedit_data_command)) {
          VG_(dmsg)("bad executable (invalid load commands): %s\n", path);
          return;
        }
        struct linkedit_data_command *le = (struct linkedit_data_command *) lc;
        // FIXME: finish exports symbols
        // exports_trie_off = le->dataoff;
        // exports_trie_size = le->datasize;
        le->dataoff = 0;
        le->datasize = 0;
        break;
      }

      case LC_SYMTAB:
        if (lc->cmdsize < sizeof(struct symtab_command)) {
          VG_(dmsg)("bad executable (invalid load commands): %s\n", path);
          return;
        }
        struct symtab_command *symtab = (struct symtab_command *) lc;

        const struct NLIST* s = 0;
        const struct NLIST* syms_start = (struct NLIST*) ((Addr) linkEditBase + symtab->symoff);
        const struct NLIST* syms_end = &syms_start[symtab->nsyms];
        const char* strings_start = (const char*) ((Addr) linkEditBase + symtab->stroff);
        const char* strings_end = &strings_start[symtab->strsize];

        // FIXME: why is linkEditBase working but not the dyld way: dyld_cache.header + symtab->symoff?
        // VG_(debugLog)(3, "dyld_cache", "syms: %#lx -> %p + %#lx (sl: %#lx) vs %#lx -> %#lx + %#lx\n", (Addr) dyld_cache.header + symtab->symoff, dyld_cache.header, symtab->symoff, dyld_cache.slide, linkEditBase + symtab->symoff, linkEditBase, symtab->symoff);

        Addr syms_offset = macho_map + seg_edit->fileoff + le_offset;
        struct NLIST* sym_index = (struct NLIST*) syms_offset;

        Addr strpool_offset = syms_offset + syms_count * sizeof(struct NLIST);
        SizeT str_offset = 1;
        VG_(memset)((void *) strpool_offset, '\0', strpool_size);

        VG_(debugLog)(4, "dyld_cache", "copying SYMTAB(symbols) to %llx (%lu bytes)\n", seg_edit->fileoff + le_offset, syms_count * sizeof(struct NLIST));
        VG_(debugLog)(4, "dyld_cache", "copying SYMTAB(strings) to %llx (%lu bytes)\n", seg_edit->fileoff + le_offset + syms_count * sizeof(struct NLIST), strpool_size);

        for (s = syms_start; s != syms_end; ++s) {
          if (local_nlists != NULL && (s->n_type & (N_TYPE|N_EXT)) == N_SECT) {
            continue;
          }
          if ((Addr) sym_index >= strpool_offset) {
            VG_(dmsg)("bad executable (invalid symbols): %s\n", path);
            return;
          }

          VG_(memcpy)(sym_index, s, sizeof(*s));
          sym_index->n_un.n_strx = str_offset;

          SizeT len = 0;
          const char* symName = &strings_start[s->n_un.n_strx];
          if (symName > strings_end) {
            symName = "<corrupt symbol name>";
          }
          len = VG_(strlen)(symName) + 1;
          if (str_offset + len > strpool_size) {
            VG_(dmsg)("bad executable (invalid strings): %s\n", path);
            return;
          }
          VG_(debugLog)(4, "dyld_cache", "found symbol: %s\n", symName);
          VG_(memcpy)((void *) (strpool_offset + str_offset), symName, len);
          str_offset += len;
          ++sym_index;
        }

        for (j = 0; j < local_nlists_size; ++j) {
          if ((Addr) sym_index >= strpool_offset) {
            VG_(dmsg)("bad executable (invalid symbols): %s\n", path);
            return;
          }

          VG_(memcpy)(sym_index, &local_nlists[j], sizeof(*local_nlists));
          sym_index->n_un.n_strx = str_offset;

          const char* localName = &dyld_cache.local_strings[local_nlists[i].n_un.n_strx];
          if (localName > dyld_cache.local_strings + dyld_cache.local_syms_info->stringsSize) {
            localName = "<corrupt local symbol name>";
          }
          SizeT len = VG_(strlen)(localName) + 1;
          if (str_offset + len > strpool_size) {
            VG_(dmsg)("bad executable (invalid strings): %s\n", path);
            return;
          }
          VG_(debugLog)(4, "dyld_cache", "found local symbol: %s\n", localName);
          VG_(memcpy)((void *) (strpool_offset + str_offset), localName, len);
          str_offset += len;
          ++sym_index;
        }

        symtab->symoff = syms_offset - macho_map;
        symtab->nsyms = syms_count;
        symtab->stroff = strpool_offset - macho_map;
        symtab->strsize = strpool_size;
        seg_edit->filesize = symtab->stroff + symtab->strsize - seg_edit->fileoff;
        seg_edit->vmsize = (seg_edit->filesize + 4095) & (-4096); // FIXME: VG_ROUNDUP?

        le_offset += syms_count * sizeof(struct NLIST) + strpool_size;
        break;

      case LC_DYSYMTAB:
        if (lc->cmdsize < sizeof(struct dysymtab_command)) {
          VG_(dmsg)("bad executable (invalid load commands): %s\n", path);
          return;
        }
        if (seg_edit == 0) {
          VG_(dmsg)("bad executable (invalid load commands): %s\n", path);
          return;
        }
        struct dysymtab_command *dysymtab = (struct dysymtab_command *) lc;
        if (local_nlists_size != 0) {
          dysymtab->ilocalsym = syms_count;
          dysymtab->nlocalsym = local_nlists_size;
        }
        dysymtab->extreloff = 0;
        dysymtab->nextrel = 0;
        dysymtab->locreloff = 0;
        dysymtab->nlocrel = 0;
        dysymtab->indirectsymoff = seg_edit->fileoff + le_offset;

        if (seg_edit->fileoff + le_offset + dysymtab->nindirectsyms > size) {
          VG_(dmsg)("bad executable (invalid load commands): %s\n", path);
          return;
        }
        VG_(memcpy)((void*) (macho_map + seg_edit->fileoff + le_offset), (void*) ((Addr) dyld_cache.header + dysymtab->indirectsymoff), dysymtab->nindirectsyms);
        VG_(debugLog)(4, "dyld_cache", "copying DYSYMTAB to %llx (%d bytes)\n", seg_edit->fileoff + le_offset, dysymtab->nindirectsyms);
        le_offset += dysymtab->nindirectsyms;
        break;

      case LC_FUNCTION_STARTS:
      case LC_DATA_IN_CODE: {
        if (lc->cmdsize < sizeof(struct linkedit_data_command)) {
          VG_(dmsg)("bad executable (invalid load commands): %s\n", path);
          return;
        }
        if (seg_edit == 0) {
          VG_(dmsg)("bad executable (invalid load commands): %s\n", path);
          return;
        }
        struct linkedit_data_command * le = (struct linkedit_data_command *) lc;
        le->dataoff = seg_edit->fileoff + le_offset;
        if (seg_edit->fileoff + le_offset + le->datasize > size) {
          VG_(dmsg)("bad executable (invalid load commands): %s\n", path);
          return;
        }
        VG_(memcpy)((void*) (macho_map + seg_edit->fileoff + le_offset), (void*) ((Addr) dyld_cache.header + le->dataoff), le->datasize);
        VG_(debugLog)(4, "dyld_cache", "copying FUNCTION_STARTS/DATA_IN_CODE to %llx (%d bytes)\n", seg_edit->fileoff + le_offset, le->datasize);
        le_offset += le->datasize;
        break;
      }

      case LC_REEXPORT_DYLIB:
      case LC_LOAD_DYLIB:
      case LC_LOAD_WEAK_DYLIB:
      case LC_LOAD_UPWARD_DYLIB:
        // FIXME: finish exports symbols
        // ++dep_index;
        // if (lc->cmd == LC_REEXPORT_DYLIB) {
        //   if (exports_index >= exports_size) {
        //     VG_(dmsg)("bad executable (invalid load commands): %s\n", path);
        //     return;
        //   }
        //   exports[exports_index++] = dep_index;
        // }
        break;

      case LC_SEGMENT_SPLIT_INFO:
        remove = 1;
        break;
      }

      // Check if we need to delete the current command
      struct load_command * next = (struct load_command *) ((Addr) lc + lc->cmdsize);
      if (remove) {
        VG_(memmove)((void*) lc, (void*) next, remaining_bytes);
        VG_(debugLog)(4, "dyld_cache", "moving %lx to %lx (%lu bytes)\n", (Addr) next - macho_map, (Addr) lc - macho_map, remaining_bytes);
        removed_commands += 1;
      } else {
        remaining_bytes -= lc->cmdsize;
        lc = next;
      }
    }

    // Removed delete parts from the header
    VG_(memset)((void*) lc, 0, remaining_bytes);
    VG_(debugLog)(4, "dyld_cache", "zeroing %lx (%lu bytes)\n", (Addr) lc - macho_map, remaining_bytes);
    mh->ncmds = mh->ncmds - removed_commands;
    mh->sizeofcmds = mh->sizeofcmds - remaining_bytes;

    // TODO: process exports using:
    //  - exports_index as the size of exports, indicating the exports to keep
    //  - exports_trie_off/size defining the trie containing the exports
    //  - extract a definite list of the exports, get the size, copy it in syms/strs

    // FIXME: finish exports symbols
    // VG_(free)(exports);

    // Can be used to debug if the image is properly relocated
    if (1) {
      VG_(debugLog)(3, "dyld_cache", "writing debug...\n");
      SysRes res = VG_(open)("./debug.dylib", VKI_O_CREAT|VKI_O_WRONLY|VKI_O_TRUNC, VKI_S_IRUSR|VKI_S_IWUSR);
      VG_(write)(sr_Res(res), (void*) macho_map, size);
      if (1) {
        VG_(exit)(1);
      }
    }
  }

  if (seg_text == 0 || seg_data == 0) {
    VG_(dmsg)("bad executable (missing segments): %s\n", path);
    return;
  }

  // Pass the __TEXT from dyld_cache directly
  {
    Addr text_addr = macho_map + seg_text->fileoff;
    ML_(notify_core_and_tool_of_mmap)(
      text_addr, seg_text->filesize,
      VKI_PROT_READ | VKI_PROT_EXEC, VKI_MAP_ANON, -1, 0
    );
    VG_(di_notify_mmap_in_memory)(
      path, macho_map, size,
      text_addr, seg_text->filesize
    );
  }

  // Copy the __DATA so it can be made rw
  {
    SysRes res = VG_(am_do_mmap_NO_NOTIFY)(0, seg_data->filesize, VKI_PROT_READ | VKI_PROT_WRITE, VKI_MAP_ANON, -1, 0);
    if (sr_isError(res)) {
      VG_(printf)("valgrind: mmap(%lld) failed in dyld cache (__DATA) "
                  "with error %lu (%s).\n",
                  seg_data->filesize,
                  sr_Err(res), VG_(strerror)(sr_Err(res)));
      VG_(exit)(1);
    }
    Addr data_map = sr_Res(res);
    VG_(memcpy)((void*) data_map, (const void *) (macho_map + seg_data->fileoff), seg_data->filesize);

    ML_(notify_core_and_tool_of_mmap)(
      data_map, seg_data->filesize,
      VKI_PROT_READ | VKI_PROT_WRITE, VKI_MAP_ANON, -1, 0
    );
    VG_(di_notify_mmap_in_memory)(
      path, macho_map, size,
      data_map, seg_data->filesize
    );
  }

  // Unmap the header as all relevant data should have been copied now
  (void)ML_(am_do_munmap_NO_NOTIFY)(macho_map, size);
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
