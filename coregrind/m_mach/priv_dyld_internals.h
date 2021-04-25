
/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

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
/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#if defined(VGO_darwin)

// This file contains a bunch of structure defined in Apple's dyld
// They are either reproduced as-is or a C++ conversion (`dyld_image_array` and `dyld_image`)

#include <stdlib.h>

// From Apple's `dyld-*/dyld3/SharedCacheRuntime.cpp`
#define CACHE_MAGIC_x86_64         "dyld_v1  x86_64"
#define CACHE_MAGIC_x86_64_HASWELL "dyld_v1 x86_64h"

// From Apple's `dyld-*/dyld3/Closure.h`: `dyld3::closure::kFormatVersion`
#define DYLD_MINIMUM_FORMAT 10

// From Apple's `dyld-*/dyld3/shared-cache/dyld_cache_format.h`
typedef struct {
	uint64_t	address;
	uint64_t	size;
	uint64_t	fileOffset;
	uint32_t	maxProt;
	uint32_t	initProt;
} dyld_cache_mapping_info;

typedef struct {
	uint64_t	address;
	uint64_t	modTime;
	uint64_t	inode;
	uint32_t	pathFileOffset;
	uint32_t	pad;
} dyld_cache_image_info;

typedef struct {
	uuid_t		uuid;
	uint64_t	loadAddress;			// unslid address of start of __TEXT
	uint32_t	textSegmentSize;
	uint32_t	pathOffset;				// offset from start of cache file
} dyld_cache_image_text_info;

typedef struct {
  char        magic[16];              // e.g. "dyld_v0    i386"
  uint32_t    mappingOffset;          // file offset to first dyld_cache_mapping_info
  uint32_t    mappingCount;           // number of dyld_cache_mapping_info entries
  uint32_t    imagesOffset;           // file offset to first dyld_cache_image_info
  uint32_t    imagesCount;            // number of dyld_cache_image_info entries
  uint64_t    dyldBaseAddress;        // base address of dyld when cache was built
  uint64_t    codeSignatureOffset;    // file offset of code signature blob
  uint64_t    codeSignatureSize;      // size of code signature blob (zero means to end of file)
  uint64_t    slideInfoOffset;        // file offset of kernel slid info
  uint64_t    slideInfoSize;          // size of kernel slid info
  uint64_t    localSymbolsOffset;     // file offset of where local symbols are stored
  uint64_t    localSymbolsSize;       // size of local symbols information
  uint8_t     uuid[16];               // unique value for each shared cache file
  uint64_t    cacheType;              // 0 for development, 1 for production
  uint32_t    branchPoolsOffset;      // file offset to table of uint64_t pool addresses
  uint32_t    branchPoolsCount;       // number of uint64_t entries
  uint64_t    accelerateInfoAddr;     // (unslid) address of optimization info
  uint64_t    accelerateInfoSize;     // size of optimization info
  uint64_t    imagesTextOffset;       // file offset to first dyld_cache_image_text_info
  uint64_t    imagesTextCount;        // number of dyld_cache_image_text_info entries
  uint64_t    dylibsImageGroupAddr;   // (unslid) address of ImageGroup for dylibs in this cache
  uint64_t    dylibsImageGroupSize;   // size of ImageGroup for dylibs in this cache
  uint64_t    otherImageGroupAddr;    // (unslid) address of ImageGroup for other OS dylibs
  uint64_t    otherImageGroupSize;    // size of oImageGroup for other OS dylibs
  uint64_t    progClosuresAddr;       // (unslid) address of list of program launch closures
  uint64_t    progClosuresSize;       // size of list of program launch closures
  uint64_t    progClosuresTrieAddr;   // (unslid) address of trie of indexes into program launch closures
  uint64_t    progClosuresTrieSize;   // size of trie of indexes into program launch closures
  uint32_t    platform;               // platform number (macOS=1, etc)
  uint32_t    formatVersion        : 8,  // dyld3::closure::kFormatVersion
              dylibsExpectedOnDisk : 1,  // dyld should expect the dylib exists on disk and to compare inode/mtime to see if cache is valid
              simulator            : 1,  // for simulator of specified platform
              locallyBuiltCache    : 1,  // 0 for B&I built cache, 1 for locally built cache
              padding              : 21; // TBD
  uint64_t    sharedRegionStart;      // base load address of cache if not slid
  uint64_t    sharedRegionSize;       // overall size of region cache can be mapped into
  uint64_t    maxSlide;               // runtime slide of cache can be between zero and this value
  uint64_t    dylibsImageArrayAddr;   // (unslid) address of ImageArray for dylibs in this cache
  uint64_t    dylibsImageArraySize;   // size of ImageArray for dylibs in this cache
  uint64_t    dylibsTrieAddr;         // (unslid) address of trie of indexes of all cached dylibs
  uint64_t    dylibsTrieSize;         // size of trie of cached dylib paths
  uint64_t    otherImageArrayAddr;    // (unslid) address of ImageArray for dylibs and bundles with dlopen closures
  uint64_t    otherImageArraySize;    // size of ImageArray for dylibs and bundles with dlopen closures
  uint64_t    otherTrieAddr;          // (unslid) address of trie of indexes of all dylibs and bundles with dlopen closures
  uint64_t    otherTrieSize;          // size of trie of dylibs and bundles with dlopen closures
} dyld_cache_header;

typedef struct {
  uint32_t    nlistOffset;        // offset into this chunk of nlist entries
  uint32_t    nlistCount;         // count of nlist entries
  uint32_t    stringsOffset;      // offset into this chunk of string pool
  uint32_t    stringsSize;        // byte count of string pool
  uint32_t    entriesOffset;      // offset into this chunk of array of dyld_cache_local_symbols_entry
  uint32_t    entriesCount;       // number of elements in dyld_cache_local_symbols_entry array
} dyld_cache_local_symbols_info;

typedef struct {
  uint32_t    dylibOffset;        // offset in cache file of start of dylib
  uint32_t    nlistStartIndex;    // start index of locals for this dylib
  uint32_t    nlistCount;         // number of local symbols for this dylib
} dyld_cache_local_symbols_entry;

// From Apple's `dyld-*/dyld3/Closure.h` (sometimes converted from C++)
typedef struct {
  uint64_t    cacheOffset : 32,
              size        : 28,
              permissions : 4;
} DyldCacheSegment;

typedef struct {
  uint32_t     type          : 8,
               payloadLength : 24;
} DyldTypedBytes;

typedef struct {
  // Inherited from DyldTypedBytes
  uint32_t     type          : 8,
               payloadLength : 24;
  //
  uint32_t     firstImageNum;
  uint32_t     count;
  uint32_t     offsets[];
} DyldImageArray;

typedef struct {
  // Inherited from DyldTypedBytes
  uint32_t     type          : 8,
               payloadLength : 24;
  //
} DyldImage;

typedef enum {
  imagetype_launchClosure    =  1, // contains TypedBytes of closure attributes including imageArray
  imagetype_imageArray       =  2, // sizeof(ImageArray) + sizeof(uint32_t)*count + size of all images
  imagetype_image            =  3, // contains TypedBytes of image attributes
  imagetype_dlopenClosure    =  4, // contains TypedBytes of closure attributes including imageArray

  // attributes for Images
  imagetype_imageFlags       =  7, // sizeof(Image::Flags)
  imagetype_pathWithHash     =  8, // len = uint32_t + length path + 1, use multiple entries for aliases
  imagetype_fileInodeAndTime =  9, // sizeof(FileInfo)
  imagetype_cdHash           = 10, // 20
  imagetype_uuid             = 11, // 16
  imagetype_mappingInfo      = 12, // sizeof(MappingInfo)
  imagetype_diskSegment      = 13, // sizeof(DiskSegment) * count
  imagetype_cacheSegment     = 14, // sizeof(DyldCacheSegment) * count
  imagetype_dependents       = 15, // sizeof(LinkedImage) * count
  imagetype_initOffsets      = 16, // sizeof(uint32_t) * count
  imagetype_dofOffsets       = 17, // sizeof(uint32_t) * count
  imagetype_codeSignLoc      = 18, // sizeof(CodeSignatureLocation)
  imagetype_fairPlayLoc      = 19, // sizeof(FairPlayRange)
  imagetype_rebaseFixups     = 20, // sizeof(RebasePattern) * count
  imagetype_bindFixups       = 21, // sizeof(BindPattern) * count
  imagetype_cachePatchInfo   = 22, // sizeof(PatchableExport) + count*sizeof(PatchLocation) + strlen(name) // only in dyld cache Images
  imagetype_textFixups       = 23, // sizeof(TextFixupPattern) * count
  imagetype_imageOverride    = 24, // sizeof(ImageNum)
  imagetype_initBefores      = 25, // sizeof(ImageNum) * count
  imagetype_chainedFixupsStarts  = 26, // sizeof(uint64_t) * count
  imagetype_chainedFixupsTargets = 27, // sizeof(ResolvedSymbolTarget) * count

  // attributes for Closures (launch or dlopen)
  imagetype_closureFlags     = 32,  // sizeof(Closure::Flags)
  imagetype_dyldCacheUUID    = 33,  // 16
  imagetype_missingFiles     = 34,
  imagetype_envVar           = 35,  // "DYLD_BLAH=stuff"
  imagetype_topImage         = 36,  // sizeof(ImageNum)
  imagetype_libDyldEntry     = 37,  // sizeof(ResolvedSymbolTarget)
  imagetype_libSystemNum     = 38,  // sizeof(ImageNum)
  imagetype_bootUUID         = 39,  // c-string 40
  imagetype_mainEntry        = 40,  // sizeof(ResolvedSymbolTarget)
  imagetype_startEntry       = 41,  // sizeof(ResolvedSymbolTarget)     // used by programs built with crt1.o
  imagetype_cacheOverrides   = 42,  // sizeof(PatchEntry) * count       // used if process uses interposing or roots (cached dylib overrides)
  imagetype_interposeTuples  = 43,  // sizeof(InterposingTuple) * count
} DyldImageTypeAttribute;

#endif
