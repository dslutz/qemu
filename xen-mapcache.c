/*
 * Copyright (C) 2011       Citrix Ltd.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "config.h"

#include <sys/resource.h>

#include "hw/xen/xen_backend.h"
#include "sysemu/blockdev.h"
#include "qemu/bitmap.h"

#include <xen/hvm/params.h>
#include <sys/mman.h>

#include "monitor/monitor.h"
#include "sysemu/xen-mapcache.h"
#include "trace.h"


#if defined(__i386__)
#  define MCACHE_BUCKET_SHIFT 16
#  define MCACHE_MAX_SIZE     (1UL<<31) /* 2GB Cap */
#  define DO_XEN_MAPCACHE_MUNMAP
#elif defined(__x86_64__)
#  define MCACHE_BUCKET_SHIFT 16
#  define MCACHE_MAX_SIZE     (1UL<<20) /* 1MB Cap */
#  define DO_BIG_ENTRY
#endif
#define MCACHE_BUCKET_SIZE (1UL << MCACHE_BUCKET_SHIFT)

/* This is the size of the virtual address space reserve to QEMU that will not
 * be use by MapCache.
 * From empirical tests I observed that qemu use 75MB more than the
 * max_mcache_size.
 */
#define NON_MCACHE_MEMORY_SIZE (80 * 1024 * 1024)

#define mapcache_lock()   ((void)0)
#define mapcache_unlock() ((void)0)

#define ERRI_MAX 4

typedef struct MapCacheEntry {
    hwaddr paddr_index;
    uint8_t *vaddr_base;
    unsigned long *valid_mapping;
    uint8_t lock;
    hwaddr size;
    struct MapCacheEntry *next;
    struct erri {
        int err_cnt;
        int err_idx;
    } erri[ERRI_MAX];
} MapCacheEntry;

typedef struct MapCacheRev {
    uint8_t *vaddr_req;
    hwaddr paddr_index;
    hwaddr size;
    MapCacheEntry *entry;
#ifdef DO_XEN_MAPCACHE_MUNMAP
    MapCacheEntry *pentry;
#endif
    QTAILQ_ENTRY(MapCacheRev) next;
} MapCacheRev;

typedef struct MapCache {
#ifdef DO_BIG_ENTRY
    MapCacheEntry bigEntry;
#endif
    MapCacheEntry *entry;
    unsigned long nr_buckets;
    QTAILQ_HEAD(map_cache_head, MapCacheRev) locked_entries;

    /* For most cases (>99.9%), the page address is the same. */
    MapCacheEntry *last_entry;
    unsigned long max_mcache_size;
    unsigned int mcache_bucket_shift;

    phys_offset_to_gaddr_t phys_offset_to_gaddr;
    void *opaque;
} MapCache;

static MapCache *mapcache;

static inline int test_bits(int nr, int size, const unsigned long *addr)
{
    unsigned long res = find_next_zero_bit(addr, size + nr, nr);
    if (res >= nr + size)
        return 1;
    else
        return 0;
}

void xen_map_cache_init(phys_offset_to_gaddr_t f, void *opaque)
{
    unsigned long size;
    struct rlimit rlimit_as;

    trace_xen_map_cache_init(f, opaque, MCACHE_BUCKET_SIZE);

    mapcache = g_malloc0(sizeof (MapCache));

    mapcache->phys_offset_to_gaddr = f;
    mapcache->opaque = opaque;

    QTAILQ_INIT(&mapcache->locked_entries);

    if (geteuid() == 0) {
        rlimit_as.rlim_cur = RLIM_INFINITY;
        rlimit_as.rlim_max = RLIM_INFINITY;
        mapcache->max_mcache_size = MCACHE_MAX_SIZE;
    } else {
        getrlimit(RLIMIT_AS, &rlimit_as);
        rlimit_as.rlim_cur = rlimit_as.rlim_max;

        if (rlimit_as.rlim_max != RLIM_INFINITY) {
            fprintf(stderr, "Warning: QEMU's maximum size of virtual"
                    " memory is not infinity.\n");
        }
        if (rlimit_as.rlim_max < MCACHE_MAX_SIZE + NON_MCACHE_MEMORY_SIZE) {
            mapcache->max_mcache_size = rlimit_as.rlim_max -
                NON_MCACHE_MEMORY_SIZE;
        } else {
            mapcache->max_mcache_size = MCACHE_MAX_SIZE;
        }
    }

    setrlimit(RLIMIT_AS, &rlimit_as);

    mapcache->nr_buckets =
        (((mapcache->max_mcache_size >> XC_PAGE_SHIFT) +
          (1UL << (MCACHE_BUCKET_SHIFT - XC_PAGE_SHIFT)) - 1) >>
         (MCACHE_BUCKET_SHIFT - XC_PAGE_SHIFT));

    size = mapcache->nr_buckets * sizeof (MapCacheEntry);
    size = (size + XC_PAGE_SIZE - 1) & ~(XC_PAGE_SIZE - 1);
    trace_xen_map_cache_init_1(mapcache->nr_buckets, size);
    mapcache->entry = g_malloc0(size);
}

static void xen_remap_bucket(MapCacheEntry *entry,
                             hwaddr size,
                             hwaddr address_index)
{
    uint8_t *vaddr_base;
    xen_pfn_t *pfns;
    int *err;
    unsigned int i;
    hwaddr nb_pfn = size >> XC_PAGE_SHIFT;
    int erri_idx = 0;

    trace_xen_remap_bucket(address_index, size);

    if (entry->vaddr_base != NULL) {
        if (entry->erri[0].err_cnt == 0 && size <= entry->size) {
            trace_xen_remap_bucket_5(entry->paddr_index, entry->size,
                                     entry->vaddr_base);
            return;
        }
        trace_xen_remap_bucket_3(address_index, entry->paddr_index,
                                 size, entry->size,
                                 entry->vaddr_base);
        if (munmap(entry->vaddr_base, entry->size) != 0) {
            perror("unmap fails");
            exit(-1);
        }
    }
    if (entry->valid_mapping != NULL) {
        g_free(entry->valid_mapping);
        entry->valid_mapping = NULL;
    }

    pfns = g_malloc0(nb_pfn * sizeof (xen_pfn_t));
    err = g_malloc0(nb_pfn * sizeof (int));

    for (i = 0; i < nb_pfn; i++) {
        pfns[i] = (address_index << (MCACHE_BUCKET_SHIFT-XC_PAGE_SHIFT)) + i;
    }

    vaddr_base = xc_map_foreign_bulk(xen_xc, xen_domid, PROT_READ|PROT_WRITE,
                                     pfns, err, nb_pfn);
    if (vaddr_base == NULL) {
        perror("xc_map_foreign_bulk");
        exit(-1);
    }

    entry->vaddr_base = vaddr_base;
    entry->paddr_index = address_index;
    entry->size = size;
    entry->valid_mapping = (unsigned long *) g_malloc0(sizeof(unsigned long) *
            BITS_TO_LONGS(size >> XC_PAGE_SHIFT));

    bitmap_zero(entry->valid_mapping, nb_pfn);
    for (i = 0; i < ERRI_MAX; i++) {
        entry->erri[0].err_cnt = 0;
        entry->erri[0].err_idx = -1;
    }
    erri_idx = 0;
    for (i = 0; i < nb_pfn; i++) {
        if (!err[i]) {
            bitmap_set(entry->valid_mapping, i, 1);
        } else {
            if (entry->erri[erri_idx].err_idx == -1) {
                entry->erri[erri_idx].err_idx = i;
            } else if ((entry->erri[erri_idx].err_idx > 0) &&
                     ((entry->erri[erri_idx].err_idx + entry->erri[erri_idx].err_cnt) != i)) {
                if (erri_idx < ERRI_MAX) {
                    erri_idx++;
                    entry->erri[erri_idx].err_idx = i;
                } else {
                    erri_idx = 0;
                    entry->erri[0].err_idx = -2;
                }
            }
            entry->erri[erri_idx].err_cnt++;
        }
    }
    trace_xen_remap_bucket_1(address_index, size, vaddr_base, erri_idx,
                             nb_pfn);
    for (i = 0; i < ERRI_MAX; i++) {
        if (!i || entry->erri[i].err_cnt)
            trace_xen_remap_bucket_6(i, entry->erri[i].err_cnt,
                                     entry->erri[i].err_idx);
        if (entry->erri[i].err_cnt) {
            if (entry->erri[i].err_idx < 0) {
                int j;

                for (j = 0; j < nb_pfn; j++) {
                    if (err[j]) {
                        trace_xen_remap_bucket_2(
                            ((hwaddr)pfns[j]) << XC_PAGE_SHIFT, j, err[j]);
                    }
                }
            } else {
                trace_xen_remap_bucket_4(
                    ((hwaddr)pfns[entry->erri[i].err_idx]) << XC_PAGE_SHIFT,
                    (((hwaddr)pfns[
                          entry->erri[i].err_idx + entry->erri[i].err_cnt - 1
                          ]) << XC_PAGE_SHIFT) + XC_PAGE_SIZE - 1,
                    err[entry->erri[i].err_idx]);
            }
        }
    }

    g_free(pfns);
    g_free(err);
}

uint8_t *xen_map_cache(hwaddr phys_addr, hwaddr size,
                       uint8_t lock)
{
    MapCacheEntry *entry, *pentry = NULL;
    hwaddr address_index;
    hwaddr address_offset;
    hwaddr __size = size;
    hwaddr __test_bit_size = size;
    bool translated = false;

#ifdef DO_BIG_ENTRY
    if (mapcache->bigEntry.vaddr_base == NULL) {
        xen_remap_bucket(&mapcache->bigEntry, phys_addr + size, 0);
    }
    if ((phys_addr < mapcache->bigEntry.size) &&
        ((phys_addr + size) <= mapcache->bigEntry.size)) {
        if (test_bits(phys_addr >> XC_PAGE_SHIFT,
                      size >> XC_PAGE_SHIFT,
                      mapcache->bigEntry.valid_mapping)) {
            trace_xen_map_cache_return_1(
                phys_addr, size, lock, mapcache->bigEntry.size,
                mapcache->bigEntry.vaddr_base,
                mapcache->bigEntry.vaddr_base + phys_addr);
            return mapcache->bigEntry.vaddr_base + phys_addr;
        }
    }
#endif

tryagain:
    address_index  = phys_addr >> MCACHE_BUCKET_SHIFT;
    address_offset = phys_addr & (MCACHE_BUCKET_SIZE - 1);

    trace_xen_map_cache(phys_addr, size, lock);

    /* __test_bit_size is always a multiple of XC_PAGE_SIZE */
    if (size) {
        __test_bit_size = size + (phys_addr & (XC_PAGE_SIZE - 1));

        if (__test_bit_size % XC_PAGE_SIZE) {
            __test_bit_size += XC_PAGE_SIZE - (__test_bit_size % XC_PAGE_SIZE);
        }
    } else {
        __test_bit_size = XC_PAGE_SIZE;
    }

    if (mapcache->last_entry != NULL &&
        mapcache->last_entry->paddr_index == address_index &&
        !lock && !__size &&
        test_bits(address_offset >> XC_PAGE_SHIFT,
                  __test_bit_size >> XC_PAGE_SHIFT,
                  mapcache->last_entry->valid_mapping)) {
        trace_xen_map_cache_return(mapcache->last_entry->vaddr_base + address_offset);
        return mapcache->last_entry->vaddr_base + address_offset;
    }

    /* size is always a multiple of MCACHE_BUCKET_SIZE */
    if (size) {
        __size = size + address_offset;
        if (__size % MCACHE_BUCKET_SIZE) {
            __size += MCACHE_BUCKET_SIZE - (__size % MCACHE_BUCKET_SIZE);
        }
    } else {
        __size = MCACHE_BUCKET_SIZE;
    }

#ifdef DO_BIG_ENTRY
    entry = &mapcache->entry[(address_index + (address_index >> 8)) % mapcache->nr_buckets];
#else
    entry = &mapcache->entry[address_index % mapcache->nr_buckets];
#endif

    while (entry && entry->lock && entry->vaddr_base &&
            (entry->paddr_index != address_index || entry->size < __size ||
             ((entry->erri[0].err_cnt != 0) &&
              !test_bits(address_offset >> XC_PAGE_SHIFT, size >> XC_PAGE_SHIFT,
                         entry->valid_mapping)))) {
        pentry = entry;
        entry = entry->next;
    }
    if (!entry) {
        entry = g_malloc0(sizeof (MapCacheEntry));
        pentry->next = entry;
        trace_xen_map_cache_1(phys_addr, address_index, size, __size, lock);
        xen_remap_bucket(entry, __size, address_index);
    } else if (!entry->lock) {
        if (!entry->vaddr_base || entry->paddr_index != address_index ||
                entry->size != __size ||
                !test_bits(address_offset >> XC_PAGE_SHIFT,
                    __test_bit_size >> XC_PAGE_SHIFT,
                    entry->valid_mapping)) {
            trace_xen_map_cache_2(phys_addr, address_index, size, __size, lock);
            xen_remap_bucket(entry, __size, address_index);
        }
    }

    if ((entry->erri[0].err_cnt != 0) &&
        !test_bits(address_offset >> XC_PAGE_SHIFT,
                   size >> XC_PAGE_SHIFT, entry->valid_mapping)) {
        mapcache->last_entry = NULL;
        if (!translated && mapcache->phys_offset_to_gaddr) {
            phys_addr = mapcache->phys_offset_to_gaddr(phys_addr, size,
                                                       mapcache->opaque);
            translated = true;
            pentry = NULL;
            goto tryagain;
        }
        trace_xen_map_cache_return(NULL);
        return NULL;
    }

    mapcache->last_entry = entry;
    if (lock) {
        MapCacheRev *reventry = g_malloc0(sizeof(MapCacheRev));
        entry->lock++;
        reventry->vaddr_req = mapcache->last_entry->vaddr_base + address_offset;
        reventry->paddr_index = mapcache->last_entry->paddr_index;
        reventry->size = entry->size;
        reventry->entry = entry;
#ifdef DO_XEN_MAPCACHE_MUNMAP
        reventry->pentry = pentry;
#endif
        QTAILQ_INSERT_HEAD(&mapcache->locked_entries, reventry, next);
    }

    trace_xen_map_cache_return(mapcache->last_entry->vaddr_base + address_offset);
    return mapcache->last_entry->vaddr_base + address_offset;
}

ram_addr_t xen_ram_addr_from_mapcache(void *ptr)
{
    MapCacheEntry *entry = NULL;
    MapCacheRev *reventry;
    int found = 0;
    int cost = 0;
#ifdef DO_BIG_ENTRY
    ram_addr_t ret = (uint8_t*)ptr - mapcache->bigEntry.vaddr_base;

    if (((uint8_t*)ptr >= mapcache->bigEntry.vaddr_base) &&
        (ret < mapcache->bigEntry.size)) {
        trace_xen_ram_addr_from_mapcache_4(ptr, ret);
        return ret;
    }
#else
    ram_addr_t ret;
#endif

    trace_xen_ram_addr_from_mapcache(ptr);

    QTAILQ_FOREACH(reventry, &mapcache->locked_entries, next) {
        cost++;
        if (reventry->vaddr_req == ptr) {
            entry = reventry->entry;
            found = 1;
            break;
        }
    }
    if (!found) {
        fprintf(stderr, "%s, could not find %p\n", __func__, ptr);
        trace_xen_ram_addr_from_mapcache_2(ptr);
        QTAILQ_FOREACH(reventry, &mapcache->locked_entries, next) {
            trace_xen_ram_addr_from_mapcache_1(reventry->paddr_index,
                                               reventry->vaddr_req);
        }
        abort();
        return 0;
    }

    ret = (reventry->paddr_index << MCACHE_BUCKET_SHIFT) +
        ((unsigned long) ptr - (unsigned long) entry->vaddr_base);
    trace_xen_ram_addr_from_mapcache_3(cost, ret);
    return ret;
}

void xen_invalidate_map_cache_entry(uint8_t *buffer)
{
    MapCacheEntry *entry = NULL;
#ifdef DO_XEN_MAPCACHE_MUNMAP
    MapCacheEntry *pentry = NULL;
#endif
    MapCacheRev *reventry;
    int found = 0;
    int cost = 0;

#ifdef DO_BIG_ENTRY
    if ((buffer >= mapcache->bigEntry.vaddr_base) &&
        ((buffer - mapcache->bigEntry.vaddr_base) < mapcache->bigEntry.size)) {
        trace_xen_invalidate_map_cache_entry_6(buffer);
        return;
    }
#endif
    trace_xen_invalidate_map_cache_entry(buffer);

    QTAILQ_FOREACH(reventry, &mapcache->locked_entries, next) {
        cost++;
        if (reventry->vaddr_req == buffer) {
            entry = reventry->entry;
#ifdef DO_XEN_MAPCACHE_MUNMAP
            pentry = reventry->pentry;
#endif
            found = 1;
            break;
        }
    }
    if (!found) {
        trace_xen_invalidate_map_cache_entry_1(buffer);
        QTAILQ_FOREACH(reventry, &mapcache->locked_entries, next) {
            trace_xen_invalidate_map_cache_entry_2(reventry->paddr_index,
                                                   reventry->vaddr_req);
        }
        return;
    }
    QTAILQ_REMOVE(&mapcache->locked_entries, reventry, next);
    g_free(reventry);

    if (mapcache->last_entry != NULL &&
        mapcache->last_entry->paddr_index == entry->paddr_index) {
        mapcache->last_entry = NULL;
    }

    entry->lock--;
#ifdef DO_XEN_MAPCACHE_MUNMAP
    if (entry->lock > 0 || pentry == NULL) {
        return;
    }

    pentry->next = entry->next;
    trace_xen_invalidate_map_cache_entry_4(entry->paddr_index, entry->size,
                                           entry->vaddr_base);
    if (munmap(entry->vaddr_base, entry->size) != 0) {
        perror("unmap fails");
        exit(-1);
    }
    g_free(entry->valid_mapping);
    g_free(entry);
#endif
}

void xen_invalidate_map_cache(void)
{
    unsigned long i;
    MapCacheRev *reventry;

    trace_xen_invalidate_map_cache();

    /* Flush pending AIO before destroying the mapcache */
    bdrv_drain_all();

    QTAILQ_FOREACH(reventry, &mapcache->locked_entries, next) {
        trace_xen_invalidate_map_cache_1(reventry->paddr_index,
                                         reventry->vaddr_req);
    }

    mapcache_lock();

    for (i = 0; i < mapcache->nr_buckets; i++) {
        MapCacheEntry *entry = &mapcache->entry[i];
        MapCacheEntry *sentry, *pentry = NULL;

        if (entry->vaddr_base == NULL) {
            continue;
        }
        pentry = entry;
        for (sentry = pentry->next; sentry; sentry = pentry->next) {
            trace_xen_invalidate_map_cache_2(sentry->paddr_index,
                                             sentry->size,
                                             sentry->vaddr_base);
            if (sentry->lock > 0) {
                pentry = sentry;
                continue;
            }
            pentry->next = sentry->next;
            if (munmap(sentry->vaddr_base, sentry->size) != 0) {
                perror("unmap fails");
                exit(-1);
            }
            g_free(sentry->valid_mapping);
            g_free(sentry);
        }

        if (entry->lock > 0) {
            continue;
        }

        trace_xen_invalidate_map_cache_3(entry->paddr_index, entry->size,
                                         entry->vaddr_base);
        if (munmap(entry->vaddr_base, entry->size) != 0) {
            perror("unmap fails");
            exit(-1);
        }

        entry->paddr_index = 0;
        entry->vaddr_base = NULL;
        entry->size = 0;
        g_free(entry->valid_mapping);
        entry->valid_mapping = NULL;
    }

    mapcache->last_entry = NULL;

    mapcache_unlock();
}

void xen_dump_map_cache(Monitor *mon)
{
    unsigned long i;
    MapCacheRev *reventry;

#ifdef DO_BIG_ENTRY
    monitor_printf(mon,
                   "bigEntry: paddr_index=%#"PRIx64
                   " size=%#"PRIx64" lock=%d"
                   " 0.err_cnt=%d .err_idx=%d"
                   " 1.err_cnt=%d .err_idx=%d"
                   " 2.err_cnt=%d .err_idx=%d"
                   " 3.err_cnt=%d .err_idx=%d"
                   " vaddr_base=%p\n",
                   mapcache->bigEntry.paddr_index,
                   mapcache->bigEntry.size,
                   mapcache->bigEntry.lock,
                   mapcache->bigEntry.erri[0].err_cnt,
                   mapcache->bigEntry.erri[0].err_idx,
                   mapcache->bigEntry.erri[1].err_cnt,
                   mapcache->bigEntry.erri[1].err_idx,
                   mapcache->bigEntry.erri[2].err_cnt,
                   mapcache->bigEntry.erri[2].err_idx,
                   mapcache->bigEntry.erri[3].err_cnt,
                   mapcache->bigEntry.erri[3].err_idx,
                   mapcache->bigEntry.vaddr_base);
#endif

    QTAILQ_FOREACH(reventry, &mapcache->locked_entries, next) {
        monitor_printf(mon,
                       "entry=%p paddr_index=%#"PRIx64" vaddr_req=%p\n",
                       reventry->entry, reventry->paddr_index,
                       reventry->vaddr_req);
    }

    for (i = 0; i < mapcache->nr_buckets; i++) {
        MapCacheEntry *entry = &mapcache->entry[i];
        MapCacheEntry *sentry;

        if (entry->vaddr_base == NULL) {
            continue;
        }
        monitor_printf(mon,
                       "entry[%lx]=%p paddr_index=%#"PRIx64" size=%#"PRIx64
                       " lock=%d 0.err_cnt=%d .err_idx=%d vaddr_base=%p\n",
                       i, entry, entry->paddr_index, entry->size,
                       entry->lock,
                       entry->erri[0].err_cnt, entry->erri[0].err_idx,
                       entry->vaddr_base);
        for (sentry = entry->next; sentry; sentry = sentry->next) {
            monitor_printf(mon,
                           " sentry=%p paddr_index=%#"PRIx64" size=%#"PRIx64
                           " lock=%d 0.err_cnt=%d .err_idx=%d"
                           " vaddr_base=%p\n",
                           sentry, sentry->paddr_index, sentry->size,
                           sentry->lock,
                           sentry->erri[0].err_cnt, sentry->erri[0].err_idx,
                           sentry->vaddr_base);
        }
    }
}
