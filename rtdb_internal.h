#pragma once
/*
 * rtdb_internal.h — on-disk layout and in-memory structures
 *
 *  FILE
 *  ┌──────────────────────────────┐
 *  │ FileHeader  (512 B, page 0)  │  magic, salt, root_page_id, n_pages
 *  ├──────────────────────────────┤
 *  │ Page 1  (4096 B)             │  B-tree node or overflow
 *  │ Page 2  (4096 B)             │
 *  │  ...                         │
 *  └──────────────────────────────┘
 *
 *  Every page is encrypted with ChaCha20 using:
 *      key   = derived master key
 *      nonce = [page_id (4B)][encrypt_counter (8B)]  (12 B total)
 *
 *  A BLAKE2b-256 MAC is stored in each page header and covers the
 *  plaintext payload. Checked on every read.
 *
 *  B-tree is an order-64 B+ tree (leaf nodes hold data, internal
 *  nodes hold separator keys + child page ids).
 */

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ */
/*  Constants                                                           */
/* ------------------------------------------------------------------ */
#define RTDB_MAGIC          0x52544442UL   /* "RTDB"                   */
#define RTDB_VERSION        1
#define RTDB_PAGE_SIZE      4096
#define RTDB_FILE_HDR_SIZE  512            /* first 512 B of file      */
#define RTDB_PAGE_HDR_SIZE  64
#define RTDB_PAYLOAD_SIZE   (RTDB_PAGE_SIZE - RTDB_PAGE_HDR_SIZE)  /* 4032 */

/* B-tree order: max keys per node.
 * Each key slot: 1B(klen) + 255B(key) + 4B(val_page) + 2B(val_off) = 262B
 * Internal slot adds 4B child ptr = 266B
 * 4032 / 266 ≈ 15 → order 15 (safe margin for metadata)           */
#define BTREE_ORDER         15             /* max keys per node        */
#define BTREE_MIN_KEYS      ((BTREE_ORDER - 1) / 2)

/* Page types */
#define PAGE_TYPE_FREE      0x00
#define PAGE_TYPE_INTERNAL  0x01
#define PAGE_TYPE_LEAF      0x02
#define PAGE_TYPE_OVERFLOW  0x03

/* ------------------------------------------------------------------ */
/*  On-disk: File Header (512 bytes, stored at byte offset 0)          */
/* ------------------------------------------------------------------ */
#pragma pack(push, 1)
typedef struct {
    uint32_t magic;          /* RTDB_MAGIC                             */
    uint8_t  version;        /* RTDB_VERSION                           */
    uint8_t  _pad0[3];
    uint8_t  salt[32];       /* random salt for key derivation         */
    uint8_t  mac[32];        /* BLAKE2b-256 over plaintext fields below*/
    /* --- fields below are part of MAC --- */
    uint32_t root_page_id;   /* page id of B-tree root                 */
    uint32_t n_pages;        /* total pages allocated (including hdr)  */
    uint32_t free_list_head; /* first free page id, 0 = none           */
    uint8_t  _pad1[512 - 4 - 1 - 3 - 32 - 32 - 4 - 4 - 4];
} FileHeader;
#pragma pack(pop)

/* ------------------------------------------------------------------ */
/*  On-disk: Page Header (64 bytes)                                    */
/* ------------------------------------------------------------------ */
#pragma pack(push, 1)
typedef struct {
    uint8_t  page_type;      /* PAGE_TYPE_*                            */
    uint8_t  n_keys;         /* number of keys in this node (leaf/int) */
    uint8_t  _pad[2];
    uint32_t page_id;        /* self page id (integrity)               */
    uint32_t next_page;      /* for overflow chain / free list         */
    uint64_t enc_counter;    /* ChaCha20 counter used when encrypting  */
    uint8_t  mac[32];        /* BLAKE2b-256(plaintext payload)         */
    uint8_t  _pad2[64 - 1 - 1 - 2 - 4 - 4 - 8 - 32];
} PageHeader;
#pragma pack(pop)

/* ------------------------------------------------------------------ */
/*  On-disk: Cell inside a leaf page                                   */
/*                                                                      */
/*  Leaf payload is a packed array of cells:                           */
/*  [klen:1][key:klen][flags:1][vlen:4][value:vlen]                   */
/*  or if flags & CELL_OVERFLOW:                                        */
/*  [klen:1][key:klen][flags:1][total_vlen:4][overflow_page_id:4]     */
/* ------------------------------------------------------------------ */
#define CELL_OVERFLOW  0x01

/* ------------------------------------------------------------------ */
/*  On-disk: Internal node slot                                         */
/*  Layout inside payload:                                              */
/*  [child_0:4] ([klen:1][key:255max][child_right:4]) * n_keys        */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/*  In-memory: loaded page                                              */
/* ------------------------------------------------------------------ */
typedef struct MemPage {
    uint32_t  page_id;
    int       dirty;          /* 1 = needs write-back                  */
    PageHeader hdr;
    uint8_t   payload[RTDB_PAYLOAD_SIZE];
} MemPage;

/* ------------------------------------------------------------------ */
/*  In-memory: db handle                                               */
/* ------------------------------------------------------------------ */
#include "rtdb.h"

/* Simple page cache (LRU would be overkill for red team tool) */
#define PAGE_CACHE_SIZE  64

typedef struct CacheEntry {
    MemPage  *page;
    uint32_t  last_use;   /* logical clock for eviction                */
} CacheEntry;

struct rtdb_t {
    int          fd;
    uint8_t      key[32];        /* derived encryption key             */
    FileHeader   fhdr;           /* cached file header                 */
    CacheEntry   cache[PAGE_CACHE_SIZE];
    uint32_t     clock;          /* monotonic counter for LRU          */
};

/* ------------------------------------------------------------------ */
/*  In-memory: iterator                                                 */
/* ------------------------------------------------------------------ */
struct rtdb_iter_t {
    rtdb_t  *db;
    /* stack for B-tree traversal */
    struct {
        uint32_t page_id;
        int      key_idx;
    } stack[32];
    int      stack_top;
    int      started;
    /* buffer for current kv */
    uint8_t *key_buf;
    size_t   key_len;
    uint8_t *val_buf;
    size_t   val_len;
};