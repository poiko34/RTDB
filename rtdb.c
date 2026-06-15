/*
 * rtdb.c — Encrypted B-tree database implementation
 *
 * Layers (bottom → top):
 *   1. crypto_*    — page encrypt/decrypt using ChaCha20 + BLAKE2b MAC
 *   2. pager_*     — read/write pages with cache + integrity check
 *   3. btree_*     — B+ tree insert / lookup / delete / iterate
 *   4. rtdb_*      — public API
 */

#include "rtdb_internal.h"
#include "crypto.h"   /* chacha20_*, blake2b_*, key21() */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#ifdef _WIN32
#  include <io.h>
#  include <fcntl.h>
#  define open  _open
#  define close _close
#  define read  _read
#  define write _write
#  define lseek _lseeki64
#  define O_RDWR   _O_RDWR
#  define O_CREAT  _O_CREAT
#  define O_BINARY _O_BINARY
#  define OPEN_FLAGS (O_RDWR|O_CREAT|O_BINARY)
#  define OPEN_MODE  0
#else
#  include <unistd.h>
#  include <fcntl.h>
#  define OPEN_FLAGS (O_RDWR|O_CREAT)
#  define OPEN_MODE  0600
#endif

/* ================================================================== */
/*  Helpers                                                             */
/* ================================================================== */

static void put_u32le(uint8_t *b, uint32_t v) {
    b[0]=(uint8_t)v; b[1]=(uint8_t)(v>>8);
    b[2]=(uint8_t)(v>>16); b[3]=(uint8_t)(v>>24);
}
static uint32_t get_u32le(const uint8_t *b) {
    return (uint32_t)b[0]|((uint32_t)b[1]<<8)|
           ((uint32_t)b[2]<<16)|((uint32_t)b[3]<<24);
}
static void put_u64le(uint8_t *b, uint64_t v) {
    for(int i=0;i<8;i++){ b[i]=(uint8_t)v; v>>=8; }
}
static uint64_t get_u64le(const uint8_t *b) {
    uint64_t v=0;
    for(int i=7;i>=0;i--) v=(v<<8)|b[i];
    return v;
}

/* ================================================================== */
/*  1. CRYPTO LAYER                                                     */
/* ================================================================== */

/*
 * Build a 12-byte ChaCha20 nonce from page_id and counter.
 * nonce = [page_id LE32][counter LE64]
 */
static void make_nonce(uint8_t nonce[12], uint32_t page_id, uint64_t counter) {
    put_u32le(nonce, page_id);
    put_u64le(nonce + 4, counter);
}

/*
 * Compute BLAKE2b-256 MAC over plaintext payload.
 * MAC is keyed with the master key so tampering ≠ recomputing.
 */
static void compute_mac(const uint8_t key[32],
                        const uint8_t *payload, size_t payload_len,
                        uint8_t mac_out[32])
{
    blake2b(mac_out, 32, key, 32, payload, payload_len);
}

/*
 * Encrypt a page payload in-place.
 * Writes enc_counter into hdr so we can decrypt later.
 * Returns the counter used (store in hdr.enc_counter).
 */
static uint64_t page_encrypt(const uint8_t key[32],
                              PageHeader *hdr,
                              uint8_t *payload)
{
    /* counter = current nonce (just use page_id xor rand for uniqueness;
       here we use a simple incrementing scheme stored in hdr)           */
    uint64_t ctr = hdr->enc_counter;
    uint8_t nonce[12];
    make_nonce(nonce, hdr->page_id, ctr);

    struct chacha20_context ctx;
    chacha20_init_context(&ctx, (uint8_t *)key, nonce, 0);
    chacha20_xor(&ctx, payload, RTDB_PAYLOAD_SIZE);
    return ctr;
}

static void page_decrypt(const uint8_t key[32],
                         const PageHeader *hdr,
                         uint8_t *payload)
{
    uint8_t nonce[12];
    make_nonce(nonce, hdr->page_id, hdr->enc_counter);

    struct chacha20_context ctx;
    chacha20_init_context(&ctx, (uint8_t *)key, nonce, 0);
    chacha20_xor(&ctx, payload, RTDB_PAYLOAD_SIZE);   /* XOR = self-inverse */
}

/* ================================================================== */
/*  2. PAGER LAYER                                                      */
/* ================================================================== */

/* Byte offset of a page in the file (page 0 = reserved for FileHeader,
   actual pages start at offset RTDB_FILE_HDR_SIZE)                    */
static off_t page_offset(uint32_t page_id) {
    return (off_t)RTDB_FILE_HDR_SIZE + (off_t)page_id * RTDB_PAGE_SIZE;
}

/* Write raw bytes at offset */
static int raw_write(int fd, off_t off, const void *buf, size_t len) {
    if (lseek(fd, off, SEEK_SET) < 0) return RTDB_ERR_IO;
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t w = write(fd, p, len);
        if (w <= 0) return RTDB_ERR_IO;
        p += w; len -= (size_t)w;
    }
    return RTDB_OK;
}

/* Read raw bytes at offset */
static int raw_read(int fd, off_t off, void *buf, size_t len) {
    if (lseek(fd, off, SEEK_SET) < 0) return RTDB_ERR_IO;
    uint8_t *p = buf;
    while (len > 0) {
        ssize_t r = read(fd, p, len);
        if (r <= 0) return RTDB_ERR_IO;
        p += r; len -= (size_t)r;
    }
    return RTDB_OK;
}

/* Serialise PageHeader to 64 bytes */
static void hdr_to_bytes(const PageHeader *h, uint8_t out[RTDB_PAGE_HDR_SIZE]) {
    memset(out, 0, RTDB_PAGE_HDR_SIZE);
    out[0] = h->page_type;
    out[1] = h->n_keys;
    put_u32le(out+4,  h->page_id);
    put_u32le(out+8,  h->next_page);
    put_u64le(out+12, h->enc_counter);
    memcpy(out+20, h->mac, 32);
}

/* Deserialise PageHeader from 64 bytes */
static void bytes_to_hdr(const uint8_t in[RTDB_PAGE_HDR_SIZE], PageHeader *h) {
    memset(h, 0, sizeof(*h));
    h->page_type   = in[0];
    h->n_keys      = in[1];
    h->page_id     = get_u32le(in+4);
    h->next_page   = get_u32le(in+8);
    h->enc_counter = get_u64le(in+12);
    memcpy(h->mac, in+20, 32);
}

/* Evict & free a cache slot (flush if dirty) */
static int cache_evict(rtdb_t *db, int slot) {
    CacheEntry *e = &db->cache[slot];
    if (!e->page) return RTDB_OK;

    if (e->page->dirty) {
        MemPage *pg = e->page;
        /* recompute MAC over plaintext payload */
        compute_mac(db->key, pg->payload, RTDB_PAYLOAD_SIZE, pg->hdr.mac);
        /* encrypt a working copy */
        uint8_t enc_buf[RTDB_PAYLOAD_SIZE];
        memcpy(enc_buf, pg->payload, RTDB_PAYLOAD_SIZE);
        /* increment counter each write to ensure nonce uniqueness */
        pg->hdr.enc_counter++;
        page_encrypt(db->key, &pg->hdr, enc_buf);

        /* serialise header + encrypted payload → disk */
        uint8_t raw[RTDB_PAGE_SIZE];
        hdr_to_bytes(&pg->hdr, raw);
        memcpy(raw + RTDB_PAGE_HDR_SIZE, enc_buf, RTDB_PAYLOAD_SIZE);

        int rc = raw_write(db->fd, page_offset(pg->page_id), raw, RTDB_PAGE_SIZE);
        if (rc != RTDB_OK) return rc;
    }
    free(e->page);
    e->page = NULL;
    e->last_use = 0;
    return RTDB_OK;
}

/* Find page in cache; returns slot index or -1 */
static int cache_find(rtdb_t *db, uint32_t page_id) {
    for (int i = 0; i < PAGE_CACHE_SIZE; i++)
        if (db->cache[i].page && db->cache[i].page->page_id == page_id)
            return i;
    return -1;
}

/* Get a free cache slot (LRU eviction) */
static int cache_alloc_slot(rtdb_t *db) {
    /* prefer empty slots */
    for (int i = 0; i < PAGE_CACHE_SIZE; i++)
        if (!db->cache[i].page) return i;
    /* evict LRU */
    int lru = 0;
    for (int i = 1; i < PAGE_CACHE_SIZE; i++)
        if (db->cache[i].last_use < db->cache[lru].last_use) lru = i;
    cache_evict(db, lru);
    return lru;
}

/* Read a page from disk into cache; return MemPage* or NULL */
static MemPage *pager_read(rtdb_t *db, uint32_t page_id) {
    int slot = cache_find(db, page_id);
    if (slot >= 0) {
        db->cache[slot].last_use = ++db->clock;
        return db->cache[slot].page;
    }

    uint8_t raw[RTDB_PAGE_SIZE];
    if (raw_read(db->fd, page_offset(page_id), raw, RTDB_PAGE_SIZE) != RTDB_OK)
        return NULL;

    MemPage *pg = calloc(1, sizeof(MemPage));
    if (!pg) return NULL;

    bytes_to_hdr(raw, &pg->hdr);
    pg->page_id = page_id;

    /* decrypt payload */
    memcpy(pg->payload, raw + RTDB_PAGE_HDR_SIZE, RTDB_PAYLOAD_SIZE);
    page_decrypt(db->key, &pg->hdr, pg->payload);

    /* verify MAC */
    uint8_t expected_mac[32];
    compute_mac(db->key, pg->payload, RTDB_PAYLOAD_SIZE, expected_mac);
    if (memcmp(expected_mac, pg->hdr.mac, 32) != 0) {
        free(pg);
        return NULL;   /* MAC mismatch → corrupt or wrong password */
    }

    slot = cache_alloc_slot(db);
    db->cache[slot].page     = pg;
    db->cache[slot].last_use = ++db->clock;
    return pg;
}

/* Get a page for write (creates if new page_id == db->fhdr.n_pages) */
static MemPage *pager_get_or_alloc(rtdb_t *db, uint32_t page_id, uint8_t type) {
    if (page_id < db->fhdr.n_pages)
        return pager_read(db, page_id);

    /* allocate new page */
    MemPage *pg = calloc(1, sizeof(MemPage));
    if (!pg) return NULL;
    pg->page_id        = page_id;
    pg->hdr.page_id    = page_id;
    pg->hdr.page_type  = type;
    pg->hdr.next_page  = 0;
    pg->hdr.enc_counter = (uint64_t)page_id * 1000;  /* initial counter */
    pg->dirty          = 1;
    db->fhdr.n_pages   = page_id + 1;

    int slot = cache_alloc_slot(db);
    db->cache[slot].page     = pg;
    db->cache[slot].last_use = ++db->clock;
    return pg;
}

/* Mark page dirty (will be flushed on eviction or close) */
static void pager_mark_dirty(rtdb_t *db, uint32_t page_id) {
    int slot = cache_find(db, page_id);
    if (slot >= 0 && db->cache[slot].page)
        db->cache[slot].page->dirty = 1;
}

/* Allocate a fresh page (use free list if available) */
static uint32_t pager_alloc_page(rtdb_t *db, uint8_t type) {
    uint32_t id;
    if (db->fhdr.free_list_head != 0) {
        id = db->fhdr.free_list_head;
        MemPage *fp = pager_read(db, id);
        if (fp) {
            db->fhdr.free_list_head = fp->hdr.next_page;
            fp->hdr.page_type  = type;
            fp->hdr.next_page  = 0;
            fp->hdr.n_keys     = 0;
            memset(fp->payload, 0, RTDB_PAYLOAD_SIZE);
            fp->dirty = 1;
        }
    } else {
        id = db->fhdr.n_pages;
        pager_get_or_alloc(db, id, type);
    }
    return id;
}

/* Free a page (add to free list) */
static void pager_free_page(rtdb_t *db, uint32_t page_id) {
    MemPage *pg = pager_read(db, page_id);
    if (!pg) return;
    memset(pg->payload, 0, RTDB_PAYLOAD_SIZE);
    pg->hdr.page_type = PAGE_TYPE_FREE;
    pg->hdr.next_page = db->fhdr.free_list_head;
    pg->dirty = 1;
    db->fhdr.free_list_head = page_id;
}

/* Flush all dirty pages */
static int pager_flush_all(rtdb_t *db) {
    for (int i = 0; i < PAGE_CACHE_SIZE; i++) {
        if (db->cache[i].page && db->cache[i].page->dirty) {
            int rc = cache_evict(db, i);
            if (rc != RTDB_OK) return rc;
        }
    }
    return RTDB_OK;
}

/* Write the file header (plain except MAC covers key fields) */
static int write_file_header(rtdb_t *db) {
    FileHeader *fh = &db->fhdr;
    /* MAC covers: root_page_id, n_pages, free_list_head */
    uint8_t mac_data[12];
    put_u32le(mac_data+0, fh->root_page_id);
    put_u32le(mac_data+4, fh->n_pages);
    put_u32le(mac_data+8, fh->free_list_head);
    blake2b(fh->mac, 32, db->key, 32, mac_data, 12);

    uint8_t raw[RTDB_FILE_HDR_SIZE];
    memset(raw, 0, sizeof(raw));
    put_u32le(raw+0,  fh->magic);
    raw[4] = fh->version;
    memcpy(raw+8,  fh->salt,  32);
    memcpy(raw+40, fh->mac,   32);
    put_u32le(raw+72, fh->root_page_id);
    put_u32le(raw+76, fh->n_pages);
    put_u32le(raw+80, fh->free_list_head);

    return raw_write(db->fd, 0, raw, RTDB_FILE_HDR_SIZE);
}

static int read_file_header(rtdb_t *db) {
    uint8_t raw[RTDB_FILE_HDR_SIZE];
    int rc = raw_read(db->fd, 0, raw, RTDB_FILE_HDR_SIZE);
    if (rc != RTDB_OK) return rc;

    FileHeader *fh = &db->fhdr;
    fh->magic   = get_u32le(raw+0);
    fh->version = raw[4];
    memcpy(fh->salt, raw+8,  32);
    memcpy(fh->mac,  raw+40, 32);
    fh->root_page_id   = get_u32le(raw+72);
    fh->n_pages        = get_u32le(raw+76);
    fh->free_list_head = get_u32le(raw+80);

    if (fh->magic != RTDB_MAGIC) return RTDB_ERR_CORRUPT;

    /* verify header MAC */
    uint8_t mac_data[12];
    put_u32le(mac_data+0, fh->root_page_id);
    put_u32le(mac_data+4, fh->n_pages);
    put_u32le(mac_data+8, fh->free_list_head);
    uint8_t expected[32];
    blake2b(expected, 32, db->key, 32, mac_data, 12);
    if (memcmp(expected, fh->mac, 32) != 0) return RTDB_ERR_CORRUPT;

    return RTDB_OK;
}

/* ================================================================== */
/*  3. B+ TREE LAYER                                                    */
/* ================================================================== */
/*
 * Payload format — LEAF node:
 *   Cells packed from offset 0, each:
 *     [klen:1][key:klen][flags:1][vlen:4][value:vlen]
 *   OR overflow:
 *     [klen:1][key:klen][flags:1][total_vlen:4][ovfl_page:4]
 *
 * Payload format — INTERNAL node:
 *   [child_0: u32]
 *   For i in 0..n_keys-1:
 *     [klen:1][key:255max][child_right: u32]
 *
 * Keys in all nodes are sorted lexicographically.
 */

/* ----- key comparison --------------------------------------------- */
static int key_cmp(const uint8_t *a, size_t alen,
                   const uint8_t *b, size_t blen) {
    size_t mn = alen < blen ? alen : blen;
    int c = memcmp(a, b, mn);
    if (c != 0) return c;
    return (alen < blen) ? -1 : (alen > blen) ? 1 : 0;
}

/* ----- overflow helpers ------------------------------------------- */

/* Write value that may span overflow pages. Returns first page id of chain. */
static uint32_t ovfl_write(rtdb_t *db, const uint8_t *val, size_t vlen) {
    uint32_t first = 0, prev_page = 0;
    const uint8_t *p = val;
    size_t remaining = vlen;

    while (remaining > 0) {
        uint32_t pid = pager_alloc_page(db, PAGE_TYPE_OVERFLOW);
        MemPage *pg  = pager_read(db, pid);
        if (!pg) return 0;

        if (first == 0) first = pid;
        if (prev_page) {
            MemPage *prev = pager_read(db, prev_page);
            if (prev) { prev->hdr.next_page = pid; prev->dirty = 1; }
        }

        size_t chunk = remaining < RTDB_PAYLOAD_SIZE ? remaining : RTDB_PAYLOAD_SIZE;
        memcpy(pg->payload, p, chunk);
        pg->hdr.next_page = 0;
        pg->dirty = 1;

        p         += chunk;
        remaining -= chunk;
        prev_page  = pid;
    }
    return first;
}

/* Read value from overflow chain. Caller must free *out. */
static int ovfl_read(rtdb_t *db, uint32_t first_page, size_t total_len,
                     uint8_t **out) {
    *out = malloc(total_len + 1);
    if (!*out) return RTDB_ERR_NOMEM;
    (*out)[total_len] = 0;

    uint8_t *dst = *out;
    size_t remaining = total_len;
    uint32_t pid = first_page;

    while (remaining > 0 && pid != 0) {
        MemPage *pg = pager_read(db, pid);
        if (!pg) { free(*out); return RTDB_ERR_CORRUPT; }
        size_t chunk = remaining < RTDB_PAYLOAD_SIZE ? remaining : RTDB_PAYLOAD_SIZE;
        memcpy(dst, pg->payload, chunk);
        dst       += chunk;
        remaining -= chunk;
        pid = pg->hdr.next_page;
    }
    return RTDB_OK;
}

/* Free overflow chain */
static void ovfl_free(rtdb_t *db, uint32_t first_page) {
    uint32_t pid = first_page;
    while (pid != 0) {
        MemPage *pg = pager_read(db, pid);
        uint32_t next = pg ? pg->hdr.next_page : 0;
        pager_free_page(db, pid);
        pid = next;
    }
}

/* ----- Leaf cell parsing ------------------------------------------ */

typedef struct {
    uint8_t  klen;
    uint8_t  key[255];
    uint8_t  flags;
    uint32_t vlen;          /* total value length                     */
    union {
        struct { uint8_t data[RTDB_PAYLOAD_SIZE]; } inline_v;
        uint32_t ovfl_page;
    } v;
    size_t   cell_size;     /* bytes this cell occupies in payload    */
} LeafCell;

/* Parse cell at payload[off]; returns 0 on error */
static int leaf_parse_cell(const uint8_t *payload, size_t off, LeafCell *cell) {
    if (off + 6 > RTDB_PAYLOAD_SIZE) return 0;
    cell->klen  = payload[off]; off++;
    if (cell->klen == 0 || off + cell->klen + 5 > RTDB_PAYLOAD_SIZE) return 0;
    memcpy(cell->key, payload+off, cell->klen); off += cell->klen;
    cell->flags = payload[off++];
    cell->vlen  = get_u32le(payload+off); off += 4;

    if (cell->flags & CELL_OVERFLOW) {
        if (off + 4 > RTDB_PAYLOAD_SIZE) return 0;
        cell->v.ovfl_page = get_u32le(payload+off); off += 4;
        cell->cell_size = 1 + cell->klen + 1 + 4 + 4;
    } else {
        if (off + cell->vlen > RTDB_PAYLOAD_SIZE) return 0;
        memcpy(cell->v.inline_v.data, payload+off, cell->vlen);
        off += cell->vlen;
        cell->cell_size = 1 + cell->klen + 1 + 4 + cell->vlen;
    }
    return 1;
}

/* Compute payload size used by all cells in a leaf */
static size_t leaf_used(MemPage *pg) {
    size_t off = 0;
    for (int i = 0; i < pg->hdr.n_keys; i++) {
        LeafCell c;
        if (!leaf_parse_cell(pg->payload, off, &c)) break;
        off += c.cell_size;
    }
    return off;
}

/* ----- Internal node parsing -------------------------------------- */

typedef struct {
    uint32_t child_left;
    struct { uint8_t klen; uint8_t key[255]; uint32_t child_right; } slots[BTREE_ORDER];
    int n;
} InternalNode;

static void internal_parse(MemPage *pg, InternalNode *nd) {
    const uint8_t *p = pg->payload;
    nd->n = pg->hdr.n_keys;
    nd->child_left = get_u32le(p); p += 4;
    for (int i = 0; i < nd->n; i++) {
        nd->slots[i].klen = *p++;
        memcpy(nd->slots[i].key, p, nd->slots[i].klen);
        p += nd->slots[i].klen;
        nd->slots[i].child_right = get_u32le(p); p += 4;
    }
}

static void internal_write(MemPage *pg, const InternalNode *nd) {
    uint8_t *p = pg->payload;
    memset(p, 0, RTDB_PAYLOAD_SIZE);
    put_u32le(p, nd->child_left); p += 4;
    for (int i = 0; i < nd->n; i++) {
        *p++ = nd->slots[i].klen;
        memcpy(p, nd->slots[i].key, nd->slots[i].klen);
        p += nd->slots[i].klen;
        put_u32le(p, nd->slots[i].child_right); p += 4;
    }
    pg->hdr.n_keys = (uint8_t)nd->n;
    pg->dirty = 1;
}

/* Return child page id for key in internal node */
static uint32_t internal_find_child(const InternalNode *nd,
                                    const uint8_t *key, size_t klen) {
    for (int i = 0; i < nd->n; i++) {
        if (key_cmp(key, klen, nd->slots[i].key, nd->slots[i].klen) < 0)
            return (i == 0) ? nd->child_left : nd->slots[i-1].child_right;
    }
    return (nd->n == 0) ? nd->child_left : nd->slots[nd->n-1].child_right;
}

/* ----- Search (B+ tree lookup) ------------------------------------ */

static int btree_search(rtdb_t *db, uint32_t root,
                        const uint8_t *key, size_t klen,
                        void **out_val, size_t *out_len) {
    uint32_t pid = root;
    for (;;) {
        MemPage *pg = pager_read(db, pid);
        if (!pg) return RTDB_ERR_IO;

        if (pg->hdr.page_type == PAGE_TYPE_LEAF) {
            size_t off = 0;
            for (int i = 0; i < pg->hdr.n_keys; i++) {
                LeafCell cell;
                if (!leaf_parse_cell(pg->payload, off, &cell))
                    return RTDB_ERR_CORRUPT;
                if (key_cmp(key, klen, cell.key, cell.klen) == 0) {
                    /* found */
                    if (cell.flags & CELL_OVERFLOW) {
                        uint8_t *buf;
                        int rc = ovfl_read(db, cell.v.ovfl_page, cell.vlen, &buf);
                        if (rc != RTDB_OK) return rc;
                        *out_val = buf;
                        *out_len = cell.vlen;
                    } else {
                        uint8_t *buf = malloc(cell.vlen + 1);
                        if (!buf) return RTDB_ERR_NOMEM;
                        memcpy(buf, cell.v.inline_v.data, cell.vlen);
                        buf[cell.vlen] = 0;
                        *out_val = buf;
                        *out_len = cell.vlen;
                    }
                    return RTDB_OK;
                }
                off += cell.cell_size;
            }
            return RTDB_ERR_NOTFOUND;
        } else {
            InternalNode nd;
            internal_parse(pg, &nd);
            pid = internal_find_child(&nd, key, klen);
        }
    }
}

/* ----- Leaf insertion helper -------------------------------------- */
/* Returns bytes needed for a cell */
static size_t cell_needed(size_t klen, size_t vlen, int *use_overflow) {
    size_t inline_sz = 1 + klen + 1 + 4 + vlen;
    if (inline_sz <= RTDB_PAYLOAD_SIZE / 2 || vlen <= RTDB_PAYLOAD_SIZE - 8) {
        *use_overflow = 0;
        return inline_sz;
    }
    *use_overflow = 1;
    return 1 + klen + 1 + 4 + 4;   /* ovfl_page replaces value       */
}

/* Write a cell into leaf at correct sorted position.
   Returns 0 if leaf is full (need split). */
static int leaf_insert_cell(MemPage *pg,
                            const uint8_t *key, size_t klen,
                            const uint8_t *val, size_t vlen,
                            rtdb_t *db) {
    int use_ovfl;
    size_t need = cell_needed(klen, vlen, &use_ovfl);
    size_t used = leaf_used(pg);
    if (used + need > RTDB_PAYLOAD_SIZE) return 0;   /* full          */

    /* parse existing cells to find insertion point */
    uint8_t tmp[RTDB_PAYLOAD_SIZE];
    memset(tmp, 0, sizeof(tmp));
    size_t off = 0, insert_off = (size_t)-1;
    int   insert_idx = pg->hdr.n_keys;

    for (int i = 0; i < pg->hdr.n_keys; i++) {
        LeafCell cell;
        if (!leaf_parse_cell(pg->payload, off, &cell)) return -1;
        if (insert_off == (size_t)-1 &&
            key_cmp(key, klen, cell.key, cell.klen) <= 0) {
            insert_off = off;
            insert_idx = i;
        }
        off += cell.cell_size;
    }
    if (insert_off == (size_t)-1) insert_off = off;

    /* build new cell */
    uint8_t cell_buf[1 + 255 + 1 + 4 + RTDB_PAYLOAD_SIZE];
    size_t ci = 0;
    cell_buf[ci++] = (uint8_t)klen;
    memcpy(cell_buf+ci, key, klen); ci += klen;
    if (use_ovfl) {
        uint32_t op = ovfl_write(db, val, vlen);
        if (!op) return -1;
        cell_buf[ci++] = CELL_OVERFLOW;
        put_u32le(cell_buf+ci, (uint32_t)vlen); ci += 4;
        put_u32le(cell_buf+ci, op); ci += 4;
    } else {
        cell_buf[ci++] = 0;
        put_u32le(cell_buf+ci, (uint32_t)vlen); ci += 4;
        memcpy(cell_buf+ci, val, vlen); ci += vlen;
    }

    /* splice into payload */
    memcpy(tmp, pg->payload, insert_off);
    memcpy(tmp + insert_off, cell_buf, ci);
    memcpy(tmp + insert_off + ci,
           pg->payload + insert_off,
           used - insert_off);
    memcpy(pg->payload, tmp, RTDB_PAYLOAD_SIZE);
    pg->hdr.n_keys++;
    pg->dirty = 1;
    (void)insert_idx;
    return 1;
}

/* ----- Node splitting -------------------------------------------- */

/* Split result: mid key goes up to parent */
typedef struct {
    uint8_t  mid_key[255];
    uint8_t  mid_klen;
    uint32_t new_page_id;
} SplitResult;

static int leaf_split(rtdb_t *db, MemPage *left, SplitResult *sr) {
    int n = left->hdr.n_keys;
    int mid = n / 2;

    uint32_t right_pid = pager_alloc_page(db, PAGE_TYPE_LEAF);
    MemPage *right = pager_read(db, right_pid);
    if (!right) return RTDB_ERR_NOMEM;

    /* collect all cells */
    LeafCell cells[BTREE_ORDER + 1];
    size_t off = 0;
    for (int i = 0; i < n; i++) {
        if (!leaf_parse_cell(left->payload, off, &cells[i]))
            return RTDB_ERR_CORRUPT;
        off += cells[i].cell_size;
    }

    /* mid key for parent */
    memcpy(sr->mid_key, cells[mid].key, cells[mid].klen);
    sr->mid_klen    = cells[mid].klen;
    sr->new_page_id = right_pid;

    /* rebuild left with [0..mid-1], right with [mid..n-1] */
    memset(left->payload, 0, RTDB_PAYLOAD_SIZE);
    left->hdr.n_keys = 0;
    size_t lo = 0;
    for (int i = 0; i < mid; i++) {
        size_t sz = cells[i].cell_size;
        /* reconstruct raw cell bytes */
        uint8_t cb[1+255+1+4+RTDB_PAYLOAD_SIZE];
        size_t ci = 0;
        cb[ci++] = cells[i].klen;
        memcpy(cb+ci, cells[i].key, cells[i].klen); ci += cells[i].klen;
        cb[ci++] = cells[i].flags;
        put_u32le(cb+ci, cells[i].vlen); ci += 4;
        if (cells[i].flags & CELL_OVERFLOW) {
            put_u32le(cb+ci, cells[i].v.ovfl_page); ci += 4;
        } else {
            memcpy(cb+ci, cells[i].v.inline_v.data, cells[i].vlen);
            ci += cells[i].vlen;
        }
        memcpy(left->payload + lo, cb, sz);
        lo += sz;
        left->hdr.n_keys++;
    }
    left->dirty = 1;

    size_t ro = 0;
    for (int i = mid; i < n; i++) {
        size_t sz = cells[i].cell_size;
        uint8_t cb[1+255+1+4+RTDB_PAYLOAD_SIZE];
        size_t ci = 0;
        cb[ci++] = cells[i].klen;
        memcpy(cb+ci, cells[i].key, cells[i].klen); ci += cells[i].klen;
        cb[ci++] = cells[i].flags;
        put_u32le(cb+ci, cells[i].vlen); ci += 4;
        if (cells[i].flags & CELL_OVERFLOW) {
            put_u32le(cb+ci, cells[i].v.ovfl_page); ci += 4;
        } else {
            memcpy(cb+ci, cells[i].v.inline_v.data, cells[i].vlen);
            ci += cells[i].vlen;
        }
        memcpy(right->payload + ro, cb, sz);
        ro += sz;
        right->hdr.n_keys++;
    }
    right->dirty = 1;
    return RTDB_OK;
}

/*
 * Recursive insert into subtree rooted at 'pid'.
 * *sr is set if a split happened and parent must absorb mid key.
 */
static int btree_insert_rec(rtdb_t *db, uint32_t pid,
                             const uint8_t *key, size_t klen,
                             const uint8_t *val, size_t vlen,
                             SplitResult *sr) {
    MemPage *pg = pager_read(db, pid);
    if (!pg) return RTDB_ERR_IO;
    sr->new_page_id = 0;

    if (pg->hdr.page_type == PAGE_TYPE_LEAF) {
        /* check for update (delete old cell first) */
        size_t off = 0;
        for (int i = 0; i < pg->hdr.n_keys; i++) {
            LeafCell cell;
            if (!leaf_parse_cell(pg->payload, off, &cell)) return RTDB_ERR_CORRUPT;
            if (key_cmp(key, klen, cell.key, cell.klen) == 0) {
                /* remove old cell */
                if (cell.flags & CELL_OVERFLOW)
                    ovfl_free(db, cell.v.ovfl_page);
                size_t tail = leaf_used(pg) - off - cell.cell_size;
                memmove(pg->payload + off,
                        pg->payload + off + cell.cell_size, tail);
                memset(pg->payload + off + tail, 0, cell.cell_size);
                pg->hdr.n_keys--;
                pg->dirty = 1;
                break;
            }
            off += cell.cell_size;
        }

        int r = leaf_insert_cell(pg, key, klen, val, vlen, db);
        if (r < 0) return RTDB_ERR_CORRUPT;
        if (r == 0) {
            /* leaf full → split */
            int rc = leaf_split(db, pg, sr);
            if (rc != RTDB_OK) return rc;
            /* retry insert on correct half */
            if (key_cmp(key, klen, sr->mid_key, sr->mid_klen) < 0) {
                leaf_insert_cell(pg, key, klen, val, vlen, db);
            } else {
                MemPage *right = pager_read(db, sr->new_page_id);
                if (!right) return RTDB_ERR_IO;
                leaf_insert_cell(right, key, klen, val, vlen, db);
            }
        }
        return RTDB_OK;
    }

    /* INTERNAL node */
    InternalNode nd;
    internal_parse(pg, &nd);
    uint32_t child_pid = internal_find_child(&nd, key, klen);

    SplitResult child_sr;
    int rc = btree_insert_rec(db, child_pid, key, klen, val, vlen, &child_sr);
    if (rc != RTDB_OK) return rc;

    if (child_sr.new_page_id == 0) return RTDB_OK;  /* no split propagation */

    /* Insert child_sr.mid_key into this internal node */
    if (nd.n < BTREE_ORDER - 1) {
        /* find position */
        int pos = nd.n;
        for (int i = 0; i < nd.n; i++) {
            if (key_cmp(child_sr.mid_key, child_sr.mid_klen,
                        nd.slots[i].key, nd.slots[i].klen) < 0) {
                pos = i; break;
            }
        }
        for (int i = nd.n; i > pos; i--) nd.slots[i] = nd.slots[i-1];
        nd.slots[pos].klen = child_sr.mid_klen;
        memcpy(nd.slots[pos].key, child_sr.mid_key, child_sr.mid_klen);
        nd.slots[pos].child_right = child_sr.new_page_id;
        nd.n++;
        internal_write(pg, &nd);
        sr->new_page_id = 0;
        return RTDB_OK;
    }

    /* Internal node full → split internal */
    /* Temporarily add the new key */
    InternalNode full;
    full = nd;
    int pos = full.n;
    for (int i = 0; i < full.n; i++) {
        if (key_cmp(child_sr.mid_key, child_sr.mid_klen,
                    full.slots[i].key, full.slots[i].klen) < 0) {
            pos = i; break;
        }
    }
    for (int i = full.n; i > pos; i--) full.slots[i] = full.slots[i-1];
    full.slots[pos].klen = child_sr.mid_klen;
    memcpy(full.slots[pos].key, child_sr.mid_key, child_sr.mid_klen);
    full.slots[pos].child_right = child_sr.new_page_id;
    full.n++;

    int mid = full.n / 2;
    /* mid key goes up */
    sr->mid_klen = full.slots[mid].klen;
    memcpy(sr->mid_key, full.slots[mid].key, full.slots[mid].klen);

    uint32_t right_pid = pager_alloc_page(db, PAGE_TYPE_INTERNAL);
    MemPage *right = pager_read(db, right_pid);
    if (!right) return RTDB_ERR_NOMEM;
    sr->new_page_id = right_pid;

    InternalNode left_nd, right_nd;
    left_nd.child_left  = full.child_left;
    left_nd.n = 0;
    for (int i = 0; i < mid; i++) left_nd.slots[left_nd.n++] = full.slots[i];

    right_nd.child_left = full.slots[mid].child_right;
    right_nd.n = 0;
    for (int i = mid+1; i < full.n; i++) right_nd.slots[right_nd.n++] = full.slots[i];

    internal_write(pg,    &left_nd);
    internal_write(right, &right_nd);
    return RTDB_OK;
}

static int btree_insert(rtdb_t *db,
                        const uint8_t *key, size_t klen,
                        const uint8_t *val, size_t vlen) {
    SplitResult sr;
    int rc = btree_insert_rec(db, db->fhdr.root_page_id,
                              key, klen, val, vlen, &sr);
    if (rc != RTDB_OK) return rc;

    if (sr.new_page_id != 0) {
        /* root split → new root */
        uint32_t new_root_pid = pager_alloc_page(db, PAGE_TYPE_INTERNAL);
        MemPage *nr = pager_read(db, new_root_pid);
        if (!nr) return RTDB_ERR_NOMEM;
        InternalNode nd;
        nd.child_left = db->fhdr.root_page_id;
        nd.n = 1;
        nd.slots[0].klen = sr.mid_klen;
        memcpy(nd.slots[0].key, sr.mid_key, sr.mid_klen);
        nd.slots[0].child_right = sr.new_page_id;
        internal_write(nr, &nd);
        db->fhdr.root_page_id = new_root_pid;
    }
    return RTDB_OK;
}

/* ----- Delete ---------------------------------------------------- */

static int btree_delete_leaf(rtdb_t *db, uint32_t pid,
                             const uint8_t *key, size_t klen) {
    MemPage *pg = pager_read(db, pid);
    if (!pg) return RTDB_ERR_IO;
    if (pg->hdr.page_type != PAGE_TYPE_LEAF) return RTDB_ERR_NOTFOUND;

    size_t off = 0;
    for (int i = 0; i < pg->hdr.n_keys; i++) {
        LeafCell cell;
        if (!leaf_parse_cell(pg->payload, off, &cell)) return RTDB_ERR_CORRUPT;
        if (key_cmp(key, klen, cell.key, cell.klen) == 0) {
            if (cell.flags & CELL_OVERFLOW)
                ovfl_free(db, cell.v.ovfl_page);
            size_t used  = leaf_used(pg);
            size_t tail  = used - off - cell.cell_size;
            memmove(pg->payload + off,
                    pg->payload + off + cell.cell_size, tail);
            memset(pg->payload + off + tail, 0, cell.cell_size);
            pg->hdr.n_keys--;
            pg->dirty = 1;
            return RTDB_OK;
        }
        off += cell.cell_size;
    }
    return RTDB_ERR_NOTFOUND;
}

static int btree_delete(rtdb_t *db,
                        const uint8_t *key, size_t klen) {
    /* Lazy delete: just remove from leaf, no rebalancing.
     * For red team usage this is fine; db stays functional. */
    uint32_t pid = db->fhdr.root_page_id;
    for (;;) {
        MemPage *pg = pager_read(db, pid);
        if (!pg) return RTDB_ERR_IO;
        if (pg->hdr.page_type == PAGE_TYPE_LEAF)
            return btree_delete_leaf(db, pid, key, klen);
        InternalNode nd;
        internal_parse(pg, &nd);
        pid = internal_find_child(&nd, key, klen);
    }
}

/* ================================================================== */
/*  4. PUBLIC API                                                       */
/* ================================================================== */

/* Derive key from password + salt using BLAKE2b (keyed hash) */
static void derive_key(const char *password, const uint8_t salt[32],
                       uint8_t out_key[32]) {
    /* key21 produces a 32-byte key from a string */
    char salted[512];
    size_t plen = strlen(password);
    size_t slen = plen < 480 ? plen : 480;
    memcpy(salted, password, slen);
    memcpy(salted + slen, salt, 32);
    key21(salted, slen + 32, out_key);
    /* stretch one more round */
    uint8_t stretched[32];
    blake2b(stretched, 32, out_key, 32, salted, slen + 32);
    memcpy(out_key, stretched, 32);
}

static void random_bytes(uint8_t *buf, size_t n) {
    /* Best-effort; for a real tool wire to getrandom()/BCryptGenRandom() */
#ifdef __linux__
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { fread(buf, 1, n, f); fclose(f); return; }
#endif
    /* fallback: mix time + stack address */
    for (size_t i = 0; i < n; i++)
        buf[i] = (uint8_t)((uintptr_t)&buf ^ (uintptr_t)i ^ (uint8_t)i);
}

int rtdb_open(const char *path, const char *password, rtdb_t **out) {
    if (!path || !password || !out) return RTDB_ERR_PARAM;

    rtdb_t *db = calloc(1, sizeof(rtdb_t));
    if (!db) return RTDB_ERR_NOMEM;

    db->fd = open(path, OPEN_FLAGS, OPEN_MODE);
    if (db->fd < 0) { free(db); return RTDB_ERR_IO; }

    /* Check if file is new (size == 0) */
    off_t sz = lseek(db->fd, 0, SEEK_END);
    if (sz < 0) { close(db->fd); free(db); return RTDB_ERR_IO; }

    if (sz == 0) {
        /* New database */
        random_bytes(db->fhdr.salt, 32);
        derive_key(password, db->fhdr.salt, db->key);

        db->fhdr.magic          = RTDB_MAGIC;
        db->fhdr.version        = RTDB_VERSION;
        db->fhdr.root_page_id   = 0;
        db->fhdr.n_pages        = 1;    /* root page */
        db->fhdr.free_list_head = 0;

        /* create root leaf */
        ftruncate(db->fd, RTDB_FILE_HDR_SIZE + RTDB_PAGE_SIZE);

        // 2. создаём root page
        MemPage *root = calloc(1, sizeof(MemPage));
        if (!root) { close(db->fd); free(db); return RTDB_ERR_NOMEM; }
        
        root->page_id = 0;
        root->hdr.page_id = 0;
        root->hdr.page_type = PAGE_TYPE_LEAF;
        root->hdr.n_keys = 0;
        root->dirty = 1;

        // 3. кладём в cache и ПИШЕМ НА ДИСК
        int slot = cache_alloc_slot(db);
        db->cache[slot].page = root;
        cache_evict(db, slot);

        // 4. синхронизируем метаданные
        db->fhdr.n_pages = 1;
        db->fhdr.root_page_id = 0;
        root->dirty = 1;

        pager_flush_all(db);
        int rc = write_file_header(db);
        if (rc != RTDB_OK) { close(db->fd); free(db); return rc; }
    } else {
        /* Existing database — read header, derive key */
        /* We need to derive key before we can verify MAC, but we need
           the salt from the header. Read raw header first. */
        uint8_t raw[RTDB_FILE_HDR_SIZE];
        if (raw_read(db->fd, 0, raw, RTDB_FILE_HDR_SIZE) != RTDB_OK) {
            close(db->fd); free(db); return RTDB_ERR_IO;
        }
        if (get_u32le(raw) != RTDB_MAGIC) {
            close(db->fd); free(db); return RTDB_ERR_CORRUPT;
        }
        memcpy(db->fhdr.salt, raw+8, 32);
        derive_key(password, db->fhdr.salt, db->key);

        int rc = read_file_header(db);
        if (rc != RTDB_OK) { close(db->fd); free(db); return rc; }
    }

    *out = db;
    return RTDB_OK;
}

void rtdb_close(rtdb_t *db) {
    if (!db) return;
    pager_flush_all(db);
    write_file_header(db);
    /* clear key from memory */
    for (int i = 0; i < PAGE_CACHE_SIZE; i++) {
        if (db->cache[i].page) free(db->cache[i].page);
    }
    memset(db->key, 0, 32);
    close(db->fd);
    free(db);
}

int rtdb_put(rtdb_t *db,
             const void *key,   size_t key_len,
             const void *value, size_t value_len) {
    if (!db || !key || !value) return RTDB_ERR_PARAM;
    if (key_len == 0 || key_len > RTDB_MAX_KEY) return RTDB_ERR_TOOBIG;
    if (value_len > RTDB_MAX_VALUE)              return RTDB_ERR_TOOBIG;
    return btree_insert(db, key, key_len, value, value_len);
}

int rtdb_get(rtdb_t *db,
             const void *key,  size_t key_len,
             void **out_value, size_t *out_value_len) {
    if (!db || !key || !out_value || !out_value_len) return RTDB_ERR_PARAM;
    if (key_len == 0 || key_len > RTDB_MAX_KEY) return RTDB_ERR_PARAM;
    return btree_search(db, db->fhdr.root_page_id,
                        key, key_len, out_value, out_value_len);
}

int rtdb_delete(rtdb_t *db, const void *key, size_t key_len) {
    if (!db || !key) return RTDB_ERR_PARAM;
    if (key_len == 0 || key_len > RTDB_MAX_KEY) return RTDB_ERR_PARAM;
    int rc = btree_delete(db, key, key_len);
    return (rc == RTDB_ERR_NOTFOUND) ? RTDB_OK : rc;
}

/* ------------------------------------------------------------------ */
/*  Iterator                                                            */
/* ------------------------------------------------------------------ */

rtdb_iter_t *rtdb_iter_new(rtdb_t *db) {
    rtdb_iter_t *it = calloc(1, sizeof(rtdb_iter_t));
    if (!it) return NULL;
    it->db = db;
    it->started = 0;
    it->stack_top = -1;
    /* descend to leftmost leaf */
    uint32_t pid = db->fhdr.root_page_id;
    for (;;) {
        MemPage *pg = pager_read(db, pid);
        if (!pg) break;
        it->stack_top++;
        it->stack[it->stack_top].page_id = pid;
        it->stack[it->stack_top].key_idx = 0;
        if (pg->hdr.page_type == PAGE_TYPE_LEAF) break;
        InternalNode nd;
        internal_parse(pg, &nd);
        pid = nd.child_left;
    }
    return it;
}

void rtdb_iter_free(rtdb_iter_t *it) {
    if (!it) return;
    free(it->key_buf);
    free(it->val_buf);
    free(it);
}

int rtdb_iter_next(rtdb_iter_t *it,
                   const void **key,   size_t *key_len,
                   const void **value, size_t *value_len) {
    /* Simple in-order traversal staying on leaf pages.
       B+ leaves aren't linked here, so we track via parent stack.    */
    while (it->stack_top >= 0) {
        uint32_t pid = it->stack[it->stack_top].page_id;
        int      idx = it->stack[it->stack_top].key_idx;
        MemPage *pg  = pager_read(it->db, pid);
        if (!pg) return RTDB_ERR_IO;

        if (pg->hdr.page_type == PAGE_TYPE_LEAF) {
            if (idx >= pg->hdr.n_keys) {
                it->stack_top--;  /* pop, go back to parent */
                continue;
            }
            /* parse cell at idx */
            size_t off = 0;
            for (int i = 0; i < idx; i++) {
                LeafCell c;
                if (!leaf_parse_cell(pg->payload, off, &c)) return RTDB_ERR_CORRUPT;
                off += c.cell_size;
            }
            LeafCell cell;
            if (!leaf_parse_cell(pg->payload, off, &cell)) return RTDB_ERR_CORRUPT;
            it->stack[it->stack_top].key_idx++;

            free(it->key_buf); it->key_buf = NULL;
            free(it->val_buf); it->val_buf = NULL;

            it->key_buf = malloc(cell.klen);
            if (!it->key_buf) return RTDB_ERR_NOMEM;
            memcpy(it->key_buf, cell.key, cell.klen);
            it->key_len = cell.klen;

            if (cell.flags & CELL_OVERFLOW) {
                int rc = ovfl_read(it->db, cell.v.ovfl_page, cell.vlen, &it->val_buf);
                if (rc != RTDB_OK) return rc;
            } else {
                it->val_buf = malloc(cell.vlen + 1);
                if (!it->val_buf) return RTDB_ERR_NOMEM;
                memcpy(it->val_buf, cell.v.inline_v.data, cell.vlen);
                it->val_buf[cell.vlen] = 0;
            }
            it->val_len = cell.vlen;

            *key       = it->key_buf;
            *key_len   = it->key_len;
            *value     = it->val_buf;
            *value_len = it->val_len;
            return RTDB_OK;
        }

        /* Internal node: if idx <= n_keys, descend into child */
        InternalNode nd;
        internal_parse(pg, &nd);
        if (idx > nd.n) {
            it->stack_top--; continue;
        }
        it->stack[it->stack_top].key_idx++;
        uint32_t child = (idx == 0) ? nd.child_left : nd.slots[idx-1].child_right;
        /* push child */
        if (it->stack_top + 1 < 32) {
            it->stack_top++;
            it->stack[it->stack_top].page_id = child;
            it->stack[it->stack_top].key_idx = 0;
        }
    }
    return RTDB_ERR_NOTFOUND;
}

/* ------------------------------------------------------------------ */
/*  Error strings                                                       */
/* ------------------------------------------------------------------ */
const char *rtdb_strerror(int err) {
    switch (err) {
    case RTDB_OK:          return "OK";
    case RTDB_ERR_IO:      return "I/O error";
    case RTDB_ERR_CORRUPT: return "database corrupt or wrong password";
    case RTDB_ERR_NOMEM:   return "out of memory";
    case RTDB_ERR_FULL:    return "database full";
    case RTDB_ERR_NOTFOUND:return "key not found";
    case RTDB_ERR_TOOBIG:  return "key or value too large";
    case RTDB_ERR_PARAM:   return "invalid parameter";
    default:               return "unknown error";
    }
}