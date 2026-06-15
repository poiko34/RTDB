#pragma once
/*
 * rtdb.h — Encrypted B-tree database for red team use
 *
 * Single-file on-disk store. Every page is encrypted with ChaCha20
 * and integrity-protected with BLAKE2b-256 MAC.
 *
 * Layout:
 *   [FILE_HEADER 512B][PAGE_0 4096B][PAGE_1 4096B]...
 *
 * Each page:
 *   [PAGE_HEADER 64B][payload 4032B]
 *
 * Key   : arbitrary bytes, max 255 bytes
 * Value : arbitrary bytes (strings or blobs), max ~3900 bytes inline
 *         (large values are split across overflow pages)
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  Error codes                                                         */
/* ------------------------------------------------------------------ */
#define RTDB_OK           0
#define RTDB_ERR_IO      -1   /* file I/O failure                      */
#define RTDB_ERR_CORRUPT -2   /* MAC mismatch / bad magic              */
#define RTDB_ERR_NOMEM   -3   /* malloc failed                         */
#define RTDB_ERR_FULL    -4   /* db has no free pages                  */
#define RTDB_ERR_NOTFOUND -5  /* key not found                         */
#define RTDB_ERR_TOOBIG  -6   /* key or value exceeds limit            */
#define RTDB_ERR_PARAM   -7   /* bad parameter                         */

/* ------------------------------------------------------------------ */
/*  Limits                                                              */
/* ------------------------------------------------------------------ */
#define RTDB_MAX_KEY     255
#define RTDB_MAX_VALUE   (1024 * 1024)   /* 1 MiB via overflow chain   */
#define RTDB_PAGE_SIZE   4096
#define RTDB_MAX_PAGES   65536           /* 256 MiB max db size        */

/* ------------------------------------------------------------------ */
/*  Opaque handle                                                       */
/* ------------------------------------------------------------------ */
typedef struct rtdb_t rtdb_t;

/* ------------------------------------------------------------------ */
/*  Open / close                                                        */
/* ------------------------------------------------------------------ */

/*
 * rtdb_open — open (or create) an encrypted database file.
 *
 *   path     : path to .db file
 *   password : master password (NUL-terminated); key derived via key21()
 *   out      : receives the db handle on success
 *
 * On create: writes an encrypted file header and an empty root page.
 * On open  : verifies magic + MAC of the file header.
 *
 * Returns RTDB_OK or negative error code.
 */
int rtdb_open(const char *path, const char *password, rtdb_t **out);

/*
 * rtdb_close — flush dirty pages and close the file.
 * Always call this; leaking is not harmful but wastes memory.
 */
void rtdb_close(rtdb_t *db);

/* ------------------------------------------------------------------ */
/*  Core operations                                                     */
/* ------------------------------------------------------------------ */

/*
 * rtdb_put — insert or update a key/value pair.
 *
 *   key, key_len     : key bytes  (max RTDB_MAX_KEY)
 *   value, value_len : value bytes (max RTDB_MAX_VALUE)
 *
 * Returns RTDB_OK or negative error code.
 */
int rtdb_put(rtdb_t *db,
             const void *key,   size_t key_len,
             const void *value, size_t value_len);

/*
 * rtdb_get — retrieve value for a key.
 *
 *   key, key_len     : key to look up
 *   out_value        : *out_value receives a malloc'd copy of the value
 *   out_value_len    : *out_value_len receives value length
 *
 * Caller must free(*out_value).
 * Returns RTDB_OK, RTDB_ERR_NOTFOUND, or negative error code.
 */
int rtdb_get(rtdb_t *db,
             const void *key,  size_t key_len,
             void **out_value, size_t *out_value_len);

/*
 * rtdb_delete — remove a key (no-op if not found).
 * Returns RTDB_OK or negative error code.
 */
int rtdb_delete(rtdb_t *db, const void *key, size_t key_len);

/* ------------------------------------------------------------------ */
/*  Iteration                                                           */
/* ------------------------------------------------------------------ */
typedef struct rtdb_iter_t rtdb_iter_t;

rtdb_iter_t *rtdb_iter_new(rtdb_t *db);   /* NULL on OOM             */
void         rtdb_iter_free(rtdb_iter_t *it);

/*
 * rtdb_iter_next — advance iterator.
 * Returns RTDB_OK with *key/*value filled (pointers into internal
 * buffer, valid until next call or rtdb_iter_free).
 * Returns RTDB_ERR_NOTFOUND when exhausted.
 */
int rtdb_iter_next(rtdb_iter_t *it,
                   const void **key,   size_t *key_len,
                   const void **value, size_t *value_len);

/* ------------------------------------------------------------------ */
/*  Utility                                                             */
/* ------------------------------------------------------------------ */
const char *rtdb_strerror(int err);

#ifdef __cplusplus
}
#endif