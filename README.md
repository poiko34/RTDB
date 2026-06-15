# RTDB

RTDB is a lightweight encrypted embedded key-value database written in C.

It stores data inside a single file using a B+ tree index and page-based storage. All page payloads are encrypted with ChaCha20 and protected with BLAKE2b integrity checks.

The project is designed for small footprint deployments, simulations, offline storage, and scenarios where a simple self-contained encrypted database is preferable to larger database systems.

---

## Features

* Single-file database
* B+ tree storage engine
* Encrypted page payloads (ChaCha20)
* Integrity protection (BLAKE2b-256)
* Arbitrary binary keys and values
* Overflow pages for large values
* Embedded-friendly API
* No external database server required
* Small codebase

---

## Database Limits

| Item                  | Limit      |
| --------------------- | ---------- |
| Maximum key size      | 255 bytes  |
| Maximum value size    | 1 MiB      |
| Page size             | 4096 bytes |
| Maximum pages         | 65536      |
| Maximum database size | ~256 MiB   |

---

## File Layout

```text
+-----------------------+
| File Header (512 B)   |
+-----------------------+
| Page 0 (4096 B)       |
+-----------------------+
| Page 1 (4096 B)       |
+-----------------------+
| Page 2 (4096 B)       |
+-----------------------+
| ...                   |
+-----------------------+
```

Each page contains:

```text
+----------------------+
| Page Header (64 B)   |
+----------------------+
| Payload (4032 B)     |
+----------------------+
```

---

## Encryption

RTDB encrypts page payloads using ChaCha20.

For each page:

* A unique nonce is derived from the page identifier and encryption counter.
* The page payload is encrypted before being written to disk.
* A BLAKE2b-256 MAC is generated and stored in the page header.
* The MAC is verified whenever a page is loaded.

This protects the stored data against unauthorized modification and accidental corruption.

### Metadata Visibility

RTDB encrypts page payloads.

The following metadata remains visible:

* Database magic value
* Database version
* Salt
* Page identifiers
* Page types
* Number of keys per page
* Page counters

The actual key-value contents are encrypted.

---

## Basic Usage

### Open Database

```c
rtdb_t *db;

int rc = rtdb_open(
    "example.db",
    "StrongPassword",
    &db
);

if (rc != RTDB_OK) {
    return 1;
}
```

### Insert Data

```c
const char *key = "username";
const char *value = "operator";

rtdb_put(
    db,
    key,
    strlen(key),
    value,
    strlen(value)
);
```

### Retrieve Data

```c
void *value;
size_t value_len;

int rc = rtdb_get(
    db,
    "username",
    8,
    &value,
    &value_len
);

if (rc == RTDB_OK) {
    printf("%.*s\n",
           (int)value_len,
           (char *)value);

    free(value);
}
```

### Delete Data

```c
rtdb_delete(
    db,
    "username",
    8
);
```

### Close Database

```c
rtdb_close(db);
```

---

## Storing Structured Records

RTDB stores arbitrary binary values.

Applications may store:

* JSON
* CBOR
* MessagePack
* Protocol Buffers
* Custom binary structures

Example:

```json
{
  "label": "GitHub",
  "url": "https://github.com",
  "login": "user",
  "password": "secret"
}
```

The entire serialized record can be stored as a single value.

---

## Iteration

```c
rtdb_iter_t *it = rtdb_iter_new(db);

const void *key;
const void *value;
size_t key_len;
size_t value_len;

while (
    rtdb_iter_next(
        it,
        &key,
        &key_len,
        &value,
        &value_len
    ) == RTDB_OK
) {
    /* process record */
}

rtdb_iter_free(it);
```

---

## Error Codes

| Code              | Description               |
| ----------------- | ------------------------- |
| RTDB_OK           | Success                   |
| RTDB_ERR_IO       | I/O error                 |
| RTDB_ERR_CORRUPT  | Corrupted database        |
| RTDB_ERR_NOMEM    | Memory allocation failure |
| RTDB_ERR_FULL     | Database full             |
| RTDB_ERR_NOTFOUND | Key not found             |
| RTDB_ERR_TOOBIG   | Key or value too large    |
| RTDB_ERR_PARAM    | Invalid parameter         |

---

## Build

Example:

```bash
gcc *.c -o rtdb_demo
```

Adjust compiler flags and crypto library dependencies as required by your environment.

---

## License

This project is provided as-is without warranty. Review and audit the code before using it in production environments.
