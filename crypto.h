#pragma once

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus 
extern "C" {
#endif

struct chacha20_context
{
	uint32_t keystream32[16];
	size_t position;

	uint8_t key[32];
	uint8_t nonce[12];
	uint64_t counter;

	uint32_t state[16];
};

typedef struct {
    uint8_t b[128];                     // input buffer
    uint64_t h[8];                      // chained state
    uint64_t t[2];                      // total number of bytes
    size_t c;                           // pointer for b[]
    size_t outlen;                      // digest size
} blake2b_ctx;

void chacha20_init_context(struct chacha20_context *ctx, uint8_t key[], uint8_t nounc[], uint64_t counter);

void chacha20_xor(struct chacha20_context *ctx, uint8_t *bytes, size_t n_bytes);

int blake2b_init(blake2b_ctx *ctx, size_t outlen,
    const void *key, size_t keylen);    // secret key

// Add "inlen" bytes from "in" into the hash.
void blake2b_update(blake2b_ctx *ctx,   // context
    const void *in, size_t inlen);      // data to be hashed

// Generate the message digest (size given in init).
//      Result placed in "out".
void blake2b_final(blake2b_ctx *ctx, void *out);

// All-in-one convenience function.
int blake2b(void *out, size_t outlen,   // return buffer for digest
    const void *key, size_t keylen,     // optional secret key
    const void *in, size_t inlen);      // data to be hashed

void key21(char* string, size_t string_len, unsigned char key[32]);
#ifdef __cplusplus 
}
#endif 