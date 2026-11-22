#ifndef AUTHCRAFT_JOSE_H
#define AUTHCRAFT_JOSE_H

/*
 * Zig compact JWS/JWT verifier C ABI (ADR 0004).
 *
 * Policy and JWKS byte buffers use the same JSON shapes as `jose-cli verify`.
 * Return codes: 0 accept, 1 reject (ADR 0003 code in result->error),
 * 2 configuration error (result->error is "config"), 3 invalid arguments.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct authcraft_jose_verify_input {
    const uint8_t *token;
    size_t token_len;
    const uint8_t *jwks;
    size_t jwks_len;
    const uint8_t *policy;
    size_t policy_len;
} authcraft_jose_verify_input;

typedef struct authcraft_jose_verify_result {
    char error[32];
    char kid[256];
    char alg[16];
} authcraft_jose_verify_result;

int authcraft_jose_verify(
    const authcraft_jose_verify_input *input,
    authcraft_jose_verify_result *result);

#ifdef __cplusplus
}
#endif

#endif /* AUTHCRAFT_JOSE_H */
