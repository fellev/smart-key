/**
 * @file smartkey_crypto.h
 * @brief SKP1 key derivation and authentication tags (mbedTLS based).
 *
 * Mirrors shared-protocols/tools/skp_crypto.py — both are validated against the
 * golden vectors in shared-protocols/test-vectors/.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "smartkey_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Domain separation bytes (protocol-spec.md §5). */
#define SKC_DOMAIN_AUTH_PHONE 0x01
#define SKC_DOMAIN_AUTH_LOCK 0x02
#define SKC_DOMAIN_SESSION_ID 0x03
#define SKC_DOMAIN_UNLOCK_EVENT 0x10
#define SKC_DOMAIN_PAIR_CONFIRM_LOCK 0x01
#define SKC_DOMAIN_PAIR_CONFIRM_PHONE 0x02

#define SKC_BEACON_EPOCH_SECONDS 15
/** Number of epochs kept on each side of the current one (clock skew tolerance). */
#define SKC_BEACON_EPOCH_SKEW 2
#define SKC_BEACON_EPOCH_SLOTS (2 * SKC_BEACON_EPOCH_SKEW + 1)

/** Maximum transcript size: label(12) + 2 ids(32) + 2 nonces(32) = 76, rounded up. */
#define SKC_AUTH_TRANSCRIPT_SIZE 76
/** Pair transcript: label(12) + 2 ids(32) + 2 pubkeys(64) + 2 nonces(32) = 140. */
#define SKC_PAIR_TRANSCRIPT_SIZE 140

typedef struct {
    uint8_t k_beacon[SKP_KEY_SIZE];
    uint8_t k_auth[SKP_KEY_SIZE];
} skc_subkeys_t;

/** HMAC-SHA256. @return 0 on success. */
int skc_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
                    uint8_t out[32]);

/** HKDF-SHA256 (RFC 5869 extract-then-expand). @return 0 on success. */
int skc_hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt, size_t salt_len,
                    const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len);

/** Constant time comparison. @return true when equal. */
bool skc_ct_equal(const uint8_t *a, const uint8_t *b, size_t len);

/** Fill @p out with cryptographically secure random bytes. @return 0 on success. */
int skc_random(uint8_t *out, size_t len);

/** Derive K_beacon / K_auth from the long term key (protocol-spec.md §1). */
int skc_derive_subkeys(const uint8_t ltk[SKP_KEY_SIZE], const uint8_t lock_id[SKP_ID_SIZE],
                       const uint8_t user_id[SKP_ID_SIZE], skc_subkeys_t *out);

/** Rolling advertising pseudonym for @p epoch (protocol-spec.md §2.2). */
int skc_pseudonym(const uint8_t k_beacon[SKP_KEY_SIZE], uint64_t epoch,
                  uint8_t out[SKP_PSEUDONYM_SIZE]);

static inline uint64_t skc_epoch_for(uint64_t unix_seconds)
{
    return unix_seconds / SKC_BEACON_EPOCH_SECONDS;
}

/** Build the handshake transcript; @p out must hold SKC_AUTH_TRANSCRIPT_SIZE bytes. */
size_t skc_auth_transcript(const uint8_t lock_id[SKP_ID_SIZE], const uint8_t user_id[SKP_ID_SIZE],
                           const uint8_t nonce_l[SKP_NONCE_SIZE],
                           const uint8_t nonce_p[SKP_NONCE_SIZE], uint8_t *out);

int skc_tag_phone(const uint8_t k_auth[SKP_KEY_SIZE], const uint8_t *transcript, size_t len,
                  uint8_t out[SKP_TAG_SIZE]);
int skc_tag_lock(const uint8_t k_auth[SKP_KEY_SIZE], const uint8_t *transcript, size_t len,
                 uint8_t out[SKP_TAG_SIZE]);
int skc_session_id(const uint8_t k_auth[SKP_KEY_SIZE], const uint8_t *transcript, size_t len,
                   uint8_t out[SKP_SESSION_ID_SIZE]);
int skc_session_key(const uint8_t k_auth[SKP_KEY_SIZE], const uint8_t lock_id[SKP_ID_SIZE],
                    const uint8_t user_id[SKP_ID_SIZE], const uint8_t nonce_l[SKP_NONCE_SIZE],
                    const uint8_t nonce_p[SKP_NONCE_SIZE], uint8_t out[SKP_KEY_SIZE]);

int skc_unlock_tag(const uint8_t k_sess[SKP_KEY_SIZE], const uint8_t sid[SKP_SESSION_ID_SIZE],
                   uint32_t counter, uint8_t result, uint8_t out[SKP_TAG_SIZE]);

/* ------------------------------------------------------------------ pairing */

/** Build the pairing transcript; @p out must hold SKC_PAIR_TRANSCRIPT_SIZE bytes. */
size_t skc_pair_transcript(const uint8_t lock_id[SKP_ID_SIZE], const uint8_t user_id[SKP_ID_SIZE],
                           const uint8_t pub_p[SKP_PUBKEY_SIZE],
                           const uint8_t pub_l[SKP_PUBKEY_SIZE],
                           const uint8_t nonce_p[SKP_NONCE_SIZE],
                           const uint8_t nonce_l[SKP_NONCE_SIZE], uint8_t *out);

int skc_pair_ltk(const uint8_t shared_z[SKP_KEY_SIZE], const uint8_t nonce_p[SKP_NONCE_SIZE],
                 const uint8_t nonce_l[SKP_NONCE_SIZE], const uint8_t *transcript,
                 size_t transcript_len, const char *pairing_code, uint8_t out[SKP_KEY_SIZE]);

int skc_pair_confirm_lock(const uint8_t ltk[SKP_KEY_SIZE], const uint8_t *transcript, size_t len,
                          uint8_t out[SKP_TAG_SIZE]);
int skc_pair_confirm_phone(const uint8_t ltk[SKP_KEY_SIZE], const uint8_t *transcript, size_t len,
                           uint8_t out[SKP_TAG_SIZE]);

/** Generate an X25519 key pair. @return 0 on success. */
int skc_x25519_keypair(uint8_t priv[SKP_KEY_SIZE], uint8_t pub[SKP_PUBKEY_SIZE]);

/** X25519 shared secret. Rejects an all-zero result. @return 0 on success. */
int skc_x25519_shared(const uint8_t priv[SKP_KEY_SIZE], const uint8_t peer_pub[SKP_PUBKEY_SIZE],
                      uint8_t out[SKP_KEY_SIZE]);

/** Wipe sensitive memory (not optimised away). */
void skc_wipe(void *buf, size_t len);

#ifdef __cplusplus
}
#endif
