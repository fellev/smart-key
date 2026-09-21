/**
 * @file smartkey_crypto.c
 * @brief SKP1 key derivation / tags, implemented on mbedTLS.
 *
 * On the ESP32-C5 mbedTLS transparently uses the SHA hardware accelerator, so a
 * HMAC-SHA256 costs tens of microseconds (protocol-spec.md §8).
 */

#include "smartkey_crypto.h"

#include <string.h>

#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"

#ifdef ESP_PLATFORM
#include "esp_random.h"
#else
#include <stdio.h>
#endif

#define SKC_INFO_BEACON "SKP1-beacon"
#define SKC_INFO_AUTH "SKP1-auth"
#define SKC_INFO_SESSION "SKP1-session"
#define SKC_INFO_PSEUDO "SKP1-pseudo"
#define SKC_TRANSCRIPT_AUTH "SKP1-auth-v1"
#define SKC_TRANSCRIPT_PAIR "SKP1-pair-v1"

/* Length of the string literals without the NUL terminator. */
#define LIT_LEN(s) (sizeof(s) - 1U)

/* ------------------------------------------------------------ primitives */

int skc_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
                    uint8_t out[32])
{
    if (key == NULL || out == NULL || (data == NULL && data_len > 0)) {
        return -1;
    }
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (info == NULL) {
        return -1;
    }
    return mbedtls_md_hmac(info, key, key_len, data, data_len, out);
}

int skc_hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt, size_t salt_len,
                    const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len)
{
    if (ikm == NULL || out == NULL || out_len == 0 || out_len > 255 * 32) {
        return -1;
    }
    const uint8_t zero_salt[32] = {0};
    if (salt == NULL || salt_len == 0) {
        salt = zero_salt;
        salt_len = sizeof(zero_salt);
    }

    /* extract */
    uint8_t prk[32];
    int rc = skc_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    if (rc != 0) {
        return rc;
    }

    /* expand */
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    rc = mbedtls_md_setup(&ctx, md, 1 /* hmac */);
    if (rc != 0) {
        goto cleanup;
    }

    uint8_t block[32];
    size_t done = 0;
    uint8_t counter = 1;
    size_t block_len = 0;
    while (done < out_len) {
        rc = mbedtls_md_hmac_starts(&ctx, prk, sizeof(prk));
        if (rc != 0) {
            goto cleanup;
        }
        if (block_len > 0) {
            rc = mbedtls_md_hmac_update(&ctx, block, block_len);
            if (rc != 0) {
                goto cleanup;
            }
        }
        if (info_len > 0) {
            rc = mbedtls_md_hmac_update(&ctx, info, info_len);
            if (rc != 0) {
                goto cleanup;
            }
        }
        rc = mbedtls_md_hmac_update(&ctx, &counter, 1);
        if (rc != 0) {
            goto cleanup;
        }
        rc = mbedtls_md_hmac_finish(&ctx, block);
        if (rc != 0) {
            goto cleanup;
        }
        block_len = sizeof(block);
        size_t chunk = out_len - done < block_len ? out_len - done : block_len;
        memcpy(out + done, block, chunk);
        done += chunk;
        counter++;
    }

cleanup:
    mbedtls_md_free(&ctx);
    mbedtls_platform_zeroize(prk, sizeof(prk));
    mbedtls_platform_zeroize(block, sizeof(block));
    return rc;
}

bool skc_ct_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    if (a == NULL || b == NULL) {
        return false;
    }
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

void skc_wipe(void *buf, size_t len)
{
    mbedtls_platform_zeroize(buf, len);
}

int skc_random(uint8_t *out, size_t len)
{
    if (out == NULL) {
        return -1;
    }
#ifdef ESP_PLATFORM
    esp_fill_random(out, len);
    return 0;
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL) {
        return -1;
    }
    size_t got = fread(out, 1, len, f);
    fclose(f);
    return got == len ? 0 : -1;
#endif
}

/* -------------------------------------------------------------- subkeys */

int skc_derive_subkeys(const uint8_t ltk[SKP_KEY_SIZE], const uint8_t lock_id[SKP_ID_SIZE],
                       const uint8_t user_id[SKP_ID_SIZE], skc_subkeys_t *out)
{
    if (ltk == NULL || lock_id == NULL || user_id == NULL || out == NULL) {
        return -1;
    }
    uint8_t salt[2 * SKP_ID_SIZE];
    memcpy(&salt[0], lock_id, SKP_ID_SIZE);
    memcpy(&salt[SKP_ID_SIZE], user_id, SKP_ID_SIZE);

    int rc = skc_hkdf_sha256(ltk, SKP_KEY_SIZE, salt, sizeof(salt),
                             (const uint8_t *)SKC_INFO_BEACON, LIT_LEN(SKC_INFO_BEACON),
                             out->k_beacon, SKP_KEY_SIZE);
    if (rc != 0) {
        return rc;
    }
    return skc_hkdf_sha256(ltk, SKP_KEY_SIZE, salt, sizeof(salt),
                           (const uint8_t *)SKC_INFO_AUTH, LIT_LEN(SKC_INFO_AUTH), out->k_auth,
                           SKP_KEY_SIZE);
}

int skc_pseudonym(const uint8_t k_beacon[SKP_KEY_SIZE], uint64_t epoch,
                  uint8_t out[SKP_PSEUDONYM_SIZE])
{
    if (k_beacon == NULL || out == NULL) {
        return -1;
    }
    uint8_t data[LIT_LEN(SKC_INFO_PSEUDO) + 8];
    memcpy(data, SKC_INFO_PSEUDO, LIT_LEN(SKC_INFO_PSEUDO));
    for (size_t i = 0; i < 8; i++) { /* uint64 little endian */
        data[LIT_LEN(SKC_INFO_PSEUDO) + i] = (uint8_t)((epoch >> (8 * i)) & 0xFF);
    }
    uint8_t tag[32];
    int rc = skc_hmac_sha256(k_beacon, SKP_KEY_SIZE, data, sizeof(data), tag);
    if (rc != 0) {
        return rc;
    }
    memcpy(out, tag, SKP_PSEUDONYM_SIZE);
    skc_wipe(tag, sizeof(tag));
    return 0;
}

/* ------------------------------------------------------------ handshake */

size_t skc_auth_transcript(const uint8_t lock_id[SKP_ID_SIZE], const uint8_t user_id[SKP_ID_SIZE],
                           const uint8_t nonce_l[SKP_NONCE_SIZE],
                           const uint8_t nonce_p[SKP_NONCE_SIZE], uint8_t *out)
{
    size_t off = 0;
    memcpy(out + off, SKC_TRANSCRIPT_AUTH, LIT_LEN(SKC_TRANSCRIPT_AUTH));
    off += LIT_LEN(SKC_TRANSCRIPT_AUTH);
    memcpy(out + off, lock_id, SKP_ID_SIZE);
    off += SKP_ID_SIZE;
    memcpy(out + off, user_id, SKP_ID_SIZE);
    off += SKP_ID_SIZE;
    memcpy(out + off, nonce_l, SKP_NONCE_SIZE);
    off += SKP_NONCE_SIZE;
    memcpy(out + off, nonce_p, SKP_NONCE_SIZE);
    off += SKP_NONCE_SIZE;
    return off; /* == SKC_AUTH_TRANSCRIPT_SIZE */
}

/** HMAC over (domain byte || data). */
static int tag_with_domain(const uint8_t key[SKP_KEY_SIZE], uint8_t domain, const uint8_t *data,
                           size_t len, uint8_t out[32])
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    int rc = mbedtls_md_setup(&ctx, md, 1);
    if (rc == 0) {
        rc = mbedtls_md_hmac_starts(&ctx, key, SKP_KEY_SIZE);
    }
    if (rc == 0) {
        rc = mbedtls_md_hmac_update(&ctx, &domain, 1);
    }
    if (rc == 0 && len > 0) {
        rc = mbedtls_md_hmac_update(&ctx, data, len);
    }
    if (rc == 0) {
        rc = mbedtls_md_hmac_finish(&ctx, out);
    }
    mbedtls_md_free(&ctx);
    return rc;
}

int skc_tag_phone(const uint8_t k_auth[SKP_KEY_SIZE], const uint8_t *transcript, size_t len,
                  uint8_t out[SKP_TAG_SIZE])
{
    return tag_with_domain(k_auth, SKC_DOMAIN_AUTH_PHONE, transcript, len, out);
}

int skc_tag_lock(const uint8_t k_auth[SKP_KEY_SIZE], const uint8_t *transcript, size_t len,
                 uint8_t out[SKP_TAG_SIZE])
{
    return tag_with_domain(k_auth, SKC_DOMAIN_AUTH_LOCK, transcript, len, out);
}

int skc_session_id(const uint8_t k_auth[SKP_KEY_SIZE], const uint8_t *transcript, size_t len,
                   uint8_t out[SKP_SESSION_ID_SIZE])
{
    uint8_t tag[32];
    int rc = tag_with_domain(k_auth, SKC_DOMAIN_SESSION_ID, transcript, len, tag);
    if (rc == 0) {
        memcpy(out, tag, SKP_SESSION_ID_SIZE);
    }
    skc_wipe(tag, sizeof(tag));
    return rc;
}

int skc_session_key(const uint8_t k_auth[SKP_KEY_SIZE], const uint8_t lock_id[SKP_ID_SIZE],
                    const uint8_t user_id[SKP_ID_SIZE], const uint8_t nonce_l[SKP_NONCE_SIZE],
                    const uint8_t nonce_p[SKP_NONCE_SIZE], uint8_t out[SKP_KEY_SIZE])
{
    uint8_t salt[2 * SKP_NONCE_SIZE];
    memcpy(&salt[0], nonce_l, SKP_NONCE_SIZE);
    memcpy(&salt[SKP_NONCE_SIZE], nonce_p, SKP_NONCE_SIZE);

    uint8_t info[LIT_LEN(SKC_INFO_SESSION) + 2 * SKP_ID_SIZE];
    memcpy(&info[0], SKC_INFO_SESSION, LIT_LEN(SKC_INFO_SESSION));
    memcpy(&info[LIT_LEN(SKC_INFO_SESSION)], lock_id, SKP_ID_SIZE);
    memcpy(&info[LIT_LEN(SKC_INFO_SESSION) + SKP_ID_SIZE], user_id, SKP_ID_SIZE);

    return skc_hkdf_sha256(k_auth, SKP_KEY_SIZE, salt, sizeof(salt), info, sizeof(info), out,
                           SKP_KEY_SIZE);
}

int skc_unlock_tag(const uint8_t k_sess[SKP_KEY_SIZE], const uint8_t sid[SKP_SESSION_ID_SIZE],
                   uint32_t counter, uint8_t result, uint8_t out[SKP_TAG_SIZE])
{
    uint8_t data[SKP_SESSION_ID_SIZE + 4 + 1];
    memcpy(&data[0], sid, SKP_SESSION_ID_SIZE);
    data[8] = (uint8_t)(counter & 0xFF);
    data[9] = (uint8_t)((counter >> 8) & 0xFF);
    data[10] = (uint8_t)((counter >> 16) & 0xFF);
    data[11] = (uint8_t)((counter >> 24) & 0xFF);
    data[12] = result;
    return tag_with_domain(k_sess, SKC_DOMAIN_UNLOCK_EVENT, data, sizeof(data), out);
}

/* -------------------------------------------------------------- pairing */

size_t skc_pair_transcript(const uint8_t lock_id[SKP_ID_SIZE], const uint8_t user_id[SKP_ID_SIZE],
                           const uint8_t pub_p[SKP_PUBKEY_SIZE],
                           const uint8_t pub_l[SKP_PUBKEY_SIZE],
                           const uint8_t nonce_p[SKP_NONCE_SIZE],
                           const uint8_t nonce_l[SKP_NONCE_SIZE], uint8_t *out)
{
    size_t off = 0;
    memcpy(out + off, SKC_TRANSCRIPT_PAIR, LIT_LEN(SKC_TRANSCRIPT_PAIR));
    off += LIT_LEN(SKC_TRANSCRIPT_PAIR);
    memcpy(out + off, lock_id, SKP_ID_SIZE);
    off += SKP_ID_SIZE;
    memcpy(out + off, user_id, SKP_ID_SIZE);
    off += SKP_ID_SIZE;
    memcpy(out + off, pub_p, SKP_PUBKEY_SIZE);
    off += SKP_PUBKEY_SIZE;
    memcpy(out + off, pub_l, SKP_PUBKEY_SIZE);
    off += SKP_PUBKEY_SIZE;
    memcpy(out + off, nonce_p, SKP_NONCE_SIZE);
    off += SKP_NONCE_SIZE;
    memcpy(out + off, nonce_l, SKP_NONCE_SIZE);
    off += SKP_NONCE_SIZE;
    return off; /* == SKC_PAIR_TRANSCRIPT_SIZE */
}

int skc_pair_ltk(const uint8_t shared_z[SKP_KEY_SIZE], const uint8_t nonce_p[SKP_NONCE_SIZE],
                 const uint8_t nonce_l[SKP_NONCE_SIZE], const uint8_t *transcript,
                 size_t transcript_len, const char *pairing_code, uint8_t out[SKP_KEY_SIZE])
{
    if (shared_z == NULL || transcript == NULL || pairing_code == NULL || out == NULL) {
        return -1;
    }
    size_t code_len = strlen(pairing_code);
    if (code_len != SKP_PAIRING_CODE_LEN) {
        return -1;
    }
    uint8_t salt[2 * SKP_NONCE_SIZE];
    memcpy(&salt[0], nonce_p, SKP_NONCE_SIZE);
    memcpy(&salt[SKP_NONCE_SIZE], nonce_l, SKP_NONCE_SIZE);

    /* info = transcript || pairing code */
    uint8_t info[SKC_PAIR_TRANSCRIPT_SIZE + SKP_PAIRING_CODE_LEN];
    if (transcript_len > SKC_PAIR_TRANSCRIPT_SIZE) {
        return -1;
    }
    memcpy(info, transcript, transcript_len);
    memcpy(info + transcript_len, pairing_code, code_len);

    return skc_hkdf_sha256(shared_z, SKP_KEY_SIZE, salt, sizeof(salt), info,
                           transcript_len + code_len, out, SKP_KEY_SIZE);
}

int skc_pair_confirm_lock(const uint8_t ltk[SKP_KEY_SIZE], const uint8_t *transcript, size_t len,
                          uint8_t out[SKP_TAG_SIZE])
{
    return tag_with_domain(ltk, SKC_DOMAIN_PAIR_CONFIRM_LOCK, transcript, len, out);
}

int skc_pair_confirm_phone(const uint8_t ltk[SKP_KEY_SIZE], const uint8_t *transcript, size_t len,
                           uint8_t out[SKP_TAG_SIZE])
{
    return tag_with_domain(ltk, SKC_DOMAIN_PAIR_CONFIRM_PHONE, transcript, len, out);
}

/* ---------------------------------------------------------------- X25519 */

/** mbedTLS RNG adapter backed by skc_random(). */
static int rng_adapter(void *ctx, unsigned char *buf, size_t len)
{
    (void)ctx;
    return skc_random(buf, len) == 0 ? 0 : -1;
}

int skc_x25519_keypair(uint8_t priv[SKP_KEY_SIZE], uint8_t pub[SKP_PUBKEY_SIZE])
{
    if (priv == NULL || pub == NULL) {
        return -1;
    }
    /* RFC 7748 clamping; mbedtls_ecdh_* re-clamps internally but we store the
     * clamped form so that the key is stable across reboots. */
    int rc = skc_random(priv, SKP_KEY_SIZE);
    if (rc != 0) {
        return rc;
    }
    priv[0] &= 248;
    priv[31] &= 127;
    priv[31] |= 64;

    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point q;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&q);

    rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (rc == 0) {
        rc = mbedtls_mpi_read_binary_le(&d, priv, SKP_KEY_SIZE);
    }
    if (rc == 0) {
        rc = mbedtls_ecp_mul(&grp, &q, &d, &grp.G, rng_adapter, NULL);
    }
    if (rc == 0) {
        rc = mbedtls_mpi_write_binary_le(&q.MBEDTLS_PRIVATE(X), pub, SKP_PUBKEY_SIZE);
    }

    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return rc;
}

int skc_x25519_shared(const uint8_t priv[SKP_KEY_SIZE], const uint8_t peer_pub[SKP_PUBKEY_SIZE],
                      uint8_t out[SKP_KEY_SIZE])
{
    if (priv == NULL || peer_pub == NULL || out == NULL) {
        return -1;
    }
    mbedtls_ecp_group grp;
    mbedtls_mpi d, z;
    mbedtls_ecp_point qp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_point_init(&qp);

    /* RFC 7748 clamping. mbedtls_ecp_check_privkey() rejects unclamped scalars,
     * and clamping is part of X25519 itself, so always apply it to a copy. */
    uint8_t clamped[SKP_KEY_SIZE];
    memcpy(clamped, priv, SKP_KEY_SIZE);
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;

    int rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (rc == 0) {
        rc = mbedtls_mpi_read_binary_le(&d, clamped, SKP_KEY_SIZE);
    }
    if (rc == 0) {
        rc = mbedtls_mpi_read_binary_le(&qp.MBEDTLS_PRIVATE(X), peer_pub, SKP_PUBKEY_SIZE);
    }
    if (rc == 0) {
        rc = mbedtls_mpi_lset(&qp.MBEDTLS_PRIVATE(Z), 1);
    }
    if (rc == 0) {
        rc = mbedtls_ecdh_compute_shared(&grp, &z, &qp, &d, rng_adapter, NULL);
    }
    if (rc == 0) {
        rc = mbedtls_mpi_write_binary_le(&z, out, SKP_KEY_SIZE);
    }
    if (rc == 0) {
        /* Reject all-zero shared secrets (low order points), security-model.md §3. */
        uint8_t acc = 0;
        for (size_t i = 0; i < SKP_KEY_SIZE; i++) {
            acc |= out[i];
        }
        if (acc == 0) {
            rc = -1;
        }
    }

    mbedtls_ecp_point_free(&qp);
    mbedtls_mpi_free(&z);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    skc_wipe(clamped, sizeof(clamped));
    return rc;
}
