/**
 * @file smartkey_store.h
 * @brief Persistent credential storage (NVS) — see pairing-spec.md §4.
 *
 * Holds the lock identity and up to CONFIG_SMARTKEY_MAX_USERS credentials.
 * Derived sub keys (K_auth / K_beacon) are cached in RAM so the presence
 * handshake never touches flash (protocol-spec.md §8).
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "smartkey_crypto.h"
#include "smartkey_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SKS_NAME_MAX 32

/** One paired phone. */
typedef struct {
    uint8_t user_id[SKP_ID_SIZE];
    uint8_t ltk[SKP_KEY_SIZE];
    skc_subkeys_t subkeys; /**< cached derivation of ltk */
    char name[SKS_NAME_MAX];
    bool enabled;
    bool used;
} sks_credential_t;

/**
 * @brief Open NVS, load the lock id (creating one on first boot) and all credentials.
 */
esp_err_t sks_init(void);

/** @brief The 16 byte identity of this door unit. */
const uint8_t *sks_lock_id(void);

/** @brief Number of populated credential slots. */
size_t sks_count(void);

/** @brief Total number of slots (CONFIG_SMARTKEY_MAX_USERS). */
size_t sks_capacity(void);

/**
 * @brief Read-only access to a slot.
 * @return NULL when the index is out of range or the slot is empty.
 */
const sks_credential_t *sks_get(size_t index);

/** @brief Find an enabled credential by user id. @return NULL when not found. */
const sks_credential_t *sks_find_by_user(const uint8_t user_id[SKP_ID_SIZE]);

/**
 * @brief Store (or replace) a credential and persist it.
 * @param[out] out_slot receives the slot index used
 * @return ESP_ERR_NO_MEM when all slots are taken.
 */
esp_err_t sks_add(const uint8_t user_id[SKP_ID_SIZE], const uint8_t ltk[SKP_KEY_SIZE],
                  const char *name, size_t *out_slot);

/** @brief Enable/disable a slot without deleting it (security-model.md §5). */
esp_err_t sks_set_enabled(size_t index, bool enabled);

/** @brief Erase a single credential. */
esp_err_t sks_remove(size_t index);

/** @brief Erase every credential (factory reset). The lock id is preserved. */
esp_err_t sks_erase_all(void);

#ifdef __cplusplus
}
#endif
