/**
 * @file pseudonym_table.c
 * @brief Implementation of the rolling pseudonym lookup (protocol-spec.md §2.2).
 */

#include "pseudonym_table.h"

#include <string.h>

#include "esp_log.h"
#include "smartkey_store.h"

static const char *TAG = "sk_pseudo";

typedef struct {
    uint8_t values[SKC_BEACON_EPOCH_SLOTS][SKP_PSEUDONYM_SIZE];
    bool valid;
} user_entry_t;

static user_entry_t s_table[CONFIG_SMARTKEY_MAX_USERS];
static uint64_t s_epoch;
static bool s_dirty = true;

void skb_pseudo_invalidate(void)
{
    s_dirty = true;
}

void skb_pseudo_rebuild(uint64_t now_epoch)
{
    if (!s_dirty && now_epoch == s_epoch) {
        return;
    }
    s_epoch = now_epoch;
    s_dirty = false;

    size_t active = 0;
    for (size_t slot = 0; slot < CONFIG_SMARTKEY_MAX_USERS; slot++) {
        const sks_credential_t *cred = sks_get(slot);
        s_table[slot].valid = false;
        if (cred == NULL || !cred->enabled) {
            continue;
        }
        bool ok = true;
        for (int i = 0; i < SKC_BEACON_EPOCH_SLOTS; i++) {
            /* Epoch window: now-SKEW .. now+SKEW, clamped at zero. */
            int64_t epoch = (int64_t)now_epoch + i - SKC_BEACON_EPOCH_SKEW;
            if (epoch < 0) {
                epoch = 0;
            }
            if (skc_pseudonym(cred->subkeys.k_beacon, (uint64_t)epoch, s_table[slot].values[i]) !=
                0) {
                ok = false;
                break;
            }
        }
        s_table[slot].valid = ok;
        if (ok) {
            active++;
        }
    }
    ESP_LOGD(TAG, "rebuilt table for epoch %llu, %u users", (unsigned long long)now_epoch,
             (unsigned)active);
}

bool skb_pseudo_match(const uint8_t pseudonym[SKP_PSEUDONYM_SIZE], size_t *out_slot)
{
    if (pseudonym == NULL) {
        return false;
    }
    for (size_t slot = 0; slot < CONFIG_SMARTKEY_MAX_USERS; slot++) {
        if (!s_table[slot].valid) {
            continue;
        }
        for (int i = 0; i < SKC_BEACON_EPOCH_SLOTS; i++) {
            if (memcmp(s_table[slot].values[i], pseudonym, SKP_PSEUDONYM_SIZE) == 0) {
                if (out_slot != NULL) {
                    *out_slot = slot;
                }
                return true;
            }
        }
    }
    return false;
}
