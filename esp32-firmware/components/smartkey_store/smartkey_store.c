/**
 * @file smartkey_store.c
 * @brief NVS backed credential store (pairing-spec.md §4).
 */

#include "smartkey_store.h"

#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"

static const char *TAG = "sk_store";

#define NVS_NAMESPACE "smartkey"
#define KEY_LOCK_ID "lock_id"

static sks_credential_t s_creds[CONFIG_SMARTKEY_MAX_USERS];
static uint8_t s_lock_id[SKP_ID_SIZE];
static bool s_ready;

/* NVS keys are limited to 15 characters: "u0.ltk" etc. fits comfortably. */
static void slot_key(char *buf, size_t size, size_t slot, const char *field)
{
    snprintf(buf, size, "u%u.%s", (unsigned)slot, field);
}

/** Recompute the cached sub keys for a slot. */
static esp_err_t refresh_subkeys(sks_credential_t *cred)
{
    if (skc_derive_subkeys(cred->ltk, s_lock_id, cred->user_id, &cred->subkeys) != 0) {
        return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t load_lock_id(nvs_handle_t h)
{
    size_t len = sizeof(s_lock_id);
    esp_err_t err = nvs_get_blob(h, KEY_LOCK_ID, s_lock_id, &len);
    if (err == ESP_OK && len == sizeof(s_lock_id)) {
        return ESP_OK;
    }

    /* First boot: mint a random identity. */
    if (skc_random(s_lock_id, sizeof(s_lock_id)) != 0) {
        return ESP_FAIL;
    }
    err = nvs_set_blob(h, KEY_LOCK_ID, s_lock_id, sizeof(s_lock_id));
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    ESP_LOGI(TAG, "generated new lock identity");
    return err;
}

static void load_slot(nvs_handle_t h, size_t slot)
{
    sks_credential_t *cred = &s_creds[slot];
    char key[16];
    size_t len;

    slot_key(key, sizeof(key), slot, "uid");
    len = sizeof(cred->user_id);
    if (nvs_get_blob(h, key, cred->user_id, &len) != ESP_OK || len != sizeof(cred->user_id)) {
        return;
    }

    slot_key(key, sizeof(key), slot, "ltk");
    len = sizeof(cred->ltk);
    if (nvs_get_blob(h, key, cred->ltk, &len) != ESP_OK || len != sizeof(cred->ltk)) {
        return;
    }

    slot_key(key, sizeof(key), slot, "name");
    len = sizeof(cred->name);
    if (nvs_get_str(h, key, cred->name, &len) != ESP_OK) {
        cred->name[0] = '\0';
    }

    uint8_t enabled = 1;
    slot_key(key, sizeof(key), slot, "en");
    nvs_get_u8(h, key, &enabled);

    cred->enabled = enabled != 0;
    cred->used = true;
    if (refresh_subkeys(cred) != ESP_OK) {
        ESP_LOGE(TAG, "slot %u: sub key derivation failed, dropping", (unsigned)slot);
        memset(cred, 0, sizeof(*cred));
    }
}

esp_err_t sks_init(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    if (err != ESP_OK) {
        return err;
    }

    nvs_handle_t h;
    err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }

    memset(s_creds, 0, sizeof(s_creds));
    err = load_lock_id(h);
    if (err == ESP_OK) {
        for (size_t i = 0; i < CONFIG_SMARTKEY_MAX_USERS; i++) {
            load_slot(h, i);
        }
    }
    nvs_close(h);

    s_ready = (err == ESP_OK);
    ESP_LOGI(TAG, "store ready, %u/%u credentials", (unsigned)sks_count(),
             (unsigned)CONFIG_SMARTKEY_MAX_USERS);
    return err;
}

const uint8_t *sks_lock_id(void)
{
    return s_lock_id;
}

size_t sks_count(void)
{
    size_t n = 0;
    for (size_t i = 0; i < CONFIG_SMARTKEY_MAX_USERS; i++) {
        if (s_creds[i].used) {
            n++;
        }
    }
    return n;
}

size_t sks_capacity(void)
{
    return CONFIG_SMARTKEY_MAX_USERS;
}

const sks_credential_t *sks_get(size_t index)
{
    if (index >= CONFIG_SMARTKEY_MAX_USERS || !s_creds[index].used) {
        return NULL;
    }
    return &s_creds[index];
}

const sks_credential_t *sks_find_by_user(const uint8_t user_id[SKP_ID_SIZE])
{
    if (user_id == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < CONFIG_SMARTKEY_MAX_USERS; i++) {
        if (s_creds[i].used && s_creds[i].enabled &&
            skc_ct_equal(s_creds[i].user_id, user_id, SKP_ID_SIZE)) {
            return &s_creds[i];
        }
    }
    return NULL;
}

esp_err_t sks_add(const uint8_t user_id[SKP_ID_SIZE], const uint8_t ltk[SKP_KEY_SIZE],
                  const char *name, size_t *out_slot)
{
    if (!s_ready || user_id == NULL || ltk == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Re-pairing the same phone replaces its slot instead of consuming a new one. */
    size_t slot = CONFIG_SMARTKEY_MAX_USERS;
    for (size_t i = 0; i < CONFIG_SMARTKEY_MAX_USERS; i++) {
        if (s_creds[i].used && memcmp(s_creds[i].user_id, user_id, SKP_ID_SIZE) == 0) {
            slot = i;
            break;
        }
    }
    if (slot == CONFIG_SMARTKEY_MAX_USERS) {
        for (size_t i = 0; i < CONFIG_SMARTKEY_MAX_USERS; i++) {
            if (!s_creds[i].used) {
                slot = i;
                break;
            }
        }
    }
    if (slot == CONFIG_SMARTKEY_MAX_USERS) {
        return ESP_ERR_NO_MEM;
    }

    sks_credential_t *cred = &s_creds[slot];
    memset(cred, 0, sizeof(*cred));
    memcpy(cred->user_id, user_id, SKP_ID_SIZE);
    memcpy(cred->ltk, ltk, SKP_KEY_SIZE);
    snprintf(cred->name, sizeof(cred->name), "%s", name != NULL ? name : "phone");
    cred->enabled = true;
    cred->used = true;

    esp_err_t err = refresh_subkeys(cred);
    if (err != ESP_OK) {
        memset(cred, 0, sizeof(*cred));
        return err;
    }

    nvs_handle_t h;
    err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }
    char key[16];
    slot_key(key, sizeof(key), slot, "uid");
    err = nvs_set_blob(h, key, cred->user_id, SKP_ID_SIZE);
    if (err == ESP_OK) {
        slot_key(key, sizeof(key), slot, "ltk");
        err = nvs_set_blob(h, key, cred->ltk, SKP_KEY_SIZE);
    }
    if (err == ESP_OK) {
        slot_key(key, sizeof(key), slot, "name");
        err = nvs_set_str(h, key, cred->name);
    }
    if (err == ESP_OK) {
        slot_key(key, sizeof(key), slot, "en");
        err = nvs_set_u8(h, key, 1);
    }
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "stored credential in slot %u (%s)", (unsigned)slot, cred->name);
        if (out_slot != NULL) {
            *out_slot = slot;
        }
    }
    return err;
}

esp_err_t sks_set_enabled(size_t index, bool enabled)
{
    if (index >= CONFIG_SMARTKEY_MAX_USERS || !s_creds[index].used) {
        return ESP_ERR_INVALID_ARG;
    }
    s_creds[index].enabled = enabled;

    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }
    char key[16];
    slot_key(key, sizeof(key), index, "en");
    err = nvs_set_u8(h, key, enabled ? 1 : 0);
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    ESP_LOGI(TAG, "slot %u %s", (unsigned)index, enabled ? "enabled" : "revoked");
    return err;
}

esp_err_t sks_remove(size_t index)
{
    if (index >= CONFIG_SMARTKEY_MAX_USERS) {
        return ESP_ERR_INVALID_ARG;
    }
    skc_wipe(&s_creds[index], sizeof(s_creds[index]));

    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }
    const char *fields[] = {"uid", "ltk", "name", "en"};
    char key[16];
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        slot_key(key, sizeof(key), index, fields[i]);
        nvs_erase_key(h, key); /* ESP_ERR_NVS_NOT_FOUND is fine */
    }
    err = nvs_commit(h);
    nvs_close(h);
    return err;
}

esp_err_t sks_erase_all(void)
{
    esp_err_t err = ESP_OK;
    for (size_t i = 0; i < CONFIG_SMARTKEY_MAX_USERS; i++) {
        esp_err_t e = sks_remove(i);
        if (e != ESP_OK) {
            err = e;
        }
    }
    ESP_LOGW(TAG, "all credentials erased");
    return err;
}
