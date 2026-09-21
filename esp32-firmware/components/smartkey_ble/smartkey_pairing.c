/**
 * @file smartkey_pairing.c
 * @brief Pairing responder: GATT server + X25519 key agreement.
 *
 * Implements the lock side of pairing-spec.md §2-3.
 */

#include "smartkey_pairing.h"

#include <string.h>

#include "esp_log.h"
#include "host/ble_gap.h"
#include "host/ble_hs.h"
#include "services/gatt/ble_svc_gatt.h"
#include "smartkey_crypto.h"
#include "smartkey_proto.h"
#include "smartkey_store.h"

static const char *TAG = "sk_pair";

#define MAX_ATTEMPTS 3

static const ble_uuid128_t UUID_PAIR_SERVICE =
    BLE_UUID128_INIT(0x10, 0x5a, 0x0c, 0x6f, 0x0a, 0x2f, 0x9e, 0x9c, 0x1e, 0x4b, 0x5f, 0x6b, 0x01,
                     0x00, 0x9a, 0x8e);
static const ble_uuid128_t UUID_PAIR_CHR =
    BLE_UUID128_INIT(0x10, 0x5a, 0x0c, 0x6f, 0x0a, 0x2f, 0x9e, 0x9c, 0x1e, 0x4b, 0x5f, 0x6b, 0x04,
                     0x00, 0x9a, 0x8e);

/** State of the in-flight pairing exchange. */
typedef struct {
    bool armed;
    char code[SKP_PAIRING_CODE_LEN + 1];
    uint8_t attempts;

    uint8_t priv_l[SKP_KEY_SIZE];
    uint8_t pub_l[SKP_PUBKEY_SIZE];
    uint8_t nonce_l[SKP_NONCE_SIZE];

    uint8_t user_id[SKP_ID_SIZE];
    uint8_t ltk[SKP_KEY_SIZE];
    uint8_t transcript[SKC_PAIR_TRANSCRIPT_SIZE];
    size_t transcript_len;
    uint8_t expected_confirm_p[SKP_TAG_SIZE];
    bool response_sent;

    uint16_t conn_handle;
    uint16_t pairing_handle;
} pairing_ctx_t;

static pairing_ctx_t s_ctx;
static skb_paired_cb_t s_paired_cb;
static void *s_paired_ctx;

static int pairing_access(uint16_t conn_handle, uint16_t attr_handle,
                          struct ble_gatt_access_ctxt *ctxt, void *arg);

static const struct ble_gatt_svc_def s_services[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &UUID_PAIR_SERVICE.u,
        .characteristics =
            (struct ble_gatt_chr_def[]){
                {
                    .uuid = &UUID_PAIR_CHR.u,
                    .access_cb = pairing_access,
                    .val_handle = &s_ctx.pairing_handle,
                    .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_NOTIFY,
                },
                {0},
            },
    },
    {0},
};

/** Send a frame back to the phone as a notification on PAIRING. */
static void notify(const uint8_t *frame, uint16_t len)
{
    struct os_mbuf *om = ble_hs_mbuf_from_flat(frame, len);
    if (om == NULL) {
        return;
    }
    ble_gatts_notify_custom(s_ctx.conn_handle, s_ctx.pairing_handle, om);
}

static void send_result(uint8_t status, uint8_t slot)
{
    uint8_t frame[SKP_HEADER_SIZE + SKP_PAIR_RESULT_SIZE];
    int n = skp_encode_pair_result(status, slot, frame, sizeof(frame));
    if (n > 0) {
        notify(frame, (uint16_t)n);
    }
}

/** Handle PAIR_START: run ECDH, derive the LTK, answer with PAIR_RESPONSE. */
static void handle_pair_start(const skp_frame_t *frame)
{
    skp_pair_start_t start;
    if (skp_parse_pair_start(frame, &start) != SKP_OK) {
        send_result(SKP_PAIR_BAD_CONFIRM, 0);
        return;
    }

    uint8_t shared[SKP_KEY_SIZE];
    if (skc_x25519_shared(s_ctx.priv_l, start.pubkey_p, shared) != 0) {
        ESP_LOGW(TAG, "rejected peer public key");
        send_result(SKP_PAIR_BAD_CONFIRM, 0);
        return;
    }

    memcpy(s_ctx.user_id, start.user_id, SKP_ID_SIZE);
    s_ctx.transcript_len =
        skc_pair_transcript(sks_lock_id(), start.user_id, start.pubkey_p, s_ctx.pub_l,
                            start.nonce_p, s_ctx.nonce_l, s_ctx.transcript);

    int rc = skc_pair_ltk(shared, start.nonce_p, s_ctx.nonce_l, s_ctx.transcript,
                          s_ctx.transcript_len, s_ctx.code, s_ctx.ltk);
    skc_wipe(shared, sizeof(shared));
    if (rc != 0) {
        send_result(SKP_PAIR_BAD_CONFIRM, 0);
        return;
    }

    skp_pair_response_t resp;
    memcpy(resp.lock_id, sks_lock_id(), SKP_ID_SIZE);
    memcpy(resp.pubkey_l, s_ctx.pub_l, SKP_PUBKEY_SIZE);
    memcpy(resp.nonce_l, s_ctx.nonce_l, SKP_NONCE_SIZE);
    if (skc_pair_confirm_lock(s_ctx.ltk, s_ctx.transcript, s_ctx.transcript_len, resp.confirm_l) !=
            0 ||
        skc_pair_confirm_phone(s_ctx.ltk, s_ctx.transcript, s_ctx.transcript_len,
                               s_ctx.expected_confirm_p) != 0) {
        send_result(SKP_PAIR_BAD_CONFIRM, 0);
        return;
    }

    uint8_t out[SKP_HEADER_SIZE + SKP_PAIR_RESPONSE_SIZE];
    int n = skp_encode_pair_response(&resp, out, sizeof(out));
    if (n > 0) {
        s_ctx.response_sent = true;
        notify(out, (uint16_t)n);
        ESP_LOGI(TAG, "sent PAIR_RESPONSE, awaiting confirmation");
    }
}

/** Handle PAIR_CONFIRM: verify the phone proved knowledge of the pairing code. */
static void handle_pair_confirm(const skp_frame_t *frame)
{
    if (!s_ctx.response_sent || frame->length != SKP_PAIR_CONFIRM_SIZE) {
        send_result(SKP_PAIR_BAD_CONFIRM, 0);
        return;
    }

    if (!skc_ct_equal(s_ctx.expected_confirm_p, frame->payload, SKP_TAG_SIZE)) {
        s_ctx.attempts++;
        ESP_LOGW(TAG, "wrong pairing code (attempt %u/%u)", s_ctx.attempts, MAX_ATTEMPTS);
        send_result(SKP_PAIR_BAD_CONFIRM, 0);
        s_ctx.response_sent = false;
        if (s_ctx.attempts >= MAX_ATTEMPTS) {
            ESP_LOGW(TAG, "too many failed attempts, leaving pairing mode");
            skb_stop_pairing();
        }
        return;
    }

    size_t slot = 0;
    esp_err_t err = sks_add(s_ctx.user_id, s_ctx.ltk, "phone", &slot);
    if (err != ESP_OK) {
        send_result(err == ESP_ERR_NO_MEM ? SKP_PAIR_STORE_FULL : SKP_PAIR_BAD_CONFIRM, 0);
        return;
    }

    ESP_LOGI(TAG, "paired successfully into slot %u", (unsigned)slot);
    send_result(SKP_PAIR_OK, (uint8_t)slot);
    if (s_paired_cb != NULL) {
        s_paired_cb(slot, s_paired_ctx);
    }
    skb_stop_pairing();
}

static int pairing_access(uint16_t conn_handle, uint16_t attr_handle,
                          struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    (void)attr_handle;
    (void)arg;
    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
        return BLE_ATT_ERR_UNLIKELY;
    }
    if (!s_ctx.armed) {
        return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
    }

    uint8_t buf[SKP_MAX_FRAME];
    uint16_t len = 0;
    if (ble_hs_mbuf_to_flat(ctxt->om, buf, sizeof(buf), &len) != 0) {
        return BLE_ATT_ERR_INSUFFICIENT_RES;
    }

    skp_frame_t frame;
    if (skp_frame_parse(buf, len, &frame) < 0) {
        return BLE_ATT_ERR_INVALID_PDU;
    }

    s_ctx.conn_handle = conn_handle;
    switch (frame.type) {
    case SKP_FRAME_PAIR_START:
        handle_pair_start(&frame);
        break;
    case SKP_FRAME_PAIR_CONFIRM:
        handle_pair_confirm(&frame);
        break;
    default:
        ESP_LOGD(TAG, "unexpected frame 0x%02x during pairing", frame.type);
        break;
    }
    return 0;
}

esp_err_t skp_pairing_gatt_register(void)
{
    ble_svc_gatt_init();
    if (ble_gatts_count_cfg(s_services) != 0) {
        return ESP_FAIL;
    }
    return ble_gatts_add_svcs(s_services) == 0 ? ESP_OK : ESP_FAIL;
}

void skp_pairing_set_callback(skb_paired_cb_t cb, void *ctx)
{
    s_paired_cb = cb;
    s_paired_ctx = ctx;
}

esp_err_t skp_pairing_begin(const char *code, uint8_t own_addr_type)
{
    if (code == NULL || strlen(code) != SKP_PAIRING_CODE_LEN) {
        return ESP_ERR_INVALID_ARG;
    }

    uint16_t handle = s_ctx.pairing_handle; /* assigned once at registration */
    memset(&s_ctx, 0, sizeof(s_ctx));
    s_ctx.pairing_handle = handle;
    snprintf(s_ctx.code, sizeof(s_ctx.code), "%s", code);

    if (skc_x25519_keypair(s_ctx.priv_l, s_ctx.pub_l) != 0 ||
        skc_random(s_ctx.nonce_l, sizeof(s_ctx.nonce_l)) != 0) {
        return ESP_FAIL;
    }
    s_ctx.armed = true;

    /* Pairing beacon: manufacturer data with the PAIRING_BEACON flag and the
     * first 6 bytes of the lock id (pairing-spec.md §1). */
    uint8_t mfg[SKP_ADV_PAYLOAD_SIZE];
    skp_adv_t beacon = {.flags = SKP_ADV_FLAG_PAIRING_BEACON, .battery_pct = 0xFF};
    memcpy(beacon.pseudonym, sks_lock_id(), SKP_PSEUDONYM_SIZE);
    if (skp_adv_build(&beacon, mfg, sizeof(mfg)) < 0) {
        return ESP_FAIL;
    }

    struct ble_hs_adv_fields fields = {
        .flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP,
        .mfg_data = mfg,
        .mfg_data_len = sizeof(mfg),
        .name = (const uint8_t *)"SK-Pair",
        .name_len = 7,
        .name_is_complete = 1,
    };
    int rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "adv_set_fields failed (%d)", rc);
        return ESP_FAIL;
    }

    struct ble_gap_adv_params adv_params = {
        .conn_mode = BLE_GAP_CONN_MODE_UND,
        .disc_mode = BLE_GAP_DISC_MODE_GEN,
        .itvl_min = BLE_GAP_ADV_FAST_INTERVAL1_MIN,
        .itvl_max = BLE_GAP_ADV_FAST_INTERVAL1_MAX,
    };
    rc = ble_gap_adv_start(own_addr_type, NULL, BLE_HS_FOREVER, &adv_params, NULL, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "adv_start failed (%d)", rc);
        return ESP_FAIL;
    }

    ESP_LOGW(TAG, "PAIRING MODE ACTIVE - code: %s", s_ctx.code);
    return ESP_OK;
}

void skp_pairing_end(void)
{
    if (!s_ctx.armed) {
        return;
    }
    ble_gap_adv_stop();
    uint16_t handle = s_ctx.pairing_handle;
    skc_wipe(&s_ctx, sizeof(s_ctx)); /* erase the private key and LTK */
    s_ctx.pairing_handle = handle;
    ESP_LOGI(TAG, "pairing mode closed");
}
