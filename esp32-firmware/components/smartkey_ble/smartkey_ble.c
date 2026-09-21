/**
 * @file smartkey_ble.c
 * @brief Door unit BLE engine: scanner + GATT client (presence) and
 *        peripheral + GATT server (pairing).
 *
 * Implements protocol-spec.md §2, §5, §6 and pairing-spec.md §2-3.
 */

#include "smartkey_ble.h"

#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "host/ble_gap.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "pseudonym_table.h"
#include "services/gap/ble_svc_gap.h"
#include "smartkey_crypto.h"
#include "smartkey_pairing.h"
#include "smartkey_proximity.h"
#include "smartkey_rearm.h"
#include "smartkey_store.h"

static const char *TAG = "sk_ble";

#define SCAN_INTERVAL_MS 60
#define SCAN_WINDOW_MS 60
#define CONN_ITVL_FAST_MS 15
#define CONN_ITVL_IDLE_MS 200
#define PSEUDO_TICK_MS 1000
/**
 * Grace period before dropping the link after an unlock, so the UNLOCK_EVENT
 * (sent write-no-response) is actually transmitted. Two connection intervals
 * at the relaxed 100-200 ms rate.
 */
#define RELEASE_FLUSH_MS 250

/* 128 bit UUIDs from protocol-spec.md §2.3, little endian byte order. */
static const ble_uuid128_t UUID_SERVICE =
    BLE_UUID128_INIT(0x10, 0x5a, 0x0c, 0x6f, 0x0a, 0x2f, 0x9e, 0x9c, 0x1e, 0x4b, 0x5f, 0x6b, 0x01,
                     0x00, 0x9a, 0x8e);
static const ble_uuid128_t UUID_CONTROL =
    BLE_UUID128_INIT(0x10, 0x5a, 0x0c, 0x6f, 0x0a, 0x2f, 0x9e, 0x9c, 0x1e, 0x4b, 0x5f, 0x6b, 0x02,
                     0x00, 0x9a, 0x8e);
static const ble_uuid128_t UUID_STATUS =
    BLE_UUID128_INIT(0x10, 0x5a, 0x0c, 0x6f, 0x0a, 0x2f, 0x9e, 0x9c, 0x1e, 0x4b, 0x5f, 0x6b, 0x03,
                     0x00, 0x9a, 0x8e);
static const ble_uuid128_t UUID_PAIRING =
    BLE_UUID128_INIT(0x10, 0x5a, 0x0c, 0x6f, 0x0a, 0x2f, 0x9e, 0x9c, 0x1e, 0x4b, 0x5f, 0x6b, 0x04,
                     0x00, 0x9a, 0x8e);

/** Everything about the connection currently being handled. */
typedef struct {
    uint16_t conn_handle;
    uint16_t control_handle;
    uint16_t status_handle;
    uint16_t status_cccd_handle;
    uint16_t pairing_handle;

    size_t slot;                          /**< credential slot of the peer */
    uint8_t nonce_l[SKP_NONCE_SIZE];
    uint8_t session_id[SKP_SESSION_ID_SIZE];
    uint8_t k_sess[SKP_KEY_SIZE];
    uint32_t unlock_counter;
    int64_t started_us;
    int8_t rssi;
    uint8_t weak_samples;
    bool authenticated;
} conn_ctx_t;

/**
 * Proximity filter for the LED gate.
 *
 * Lives outside conn_ctx_t because it is seeded from advertisements *before*
 * the connection exists: by the time the handshake finishes the window is
 * already populated, so the LED decision is immediate rather than waiting for
 * several connection-interval RSSI polls.
 */
static skpx_filter_t s_proximity;
/** Address the filter currently describes, so a different phone starts clean. */
static ble_addr_t s_proximity_addr;
static bool s_proximity_addr_valid;

/**
 * Scan throughput counters.
 *
 * The door beacon makes the radio interleave advertising with scanning, and
 * scanning is what actually has to stay fast: every advertisement missed is an
 * RSSI sample the proximity filter does not get. These counters exist so the
 * cost can be *measured* on real hardware ('scanstats' on the console) instead
 * of assumed. See README.md "Verifying beacon/scan coexistence".
 */
typedef struct {
    uint32_t adv_seen;    /**< every advertisement report, SmartKey or not */
    uint32_t adv_smartkey;/**< parsed as a SmartKey phone beacon */
    uint32_t adv_known;   /**< matched a paired pseudonym (feeds the filter) */
    int64_t since_us;     /**< when the counters were last cleared */
} skb_scan_stats_t;

static skb_scan_stats_t s_scan_stats;

/**
 * Post-unlock hold for the phone that just opened the door.
 *
 * Kept per-address rather than per-slot so that a second paired phone
 * arriving with the first is unaffected: only the credential that actually
 * opened the door is held back.
 */
#if CONFIG_SMARTKEY_RELEASE_AFTER_UNLOCK
static skra_t s_rearm;
static ble_addr_t s_rearm_addr;
static bool s_rearm_addr_valid;
#endif

static skb_config_t s_cfg;
static volatile skb_state_t s_state = SKB_STATE_IDLE;
#if CONFIG_SMARTKEY_DOOR_BEACON_ENABLE
/** True while the non-connectable door beacon is being advertised. */
static bool s_door_beacon_on;
#endif
static conn_ctx_t s_conn = {.conn_handle = BLE_HS_CONN_HANDLE_NONE};
static char s_pairing_code[SKP_PAIRING_CODE_LEN + 1];
static int64_t s_pairing_until_us;
static uint8_t s_own_addr_type;

static void start_scan(void);
static int gap_event(struct ble_gap_event *event, void *arg);
static void update_door_beacon(void);
static void stop_door_beacon(void);

/* --------------------------------------------------------------- helpers */

static void set_state(skb_state_t state)
{
    if (s_state == state) {
        return;
    }
    s_state = state;

    /* The beacon is only useful in some states, so it follows every
     * transition rather than being toggled from a dozen call sites. */
    update_door_beacon();

    skb_session_t session;
    bool have = skb_get_session(&session);
    if (s_cfg.on_state != NULL) {
        s_cfg.on_state(state, have ? &session : NULL, s_cfg.ctx);
    }
}

static void reset_conn(void)
{
    skc_wipe(s_conn.k_sess, sizeof(s_conn.k_sess));
    memset(&s_conn, 0, sizeof(s_conn));
    s_conn.conn_handle = BLE_HS_CONN_HANDLE_NONE;
}

/** Apply the Kconfig tuning to the proximity filter. */
static void proximity_configure(void)
{
    const skpx_config_t cfg = {
        .near_dbm = CONFIG_SMARTKEY_PROXIMITY_NEAR_DBM,
        .far_dbm = CONFIG_SMARTKEY_PROXIMITY_FAR_DBM,
        .window = CONFIG_SMARTKEY_PROXIMITY_WINDOW,
        .min_samples = CONFIG_SMARTKEY_PROXIMITY_MIN_SAMPLES,
    };
    skpx_init(&s_proximity, &cfg);
}

/**
 * @brief Feed a sample, restarting the filter when the peer changes.
 *
 * Mixing two phones' RSSI in one window would let a distant phone's samples
 * prop up a near verdict for another, so the history is dropped whenever the
 * address changes.
 */
static void proximity_sample(const ble_addr_t *addr, int8_t rssi)
{
    if (addr != NULL) {
        if (!s_proximity_addr_valid || ble_addr_cmp(&s_proximity_addr, addr) != 0) {
            skpx_reset(&s_proximity);
            s_proximity_addr = *addr;
            s_proximity_addr_valid = true;
        }
    }
    skpx_add_sample(&s_proximity, rssi);
}

static void proximity_forget(void)
{
    skpx_reset(&s_proximity);
    s_proximity_addr_valid = false;
}

/* ------------------------------------------------- post-unlock re-arm */

#if CONFIG_SMARTKEY_RELEASE_AFTER_UNLOCK

/** Monotonic milliseconds, the time base the re-arm logic works in. */
static int64_t now_ms(void)
{
    return esp_timer_get_time() / 1000;
}

/** Apply the Kconfig tuning to the re-arm rule. */
static void rearm_configure(void)
{
    const skra_config_t cfg = {
        .depart_dbm = CONFIG_SMARTKEY_REARM_DEPART_DBM,
        .absent_ms = CONFIG_SMARTKEY_REARM_ABSENT_MS,
        .max_hold_ms = CONFIG_SMARTKEY_REARM_MAX_HOLD_MS,
    };
    skra_init(&s_rearm, &cfg);
}

/**
 * @brief Is this advertisement from the phone that just opened the door?
 *
 * Matching is by address. The phone rotates its pseudonym every 15 s but
 * keeps its resolvable private address for much longer, so the address is
 * the stable handle over the few seconds the hold lasts.
 */
static bool rearm_is_held_peer(const ble_addr_t *addr)
{
    return s_rearm_addr_valid && addr != NULL &&
           ble_addr_cmp(&s_rearm_addr, addr) == 0;
}

/** Start refusing @p addr until it is seen to leave. */
static void rearm_hold(const ble_addr_t *addr)
{
    if (addr == NULL) {
        return;
    }
    s_rearm_addr = *addr;
    s_rearm_addr_valid = true;
    skra_hold(&s_rearm, now_ms());
    ESP_LOGI(TAG, "door opened; holding this phone until it moves away");
}

/**
 * @brief Should this advertisement be ignored because of a post-unlock hold?
 *
 * Feeds the sighting into the rule as a side effect, which is what lets a
 * weak reading release the hold the moment the user steps away.
 */
static bool rearm_should_ignore(const ble_addr_t *addr, int8_t rssi)
{
    if (!rearm_is_held_peer(addr)) {
        return false;
    }
    const int64_t t = now_ms();
    skra_observe(&s_rearm, t, rssi);
    if (!skra_blocked(&s_rearm, t)) {
        ESP_LOGI(TAG, "phone has left the door, re-armed");
        s_rearm_addr_valid = false;
        return false;
    }
    return true;
}

/** Expire a hold that nothing is refreshing (phone gone out of range). */
static void rearm_tick(void)
{
    if (!s_rearm_addr_valid) {
        return;
    }
    if (!skra_blocked(&s_rearm, now_ms())) {
        ESP_LOGI(TAG, "phone no longer seen, re-armed");
        s_rearm_addr_valid = false;
    }
}

static void rearm_clear(void)
{
    skra_clear(&s_rearm);
    s_rearm_addr_valid = false;
}

#else /* feature compiled out */
static void rearm_configure(void) {}
static bool rearm_should_ignore(const ble_addr_t *addr, int8_t rssi)
{
    (void)addr;
    (void)rssi;
    return false;
}
static void rearm_tick(void) {}
static void rearm_clear(void) {}
#endif /* CONFIG_SMARTKEY_RELEASE_AFTER_UNLOCK */

skb_state_t skb_state(void)
{
    return s_state;
}

bool skb_get_session(skb_session_t *out)
{
    if (out == NULL || !s_conn.authenticated) {
        return false;
    }
    const sks_credential_t *cred = sks_get(s_conn.slot);
    if (cred == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->active = true;
    memcpy(out->user_id, cred->user_id, SKP_ID_SIZE);
    memcpy(out->session_id, s_conn.session_id, SKP_SESSION_ID_SIZE);
    snprintf(out->user_name, sizeof(out->user_name), "%s", cred->name);
    out->rssi = s_conn.rssi;
    out->filtered_rssi = skpx_median(&s_proximity);
    out->near = skpx_is_near(&s_proximity);
    return true;
}

/** Write a frame to the peer's CONTROL characteristic. */
static int write_control(const uint8_t *frame, uint16_t len)
{
    if (s_conn.conn_handle == BLE_HS_CONN_HANDLE_NONE || s_conn.control_handle == 0) {
        return BLE_HS_ENOTCONN;
    }
    return ble_gattc_write_no_rsp_flat(s_conn.conn_handle, s_conn.control_handle, frame, len);
}

static void disconnect(uint8_t reason)
{
    if (s_conn.conn_handle != BLE_HS_CONN_HANDLE_NONE) {
        ble_gap_terminate(s_conn.conn_handle, reason);
    }
}

static void send_error_and_close(uint8_t code)
{
    uint8_t frame[SKP_HEADER_SIZE + SKP_ERROR_SIZE];
    int n = skp_encode_error(code, 0, frame, sizeof(frame));
    if (n > 0) {
        write_control(frame, (uint16_t)n);
    }
    disconnect(BLE_ERR_REM_USER_CONN_TERM);
}

/* ------------------------------------------------------------ handshake */

/** Send HELLO with a fresh nonce; the phone answers with AUTH (spec §5.1). */
static void send_hello(void)
{
    skp_hello_t hello = {.caps = 0x03}; /* UNLOCK_EVENT + pairing supported */
    memcpy(hello.lock_id, sks_lock_id(), SKP_ID_SIZE);
    if (skc_random(s_conn.nonce_l, sizeof(s_conn.nonce_l)) != 0) {
        ESP_LOGE(TAG, "rng failure");
        disconnect(BLE_ERR_REM_USER_CONN_TERM);
        return;
    }
    memcpy(hello.nonce_l, s_conn.nonce_l, SKP_NONCE_SIZE);

    uint8_t frame[SKP_HEADER_SIZE + SKP_HELLO_SIZE];
    int n = skp_encode_hello(&hello, frame, sizeof(frame));
    if (n < 0 || write_control(frame, (uint16_t)n) != 0) {
        ESP_LOGW(TAG, "failed to send HELLO");
        disconnect(BLE_ERR_REM_USER_CONN_TERM);
        return;
    }
    set_state(SKB_STATE_HANDSHAKING);
}

/**
 * @brief Verify AUTH and answer with SESSION_OK (spec §5.2, §5.3).
 *
 * All comparisons are constant time; any failure closes the connection without
 * revealing which step failed.
 */
static void handle_auth(const skp_frame_t *frame)
{
    skp_auth_t auth;
    if (skp_parse_auth(frame, &auth) != SKP_OK) {
        send_error_and_close(SKP_ERR_MALFORMED_FRAME);
        return;
    }

    const sks_credential_t *cred = sks_find_by_user(auth.user_id);
    if (cred == NULL) {
        ESP_LOGW(TAG, "AUTH from unknown user");
        send_error_and_close(SKP_ERR_UNKNOWN_USER);
        return;
    }

    uint8_t transcript[SKC_AUTH_TRANSCRIPT_SIZE];
    size_t tlen = skc_auth_transcript(sks_lock_id(), cred->user_id, s_conn.nonce_l, auth.nonce_p,
                                      transcript);

    uint8_t expected[SKP_TAG_SIZE];
    if (skc_tag_phone(cred->subkeys.k_auth, transcript, tlen, expected) != 0) {
        send_error_and_close(SKP_ERR_INTERNAL);
        return;
    }
    if (!skc_ct_equal(expected, auth.tag_p, SKP_TAG_SIZE)) {
        ESP_LOGW(TAG, "AUTH tag mismatch for '%s'", cred->name);
        send_error_and_close(SKP_ERR_AUTH_FAILED);
        return;
    }

    /* Authenticated: derive the session material and grant access. */
    skp_session_ok_t ok = {.grant = 1, .ttl_s = CONFIG_SMARTKEY_SESSION_TTL_S};
    if (skc_tag_lock(cred->subkeys.k_auth, transcript, tlen, ok.tag_l) != 0 ||
        skc_session_id(cred->subkeys.k_auth, transcript, tlen, ok.session_id) != 0 ||
        skc_session_key(cred->subkeys.k_auth, sks_lock_id(), cred->user_id, s_conn.nonce_l,
                        auth.nonce_p, s_conn.k_sess) != 0) {
        send_error_and_close(SKP_ERR_INTERNAL);
        return;
    }

    /* Find the slot index so the session can be described to the application. */
    for (size_t i = 0; i < sks_capacity(); i++) {
        if (sks_get(i) == cred) {
            s_conn.slot = i;
            break;
        }
    }
    memcpy(s_conn.session_id, ok.session_id, SKP_SESSION_ID_SIZE);
    s_conn.unlock_counter = 0;
    s_conn.authenticated = true;

    uint8_t out[SKP_HEADER_SIZE + SKP_SESSION_OK_SIZE];
    int n = skp_encode_session_ok(&ok, out, sizeof(out));
    if (n < 0 || write_control(out, (uint16_t)n) != 0) {
        ESP_LOGW(TAG, "failed to send SESSION_OK");
        disconnect(BLE_ERR_REM_USER_CONN_TERM);
        return;
    }

    int64_t elapsed_ms = (esp_timer_get_time() - s_conn.started_us) / 1000;

    /*
     * Authentication alone does not light the LED: the phone must also be
     * measured to be next to the board. The filter was pre-seeded from the
     * advertisements that triggered this connection, so in the normal
     * walk-up case the verdict is already available here and the LED is
     * immediate.
     */
    if (skpx_is_near(&s_proximity)) {
        ESP_LOGI(TAG, "access granted to '%s' in %lld ms (rssi %d dBm)", cred->name,
                 elapsed_ms, skpx_median(&s_proximity));
        set_state(SKB_STATE_GRANTED);
    } else {
        ESP_LOGI(TAG, "'%s' authenticated in %lld ms but is too far (rssi %d dBm)",
                 cred->name, elapsed_ms, skpx_median(&s_proximity));
        set_state(SKB_STATE_LINGERING);
    }

    /* Relax the connection interval now that the latency critical part is done. */
    struct ble_gap_upd_params params = {
        .itvl_min = CONN_ITVL_IDLE_MS * 4 / 5,
        .itvl_max = CONN_ITVL_IDLE_MS * 4 / 5,
        .latency = 0,
        .supervision_timeout = 400, /* 4 s */
    };
    ble_gap_update_params(s_conn.conn_handle, &params);
}

/** Dispatch a frame received as a STATUS notification. */
static void handle_frame(const uint8_t *data, uint16_t len)
{
    skp_frame_t frame;
    int rc = skp_frame_parse(data, len, &frame);
    if (rc < 0) {
        ESP_LOGW(TAG, "malformed frame (%d)", rc);
        send_error_and_close(SKP_ERR_MALFORMED_FRAME);
        return;
    }

    switch (frame.type) {
    case SKP_FRAME_AUTH:
        if (s_state == SKB_STATE_HANDSHAKING) {
            handle_auth(&frame);
        }
        break;

    case SKP_FRAME_PRESENCE_PONG:
        s_conn.weak_samples = 0;
        break;

    case SKP_FRAME_UNLOCK_ACK:
        ESP_LOGD(TAG, "unlock acknowledged by the phone");
        break;

    case SKP_FRAME_ERROR:
        ESP_LOGW(TAG, "phone reported error 0x%02x", frame.payload[0]);
        disconnect(BLE_ERR_REM_USER_CONN_TERM);
        break;

    default:
        ESP_LOGD(TAG, "ignoring frame type 0x%02x", frame.type);
        break;
    }
}

esp_err_t skb_report_unlock(uint8_t result)
{
    if (!s_conn.authenticated) {
        return ESP_ERR_INVALID_STATE;
    }
    skp_unlock_event_t event = {
        .counter = ++s_conn.unlock_counter,
        .result = result,
    };
    memcpy(event.session_id, s_conn.session_id, SKP_SESSION_ID_SIZE);
    if (skc_unlock_tag(s_conn.k_sess, event.session_id, event.counter, event.result, event.tag) !=
        0) {
        return ESP_FAIL;
    }

    uint8_t frame[SKP_HEADER_SIZE + SKP_UNLOCK_EVENT_SIZE];
    int n = skp_encode_unlock_event(&event, frame, sizeof(frame));
    if (n < 0) {
        return ESP_FAIL;
    }
    return write_control(frame, (uint16_t)n) == 0 ? ESP_OK : ESP_FAIL;
}

void skb_release_after_unlock(void)
{
#if CONFIG_SMARTKEY_RELEASE_AFTER_UNLOCK
    if (!s_conn.authenticated) {
        return;
    }

    /* Remember who to hold before reset_conn() clears the connection. */
    struct ble_gap_conn_desc desc;
    bool have_addr = s_conn.conn_handle != BLE_HS_CONN_HANDLE_NONE &&
                     ble_gap_conn_find(s_conn.conn_handle, &desc) == 0;

    /* The UNLOCK_EVENT was written with write-no-response just before this
     * call. Give the controller a moment to put it on air, otherwise tearing
     * the link down here would race it and the app would never show
     * "Door opened". */
    vTaskDelay(pdMS_TO_TICKS(RELEASE_FLUSH_MS));

    if (have_addr) {
        rearm_hold(&desc.peer_id_addr);
    }

    ESP_LOGI(TAG, "unlock complete, releasing the session");
    disconnect(BLE_ERR_REM_USER_CONN_TERM);
    /* BLE_GAP_EVENT_DISCONNECT does the rest: reset_conn(), proximity_forget(),
     * back to IDLE and rescanning. */
#endif
}

/* ------------------------------------------------- GATT discovery chain */

static int on_cccd_written(uint16_t conn_handle, const struct ble_gatt_error *error,
                           struct ble_gatt_attr *attr, void *arg)
{
    if (error->status != 0) {
        ESP_LOGW(TAG, "enabling notifications failed (%d)", error->status);
        disconnect(BLE_ERR_REM_USER_CONN_TERM);
        return 0;
    }
    send_hello();
    return 0;
}

/** Subscribe to STATUS notifications, then start the handshake. */
static void enable_notifications(void)
{
    static const uint8_t value[2] = {0x01, 0x00}; /* notifications on */
    int rc = ble_gattc_write_flat(s_conn.conn_handle, s_conn.status_cccd_handle, value,
                                  sizeof(value), on_cccd_written, NULL);
    if (rc != 0) {
        ESP_LOGW(TAG, "CCCD write failed (%d)", rc);
        disconnect(BLE_ERR_REM_USER_CONN_TERM);
    }
}

static int on_dsc_disc(uint16_t conn_handle, const struct ble_gatt_error *error,
                       uint16_t chr_val_handle, const struct ble_gatt_dsc *dsc, void *arg)
{
    if (error->status == 0 && dsc != NULL &&
        ble_uuid_u16(&dsc->uuid.u) == BLE_GATT_DSC_CLT_CFG_UUID16) {
        s_conn.status_cccd_handle = dsc->handle;
        return 0;
    }
    if (error->status == BLE_HS_EDONE) {
        if (s_conn.status_cccd_handle != 0) {
            enable_notifications();
        } else {
            ESP_LOGW(TAG, "peer has no CCCD on STATUS");
            disconnect(BLE_ERR_REM_USER_CONN_TERM);
        }
    }
    return 0;
}

static int on_chr_disc(uint16_t conn_handle, const struct ble_gatt_error *error,
                       const struct ble_gatt_chr *chr, void *arg)
{
    if (error->status == 0 && chr != NULL) {
        if (ble_uuid_cmp(&chr->uuid.u, &UUID_CONTROL.u) == 0) {
            s_conn.control_handle = chr->val_handle;
        } else if (ble_uuid_cmp(&chr->uuid.u, &UUID_STATUS.u) == 0) {
            s_conn.status_handle = chr->val_handle;
        } else if (ble_uuid_cmp(&chr->uuid.u, &UUID_PAIRING.u) == 0) {
            s_conn.pairing_handle = chr->val_handle;
        }
        return 0;
    }
    if (error->status != BLE_HS_EDONE) {
        ESP_LOGW(TAG, "characteristic discovery failed (%d)", error->status);
        disconnect(BLE_ERR_REM_USER_CONN_TERM);
        return 0;
    }
    if (s_conn.control_handle == 0 || s_conn.status_handle == 0) {
        ESP_LOGW(TAG, "peer is missing the SmartKey characteristics");
        disconnect(BLE_ERR_REM_USER_CONN_TERM);
        return 0;
    }
    /* Descriptors of STATUS only: that is where the CCCD lives. */
    ble_gattc_disc_all_dscs(conn_handle, s_conn.status_handle, s_conn.status_handle + 2,
                            on_dsc_disc, NULL);
    return 0;
}

static int on_svc_disc(uint16_t conn_handle, const struct ble_gatt_error *error,
                       const struct ble_gatt_svc *service, void *arg)
{
    if (error->status == 0 && service != NULL) {
        ble_gattc_disc_all_chrs(conn_handle, service->start_handle, service->end_handle,
                                on_chr_disc, NULL);
        return 0;
    }
    if (error->status == BLE_HS_EDONE && s_conn.control_handle == 0) {
        ESP_LOGW(TAG, "SmartKey service not found on peer");
        disconnect(BLE_ERR_REM_USER_CONN_TERM);
    }
    return 0;
}

static int on_mtu_exchanged(uint16_t conn_handle, const struct ble_gatt_error *error,
                            uint16_t mtu, void *arg)
{
    if (error->status == 0 && mtu < SKP_HEADER_SIZE + 100) {
        ESP_LOGW(TAG, "peer MTU %u too small", mtu);
        disconnect(BLE_ERR_REM_USER_CONN_TERM);
        return 0;
    }
    ble_gattc_disc_svc_by_uuid(conn_handle, &UUID_SERVICE.u, on_svc_disc, NULL);
    return 0;
}

/* -------------------------------------------------------------- scanner */

/** Extract the SmartKey manufacturer data from an advertisement, if present. */
static bool parse_smartkey_adv(const uint8_t *data, uint8_t len, skp_adv_t *out)
{
    struct ble_hs_adv_fields fields;
    if (ble_hs_adv_parse_fields(&fields, data, len) != 0) {
        return false;
    }
    if (fields.mfg_data == NULL || fields.mfg_data_len < SKP_ADV_PAYLOAD_SIZE) {
        return false;
    }
    return skp_adv_parse(fields.mfg_data, fields.mfg_data_len, out) == SKP_OK;
}

/**
 * @brief Decide whether an advertisement should trigger a connection.
 *
 * Also feeds every advertisement from a known phone into the proximity filter,
 * so the LED gate already has a populated window by the time the handshake
 * completes (that is what keeps the LED inside the 1 s budget while still
 * requiring several consistent samples).
 */
static bool should_connect(const struct ble_gap_disc_desc *desc, size_t *out_slot)
{
    s_scan_stats.adv_seen++;

    skp_adv_t adv;
    if (!parse_smartkey_adv(desc->data, desc->length_data, &adv)) {
        return false;
    }
    s_scan_stats.adv_smartkey++;
    if (adv.flags & SKP_ADV_FLAG_PAIRING_BEACON) {
        return false; /* another lock's pairing beacon */
    }
#if CONFIG_SMARTKEY_REQUIRE_PHONE_UNLOCKED
    if (!(adv.flags & SKP_ADV_FLAG_UNLOCKED)) {
        return false;
    }
#endif
    if (!skb_pseudo_match(adv.pseudonym, out_slot)) {
        return false;
    }

    /* Known phone: track its distance even before we connect. */
    s_scan_stats.adv_known++;

    /* This phone just opened the door and has not left yet: ignore it, or we
     * would reconnect within a few hundred ms and relight the LED while the
     * user is still standing there. Checked before the proximity filter so a
     * held phone's samples cannot pre-seed the next grant either. */
    if (rearm_should_ignore(&desc->addr, desc->rssi)) {
        return false;
    }

    proximity_sample(&desc->addr, desc->rssi);

    if (s_state != SKB_STATE_IDLE) {
        return false; /* already busy with a peer */
    }
    return desc->rssi >= CONFIG_SMARTKEY_RSSI_ENTER_DBM;
}

/* ------------------------------------------------------- door beacon */

#if CONFIG_SMARTKEY_DOOR_BEACON_ENABLE

/**
 * @brief Start the static, non-connectable door beacon.
 *
 * Recovery mechanism only (protocol-spec.md §2.4): it lets a phone whose
 * presence service was killed by the OS notice the door and restart it. The
 * beacon is non-connectable because nothing should ever dial in on it — the
 * session is always established the other way round.
 *
 * Note this shares the radio with scanning. The interval is deliberately slow
 * and 'scanstats' exists to prove the scan rate is not being harmed.
 */
static void start_door_beacon(void)
{
    if (s_door_beacon_on) {
        return;
    }
    /* Never compete with the pairing advertisement for the radio. */
    if (s_state == SKB_STATE_PAIRING) {
        return;
    }

    skp_door_adv_t beacon = {.flags = 0};
    const uint8_t *lock_id = sks_lock_id();
    if (lock_id == NULL) {
        return;
    }
    memcpy(beacon.lock_id, lock_id, SKP_DOOR_ID_SIZE);
    if (sks_count() > 0) {
        beacon.flags |= SKP_DOOR_FLAG_ENROLLED;
    }

    uint8_t payload[SKP_DOOR_PAYLOAD_SIZE];
    if (skp_door_adv_build(&beacon, payload, sizeof(payload)) != SKP_DOOR_PAYLOAD_SIZE) {
        return;
    }

    struct ble_hs_adv_fields fields = {0};
    fields.mfg_data = payload;
    fields.mfg_data_len = sizeof(payload);
    int rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGW(TAG, "door beacon fields rejected (%d)", rc);
        return;
    }

    struct ble_gap_adv_params params = {
        /* Non-connectable, non-scannable: a pure broadcast. */
        .conn_mode = BLE_GAP_CONN_MODE_NON,
        .disc_mode = BLE_GAP_DISC_MODE_GEN,
        .itvl_min = (CONFIG_SMARTKEY_DOOR_BEACON_INTERVAL_MS * 1000) / BLE_HCI_ADV_ITVL,
        .itvl_max = (CONFIG_SMARTKEY_DOOR_BEACON_INTERVAL_MS * 1000) / BLE_HCI_ADV_ITVL,
    };
    rc = ble_gap_adv_start(s_own_addr_type, NULL, BLE_HS_FOREVER, &params, NULL, NULL);
    if (rc != 0) {
        ESP_LOGW(TAG, "door beacon failed to start (%d)", rc);
        return;
    }
    s_door_beacon_on = true;
    ESP_LOGI(TAG, "door beacon advertising every %d ms",
             CONFIG_SMARTKEY_DOOR_BEACON_INTERVAL_MS);
}

static void stop_door_beacon(void)
{
    if (!s_door_beacon_on) {
        return;
    }
    ble_gap_adv_stop();
    s_door_beacon_on = false;
}

/**
 * @brief Enable the beacon only when it can actually be useful.
 *
 * With a phone connected there is nobody to wake, so the radio time is better
 * spent on the live session.
 */
static void update_door_beacon(void)
{
#if CONFIG_SMARTKEY_DOOR_BEACON_IDLE_ONLY
    if (s_state == SKB_STATE_IDLE) {
        start_door_beacon();
    } else {
        stop_door_beacon();
    }
#else
    if (s_state == SKB_STATE_PAIRING) {
        stop_door_beacon();
    } else {
        start_door_beacon();
    }
#endif
}

#else /* beacon disabled at build time: compile to nothing */
static void stop_door_beacon(void) {}
static void update_door_beacon(void) {}
#endif /* CONFIG_SMARTKEY_DOOR_BEACON_ENABLE */

static void start_scan(void)
{
    struct ble_gap_disc_params params = {
        .itvl = (SCAN_INTERVAL_MS * 1000) / BLE_HCI_SCAN_ITVL, /* units of 0.625 ms */
        .window = (SCAN_WINDOW_MS * 1000) / BLE_HCI_SCAN_ITVL,
        .filter_policy = BLE_HCI_SCAN_FILT_NO_WL,
        .limited = 0,
        .passive = 1, /* the beacon fits in ADV_IND, no scan response needed */
        .filter_duplicates = 0,
    };
    int rc = ble_gap_disc(s_own_addr_type, BLE_HS_FOREVER, &params, gap_event, NULL);
    if (rc != 0 && rc != BLE_HS_EALREADY) {
        ESP_LOGE(TAG, "failed to start scanning (%d)", rc);
    }
}

static void connect_to(const struct ble_gap_disc_desc *desc, size_t slot)
{
    ble_gap_disc_cancel();

    struct ble_gap_conn_params params = {
        .scan_itvl = (SCAN_INTERVAL_MS * 1000) / BLE_HCI_SCAN_ITVL,
        .scan_window = (SCAN_WINDOW_MS * 1000) / BLE_HCI_SCAN_ITVL,
        /* Fastest allowed interval during the handshake (protocol-spec.md §8). */
        .itvl_min = 6,  /* 7.5 ms */
        .itvl_max = 12, /* 15 ms  */
        .latency = 0,
        .supervision_timeout = 200, /* 2 s */
        .min_ce_len = 0,
        .max_ce_len = 0,
    };

    reset_conn();
    s_conn.slot = slot;
    s_conn.rssi = desc->rssi;
    s_conn.started_us = esp_timer_get_time();
    set_state(SKB_STATE_CONNECTING);

    int rc = ble_gap_connect(s_own_addr_type, &desc->addr, CONFIG_SMARTKEY_HANDSHAKE_TIMEOUT_MS,
                             &params, gap_event, NULL);
    if (rc != 0) {
        ESP_LOGW(TAG, "connect failed (%d)", rc);
        reset_conn();
        set_state(SKB_STATE_IDLE);
        start_scan();
    }
}

/* --------------------------------------------------------- GAP events */

static int gap_event(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {
    case BLE_GAP_EVENT_DISC: {
        size_t slot;
        if (should_connect(&event->disc, &slot)) {
            ESP_LOGI(TAG, "known phone in range (slot %u, rssi %d)", (unsigned)slot,
                     event->disc.rssi);
            connect_to(&event->disc, slot);
        }
        break;
    }

    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            s_conn.conn_handle = event->connect.conn_handle;
            ble_gattc_exchange_mtu(s_conn.conn_handle, on_mtu_exchanged, NULL);
        } else {
            ESP_LOGW(TAG, "connection failed (status %d)", event->connect.status);
            reset_conn();
            set_state(SKB_STATE_IDLE);
            start_scan();
        }
        break;

    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "disconnected (reason 0x%x)", event->disconnect.reason);
        reset_conn();
        /* Stale distance data must never carry into the next encounter. */
        proximity_forget();
        if (s_state != SKB_STATE_PAIRING) {
            set_state(SKB_STATE_IDLE);
            start_scan();
        }
        break;

    case BLE_GAP_EVENT_NOTIFY_RX: {
        if (event->notify_rx.attr_handle != s_conn.status_handle) {
            break;
        }
        uint8_t buf[SKP_MAX_FRAME];
        uint16_t len = OS_MBUF_PKTLEN(event->notify_rx.om);
        if (len > sizeof(buf)) {
            ESP_LOGW(TAG, "notification too large (%u)", len);
            break;
        }
        if (ble_hs_mbuf_to_flat(event->notify_rx.om, buf, sizeof(buf), &len) == 0) {
            handle_frame(buf, len);
        }
        break;
    }

    case BLE_GAP_EVENT_CONN_UPDATE:
    case BLE_GAP_EVENT_MTU:
        break;

    default:
        ESP_LOGD(TAG, "gap event %d", event->type);
        break;
    }
    return 0;
}

/* ------------------------------------------------- presence keep-alive */

/**
 * @brief Sample the live connection RSSI and move between GRANTED and LINGERING.
 *
 * Runs every CONFIG_SMARTKEY_PROXIMITY_POLL_MS so the LED tracks the user, and
 * closes the link entirely once the phone is clearly gone.
 */
static void proximity_tick(void)
{
    if (!s_conn.authenticated ||
        (s_state != SKB_STATE_GRANTED && s_state != SKB_STATE_LINGERING)) {
        return;
    }

    int8_t rssi = 0;
    if (ble_gap_conn_rssi(s_conn.conn_handle, &rssi) != 0 || rssi == 0) {
        return; /* no reading this round; keep the previous verdict */
    }
    s_conn.rssi = rssi;
    proximity_sample(NULL, rssi);

    /* Far enough for long enough ⇒ the phone has left, release the link. */
    if (rssi < CONFIG_SMARTKEY_RSSI_EXIT_DBM) {
        if (++s_conn.weak_samples >= CONFIG_SMARTKEY_RSSI_EXIT_SAMPLES) {
            ESP_LOGI(TAG, "phone out of range (rssi %d dBm), disconnecting", rssi);
            disconnect(BLE_ERR_REM_USER_CONN_TERM);
            return;
        }
    } else {
        s_conn.weak_samples = 0;
    }

    /* The LED follows the filtered verdict, not the raw sample. */
    const bool near = skpx_is_near(&s_proximity);
    if (near && s_state == SKB_STATE_LINGERING) {
        ESP_LOGI(TAG, "phone came close (rssi %d dBm), LED on", skpx_median(&s_proximity));
        set_state(SKB_STATE_GRANTED);
    } else if (!near && s_state == SKB_STATE_GRANTED) {
        ESP_LOGI(TAG, "phone stepped away (rssi %d dBm), LED off",
                 skpx_median(&s_proximity));
        set_state(SKB_STATE_LINGERING);
    }
}

/** Keep-alive: PRESENCE_PING, and drop the session if the phone stops answering. */
static void presence_tick(void)
{
    if (!s_conn.authenticated) {
        return;
    }
    uint8_t frame[SKP_HEADER_SIZE];
    int n = skp_encode_empty(SKP_FRAME_PRESENCE_PING, frame, sizeof(frame));
    if (n > 0) {
        write_control(frame, (uint16_t)n);
    }
}

/**
 * @brief Housekeeping: proximity polling, keep-alive, pseudonyms, pairing window.
 *
 * The loop runs at the proximity poll rate (the fastest of the three jobs) and
 * the slower jobs are divided down from it.
 */
static void housekeeping_task(void *arg)
{
    (void)arg;
    const TickType_t tick = pdMS_TO_TICKS(CONFIG_SMARTKEY_PROXIMITY_POLL_MS);
    const TickType_t ping_period = pdMS_TO_TICKS((CONFIG_SMARTKEY_SESSION_TTL_S * 1000) / 2);
    const TickType_t pseudo_period = pdMS_TO_TICKS(PSEUDO_TICK_MS);

    TickType_t last_ping = xTaskGetTickCount();
    TickType_t last_pseudo = 0; /* forces a rebuild on the first pass */

    for (;;) {
        const TickType_t now = xTaskGetTickCount();

        /* Distance to the phone: drives the LED, so it runs every tick. */
        proximity_tick();

        /* Expire a post-unlock hold whose phone simply vanished (walked
         * through the door), which produces no advertisements to react to. */
        rearm_tick();

        if (last_pseudo == 0 || (now - last_pseudo) >= pseudo_period) {
            last_pseudo = now;
            /* Epochs are 15 s wide; once per second is plenty and cheap. */
            skb_pseudo_rebuild(skc_epoch_for((uint64_t)(esp_timer_get_time() / 1000000)));
        }

        if ((now - last_ping) >= ping_period) {
            last_ping = now;
            presence_tick();
        }

        if (s_state == SKB_STATE_PAIRING && esp_timer_get_time() > s_pairing_until_us) {
            ESP_LOGI(TAG, "pairing window expired");
            skb_stop_pairing();
        }

        vTaskDelay(tick);
    }
}

/* --------------------------------------------------------- pairing mode */

/** Pick the configured code, or generate a random one for this window. */
static void choose_pairing_code(void)
{
#ifdef CONFIG_SMARTKEY_PAIRING_CODE
    if (strlen(CONFIG_SMARTKEY_PAIRING_CODE) == SKP_PAIRING_CODE_LEN) {
        snprintf(s_pairing_code, sizeof(s_pairing_code), "%s", CONFIG_SMARTKEY_PAIRING_CODE);
        return;
    }
#endif
    uint32_t value = 0;
    skc_random((uint8_t *)&value, sizeof(value));
    snprintf(s_pairing_code, sizeof(s_pairing_code), "%08u", (unsigned)(value % 100000000u));
}

esp_err_t skb_start_pairing(void)
{
    if (s_state == SKB_STATE_PAIRING) {
        return ESP_OK;
    }

    /* The radio cannot scan and advertise a connectable beacon usefully at the
     * same time here, so presence detection pauses during the window. The
     * recovery beacon shares the single advertising instance, so it must go
     * first or ble_gap_adv_start() for pairing would fail with EALREADY. */
    stop_door_beacon();
    ble_gap_disc_cancel();
    disconnect(BLE_ERR_REM_USER_CONN_TERM);
    reset_conn();

    choose_pairing_code();
    esp_err_t err = skp_pairing_begin(s_pairing_code, s_own_addr_type);
    if (err != ESP_OK) {
        start_scan();
        return err;
    }
    s_pairing_until_us =
        esp_timer_get_time() + (int64_t)CONFIG_SMARTKEY_PAIRING_WINDOW_S * 1000000;
    set_state(SKB_STATE_PAIRING);
    return ESP_OK;
}

esp_err_t skb_stop_pairing(void)
{
    if (s_state != SKB_STATE_PAIRING) {
        return ESP_OK;
    }
    skp_pairing_end();
    memset(s_pairing_code, 0, sizeof(s_pairing_code));
    skb_refresh_pseudonyms(); /* a new credential may have appeared */
    set_state(SKB_STATE_IDLE);
    start_scan();
    return ESP_OK;
}

const char *skb_pairing_code(void)
{
    return s_state == SKB_STATE_PAIRING ? s_pairing_code : NULL;
}

bool skb_rearm_holding(void)
{
#if CONFIG_SMARTKEY_RELEASE_AFTER_UNLOCK
    return s_rearm_addr_valid && skra_blocked(&s_rearm, now_ms());
#else
    return false;
#endif
}

void skb_scan_report(skb_scan_report_t *out, bool reset)
{
    if (out == NULL) {
        return;
    }
    const int64_t now = esp_timer_get_time();
    out->adv_seen = s_scan_stats.adv_seen;
    out->adv_smartkey = s_scan_stats.adv_smartkey;
    out->adv_known = s_scan_stats.adv_known;
    out->elapsed_ms = (uint32_t)((now - s_scan_stats.since_us) / 1000);
#if CONFIG_SMARTKEY_DOOR_BEACON_ENABLE
    out->door_beacon_on = s_door_beacon_on;
#else
    out->door_beacon_on = false;
#endif
    if (reset) {
        s_scan_stats.adv_seen = 0;
        s_scan_stats.adv_smartkey = 0;
        s_scan_stats.adv_known = 0;
        s_scan_stats.since_us = now;
    }
}

void skb_refresh_pseudonyms(void)
{
    /* Credentials changed (pairing, revocation, reset): a stale post-unlock
     * hold must not outlive them and lock out a freshly paired phone. */
    rearm_clear();
    skb_pseudo_invalidate();
    skb_pseudo_rebuild(skc_epoch_for((uint64_t)(esp_timer_get_time() / 1000000)));
}

/* --------------------------------------------------------------- init */

static void on_sync(void)
{
    ble_hs_util_ensure_addr(0);
    int rc = ble_hs_id_infer_auto(0, &s_own_addr_type);
    if (rc != 0) {
        ESP_LOGE(TAG, "no usable BLE address (%d)", rc);
        return;
    }
    skb_refresh_pseudonyms();
    ESP_LOGI(TAG, "host synced, scanning for SmartKey phones");
    s_scan_stats.since_us = esp_timer_get_time();
    start_scan();
    /* set_state() is not called here (we are already IDLE), so the recovery
     * beacon needs starting explicitly on this path. */
    update_door_beacon();
}

static void on_reset(int reason)
{
    ESP_LOGW(TAG, "nimble host reset, reason %d", reason);
    reset_conn();
    s_state = SKB_STATE_IDLE;
}

static void nimble_host_task(void *param)
{
    (void)param;
    nimble_port_run();
    nimble_port_freertos_deinit();
}

esp_err_t skb_init(const skb_config_t *cfg)
{
    if (cfg != NULL) {
        s_cfg = *cfg;
    }
    reset_conn();
    proximity_configure();
    rearm_configure();

    esp_err_t err = nimble_port_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nimble_port_init failed (%s)", esp_err_to_name(err));
        return err;
    }

    ble_hs_cfg.sync_cb = on_sync;
    ble_hs_cfg.reset_cb = on_reset;
    /* No bonding: the application layer authenticates (security-model.md §4). */
    ble_hs_cfg.sm_bonding = 0;
    ble_hs_cfg.sm_mitm = 0;
    ble_hs_cfg.sm_sc = 0;

    ble_svc_gap_init();
    int rc = ble_svc_gap_device_name_set("SmartKey Door");
    if (rc != 0) {
        ESP_LOGW(TAG, "failed to set device name (%d)", rc);
    }

    /* The pairing GATT service must exist before the host starts. */
    err = skp_pairing_gatt_register();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "failed to register the pairing service");
        return err;
    }
    skp_pairing_set_callback(s_cfg.on_paired, s_cfg.ctx);

    nimble_port_freertos_init(nimble_host_task);

    if (xTaskCreate(housekeeping_task, "sk_ble_hk", 4096, NULL, 4, NULL) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}
