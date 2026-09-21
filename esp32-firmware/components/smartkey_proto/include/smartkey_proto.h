/**
 * @file smartkey_proto.h
 * @brief SmartKey wire protocol (SKP1) — frame codec and constants.
 *
 * Implementation of ../../../shared-protocols/protocol-spec.md.
 * This component is platform independent (no ESP-IDF dependency) so it can be
 * compiled and unit tested on the host.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SKP_VERSION 0x01

/* --- sizes (protocol-spec.md §1, §3) ------------------------------------ */
#define SKP_ID_SIZE 16
#define SKP_KEY_SIZE 32
#define SKP_NONCE_SIZE 16
#define SKP_TAG_SIZE 32
#define SKP_SESSION_ID_SIZE 8
#define SKP_PSEUDONYM_SIZE 6
#define SKP_PUBKEY_SIZE 32
#define SKP_PAIRING_CODE_LEN 8

#define SKP_HEADER_SIZE 4
#define SKP_MAX_PAYLOAD 236
#define SKP_MAX_FRAME (SKP_HEADER_SIZE + SKP_MAX_PAYLOAD)

/* --- advertising (protocol-spec.md §2.1) -------------------------------- */
#define SKP_ADV_COMPANY_ID 0xFFFF
#define SKP_ADV_MAGIC 0x4B
#define SKP_ADV_PAYLOAD_SIZE 12 /**< incl. the 2 byte company id */

#define SKP_ADV_FLAG_SCREEN_ON 0x01
#define SKP_ADV_FLAG_UNLOCKED 0x02
#define SKP_ADV_FLAG_PAIRING_MODE 0x04
#define SKP_ADV_FLAG_PAIRING_BEACON 0x80

/* --- door beacon (protocol-spec.md §2.4) --------------------------------
 *
 * Emitted by the door unit, *not* the phone. Where the phone beacon carries a
 * pseudonym that rotates every 15 s to stay unlinkable, this one is
 * deliberately STATIC: the door is a fixed object bolted to a wall, so it has
 * no location privacy to lose, and a constant byte pattern is what lets
 * Android push the scan filter down into the Bluetooth controller
 * (offloaded filtering). That is what makes the phone side recovery scan cost
 * essentially no battery.
 *
 * It is non-connectable: its only job is to wake a phone whose presence
 * service was killed by the OS. The real session always runs the other way
 * round (door connects to phone).
 */
#define SKP_DOOR_MAGIC 0x44 /**< 'D', distinguishes it from the phone beacon 'K' */
#define SKP_DOOR_PAYLOAD_SIZE 12 /**< incl. the 2 byte company id */
#define SKP_DOOR_ID_SIZE 6       /**< leading bytes of lock_id carried in the beacon */

/** The door currently has a pairing window open. */
#define SKP_DOOR_FLAG_PAIRING 0x01
/** The door has at least one credential and is worth waking up for. */
#define SKP_DOOR_FLAG_ENROLLED 0x02

/* --- frame types (protocol-spec.md §4) ---------------------------------- */
typedef enum {
    SKP_FRAME_HELLO = 0x01,
    SKP_FRAME_AUTH = 0x02,
    SKP_FRAME_SESSION_OK = 0x03,
    SKP_FRAME_UNLOCK_EVENT = 0x04,
    SKP_FRAME_UNLOCK_ACK = 0x05,
    SKP_FRAME_PRESENCE_PING = 0x06,
    SKP_FRAME_PRESENCE_PONG = 0x07,
    SKP_FRAME_PAIR_START = 0x10,
    SKP_FRAME_PAIR_RESPONSE = 0x11,
    SKP_FRAME_PAIR_CONFIRM = 0x12,
    SKP_FRAME_PAIR_RESULT = 0x13,
    SKP_FRAME_ERROR = 0x7F,
} skp_frame_type_t;

/* --- payload sizes ------------------------------------------------------ */
#define SKP_HELLO_SIZE 34
#define SKP_AUTH_SIZE 64
#define SKP_SESSION_OK_SIZE 42
#define SKP_UNLOCK_EVENT_SIZE 46
#define SKP_UNLOCK_ACK_SIZE 12
#define SKP_PAIR_START_SIZE 64
#define SKP_PAIR_RESPONSE_SIZE 96
#define SKP_PAIR_CONFIRM_SIZE 32
#define SKP_PAIR_RESULT_SIZE 4
#define SKP_ERROR_SIZE 2

/* --- error codes (protocol-spec.md §7) ---------------------------------- */
typedef enum {
    SKP_ERR_UNSUPPORTED_VERSION = 0x01,
    SKP_ERR_MALFORMED_FRAME = 0x02,
    SKP_ERR_UNKNOWN_USER = 0x03,
    SKP_ERR_AUTH_FAILED = 0x04,
    SKP_ERR_NOT_PAIRED = 0x05,
    SKP_ERR_PAIRING_DISABLED = 0x06,
    SKP_ERR_RATE_LIMITED = 0x07,
    SKP_ERR_TIMEOUT = 0x08,
    SKP_ERR_INTERNAL = 0x09,
} skp_error_code_t;

/** Unlock result codes carried in UNLOCK_EVENT. */
typedef enum {
    SKP_UNLOCK_OK = 0,
    SKP_UNLOCK_ZIGBEE_ERROR = 1,
    SKP_UNLOCK_NOT_PERMITTED = 2,
    SKP_UNLOCK_RATE_LIMITED = 3,
} skp_unlock_result_t;

/** Pairing result codes carried in PAIR_RESULT. */
typedef enum {
    SKP_PAIR_OK = 0,
    SKP_PAIR_BAD_CONFIRM = 1,
    SKP_PAIR_STORE_FULL = 2,
    SKP_PAIR_DISABLED = 3,
} skp_pair_result_t;

/** Codec return codes. */
typedef enum {
    SKP_OK = 0,
    SKP_ERR_ARG = -1,       /**< NULL pointer or buffer too small */
    SKP_ERR_TRUNCATED = -2, /**< need more bytes to complete the frame */
    SKP_ERR_BAD_VERSION = -3,
    SKP_ERR_BAD_LENGTH = -4,
} skp_status_t;

/* ------------------------------------------------------------------ frames */

typedef struct {
    uint8_t version;
    uint8_t type;
    uint16_t length;
    const uint8_t *payload; /**< points into the caller's buffer, not copied */
} skp_frame_t;

typedef struct {
    uint8_t lock_id[SKP_ID_SIZE];
    uint8_t nonce_l[SKP_NONCE_SIZE];
    uint8_t caps;
} skp_hello_t;

typedef struct {
    uint8_t user_id[SKP_ID_SIZE];
    uint8_t nonce_p[SKP_NONCE_SIZE];
    uint8_t tag_p[SKP_TAG_SIZE];
} skp_auth_t;

typedef struct {
    uint8_t tag_l[SKP_TAG_SIZE];
    uint8_t session_id[SKP_SESSION_ID_SIZE];
    uint8_t grant;
    uint8_t ttl_s;
} skp_session_ok_t;

typedef struct {
    uint8_t session_id[SKP_SESSION_ID_SIZE];
    uint32_t counter;
    uint8_t result;
    uint8_t tag[SKP_TAG_SIZE];
} skp_unlock_event_t;

typedef struct {
    uint8_t session_id[SKP_SESSION_ID_SIZE];
    uint32_t counter;
} skp_unlock_ack_t;

typedef struct {
    uint8_t user_id[SKP_ID_SIZE];
    uint8_t pubkey_p[SKP_PUBKEY_SIZE];
    uint8_t nonce_p[SKP_NONCE_SIZE];
} skp_pair_start_t;

typedef struct {
    uint8_t lock_id[SKP_ID_SIZE];
    uint8_t pubkey_l[SKP_PUBKEY_SIZE];
    uint8_t nonce_l[SKP_NONCE_SIZE];
    uint8_t confirm_l[SKP_TAG_SIZE];
} skp_pair_response_t;

/** Parsed SmartKey advertisement (phone beacon). */
typedef struct {
    uint8_t flags;
    uint8_t pseudonym[SKP_PSEUDONYM_SIZE];
    uint8_t battery_pct;
} skp_adv_t;

/** Parsed door beacon (door unit → phone, static identifier). */
typedef struct {
    uint8_t flags;
    uint8_t lock_id[SKP_DOOR_ID_SIZE];
} skp_door_adv_t;

/* ------------------------------------------------------------------- API */

/** Encode a generic frame. @return bytes written, or negative skp_status_t. */
int skp_frame_encode(uint8_t type, const uint8_t *payload, uint16_t len, uint8_t *out,
                     size_t out_size);

/** Parse a frame header + payload from @p buf. @return total frame size or negative. */
int skp_frame_parse(const uint8_t *buf, size_t len, skp_frame_t *out);

int skp_encode_hello(const skp_hello_t *in, uint8_t *out, size_t out_size);
int skp_parse_hello(const skp_frame_t *f, skp_hello_t *out);

int skp_encode_auth(const skp_auth_t *in, uint8_t *out, size_t out_size);
int skp_parse_auth(const skp_frame_t *f, skp_auth_t *out);

int skp_encode_session_ok(const skp_session_ok_t *in, uint8_t *out, size_t out_size);
int skp_parse_session_ok(const skp_frame_t *f, skp_session_ok_t *out);

int skp_encode_unlock_event(const skp_unlock_event_t *in, uint8_t *out, size_t out_size);
int skp_parse_unlock_event(const skp_frame_t *f, skp_unlock_event_t *out);

int skp_encode_unlock_ack(const skp_unlock_ack_t *in, uint8_t *out, size_t out_size);
int skp_parse_unlock_ack(const skp_frame_t *f, skp_unlock_ack_t *out);

int skp_encode_pair_start(const skp_pair_start_t *in, uint8_t *out, size_t out_size);
int skp_parse_pair_start(const skp_frame_t *f, skp_pair_start_t *out);

int skp_encode_pair_response(const skp_pair_response_t *in, uint8_t *out, size_t out_size);
int skp_parse_pair_response(const skp_frame_t *f, skp_pair_response_t *out);

int skp_encode_pair_confirm(const uint8_t confirm_p[SKP_TAG_SIZE], uint8_t *out,
                            size_t out_size);
int skp_encode_pair_result(uint8_t status, uint8_t slot, uint8_t *out, size_t out_size);

int skp_encode_error(uint8_t code, uint8_t detail, uint8_t *out, size_t out_size);
int skp_encode_empty(uint8_t type, uint8_t *out, size_t out_size);

/**
 * @brief Parse the manufacturer specific data of a SmartKey advertisement.
 * @param data manufacturer data including the 2 byte company id
 * @return SKP_OK when this is a valid SKP1 phone beacon.
 */
int skp_adv_parse(const uint8_t *data, size_t len, skp_adv_t *out);

/** @brief Build the 12 byte manufacturer specific advertisement payload. */
int skp_adv_build(const skp_adv_t *in, uint8_t *out, size_t out_size);

/**
 * @brief Parse a door beacon (protocol-spec.md §2.4).
 *
 * Rejects phone beacons: the magic byte differs, so the two advertisement
 * types can never be confused even though they share a company id.
 */
int skp_door_adv_parse(const uint8_t *data, size_t len, skp_door_adv_t *out);

/** @brief Build the 12 byte door beacon manufacturer payload. */
int skp_door_adv_build(const skp_door_adv_t *in, uint8_t *out, size_t out_size);

#ifdef __cplusplus
}
#endif
