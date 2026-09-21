/**
 * @file smartkey_proto.c
 * @brief SKP1 frame codec. Platform independent, no dynamic allocation.
 */

#include "smartkey_proto.h"

#include <string.h>

/* ------------------------------------------------------------- helpers */

static inline void put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)(v >> 8);
}

static inline uint16_t get_u16(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static inline void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static inline uint32_t get_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/** Validate a parsed frame against the expected type and payload size. */
static int check(const skp_frame_t *f, uint8_t type, uint16_t size)
{
    if (f == NULL || f->payload == NULL) {
        return SKP_ERR_ARG;
    }
    if (f->version != SKP_VERSION) {
        return SKP_ERR_BAD_VERSION;
    }
    if (f->type != type || f->length != size) {
        return SKP_ERR_BAD_LENGTH;
    }
    return SKP_OK;
}

/* ------------------------------------------------------------- generic */

int skp_frame_encode(uint8_t type, const uint8_t *payload, uint16_t len, uint8_t *out,
                     size_t out_size)
{
    if (out == NULL || (len > 0 && payload == NULL)) {
        return SKP_ERR_ARG;
    }
    if (len > SKP_MAX_PAYLOAD) {
        return SKP_ERR_BAD_LENGTH;
    }
    if (out_size < (size_t)(SKP_HEADER_SIZE + len)) {
        return SKP_ERR_ARG;
    }
    out[0] = SKP_VERSION;
    out[1] = type;
    put_u16(&out[2], len);
    if (len > 0) {
        memcpy(&out[SKP_HEADER_SIZE], payload, len);
    }
    return SKP_HEADER_SIZE + (int)len;
}

int skp_frame_parse(const uint8_t *buf, size_t len, skp_frame_t *out)
{
    if (buf == NULL || out == NULL) {
        return SKP_ERR_ARG;
    }
    if (len < SKP_HEADER_SIZE) {
        return SKP_ERR_TRUNCATED;
    }
    if (buf[0] != SKP_VERSION) {
        return SKP_ERR_BAD_VERSION;
    }
    uint16_t payload_len = get_u16(&buf[2]);
    if (payload_len > SKP_MAX_PAYLOAD) {
        return SKP_ERR_BAD_LENGTH;
    }
    if (len < (size_t)(SKP_HEADER_SIZE + payload_len)) {
        return SKP_ERR_TRUNCATED;
    }
    out->version = buf[0];
    out->type = buf[1];
    out->length = payload_len;
    out->payload = &buf[SKP_HEADER_SIZE];
    return SKP_HEADER_SIZE + (int)payload_len;
}

int skp_encode_empty(uint8_t type, uint8_t *out, size_t out_size)
{
    return skp_frame_encode(type, NULL, 0, out, out_size);
}

int skp_encode_error(uint8_t code, uint8_t detail, uint8_t *out, size_t out_size)
{
    const uint8_t payload[SKP_ERROR_SIZE] = {code, detail};
    return skp_frame_encode(SKP_FRAME_ERROR, payload, sizeof(payload), out, out_size);
}

/* --------------------------------------------------------------- HELLO */

int skp_encode_hello(const skp_hello_t *in, uint8_t *out, size_t out_size)
{
    if (in == NULL) {
        return SKP_ERR_ARG;
    }
    uint8_t p[SKP_HELLO_SIZE];
    memcpy(&p[0], in->lock_id, SKP_ID_SIZE);
    memcpy(&p[16], in->nonce_l, SKP_NONCE_SIZE);
    p[32] = in->caps;
    p[33] = 0;
    return skp_frame_encode(SKP_FRAME_HELLO, p, sizeof(p), out, out_size);
}

int skp_parse_hello(const skp_frame_t *f, skp_hello_t *out)
{
    int rc = check(f, SKP_FRAME_HELLO, SKP_HELLO_SIZE);
    if (rc != SKP_OK || out == NULL) {
        return rc != SKP_OK ? rc : SKP_ERR_ARG;
    }
    memcpy(out->lock_id, &f->payload[0], SKP_ID_SIZE);
    memcpy(out->nonce_l, &f->payload[16], SKP_NONCE_SIZE);
    out->caps = f->payload[32];
    return SKP_OK;
}

/* ---------------------------------------------------------------- AUTH */

int skp_encode_auth(const skp_auth_t *in, uint8_t *out, size_t out_size)
{
    if (in == NULL) {
        return SKP_ERR_ARG;
    }
    uint8_t p[SKP_AUTH_SIZE];
    memcpy(&p[0], in->user_id, SKP_ID_SIZE);
    memcpy(&p[16], in->nonce_p, SKP_NONCE_SIZE);
    memcpy(&p[32], in->tag_p, SKP_TAG_SIZE);
    return skp_frame_encode(SKP_FRAME_AUTH, p, sizeof(p), out, out_size);
}

int skp_parse_auth(const skp_frame_t *f, skp_auth_t *out)
{
    int rc = check(f, SKP_FRAME_AUTH, SKP_AUTH_SIZE);
    if (rc != SKP_OK || out == NULL) {
        return rc != SKP_OK ? rc : SKP_ERR_ARG;
    }
    memcpy(out->user_id, &f->payload[0], SKP_ID_SIZE);
    memcpy(out->nonce_p, &f->payload[16], SKP_NONCE_SIZE);
    memcpy(out->tag_p, &f->payload[32], SKP_TAG_SIZE);
    return SKP_OK;
}

/* ---------------------------------------------------------- SESSION_OK */

int skp_encode_session_ok(const skp_session_ok_t *in, uint8_t *out, size_t out_size)
{
    if (in == NULL) {
        return SKP_ERR_ARG;
    }
    uint8_t p[SKP_SESSION_OK_SIZE];
    memcpy(&p[0], in->tag_l, SKP_TAG_SIZE);
    memcpy(&p[32], in->session_id, SKP_SESSION_ID_SIZE);
    p[40] = in->grant;
    p[41] = in->ttl_s;
    return skp_frame_encode(SKP_FRAME_SESSION_OK, p, sizeof(p), out, out_size);
}

int skp_parse_session_ok(const skp_frame_t *f, skp_session_ok_t *out)
{
    int rc = check(f, SKP_FRAME_SESSION_OK, SKP_SESSION_OK_SIZE);
    if (rc != SKP_OK || out == NULL) {
        return rc != SKP_OK ? rc : SKP_ERR_ARG;
    }
    memcpy(out->tag_l, &f->payload[0], SKP_TAG_SIZE);
    memcpy(out->session_id, &f->payload[32], SKP_SESSION_ID_SIZE);
    out->grant = f->payload[40];
    out->ttl_s = f->payload[41];
    return SKP_OK;
}

/* -------------------------------------------------------- UNLOCK_EVENT */

int skp_encode_unlock_event(const skp_unlock_event_t *in, uint8_t *out, size_t out_size)
{
    if (in == NULL) {
        return SKP_ERR_ARG;
    }
    uint8_t p[SKP_UNLOCK_EVENT_SIZE];
    memcpy(&p[0], in->session_id, SKP_SESSION_ID_SIZE);
    put_u32(&p[8], in->counter);
    p[12] = in->result;
    p[13] = 0;
    memcpy(&p[14], in->tag, SKP_TAG_SIZE);
    return skp_frame_encode(SKP_FRAME_UNLOCK_EVENT, p, sizeof(p), out, out_size);
}

int skp_parse_unlock_event(const skp_frame_t *f, skp_unlock_event_t *out)
{
    int rc = check(f, SKP_FRAME_UNLOCK_EVENT, SKP_UNLOCK_EVENT_SIZE);
    if (rc != SKP_OK || out == NULL) {
        return rc != SKP_OK ? rc : SKP_ERR_ARG;
    }
    memcpy(out->session_id, &f->payload[0], SKP_SESSION_ID_SIZE);
    out->counter = get_u32(&f->payload[8]);
    out->result = f->payload[12];
    memcpy(out->tag, &f->payload[14], SKP_TAG_SIZE);
    return SKP_OK;
}

/* ---------------------------------------------------------- UNLOCK_ACK */

int skp_encode_unlock_ack(const skp_unlock_ack_t *in, uint8_t *out, size_t out_size)
{
    if (in == NULL) {
        return SKP_ERR_ARG;
    }
    uint8_t p[SKP_UNLOCK_ACK_SIZE];
    memcpy(&p[0], in->session_id, SKP_SESSION_ID_SIZE);
    put_u32(&p[8], in->counter);
    return skp_frame_encode(SKP_FRAME_UNLOCK_ACK, p, sizeof(p), out, out_size);
}

int skp_parse_unlock_ack(const skp_frame_t *f, skp_unlock_ack_t *out)
{
    int rc = check(f, SKP_FRAME_UNLOCK_ACK, SKP_UNLOCK_ACK_SIZE);
    if (rc != SKP_OK || out == NULL) {
        return rc != SKP_OK ? rc : SKP_ERR_ARG;
    }
    memcpy(out->session_id, &f->payload[0], SKP_SESSION_ID_SIZE);
    out->counter = get_u32(&f->payload[8]);
    return SKP_OK;
}

/* -------------------------------------------------------------- pairing */

int skp_encode_pair_start(const skp_pair_start_t *in, uint8_t *out, size_t out_size)
{
    if (in == NULL) {
        return SKP_ERR_ARG;
    }
    uint8_t p[SKP_PAIR_START_SIZE];
    memcpy(&p[0], in->user_id, SKP_ID_SIZE);
    memcpy(&p[16], in->pubkey_p, SKP_PUBKEY_SIZE);
    memcpy(&p[48], in->nonce_p, SKP_NONCE_SIZE);
    return skp_frame_encode(SKP_FRAME_PAIR_START, p, sizeof(p), out, out_size);
}

int skp_parse_pair_start(const skp_frame_t *f, skp_pair_start_t *out)
{
    int rc = check(f, SKP_FRAME_PAIR_START, SKP_PAIR_START_SIZE);
    if (rc != SKP_OK || out == NULL) {
        return rc != SKP_OK ? rc : SKP_ERR_ARG;
    }
    memcpy(out->user_id, &f->payload[0], SKP_ID_SIZE);
    memcpy(out->pubkey_p, &f->payload[16], SKP_PUBKEY_SIZE);
    memcpy(out->nonce_p, &f->payload[48], SKP_NONCE_SIZE);
    return SKP_OK;
}

int skp_encode_pair_response(const skp_pair_response_t *in, uint8_t *out, size_t out_size)
{
    if (in == NULL) {
        return SKP_ERR_ARG;
    }
    uint8_t p[SKP_PAIR_RESPONSE_SIZE];
    memcpy(&p[0], in->lock_id, SKP_ID_SIZE);
    memcpy(&p[16], in->pubkey_l, SKP_PUBKEY_SIZE);
    memcpy(&p[48], in->nonce_l, SKP_NONCE_SIZE);
    memcpy(&p[64], in->confirm_l, SKP_TAG_SIZE);
    return skp_frame_encode(SKP_FRAME_PAIR_RESPONSE, p, sizeof(p), out, out_size);
}

int skp_parse_pair_response(const skp_frame_t *f, skp_pair_response_t *out)
{
    int rc = check(f, SKP_FRAME_PAIR_RESPONSE, SKP_PAIR_RESPONSE_SIZE);
    if (rc != SKP_OK || out == NULL) {
        return rc != SKP_OK ? rc : SKP_ERR_ARG;
    }
    memcpy(out->lock_id, &f->payload[0], SKP_ID_SIZE);
    memcpy(out->pubkey_l, &f->payload[16], SKP_PUBKEY_SIZE);
    memcpy(out->nonce_l, &f->payload[48], SKP_NONCE_SIZE);
    memcpy(out->confirm_l, &f->payload[64], SKP_TAG_SIZE);
    return SKP_OK;
}

int skp_encode_pair_confirm(const uint8_t confirm_p[SKP_TAG_SIZE], uint8_t *out, size_t out_size)
{
    if (confirm_p == NULL) {
        return SKP_ERR_ARG;
    }
    return skp_frame_encode(SKP_FRAME_PAIR_CONFIRM, confirm_p, SKP_PAIR_CONFIRM_SIZE, out,
                            out_size);
}

int skp_encode_pair_result(uint8_t status, uint8_t slot, uint8_t *out, size_t out_size)
{
    const uint8_t p[SKP_PAIR_RESULT_SIZE] = {status, slot, 0, 0};
    return skp_frame_encode(SKP_FRAME_PAIR_RESULT, p, sizeof(p), out, out_size);
}

/* -------------------------------------------------------- advertisement */

int skp_adv_parse(const uint8_t *data, size_t len, skp_adv_t *out)
{
    if (data == NULL || out == NULL) {
        return SKP_ERR_ARG;
    }
    if (len < SKP_ADV_PAYLOAD_SIZE) {
        return SKP_ERR_TRUNCATED;
    }
    if (get_u16(&data[0]) != SKP_ADV_COMPANY_ID) {
        return SKP_ERR_BAD_LENGTH;
    }
    if (data[2] != SKP_ADV_MAGIC) {
        return SKP_ERR_BAD_LENGTH;
    }
    if (data[3] != SKP_VERSION) {
        return SKP_ERR_BAD_VERSION;
    }
    out->flags = data[4];
    memcpy(out->pseudonym, &data[5], SKP_PSEUDONYM_SIZE);
    out->battery_pct = data[11];
    return SKP_OK;
}

int skp_adv_build(const skp_adv_t *in, uint8_t *out, size_t out_size)
{
    if (in == NULL || out == NULL) {
        return SKP_ERR_ARG;
    }
    if (out_size < SKP_ADV_PAYLOAD_SIZE) {
        return SKP_ERR_ARG;
    }
    put_u16(&out[0], SKP_ADV_COMPANY_ID);
    out[2] = SKP_ADV_MAGIC;
    out[3] = SKP_VERSION;
    out[4] = in->flags;
    memcpy(&out[5], in->pseudonym, SKP_PSEUDONYM_SIZE);
    out[11] = in->battery_pct;
    return SKP_ADV_PAYLOAD_SIZE;
}

int skp_door_adv_parse(const uint8_t *data, size_t len, skp_door_adv_t *out)
{
    if (data == NULL || out == NULL) {
        return SKP_ERR_ARG;
    }
    if (len < SKP_DOOR_PAYLOAD_SIZE) {
        return SKP_ERR_TRUNCATED;
    }
    if (get_u16(&data[0]) != SKP_ADV_COMPANY_ID) {
        return SKP_ERR_BAD_LENGTH;
    }
    /* 'D' not 'K': a phone beacon must never be accepted here. */
    if (data[2] != SKP_DOOR_MAGIC) {
        return SKP_ERR_BAD_LENGTH;
    }
    if (data[3] != SKP_VERSION) {
        return SKP_ERR_BAD_VERSION;
    }
    out->flags = data[4];
    memcpy(out->lock_id, &data[5], SKP_DOOR_ID_SIZE);
    return SKP_OK;
}

int skp_door_adv_build(const skp_door_adv_t *in, uint8_t *out, size_t out_size)
{
    if (in == NULL || out == NULL) {
        return SKP_ERR_ARG;
    }
    if (out_size < SKP_DOOR_PAYLOAD_SIZE) {
        return SKP_ERR_ARG;
    }
    put_u16(&out[0], SKP_ADV_COMPANY_ID);
    out[2] = SKP_DOOR_MAGIC;
    out[3] = SKP_VERSION;
    out[4] = in->flags;
    memcpy(&out[5], in->lock_id, SKP_DOOR_ID_SIZE);
    out[11] = 0; /* reserved, must be zero for future use */
    return SKP_DOOR_PAYLOAD_SIZE;
}
