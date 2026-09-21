/**
 * @file test_smartkey_proto.c
 * @brief Host unit tests for smartkey_proto / smartkey_crypto.
 *
 * Validates the firmware implementation against the golden vectors shared with
 * the Android app (shared-protocols/test-vectors/), so that the two sides can
 * never drift apart silently.
 *
 * Build & run:  test/host/run_tests.sh
 */

#include <stdio.h>
#include <string.h>

#include "smartkey_crypto.h"
#include "smartkey_proto.h"
#include "smartkey_proximity.h"
#include "smartkey_rearm.h"
#include "test_vectors.h"

static int g_failures;
static int g_checks;

/* ----------------------------------------------------------- utilities */

static size_t unhex(const char *hex, uint8_t *out, size_t out_size)
{
    size_t len = strlen(hex) / 2;
    if (len > out_size) {
        printf("unhex: buffer too small (%zu > %zu)\n", len, out_size);
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned int byte = 0;
        sscanf(hex + 2 * i, "%2x", &byte);
        out[i] = (uint8_t)byte;
    }
    return len;
}

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("      %s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static void check_bytes(const char *name, const uint8_t *got, size_t got_len, const char *expect_hex)
{
    uint8_t expect[512];
    size_t expect_len = unhex(expect_hex, expect, sizeof(expect));
    g_checks++;
    if (got_len != expect_len || memcmp(got, expect, got_len) != 0) {
        g_failures++;
        printf("FAIL  %s\n", name);
        print_hex("got     ", got, got_len);
        print_hex("expected", expect, expect_len);
    } else {
        printf("ok    %s\n", name);
    }
}

static void check_true(const char *name, bool cond)
{
    g_checks++;
    if (!cond) {
        g_failures++;
        printf("FAIL  %s\n", name);
    } else {
        printf("ok    %s\n", name);
    }
}

static void check_int(const char *name, long got, long expect)
{
    g_checks++;
    if (got != expect) {
        g_failures++;
        printf("FAIL  %s (got %ld, expected %ld)\n", name, got, expect);
    } else {
        printf("ok    %s\n", name);
    }
}

/* ------------------------------------------------------------- crypto */

static void test_hkdf(void)
{
    uint8_t ikm[64], salt[64], info[64], okm[64];
    size_t ikm_len = unhex(TV_HKDF_IKM, ikm, sizeof(ikm));
    size_t salt_len = unhex(TV_HKDF_SALT, salt, sizeof(salt));
    size_t info_len = unhex(TV_HKDF_INFO, info, sizeof(info));

    int rc = skc_hkdf_sha256(ikm, ikm_len, salt, salt_len, info, info_len, okm, TV_HKDF_LEN);
    check_int("hkdf rc", rc, 0);
    check_bytes("hkdf rfc5869 test case 1", okm, TV_HKDF_LEN, TV_HKDF_OKM);
}

static void test_subkeys(void)
{
    uint8_t ltk[32], lock_id[16], user_id[16];
    unhex(TV_LTK, ltk, sizeof(ltk));
    unhex(TV_LOCK_ID, lock_id, sizeof(lock_id));
    unhex(TV_USER_ID, user_id, sizeof(user_id));

    skc_subkeys_t sub;
    int rc = skc_derive_subkeys(ltk, lock_id, user_id, &sub);
    check_int("derive_subkeys rc", rc, 0);
    check_bytes("k_beacon", sub.k_beacon, sizeof(sub.k_beacon), TV_K_BEACON);
    check_bytes("k_auth", sub.k_auth, sizeof(sub.k_auth), TV_K_AUTH);
}

static void test_pseudonyms(void)
{
    const uint64_t epochs[] = TV_PSEUDONYM_EPOCHS;
    const char *values[] = TV_PSEUDONYM_VALUES;

    uint8_t k_beacon[32];
    unhex(TV_K_BEACON, k_beacon, sizeof(k_beacon));

    for (int i = 0; i < TV_PSEUDONYM_COUNT; i++) {
        uint8_t pseudo[SKP_PSEUDONYM_SIZE];
        int rc = skc_pseudonym(k_beacon, epochs[i], pseudo);
        check_int("pseudonym rc", rc, 0);
        char name[64];
        snprintf(name, sizeof(name), "pseudonym epoch %llu", (unsigned long long)epochs[i]);
        check_bytes(name, pseudo, sizeof(pseudo), values[i]);
    }

    check_int("epoch_for(0)", (long)skc_epoch_for(0), 0);
    check_int("epoch_for(14)", (long)skc_epoch_for(14), 0);
    check_int("epoch_for(15)", (long)skc_epoch_for(15), 1);
    check_int("epoch_for(1758412800)", (long)skc_epoch_for(1758412800ULL), 117227520L);
}

static void test_handshake_tags(void)
{
    uint8_t lock_id[16], user_id[16], nonce_l[16], nonce_p[16], k_auth[32];
    unhex(TV_LOCK_ID, lock_id, sizeof(lock_id));
    unhex(TV_USER_ID, user_id, sizeof(user_id));
    unhex(TV_NONCE_L, nonce_l, sizeof(nonce_l));
    unhex(TV_NONCE_P, nonce_p, sizeof(nonce_p));
    unhex(TV_K_AUTH, k_auth, sizeof(k_auth));

    uint8_t transcript[SKC_AUTH_TRANSCRIPT_SIZE];
    size_t tlen = skc_auth_transcript(lock_id, user_id, nonce_l, nonce_p, transcript);
    check_int("auth transcript length", (long)tlen, SKC_AUTH_TRANSCRIPT_SIZE);
    check_bytes("auth transcript", transcript, tlen, TV_TRANSCRIPT);

    uint8_t tag[SKP_TAG_SIZE];
    skc_tag_phone(k_auth, transcript, tlen, tag);
    check_bytes("tag_p", tag, sizeof(tag), TV_TAG_P);

    skc_tag_lock(k_auth, transcript, tlen, tag);
    check_bytes("tag_l", tag, sizeof(tag), TV_TAG_L);

    uint8_t sid[SKP_SESSION_ID_SIZE];
    skc_session_id(k_auth, transcript, tlen, sid);
    check_bytes("session_id", sid, sizeof(sid), TV_SESSION_ID);

    uint8_t k_sess[SKP_KEY_SIZE];
    skc_session_key(k_auth, lock_id, user_id, nonce_l, nonce_p, k_sess);
    check_bytes("k_sess", k_sess, sizeof(k_sess), TV_K_SESS);

    uint8_t utag[SKP_TAG_SIZE];
    skc_unlock_tag(k_sess, sid, TV_UNLOCK_COUNTER, TV_UNLOCK_RESULT, utag);
    check_bytes("unlock tag", utag, sizeof(utag), TV_UNLOCK_TAG);
}

static void test_ct_equal(void)
{
    const uint8_t a[4] = {1, 2, 3, 4};
    const uint8_t b[4] = {1, 2, 3, 4};
    const uint8_t c[4] = {1, 2, 3, 5};
    check_true("ct_equal same", skc_ct_equal(a, b, 4));
    check_true("ct_equal differs", !skc_ct_equal(a, c, 4));
    check_true("ct_equal null", !skc_ct_equal(a, NULL, 4));
}

/* -------------------------------------------------------------- codec */

static void test_frames(void)
{
    uint8_t buf[SKP_MAX_FRAME];

    /* HELLO */
    skp_hello_t hello = {.caps = 0x03};
    unhex(TV_LOCK_ID, hello.lock_id, sizeof(hello.lock_id));
    unhex(TV_NONCE_L, hello.nonce_l, sizeof(hello.nonce_l));
    int n = skp_encode_hello(&hello, buf, sizeof(buf));
    check_int("hello encoded size", n, SKP_HEADER_SIZE + SKP_HELLO_SIZE);
    check_bytes("hello frame", buf, (size_t)n, TV_FRAME_HELLO);

    skp_frame_t f;
    check_int("hello parse frame", skp_frame_parse(buf, (size_t)n, &f), n);
    skp_hello_t hello_rt;
    check_int("hello parse payload", skp_parse_hello(&f, &hello_rt), SKP_OK);
    check_true("hello round trip", memcmp(&hello, &hello_rt, sizeof(hello)) == 0);

    /* AUTH */
    skp_auth_t auth;
    unhex(TV_USER_ID, auth.user_id, sizeof(auth.user_id));
    unhex(TV_NONCE_P, auth.nonce_p, sizeof(auth.nonce_p));
    unhex(TV_TAG_P, auth.tag_p, sizeof(auth.tag_p));
    n = skp_encode_auth(&auth, buf, sizeof(buf));
    check_bytes("auth frame", buf, (size_t)n, TV_FRAME_AUTH);
    skp_frame_parse(buf, (size_t)n, &f);
    skp_auth_t auth_rt;
    check_int("auth parse", skp_parse_auth(&f, &auth_rt), SKP_OK);
    check_true("auth round trip", memcmp(&auth, &auth_rt, sizeof(auth)) == 0);

    /* SESSION_OK */
    skp_session_ok_t sok = {.grant = 1, .ttl_s = 10};
    unhex(TV_TAG_L, sok.tag_l, sizeof(sok.tag_l));
    unhex(TV_SESSION_ID, sok.session_id, sizeof(sok.session_id));
    n = skp_encode_session_ok(&sok, buf, sizeof(buf));
    check_bytes("session_ok frame", buf, (size_t)n, TV_FRAME_SESSION_OK);
    skp_frame_parse(buf, (size_t)n, &f);
    skp_session_ok_t sok_rt;
    check_int("session_ok parse", skp_parse_session_ok(&f, &sok_rt), SKP_OK);
    check_true("session_ok round trip", memcmp(&sok, &sok_rt, sizeof(sok)) == 0);

    /* UNLOCK_EVENT */
    skp_unlock_event_t ue = {.counter = TV_UNLOCK_COUNTER, .result = TV_UNLOCK_RESULT};
    unhex(TV_SESSION_ID, ue.session_id, sizeof(ue.session_id));
    unhex(TV_UNLOCK_TAG, ue.tag, sizeof(ue.tag));
    n = skp_encode_unlock_event(&ue, buf, sizeof(buf));
    check_bytes("unlock_event frame", buf, (size_t)n, TV_FRAME_UNLOCK_EVENT);
    skp_frame_parse(buf, (size_t)n, &f);
    skp_unlock_event_t ue_rt;
    check_int("unlock_event parse", skp_parse_unlock_event(&f, &ue_rt), SKP_OK);
    /* Compared field by field: the struct contains alignment padding. */
    check_true("unlock_event round trip",
               memcmp(ue.session_id, ue_rt.session_id, sizeof(ue.session_id)) == 0 &&
                   ue.counter == ue_rt.counter && ue.result == ue_rt.result &&
                   memcmp(ue.tag, ue_rt.tag, sizeof(ue.tag)) == 0);

    /* UNLOCK_ACK round trip (symmetry check, no golden vector) */
    skp_unlock_ack_t ack = {.counter = 0x01020304};
    unhex(TV_SESSION_ID, ack.session_id, sizeof(ack.session_id));
    n = skp_encode_unlock_ack(&ack, buf, sizeof(buf));
    check_int("unlock_ack size", n, SKP_HEADER_SIZE + SKP_UNLOCK_ACK_SIZE);
    skp_frame_parse(buf, (size_t)n, &f);
    skp_unlock_ack_t ack_rt;
    check_int("unlock_ack parse", skp_parse_unlock_ack(&f, &ack_rt), SKP_OK);
    check_true("unlock_ack round trip",
               memcmp(ack.session_id, ack_rt.session_id, sizeof(ack.session_id)) == 0 &&
                   ack.counter == ack_rt.counter);

    /* PRESENCE_PING / ERROR */
    n = skp_encode_empty(SKP_FRAME_PRESENCE_PING, buf, sizeof(buf));
    check_bytes("presence_ping frame", buf, (size_t)n, TV_FRAME_PRESENCE_PING);
    n = skp_encode_error(SKP_ERR_AUTH_FAILED, 0, buf, sizeof(buf));
    check_bytes("error frame", buf, (size_t)n, TV_FRAME_ERROR_AUTH_FAILED);
}

static void test_frame_errors(void)
{
    uint8_t buf[SKP_MAX_FRAME];
    skp_frame_t f;

    const uint8_t short_buf[3] = {0x01, 0x01, 0x00};
    check_int("truncated header", skp_frame_parse(short_buf, sizeof(short_buf), &f),
              SKP_ERR_TRUNCATED);

    const uint8_t bad_version[4] = {0x02, 0x01, 0x00, 0x00};
    check_int("bad version", skp_frame_parse(bad_version, sizeof(bad_version), &f),
              SKP_ERR_BAD_VERSION);

    /* header announces 10 bytes but only 2 are present */
    const uint8_t truncated_payload[6] = {0x01, 0x01, 0x0A, 0x00, 0xAA, 0xBB};
    check_int("truncated payload",
              skp_frame_parse(truncated_payload, sizeof(truncated_payload), &f),
              SKP_ERR_TRUNCATED);

    /* length beyond SKP_MAX_PAYLOAD */
    const uint8_t oversize[4] = {0x01, 0x01, 0xFF, 0x00};
    check_int("oversize length", skp_frame_parse(oversize, sizeof(oversize), &f),
              SKP_ERR_BAD_LENGTH);

    check_int("null args", skp_frame_parse(NULL, 4, &f), SKP_ERR_ARG);
    check_int("encode buffer too small", skp_encode_empty(SKP_FRAME_PRESENCE_PING, buf, 2),
              SKP_ERR_ARG);

    /* wrong type for the typed parser */
    int n = skp_encode_empty(SKP_FRAME_PRESENCE_PONG, buf, sizeof(buf));
    skp_frame_parse(buf, (size_t)n, &f);
    skp_hello_t hello;
    check_int("wrong type rejected", skp_parse_hello(&f, &hello), SKP_ERR_BAD_LENGTH);
}

static void test_advertisement(void)
{
    uint8_t k_beacon[32], adv_buf[SKP_ADV_PAYLOAD_SIZE];
    unhex(TV_K_BEACON, k_beacon, sizeof(k_beacon));

    skp_adv_t adv = {.flags = TV_ADV_FLAGS, .battery_pct = TV_ADV_BATTERY};
    skc_pseudonym(k_beacon, TV_ADV_EPOCH, adv.pseudonym);

    int n = skp_adv_build(&adv, adv_buf, sizeof(adv_buf));
    check_int("adv build size", n, SKP_ADV_PAYLOAD_SIZE);
    check_bytes("adv payload", adv_buf, (size_t)n, TV_ADV_BYTES);

    skp_adv_t parsed;
    check_int("adv parse", skp_adv_parse(adv_buf, sizeof(adv_buf), &parsed), SKP_OK);
    check_true("adv round trip", memcmp(&adv, &parsed, sizeof(adv)) == 0);

    /* reject foreign manufacturer data */
    uint8_t foreign[SKP_ADV_PAYLOAD_SIZE];
    memcpy(foreign, adv_buf, sizeof(foreign));
    foreign[2] = 0x00; /* wrong magic */
    check_true("adv rejects wrong magic",
               skp_adv_parse(foreign, sizeof(foreign), &parsed) != SKP_OK);
    check_int("adv rejects short data", skp_adv_parse(adv_buf, 4, &parsed), SKP_ERR_TRUNCATED);
}

/* --------------------------------------------------------- door beacon */

/**
 * The door beacon is the recovery path: a phone whose presence service was
 * killed by the OS notices it and restarts. Two properties matter most here —
 * the identifier is STATIC (so Android can offload the scan filter into the
 * controller), and it can never be confused with a phone beacon despite
 * sharing a company id.
 */
static void test_door_beacon(void)
{
    skp_door_adv_t door = {.flags = SKP_DOOR_FLAG_ENROLLED,
                           .lock_id = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02}};

    uint8_t buf[SKP_DOOR_PAYLOAD_SIZE];
    int n = skp_door_adv_build(&door, buf, sizeof(buf));
    check_int("door beacon build size", n, SKP_DOOR_PAYLOAD_SIZE);
    check_int("door beacon magic is 'D'", buf[2], SKP_DOOR_MAGIC);
    check_int("door beacon reserved byte is zero", buf[11], 0);

    skp_door_adv_t parsed;
    check_int("door beacon parse", skp_door_adv_parse(buf, sizeof(buf), &parsed), SKP_OK);
    check_true("door beacon round trip", memcmp(&door, &parsed, sizeof(door)) == 0);

    /* Determinism is the whole point: an offloaded scan filter matches fixed
     * bytes, so the same input must always produce the identical payload. */
    uint8_t again[SKP_DOOR_PAYLOAD_SIZE];
    skp_door_adv_build(&door, again, sizeof(again));
    check_true("door beacon is static across builds",
               memcmp(buf, again, sizeof(buf)) == 0);

    /* A phone beacon must never parse as a door beacon, and vice versa. */
    uint8_t phone_buf[SKP_ADV_PAYLOAD_SIZE];
    skp_adv_t phone = {.flags = 0, .battery_pct = 50};
    memset(phone.pseudonym, 0xAB, sizeof(phone.pseudonym));
    skp_adv_build(&phone, phone_buf, sizeof(phone_buf));
    check_true("door parser rejects a phone beacon",
               skp_door_adv_parse(phone_buf, sizeof(phone_buf), &parsed) != SKP_OK);
    skp_adv_t phone_parsed;
    check_true("phone parser rejects a door beacon",
               skp_adv_parse(buf, sizeof(buf), &phone_parsed) != SKP_OK);

    /* Malformed input */
    check_int("door beacon rejects short data", skp_door_adv_parse(buf, 4, &parsed),
              SKP_ERR_TRUNCATED);
    uint8_t bad_version[SKP_DOOR_PAYLOAD_SIZE];
    memcpy(bad_version, buf, sizeof(bad_version));
    bad_version[3] = 0x02;
    check_int("door beacon rejects future version",
              skp_door_adv_parse(bad_version, sizeof(bad_version), &parsed),
              SKP_ERR_BAD_VERSION);
    check_int("door beacon parse rejects NULL",
              skp_door_adv_parse(NULL, SKP_DOOR_PAYLOAD_SIZE, &parsed), SKP_ERR_ARG);
    check_int("door beacon build rejects NULL", skp_door_adv_build(&door, NULL, 0),
              SKP_ERR_ARG);
    check_int("door beacon build rejects small buffer",
              skp_door_adv_build(&door, buf, 4), SKP_ERR_ARG);

    /* An un-enrolled door still beacons, just without the ENROLLED flag, so a
     * phone can tell "this door has no credentials" from "this is my door". */
    skp_door_adv_t fresh = {.flags = 0, .lock_id = {1, 2, 3, 4, 5, 6}};
    skp_door_adv_build(&fresh, buf, sizeof(buf));
    check_int("fresh door beacon parses", skp_door_adv_parse(buf, sizeof(buf), &parsed),
              SKP_OK);
    check_true("fresh door is not marked enrolled",
               (parsed.flags & SKP_DOOR_FLAG_ENROLLED) == 0);
}

/* ------------------------------------------------------------- pairing */

static void test_pairing(void)
{
    uint8_t priv_p[32], priv_l[32], pub_p[32], pub_l[32];
    unhex(TV_PAIR_PRIV_P, priv_p, sizeof(priv_p));
    unhex(TV_PAIR_PRIV_L, priv_l, sizeof(priv_l));
    unhex(TV_PAIR_PUB_P, pub_p, sizeof(pub_p));
    unhex(TV_PAIR_PUB_L, pub_l, sizeof(pub_l));

    uint8_t z_phone[32], z_lock[32];
    check_int("x25519 phone shared rc", skc_x25519_shared(priv_p, pub_l, z_phone), 0);
    check_bytes("x25519 shared (phone side)", z_phone, sizeof(z_phone), TV_PAIR_SHARED);
    check_int("x25519 lock shared rc", skc_x25519_shared(priv_l, pub_p, z_lock), 0);
    check_bytes("x25519 shared (lock side)", z_lock, sizeof(z_lock), TV_PAIR_SHARED);

    uint8_t lock_id[16], user_id[16], nonce_p[16], nonce_l[16];
    unhex(TV_PAIR_LOCK_ID, lock_id, sizeof(lock_id));
    unhex(TV_PAIR_USER_ID, user_id, sizeof(user_id));
    unhex(TV_PAIR_NONCE_P, nonce_p, sizeof(nonce_p));
    unhex(TV_PAIR_NONCE_L, nonce_l, sizeof(nonce_l));

    uint8_t transcript[SKC_PAIR_TRANSCRIPT_SIZE];
    size_t tlen = skc_pair_transcript(lock_id, user_id, pub_p, pub_l, nonce_p, nonce_l, transcript);
    check_int("pair transcript length", (long)tlen, SKC_PAIR_TRANSCRIPT_SIZE);
    check_bytes("pair transcript", transcript, tlen, TV_PAIR_TRANSCRIPT);

    uint8_t ltk[32];
    check_int("pair ltk rc",
              skc_pair_ltk(z_phone, nonce_p, nonce_l, transcript, tlen, TV_PAIR_CODE, ltk), 0);
    check_bytes("pair ltk", ltk, sizeof(ltk), TV_PAIR_LTK);

    uint8_t confirm[32];
    skc_pair_confirm_lock(ltk, transcript, tlen, confirm);
    check_bytes("pair confirm_l", confirm, sizeof(confirm), TV_PAIR_CONFIRM_L);
    skc_pair_confirm_phone(ltk, transcript, tlen, confirm);
    check_bytes("pair confirm_p", confirm, sizeof(confirm), TV_PAIR_CONFIRM_P);

    /* A wrong pairing code must produce a different key (pairing-spec.md §2). */
    uint8_t wrong_ltk[32];
    skc_pair_ltk(z_phone, nonce_p, nonce_l, transcript, tlen, "00000000", wrong_ltk);
    check_bytes("wrong code ltk", wrong_ltk, sizeof(wrong_ltk), TV_PAIR_WRONG_CODE_LTK);
    check_true("wrong code differs", !skc_ct_equal(ltk, wrong_ltk, sizeof(ltk)));
    check_int("pair ltk rejects short code",
              skc_pair_ltk(z_phone, nonce_p, nonce_l, transcript, tlen, "123", ltk) == 0, 0);

    /* Freshly generated key pairs must interoperate with the fixed ones. */
    uint8_t gen_priv[32], gen_pub[32], gz1[32], gz2[32];
    check_int("keypair rc", skc_x25519_keypair(gen_priv, gen_pub), 0);
    check_int("keypair ecdh a", skc_x25519_shared(priv_p, gen_pub, gz1), 0);
    check_int("keypair ecdh b", skc_x25519_shared(gen_priv, pub_p, gz2), 0);
    check_true("generated keypair agrees", skc_ct_equal(gz1, gz2, sizeof(gz1)));

    /* Pairing frames must match the golden encodings. */
    uint8_t buf[SKP_MAX_FRAME];
    skp_pair_start_t ps;
    memcpy(ps.user_id, user_id, sizeof(ps.user_id));
    memcpy(ps.pubkey_p, pub_p, sizeof(ps.pubkey_p));
    memcpy(ps.nonce_p, nonce_p, sizeof(ps.nonce_p));
    int n = skp_encode_pair_start(&ps, buf, sizeof(buf));
    check_bytes("pair_start frame", buf, (size_t)n, TV_FRAME_PAIR_START);

    skp_frame_t f;
    skp_frame_parse(buf, (size_t)n, &f);
    skp_pair_start_t ps_rt;
    check_int("pair_start parse", skp_parse_pair_start(&f, &ps_rt), SKP_OK);
    check_true("pair_start round trip", memcmp(&ps, &ps_rt, sizeof(ps)) == 0);

    skp_pair_response_t pr;
    memcpy(pr.lock_id, lock_id, sizeof(pr.lock_id));
    memcpy(pr.pubkey_l, pub_l, sizeof(pr.pubkey_l));
    memcpy(pr.nonce_l, nonce_l, sizeof(pr.nonce_l));
    unhex(TV_PAIR_CONFIRM_L, pr.confirm_l, sizeof(pr.confirm_l));
    n = skp_encode_pair_response(&pr, buf, sizeof(buf));
    check_bytes("pair_response frame", buf, (size_t)n, TV_FRAME_PAIR_RESPONSE);

    uint8_t confirm_p[32];
    unhex(TV_PAIR_CONFIRM_P, confirm_p, sizeof(confirm_p));
    n = skp_encode_pair_confirm(confirm_p, buf, sizeof(buf));
    check_bytes("pair_confirm frame", buf, (size_t)n, TV_FRAME_PAIR_CONFIRM);

    n = skp_encode_pair_result(SKP_PAIR_OK, 0, buf, sizeof(buf));
    check_bytes("pair_result frame", buf, (size_t)n, TV_FRAME_PAIR_RESULT_OK);
}

/* ----------------------------------------------------------- proximity */

/** Standard tuning used by most of the proximity tests. */
static skpx_filter_t make_filter(void)
{
    const skpx_config_t cfg = {
        .near_dbm = -60,
        .far_dbm = -72,
        .window = 5,
        .min_samples = 3,
    };
    skpx_filter_t filter;
    skpx_init(&filter, &cfg);
    return filter;
}

static void feed(skpx_filter_t *filter, int8_t rssi, int times)
{
    for (int i = 0; i < times; i++) {
        skpx_add_sample(filter, rssi);
    }
}

static void test_proximity_basics(void)
{
    skpx_filter_t filter = make_filter();

    check_true("proximity starts far", !skpx_is_near(&filter));
    check_true("proximity starts unready", !skpx_ready(&filter));
    check_int("median with no samples", skpx_median(&filter), SKPX_RSSI_UNKNOWN);

    /* One strong sample must NOT be enough: that is the false grant we are
     * defending against. */
    skpx_add_sample(&filter, -40);
    check_true("one strong sample does not grant", !skpx_is_near(&filter));

    skpx_add_sample(&filter, -40);
    check_true("two strong samples still do not grant", !skpx_is_near(&filter));

    skpx_add_sample(&filter, -40);
    check_true("three strong samples grant", skpx_is_near(&filter));
    check_true("filter reports ready", skpx_ready(&filter));
    check_int("median of strong samples", skpx_median(&filter), -40);
}

static void test_proximity_rejects_spikes(void)
{
    skpx_filter_t filter = make_filter();

    /* A phone across the room with one lucky multipath reflection. */
    feed(&filter, -85, 2);
    skpx_add_sample(&filter, -35); /* the spike */
    feed(&filter, -85, 2);

    check_true("a single spike never grants access", !skpx_is_near(&filter));
    check_int("median ignores the spike", skpx_median(&filter), -85);
}

static void test_proximity_rejects_dropouts(void)
{
    skpx_filter_t filter = make_filter();

    /* A phone right at the reader, with one packet lost to body shadowing. */
    feed(&filter, -45, 3);
    check_true("near after steady strong samples", skpx_is_near(&filter));

    skpx_add_sample(&filter, -95); /* momentary deep fade */
    check_true("a single dropout does not revoke access", skpx_is_near(&filter));
    check_int("median survives the dropout", skpx_median(&filter), -45);
}

static void test_proximity_hysteresis(void)
{
    skpx_filter_t filter = make_filter();

    feed(&filter, -50, 5);
    check_true("near at -50", skpx_is_near(&filter));

    /* Between the thresholds: must hold its current state, not chatter. */
    feed(&filter, -65, 5);
    check_true("stays near inside the hysteresis band", skpx_is_near(&filter));

    feed(&filter, -80, 5);
    check_true("goes far past the exit threshold", !skpx_is_near(&filter));

    /* Coming back into the band must NOT re-grant; it must reach near_dbm. */
    feed(&filter, -65, 5);
    check_true("does not re-grant inside the band", !skpx_is_near(&filter));

    feed(&filter, -55, 5);
    check_true("re-grants once genuinely near again", skpx_is_near(&filter));
}

static void test_proximity_boundaries(void)
{
    skpx_filter_t filter = make_filter();

    /* Exactly at the near threshold counts as near (>=). */
    feed(&filter, -60, 3);
    check_true("exactly at near_dbm grants", skpx_is_near(&filter));

    /* Exactly at the far threshold is still inside the band (not < far). */
    skpx_filter_t band = make_filter();
    feed(&band, -50, 3);
    feed(&band, -72, 5);
    check_true("exactly at far_dbm holds", skpx_is_near(&band));

    feed(&band, -73, 5);
    check_true("one dB below far_dbm releases", !skpx_is_near(&band));
}

static void test_proximity_reset_and_config(void)
{
    skpx_filter_t filter = make_filter();
    feed(&filter, -40, 5);
    check_true("near before reset", skpx_is_near(&filter));

    skpx_reset(&filter);
    check_true("reset clears the near state", !skpx_is_near(&filter));
    check_true("reset clears readiness", !skpx_ready(&filter));
    check_int("reset clears the median", skpx_median(&filter), SKPX_RSSI_UNKNOWN);
    /* Tuning must survive a reset. */
    feed(&filter, -40, 3);
    check_true("still usable after reset", skpx_is_near(&filter));

    /* Nonsense configuration must be clamped, never fatal. */
    const skpx_config_t bad = {
        .near_dbm = -80,
        .far_dbm = -50, /* inverted on purpose */
        .window = 200,  /* far beyond the buffer */
        .min_samples = 99,
    };
    skpx_filter_t clamped;
    skpx_init(&clamped, &bad);
    check_int("window clamped", clamped.cfg.window, SKPX_MAX_WINDOW);
    check_true("min_samples clamped to the window",
               clamped.cfg.min_samples <= clamped.cfg.window);
    check_true("inverted thresholds corrected", clamped.cfg.far_dbm <= clamped.cfg.near_dbm);

    feed(&clamped, -70, SKPX_MAX_WINDOW);
    check_true("clamped filter still decides", skpx_is_near(&clamped));

    /* NULL handling must be total. */
    check_true("null is never near", !skpx_is_near(NULL));
    check_true("null is never ready", !skpx_ready(NULL));
    check_int("null median", skpx_median(NULL), SKPX_RSSI_UNKNOWN);
    check_true("null add is safe", !skpx_add_sample(NULL, -40));
    skpx_init(NULL, &bad);
    skpx_reset(NULL);
}

static void test_proximity_walk_up(void)
{
    /* A realistic approach: noisy far samples, then a steady close hold. */
    const int8_t approach[] = {-92, -88, -95, -84, -81, -77, -70, -62, -55, -48, -45, -44};
    skpx_filter_t filter = make_filter();

    bool granted_early = false;
    for (size_t i = 0; i < sizeof(approach) / sizeof(approach[0]); i++) {
        skpx_add_sample(&filter, approach[i]);
        /* Nothing in the far half of the walk should ever grant. */
        if (i < 7 && skpx_is_near(&filter)) {
            granted_early = true;
        }
    }
    check_true("no grant while still far away", !granted_early);
    check_true("granted once at the door", skpx_is_near(&filter));

    /* Walking away again must release. */
    const int8_t leaving[] = {-58, -68, -78, -86, -90, -93};
    for (size_t i = 0; i < sizeof(leaving) / sizeof(leaving[0]); i++) {
        skpx_add_sample(&filter, leaving[i]);
    }
    check_true("released after walking away", !skpx_is_near(&filter));
}

/* ----------------------------------------------- post-unlock re-arm */

static skra_config_t rearm_cfg(void)
{
    const skra_config_t cfg = {
        .depart_dbm = -75,
        .absent_ms = 3000,
        .max_hold_ms = 60000,
    };
    return cfg;
}

/**
 * After the door opens the unit goes idle, but the phone that opened it is
 * still standing at the reader. The hold is what stops the scanner simply
 * reconnecting and relighting the LED a few hundred milliseconds later.
 */
static void test_rearm_basics(void)
{
    printf("\n-- post-unlock re-arm --\n");
    skra_t ra;
    const skra_config_t cfg = rearm_cfg();
    skra_init(&ra, &cfg);

    check_true("not holding before an unlock", !skra_blocked(&ra, 1000));

    skra_hold(&ra, 1000);
    check_true("holds immediately after the unlock", skra_blocked(&ra, 1000));

    /* The user is still at the door: strong signal, still refused. This is
     * the case a naive "just disconnect" implementation gets wrong. */
    skra_observe(&ra, 1200, -55);
    check_true("still held while the phone is at the door",
               skra_blocked(&ra, 1200));
    skra_observe(&ra, 1500, -50);
    check_true("still held after several close sightings",
               skra_blocked(&ra, 1500));
}

static void test_rearm_releases_on_departure(void)
{
    skra_t ra;
    const skra_config_t cfg = rearm_cfg();
    skra_init(&ra, &cfg);
    skra_hold(&ra, 1000);

    skra_observe(&ra, 1200, -60); /* still close */
    check_true("held at -60", skra_blocked(&ra, 1200));

    skra_observe(&ra, 2000, -80); /* walked away */
    check_true("released once seen far away", !skra_blocked(&ra, 2000));

    /* And a genuine second approach works straight away, with no timer. */
    check_true("re-approach is allowed immediately", !skra_blocked(&ra, 2100));
}

static void test_rearm_releases_on_absence(void)
{
    skra_t ra;
    const skra_config_t cfg = rearm_cfg();
    skra_init(&ra, &cfg);
    skra_hold(&ra, 1000);

    /* The usual case: the user walks through the door and the phone stops
     * being seen entirely, so there are no advertisements to react to. */
    check_true("held just before the absence timeout", skra_blocked(&ra, 3999));
    check_true("released after the absence timeout", !skra_blocked(&ra, 4000));
}

static void test_rearm_absence_timer_is_refreshed(void)
{
    skra_t ra;
    const skra_config_t cfg = rearm_cfg();
    skra_init(&ra, &cfg);
    skra_hold(&ra, 1000);

    /* Lingering at the door keeps refreshing the sighting, so the absence
     * rule must not fire while the user is demonstrably still present. */
    skra_observe(&ra, 2500, -55);
    check_true("absence does not fire while still being seen",
               skra_blocked(&ra, 4000));
    skra_observe(&ra, 5000, -55);
    check_true("still held after more close sightings", skra_blocked(&ra, 6000));
    check_true("released once sightings finally stop", !skra_blocked(&ra, 8001));
}

static void test_rearm_max_hold_cap(void)
{
    skra_t ra;
    const skra_config_t cfg = rearm_cfg();
    skra_init(&ra, &cfg);
    skra_hold(&ra, 0);

    /* A phone left lying next to the reader: always seen, always close, so
     * neither departure nor absence will ever fire. The cap must stop this
     * locking the user out permanently. */
    for (int64_t t = 0; t < 60000; t += 500) {
        skra_observe(&ra, t, -50);
    }
    check_true("still held just before the cap", skra_blocked(&ra, 59999));
    check_true("cap releases the hold", !skra_blocked(&ra, 60000));
}

static void test_rearm_boundaries_and_config(void)
{
    skra_t ra;
    skra_config_t cfg = rearm_cfg();
    skra_init(&ra, &cfg);
    skra_hold(&ra, 1000);

    /* depart_dbm is exclusive: exactly at the threshold is still "here". */
    skra_observe(&ra, 1100, -75);
    check_true("exactly at depart_dbm stays held", skra_blocked(&ra, 1100));
    skra_observe(&ra, 1200, -76);
    check_true("one dB below depart_dbm releases", !skra_blocked(&ra, 1200));

    /* Absence disabled: only departure or the cap can release. */
    cfg.absent_ms = 0;
    skra_init(&ra, &cfg);
    skra_hold(&ra, 0);
    check_true("absence disabled keeps the hold", skra_blocked(&ra, 30000));
    check_true("cap still applies", !skra_blocked(&ra, 60000));

    /* Nonsense configuration must be clamped, never fatal. */
    skra_config_t bad = {.depart_dbm = 50, .absent_ms = 1000, .max_hold_ms = 99999999};
    skra_init(&ra, &bad);
    skra_hold(&ra, 0);
    skra_observe(&ra, 100, -90);
    check_true("clamped config still releases on departure",
               !skra_blocked(&ra, 100));

    /* NULL safety. */
    check_true("null is never blocking", !skra_blocked(NULL, 0));
    skra_hold(NULL, 0);
    skra_observe(NULL, 0, -50);
    skra_clear(NULL);
    skra_init(NULL, &cfg);
    check_true("null calls are safe", true);
}

static void test_rearm_clear(void)
{
    skra_t ra;
    const skra_config_t cfg = rearm_cfg();
    skra_init(&ra, &cfg);
    skra_hold(&ra, 1000);
    check_true("held before clear", skra_blocked(&ra, 1000));

    /* Re-pairing or revoking must not leave a phone locked out. */
    skra_clear(&ra);
    check_true("clear releases the hold", !skra_blocked(&ra, 1000));
}

/** End to end: open the door, walk through, come back later. */
static void test_rearm_full_cycle(void)
{
    skra_t ra;
    const skra_config_t cfg = rearm_cfg();
    skra_init(&ra, &cfg);

    int64_t t = 0;
    skra_hold(&ra, t); /* door opens */

    /* Standing in the doorway for a second, phone still close. */
    for (int i = 0; i < 4; i++) {
        t += 250;
        skra_observe(&ra, t, -52);
        check_true("LED stays off while still in the doorway",
                   skra_blocked(&ra, t));
    }

    /* Walking away: signal fades. */
    t += 500;
    skra_observe(&ra, t, -78);
    check_true("re-armed once the user has left", !skra_blocked(&ra, t));

    /* Coming back later is a normal approach again. */
    t += 30000;
    check_true("later approach is not blocked", !skra_blocked(&ra, t));
}

int main(void)
{
    printf("=== SmartKey firmware protocol tests ===\n");
    test_hkdf();
    test_subkeys();
    test_pseudonyms();
    test_handshake_tags();
    test_ct_equal();
    test_frames();
    test_frame_errors();
    test_advertisement();
    test_door_beacon();
    test_pairing();
    test_proximity_basics();
    test_proximity_rejects_spikes();
    test_proximity_rejects_dropouts();
    test_proximity_hysteresis();
    test_proximity_boundaries();
    test_proximity_reset_and_config();
    test_proximity_walk_up();
    test_rearm_basics();
    test_rearm_releases_on_departure();
    test_rearm_releases_on_absence();
    test_rearm_absence_timer_is_refreshed();
    test_rearm_max_hold_cap();
    test_rearm_boundaries_and_config();
    test_rearm_clear();
    test_rearm_full_cycle();

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
