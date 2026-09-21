/**
 * @file pseudonym_table.h
 * @brief Rolling pseudonym lookup table (protocol-spec.md §2.2).
 *
 * For every paired user we precompute the pseudonyms of epochs e-2 .. e+2 once
 * per epoch, so matching an advertisement is a handful of 6 byte memcmps.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "smartkey_crypto.h"
#include "smartkey_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Rebuild the table for @p now_epoch. Cheap enough to call once per second. */
void skb_pseudo_rebuild(uint64_t now_epoch);

/** Force a rebuild on the next call, e.g. after pairing or revocation. */
void skb_pseudo_invalidate(void);

/**
 * @brief Look up an advertised pseudonym.
 * @param[out] out_slot credential slot of the match
 * @return true when the pseudonym belongs to a known, enabled user.
 */
bool skb_pseudo_match(const uint8_t pseudonym[SKP_PSEUDONYM_SIZE], size_t *out_slot);

#ifdef __cplusplus
}
#endif
