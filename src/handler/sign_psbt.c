/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2024 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>
#include <stdlib.h>

#include "lib_standard_app/crypto_helpers.h"

#include "../boilerplate/dispatcher.h"
#include "../boilerplate/sw.h"
#include "../common/bitvector.h"
#include "../common/merkle.h"
#include "../common/psbt.h"
#include "../common/read.h"
#include "../common/script.h"
#include "../common/varint.h"
#include "../common/wallet.h"
#include "../common/write.h"

#include "../commands.h"
#include "../constants.h"
#include "../crypto.h"
#include "../error_codes.h"
#include "../ui/display.h"
#include "../ui/menu.h"

#include "client_commands.h"

#include "lib/policy.h"
#include "lib/check_merkle_tree_sorted.h"
#include "lib/get_preimage.h"
#include "lib/get_merkleized_map.h"
#include "lib/get_merkleized_map_value.h"
#include "lib/get_merkle_leaf_element.h"
#include "lib/psbt_parse_rawtx.h"

#include "handlers.h"
#include "sign_psbt.h"
#include "sign_psbt/compare_wallet_script_at_path.h"
#include "sign_psbt/extract_bip32_derivation.h"
#include "sign_psbt/sign_psbt_cache.h"
#include "sign_psbt/update_hashes_with_map_value.h"

#include "../swap/swap_globals.h"
#include "../swap/handle_swap_sign_transaction.h"

#include "../common/segwit_addr.h"

/* BIP0341 tags for computing the tagged hashes when computing he sighash */
static const uint8_t BIP0341_sighash_tag[] = {'T', 'a', 'p', 'S', 'i', 'g', 'h', 'a', 's', 'h'};
static const uint8_t BIP0322_msghash_tag[] = {'B', 'I', 'P', '0', '3', '2', '2', '-',
                                              's', 'i', 'g', 'n', 'e', 'd', '-', 'm',
                                              'e', 's', 's', 'a', 'g', 'e'};
static void get_fee_from_desciptor(sign_psbt_state_t *st) {
    unsigned int cov_count = count_psbt_covenant_pk_state(st->psbt_covenant_pk_state);
    if (st->bbn_action_type == BBN_POLICY_UNBOND) {
        memcpy(&st->psbt_fee, st->psbt_covenant_pk[cov_count - 1], 8);
    } else if (st->bbn_action_type == BBN_POLICY_SLASHING ||
               st->bbn_action_type == BBN_POLICY_SLASHING_UNBONDING) {
        memcpy(&st->psbt_fee, st->psbt_covenant_pk[cov_count - 1], 8);
    } else {
        st->psbt_fee = 0;
    }
}
void bytes_to_ascii_hex(const uint8_t *input, size_t input_len, uint8_t *output) {
    const char hex_chars[] = "0123456789abcdef";

    for (size_t i = 0; i < input_len; ++i) {
        output[2 * i] = hex_chars[(input[i] >> 4) & 0x0F];  // high nibble
        output[2 * i + 1] = hex_chars[input[i] & 0x0F];     // low nibble
    }
}

static bool compute_bip322_txid_by_message(const uint8_t *address,
                                           size_t address_len,
                                           const uint8_t *tappub,
                                           const uint8_t *message_hash,
                                           uint8_t *txid_out,
                                           char *message_out,
                                           size_t *message_out_len) {
    uint8_t tx[] = {TX_PREFIX, TX_DUMMY_TXID, TX_MIDFIX, TX_DUMMY_TXID, TX_SUFFIX};
    cx_sha256_t sighash_context, txhash_context, txid_context;
    uint8_t hash[32];
    uint8_t converted_5bit[32 * 2] = {0};
    size_t datalen = 0;
    char address_str[128] = {0};
    uint8_t converted_message[256] = {0};
    char prefix[16] = {0};
    int32_t prefix_len = 0;

    crypto_tr_tagged_hash_init(&sighash_context, BIP0322_msghash_tag, sizeof(BIP0322_msghash_tag));
    prefix_len = address[MESSAGE_DATA_LEN];
    if (prefix_len > MAX_PREFIX_LEN) {
        PRINTF("prefix too long %d\n", prefix_len);
        return false;
    }

    convert_bits(converted_5bit, &datalen, 5, address, address_len, 8, 1);
    memcpy(prefix, address + MESSAGE_DATA_LEN + 1, prefix_len);
    prefix[prefix_len] = '\0';
    memset(address_str, 0, sizeof(address_str));
    bech32_encode(address_str,
                  (const char *) prefix,
                  converted_5bit,
                  datalen,
                  BECH32_ENCODING_BECH32);  // bech32 encode the message

    bool all_ff = true;
    uint32_t message_len = strlen(address_str);
    for (size_t i = 0; i < 32; ++i) {
        if (message_hash[i] != 0xFF) {
            all_ff = false;
            break;
        }
    }
    if (!all_ff) {
        PRINTF("message_hash is not all 0xff\n");
        bytes_to_ascii_hex(message_hash, 32, converted_message);
        memcpy(converted_message + 64, address_str, strlen(address_str));
        PRINTF_BUF(converted_message, 64 + strlen(address_str));
        message_len += 64;
    } else {
        memcpy(converted_message, address_str, strlen(address_str));
        PRINTF_BUF(converted_message, strlen(address_str));
    }

    crypto_hash_update(&sighash_context.header, converted_message, message_len);
    crypto_hash_digest(&sighash_context.header, hash, 32);
    memcpy(tx + OFFSET_MSG_HASH, hash, 32);
    memcpy(tx + OFFSET_PUBKEY, tappub, 32);

    cx_sha256_init(&txhash_context);
    crypto_hash_update(&txhash_context.header, tx, sizeof(tx));
    crypto_hash_digest(&txhash_context.header, hash, 32);
    cx_sha256_init(&txid_context);
    crypto_hash_update(&txid_context.header, hash, 32);
    crypto_hash_digest(&txid_context.header, txid_out, 32);

    if (*message_out_len < message_len) {
        PRINTF("message_out buffer too small\n");
        return false;
    }
    memcpy(message_out, converted_message, message_len);
    *message_out_len = message_len;
    return true;
}

static void bbn_leafhash_compute(uint8_t *tapscript, int tapscript_len, uint8_t *leafhash) {
    cx_sha256_t hash_context;
    crypto_tr_tapleaf_hash_init(&hash_context);
    crypto_hash_update_u8(&hash_context.header, 0xC0);
    crypto_hash_update_varint(&hash_context.header, tapscript_len);
    crypto_hash_update(&hash_context.header, tapscript, tapscript_len);
    crypto_hash_digest(&hash_context.header, leafhash, 32);
}

static void compute_bbn_leafhash_slasing(sign_psbt_state_t *st, uint8_t *leafhash) {
    uint8_t tapscript[1024] = {0};
    int offset = 0;

    tapscript[offset++] = 0x20;
    memcpy(tapscript + offset, st->psbt_staker_pk, 32);
    offset += 32;
    tapscript[offset++] = 0xad;
    tapscript[offset++] = 0x20;
    memcpy(tapscript + offset, st->psbt_finality_pk, 32);
    offset += 32;
    tapscript[offset++] = 0xad;

    unsigned int cov_count = count_psbt_covenant_pk_state(st->psbt_covenant_pk_state);
    if (cov_count < 3) {
        return;
    } else {
        if (st->bbn_action_type == BBN_POLICY_SLASHING ||
            st->bbn_action_type == BBN_POLICY_SLASHING_UNBONDING)
            cov_count = cov_count - 2;
        if (st->bbn_action_type == BBN_POLICY_UNBOND) cov_count = cov_count - 1;
    }
    for (unsigned int i = 0; i < cov_count; i++) {
        tapscript[offset++] = 0x20;
        memcpy(tapscript + offset, st->psbt_covenant_pk[i], 32);
        offset += 32;
        if (i == 0)
            tapscript[offset++] = 0xac;
        else
            tapscript[offset++] = 0xba;
    }

    tapscript[offset++] = 0x50 + st->psbt_quorum;
    tapscript[offset++] = 0x9c;

    // Compute leaf hash
    bbn_leafhash_compute(tapscript, offset, leafhash);
}

static void compute_bbn_leafhash_unbonding(sign_psbt_state_t *st, uint8_t *leafhash) {
    uint8_t tapscript[1024] = {0};
    int offset = 0;

    tapscript[offset++] = 0x20;
    memcpy(tapscript + offset, st->psbt_staker_pk, 32);
    offset += 32;
    tapscript[offset++] = 0xad;

    unsigned int cov_count = count_psbt_covenant_pk_state(st->psbt_covenant_pk_state);
    if (cov_count < 2) {
        return;
    } else {
        if (st->bbn_action_type != BBN_POLICY_STAKE_TRANSFER) cov_count = cov_count - 1;
    }
    for (unsigned int i = 0; i < cov_count; i++) {
        tapscript[offset++] = 0x20;
        memcpy(tapscript + offset, st->psbt_covenant_pk[i], 32);
        offset += 32;
        if (i == 0)
            tapscript[offset++] = 0xac;
        else
            tapscript[offset++] = 0xba;
    }

    tapscript[offset++] = 0x50 + st->psbt_quorum;
    tapscript[offset++] = 0x9c;

    // Compute leaf hash
    bbn_leafhash_compute(tapscript, offset, leafhash);
}

static int encode_minimal_push(uint32_t value, uint8_t *buffer) {
    if (value == 0) {
        buffer[0] = 0x00;
        return 1;
    }

    if (value >= 1 && value <= 15) {
        buffer[0] = 0x50 + value;
        return 1;
    }

    int size = 0;
    int is_negative = (value < 0);
    uint32_t abs_value = (is_negative) ? -value : value;

    while (abs_value) {
        buffer[size++] = abs_value & 0xFF;
        abs_value >>= 8;
    }

    if (buffer[size - 1] & 0x80) {
        buffer[size++] = is_negative ? 0x80 : 0x00;
    } else if (is_negative) {
        buffer[size - 1] |= 0x80;
    }

    return size;
}

static void compute_bbn_leafhash_timelock(sign_psbt_state_t *st, uint8_t *leafhash) {
    uint8_t tapscript[1024] = {0};
    int offset = 0;

    tapscript[offset++] = 0x20;
    memcpy(tapscript + offset, st->psbt_staker_pk, 32);
    offset += 32;
    tapscript[offset++] = 0xad;

    uint8_t value_buffer[4];
    int len = encode_minimal_push(st->psbt_timelock, value_buffer);
    if (st->psbt_timelock > 15) tapscript[offset++] = len;
    memcpy(tapscript + offset, value_buffer, len);
    offset += len;
    tapscript[offset++] = 0xb2;

    bbn_leafhash_compute(tapscript, offset, leafhash);
}

static void compute_bbn_merkle_root(sign_psbt_state_t *st, uint8_t *roothash) {
    uint8_t slashing_leafhash[32];
    uint8_t unbonding_leafhash[32];
    uint8_t timelock_leafhash[32];

    compute_bbn_leafhash_slasing(st, slashing_leafhash);
    compute_bbn_leafhash_unbonding(st, unbonding_leafhash);
    compute_bbn_leafhash_timelock(st, timelock_leafhash);

    uint8_t branch_hash[32];
    crypto_tr_combine_taptree_hashes(unbonding_leafhash, timelock_leafhash, branch_hash);

    crypto_tr_combine_taptree_hashes(slashing_leafhash, branch_hash, roothash);
}

static bool bbn_check_address(sign_psbt_state_t *st) {
    uint8_t tweaked_pubkey[34];
    uint8_t merkle_root[32];

    // to check uint32_t psbt_timelock here
    // if 0 or negative, return false
    // to advoid BBN-#04 Potential buffer overflow
    if (st->psbt_timelock == 0 || st->psbt_timelock > 0x7FFFFFFF) {
        PRINTF("timelock state is 0 or negtive\n");
        return false;
    }
    // Compute the merkle root
    compute_bbn_merkle_root(st, merkle_root);
    uint8_t parity;
    // Tweak the staker public key with the merkle root
    uint8_t NUMS_PUBKEY[] = {0x02, 0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b,
                             0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28,
                             0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0};
    if (crypto_tr_tweak_pubkey(NUMS_PUBKEY + 1, merkle_root, 32, &parity, tweaked_pubkey) != 0) {
        PRINTF("Failed to tweak public key\n");
        return false;
    }

    uint8_t out_scriptPubKey[MAX_OUTPUT_SCRIPTPUBKEY_LEN];
    size_t out_scriptPubKey_len;
    out_scriptPubKey_len = st->outputs.output_script_lengths[0];
    memcpy(out_scriptPubKey, st->outputs.output_scripts[0], out_scriptPubKey_len);

    if (memcmp(out_scriptPubKey + 2, tweaked_pubkey, 32)) {
        PRINTF("tweak public key cmp fail\n");
        PRINTF_BUF(tweaked_pubkey, 32);
        PRINTF_BUF(out_scriptPubKey + 2, 32);
        return false;
    }
    return true;
}

static bool bbn_check_slashing(sign_psbt_state_t *st) {
    uint8_t tweaked_pubkey[34];
    uint8_t merkle_root[32];

    get_fee_from_desciptor(st);
    uint64_t fee = st->inputs_total_amount - st->outputs.total_amount;
    if (fee < st->psbt_fee) {
        PRINTF("Fee too low\n");
        return false;
    }

    // Compute the merkle root
    compute_bbn_leafhash_timelock(st, merkle_root);
    uint8_t parity;
    // Tweak the staker public key with the merkle root
    uint8_t NUMS_PUBKEY[] = {0x02, 0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b,
                             0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28,
                             0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0};
    if (crypto_tr_tweak_pubkey(NUMS_PUBKEY + 1, merkle_root, 32, &parity, tweaked_pubkey) != 0) {
        PRINTF("Failed to tweak public key\n");
        PRINTF_BUF(tweaked_pubkey, 32);
        return false;
    }

    uint8_t out_scriptPubKey[MAX_OUTPUT_SCRIPTPUBKEY_LEN];
    size_t out_scriptPubKey_len;
    out_scriptPubKey_len = st->outputs.output_script_lengths[1];
    memcpy(out_scriptPubKey, st->outputs.output_scripts[1], out_scriptPubKey_len);

    // check the slashing output refund address
    if (memcmp(out_scriptPubKey + 2, tweaked_pubkey, 32)) {
        PRINTF("Slashing Tweaked public key:\n");
        PRINTF_BUF(tweaked_pubkey, 32);
        PRINTF("Slashing out_scriptPubKey_len 1: %d\n", out_scriptPubKey_len);
        PRINTF_BUF(out_scriptPubKey + 2, 32);
        PRINTF("tweak public key cmp fail\n");
        return false;
    }

    // check the burn address
    unsigned int cov_count = count_psbt_covenant_pk_state(st->psbt_covenant_pk_state);

    uint8_t *slashPkScript = st->psbt_covenant_pk[cov_count - 2];
    if (slashPkScript == NULL) {
        PRINTF("missing burn address null\n");
        return false;
    }
    if (memcmp(st->outputs.output_scripts[0], slashPkScript, 32)) {
        PRINTF("Slashing burn address:\n");
        PRINTF_BUF(slashPkScript, 32);
        PRINTF_BUF(st->outputs.output_scripts[0], 32);
        PRINTF("tweak public key cmp fail\n");
        return false;
    }
    // to check OP_return is the first byte of the burn address script
    // however, this is only for mainnet, not for testnet due to test data

    if (BIP32_PUBKEY_VERSION == BIP32_PUBKEY_MAINNET &&
        st->outputs.output_scripts[0][0] != OP_RETURN) {
        PRINTF("Burn address script is not OP_RETURN\n");
        return false;
    }
    return true;
}

static void compute_bbn_unbond_root(sign_psbt_state_t *st, uint8_t *roothash) {
    uint8_t slashing_leafhash[32];
    uint8_t timelock_leafhash[32];

    compute_bbn_leafhash_slasing(st, slashing_leafhash);
    compute_bbn_leafhash_timelock(st, timelock_leafhash);
    crypto_tr_combine_taptree_hashes(slashing_leafhash, timelock_leafhash, roothash);
}

static bool bbn_check_unbond(sign_psbt_state_t *st) {
    uint8_t tweaked_pubkey[34];
    uint8_t merkle_root[32];
    if (st->psbt_timelock == 0) {
        PRINTF("timelock state is 0\n");
        return false;
    }
    uint64_t fee = st->inputs_total_amount - st->outputs.total_amount;
    get_fee_from_desciptor(st);
    if (fee != st->psbt_fee) {
        PRINTF("unbond fee mismatch\n");
        return false;
    }
    compute_bbn_unbond_root(st, merkle_root);
    uint8_t parity;

    uint8_t NUMS_PUBKEY[] = {0x02, 0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b,
                             0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28,
                             0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0};

    if (crypto_tr_tweak_pubkey(NUMS_PUBKEY + 1, merkle_root, 32, &parity, tweaked_pubkey) != 0) {
        PRINTF("Failed to tweak public key\n");
        return false;
    }

    uint8_t out_scriptPubKey[MAX_OUTPUT_SCRIPTPUBKEY_LEN];
    size_t out_scriptPubKey_len;
    out_scriptPubKey_len = st->outputs.output_script_lengths[0];
    memcpy(out_scriptPubKey, st->outputs.output_scripts[0], out_scriptPubKey_len);

    if (memcmp(out_scriptPubKey + 2, tweaked_pubkey, 32)) {
        PRINTF("Tweaked public key:\n");
        // PRINTF_BUF(tweaked_pubkey, 32);
        PRINTF("out_scriptPubKey_len: %d\n", out_scriptPubKey_len);
        // PRINTF_BUF(out_scriptPubKey + 2, 32);
        PRINTF("bbn_check_unbond tweak public key cmp fail\n");
        return false;
    }
    return true;
}

static bool bbn_check_and_display_message(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    uint8_t txid[32];
    char message_str[128] = {0};
    size_t message_str_len = 128;

    memset(txid, 0, 32);
    memset(message_str, 0, 128);

    if (!compute_bip322_txid_by_message(st->psbt_leafhash + 1,
                                        st->psbt_leafhash_state,
                                        st->psbt_finality_pk,
                                        st->psbt_message_hash,
                                        txid,
                                        message_str,
                                        &message_str_len)) {
        PRINTF("compute_bip322_txid_by_message failed\n");
        SEND_SW(dc, SW_DENY);
        return false;
    }

    if (memcmp(txid, st->psbt_staker_pk, 32) != 0) {
        PRINTF("txid\n");
        PRINTF_BUF(txid, 32);
        PRINTF("st->psbt_staker_pk\n");
        PRINTF_BUF(st->psbt_staker_pk, 32);
        SEND_SW(dc, SW_DENY);
        return false;
    }

    if (!ui_confirm_bbn_message(dc, message_str, "message")) {
        PRINTF("message_str %s\n", message_str);
        SEND_SW(dc, SW_DENY);
        return false;
    }
    return true;
}

/*
Current assumptions during signing:
  1) exactly one of the keys in the wallet is internal (enforce during wallet registration)
  2) all the keys in the wallet have a wildcard (that is, they end with '**'), with at most
     4 derivation steps before it.

Assumption 2 simplifies the handling of pubkeys (and their paths) used for signing,
as all the internal keys will have a path that ends with /change/address_index (BIP44-style).

It would be possible to generalize to more complex scripts, but it makes it more difficult to detect
the right paths to identify internal inputs/outputs.
*/

// HELPER FUNCTIONS
// Updates the hash_context with the output of given index
// returns -1 on error. 0 on success.
static int hash_output_n(dispatcher_context_t *dc,
                         sign_psbt_state_t *st,
                         cx_hash_t *hash_context,
                         unsigned int index) {
    if (index >= st->n_outputs) {
        return -1;
    }

    // get this output's map
    merkleized_map_commitment_t ith_map;

    int res = call_get_merkleized_map(dc, st->outputs_root, st->n_outputs, index, &ith_map);
    if (res < 0) {
        return -1;
    }
    // get output's amount
    uint8_t amount_raw[8];
    if (8 != call_get_merkleized_map_value(dc,
                                           &ith_map,
                                           (uint8_t[]){PSBT_OUT_AMOUNT},
                                           1,
                                           amount_raw,
                                           8)) {
        return -1;
    }

    crypto_hash_update(hash_context, amount_raw, 8);

    // get output's scriptPubKey

    uint8_t out_script[MAX_OUTPUT_SCRIPTPUBKEY_LEN];
    int out_script_len = call_get_merkleized_map_value(dc,
                                                       &ith_map,
                                                       (uint8_t[]){PSBT_OUT_SCRIPT},
                                                       1,
                                                       out_script,
                                                       sizeof(out_script));
    if (out_script_len == -1) {
        return -1;
    }

    crypto_hash_update_varint(hash_context, out_script_len);
    crypto_hash_update(hash_context, out_script, out_script_len);
    return 0;
}

// Updates the hash_context with the network serialization of all the outputs
// returns -1 on error. 0 on success.
static int hash_outputs(dispatcher_context_t *dc, sign_psbt_state_t *st, cx_hash_t *hash_context) {
    for (unsigned int i = 0; i < st->n_outputs; i++) {
        if (hash_output_n(dc, st, hash_context, i)) {
            return -1;
        }
    }
    return 0;
}

/*
 Convenience function to get the amount and scriptpubkey from the non-witness-utxo of a certain
 input in a PSBTv2.
 If expected_prevout_hash is not NULL, the function fails if the txid computed from the
 non-witness-utxo does not match the one pointed by expected_prevout_hash. Returns -1 on failure, 0
 on success.
*/
static int __attribute__((noinline)) get_amount_scriptpubkey_from_psbt_nonwitness(
    dispatcher_context_t *dc,
    const merkleized_map_commitment_t *input_map,
    uint64_t *amount,
    uint8_t scriptPubKey[static MAX_PREVOUT_SCRIPTPUBKEY_LEN],
    size_t *scriptPubKey_len,
    const uint8_t *expected_prevout_hash) {
    // If there is no witness-utxo, it must be the case that this is a legacy input.
    // In this case, we can only retrieve the prevout amount and scriptPubKey by parsing
    // the non-witness-utxo

    // Read the prevout index
    uint32_t prevout_n;
    if (4 != call_get_merkleized_map_value_u32_le(dc,
                                                  input_map,
                                                  (uint8_t[]){PSBT_IN_OUTPUT_INDEX},
                                                  1,
                                                  &prevout_n)) {
        return -1;
    }

    txid_parser_outputs_t parser_outputs;
    // request non-witness utxo, and get the prevout's value and scriptpubkey
    int res = call_psbt_parse_rawtx(dc,
                                    input_map,
                                    (uint8_t[]){PSBT_IN_NON_WITNESS_UTXO},
                                    1,
                                    prevout_n,
                                    &parser_outputs);
    if (res < 0) {
        PRINTF("Parsing rawtx failed\n");
        return -1;
    }

    // if expected_prevout_hash is given, check that it matches the txid obtained from the parser
    if (expected_prevout_hash != NULL &&
        memcmp(parser_outputs.txid, expected_prevout_hash, 32) != 0) {
        PRINTF("Prevout hash did not match non-witness-utxo transaction hash\n");

        return -1;
    }

    *amount = parser_outputs.vout_value;
    *scriptPubKey_len = parser_outputs.vout_scriptpubkey_len;
    memcpy(scriptPubKey, parser_outputs.vout_scriptpubkey, parser_outputs.vout_scriptpubkey_len);

    return 0;
}

/*
 Convenience function to get the amount and scriptpubkey from the witness-utxo of a certain input in
 a PSBTv2.
 Returns -1 on failure, 0 on success.
*/
static int __attribute__((noinline))
get_amount_scriptpubkey_from_psbt_witness(dispatcher_context_t *dc,
                                          const merkleized_map_commitment_t *input_map,
                                          uint64_t *amount,
                                          uint8_t scriptPubKey[static MAX_PREVOUT_SCRIPTPUBKEY_LEN],
                                          size_t *scriptPubKey_len) {
    uint8_t raw_witnessUtxo[8 + 1 + MAX_PREVOUT_SCRIPTPUBKEY_LEN];

    int wit_utxo_len = call_get_merkleized_map_value(dc,
                                                     input_map,
                                                     (uint8_t[]){PSBT_IN_WITNESS_UTXO},
                                                     1,
                                                     raw_witnessUtxo,
                                                     sizeof(raw_witnessUtxo));

    if (wit_utxo_len < 0) {
        return -1;
    }
    int wit_utxo_scriptPubkey_len = raw_witnessUtxo[8];

    if (wit_utxo_len != 8 + 1 + wit_utxo_scriptPubkey_len) {
        PRINTF("Length mismatch for witness utxo's scriptPubKey\n");
        return -1;
    }

    uint8_t *wit_utxo_scriptPubkey = raw_witnessUtxo + 9;
    uint64_t wit_utxo_prevout_amount = read_u64_le(&raw_witnessUtxo[0], 0);

    *amount = wit_utxo_prevout_amount;
    *scriptPubKey_len = wit_utxo_scriptPubkey_len;
    memcpy(scriptPubKey, wit_utxo_scriptPubkey, wit_utxo_scriptPubkey_len);
    return 0;
}

/*
 Convenience function to get the amount and scriptpubkey of a certain input in a PSBTv2.
 It first tries to obtain it from the witness-utxo field; in case of failure, it then obtains it
 from the non-witness-utxo.
 Returns -1 on failure, 0 on success.
*/
static int get_amount_scriptpubkey_from_psbt(
    dispatcher_context_t *dc,
    const merkleized_map_commitment_t *input_map,
    uint64_t *amount,
    uint8_t scriptPubKey[static MAX_PREVOUT_SCRIPTPUBKEY_LEN],
    size_t *scriptPubKey_len) {
    int ret = get_amount_scriptpubkey_from_psbt_witness(dc,
                                                        input_map,
                                                        amount,
                                                        scriptPubKey,
                                                        scriptPubKey_len);
    if (ret >= 0) {
        return ret;
    }

    return get_amount_scriptpubkey_from_psbt_nonwitness(dc,
                                                        input_map,
                                                        amount,
                                                        scriptPubKey,
                                                        scriptPubKey_len,
                                                        NULL);
}

typedef struct {
    uint32_t fingerprint;
    size_t derivation_len;
    uint32_t key_origin[MAX_BIP32_PATH_STEPS];
} derivation_info_t;

// Convenience function to share common logic when parsing the
// PSBT_{IN|OUT}_{TAP}?_BIP32_DERIVATION fields from inputs or outputs.
// Note: This function must return -1 only on errors (causing signing to abort).
//       It returns 1 if a that might match the wallet policy is found.
//       It returns 0 otherwise (not a match, but continue the signing flow).
static int read_change_and_index_from_psbt_bip32_derivation(
    dispatcher_context_t *dc,
    int psbt_key_type,
    buffer_t *data,
    const merkleized_map_commitment_t *map_commitment,
    int index,
    derivation_info_t *derivation_info) {
    uint8_t bip32_derivation_pubkey[33];

    bool is_tap = psbt_key_type == PSBT_IN_TAP_BIP32_DERIVATION ||
                  psbt_key_type == PSBT_OUT_TAP_BIP32_DERIVATION;
    int key_len = is_tap ? 32 : 33;

    if (!buffer_read_bytes(data,
                           bip32_derivation_pubkey,
                           key_len)  // read compressed pubkey or x-only pubkey
        || buffer_can_read(data, 1)  // ...but should not be able to read more
    ) {
        PRINTF("Unexpected pubkey length\n");
        return -1;
    }

    // get the corresponding value in the values Merkle tree,
    // then fetch the bip32 path from the field
    uint32_t fpt_der[1 + MAX_BIP32_PATH_STEPS];

    int der_len = extract_bip32_derivation(dc,
                                           psbt_key_type,
                                           map_commitment->values_root,
                                           map_commitment->size,
                                           index,
                                           fpt_der);
    if (der_len < 0) {
        PRINTF("Failed to read BIP32_DERIVATION\n");
        return -1;
    }

    if (der_len < 2 || der_len > MAX_BIP32_PATH_STEPS) {
        PRINTF("BIP32_DERIVATION path too long\n");
        return 0;
    }

    derivation_info->fingerprint = fpt_der[0];
    for (int i = 0; i < der_len; i++) {
        derivation_info->key_origin[i] = fpt_der[i + 1];
    }
    derivation_info->derivation_len = der_len;

    return 1;
}

bool is_keyexpr_compatible_with_derivation_info(const keyexpr_info_t *keyexpr_info,
                                                const derivation_info_t *derivation_info) {
    if (keyexpr_info->fingerprint != derivation_info->fingerprint) {
        return false;
    }
    if (keyexpr_info->psbt_root_key_derivation_length + 2 != derivation_info->derivation_len) {
        return false;
    }
    for (int i = 0; i < keyexpr_info->psbt_root_key_derivation_length; i++) {
        if (keyexpr_info->key_derivation[i] != derivation_info->key_origin[i]) {
            return false;
        }
    }
    uint32_t change_step = derivation_info->key_origin[derivation_info->derivation_len - 2];
    if (change_step != keyexpr_info->key_expression_ptr->num_first &&
        change_step != keyexpr_info->key_expression_ptr->num_second) {
        return false;
    }
    return true;
}

/**
 * Verifies if a certain input/output is internal (that is, controlled by the wallet being used for
 * signing). This uses the state of sign_psbt and is not meant as a general-purpose function;
 * rather, it avoids some substantial code duplication and removes complexity from sign_psbt.
 *
 * @return 1 if the given input/output is internal; 0 if external; -1 on error.
 */
static int is_in_out_internal(dispatcher_context_t *dispatcher_context,
                              const sign_psbt_state_t *state,
                              sign_psbt_cache_t *sign_psbt_cache,
                              const in_out_info_t *in_out_info,
                              bool is_input) {
    // If we did not find any info about the pubkey associated to the key expression we're
    // considering, then it's external
    if (!in_out_info->key_expression_found) {
        return 0;
    }

    if (!is_input && in_out_info->is_change != 1) {
        // unlike for inputs, we only consider outputs internal if they are on the change path
        return 0;
    }
    return compare_wallet_script_at_path(dispatcher_context,
                                         sign_psbt_cache,
                                         in_out_info->is_change,
                                         in_out_info->address_index,
                                         state->wallet_policy_map,
                                         state->wallet_header.version,
                                         state->wallet_header.keys_info_merkle_root,
                                         state->wallet_header.n_keys,
                                         in_out_info->scriptPubKey,
                                         in_out_info->scriptPubKey_len);
}

static bool __attribute__((noinline))
init_global_state(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    merkleized_map_commitment_t global_map;
    if (!buffer_read_varint(&dc->read_buffer, &global_map.size)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return false;
    }

    if (!buffer_read_bytes(&dc->read_buffer, global_map.keys_root, 32) ||
        !buffer_read_bytes(&dc->read_buffer, global_map.values_root, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return false;
    }

    // we already know n_inputs and n_outputs, so we skip reading from the global map

    uint64_t n_inputs_u64;
    if (!buffer_read_varint(&dc->read_buffer, &n_inputs_u64) ||
        !buffer_read_bytes(&dc->read_buffer, st->inputs_root, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return false;
    }

    if (n_inputs_u64 > MAX_N_INPUTS_CAN_SIGN) {
        PRINTF("At most %d inputs are supported\n", MAX_N_INPUTS_CAN_SIGN);
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return false;
    }
    st->n_inputs = (unsigned int) n_inputs_u64;

    uint64_t n_outputs_u64;
    if (!buffer_read_varint(&dc->read_buffer, &n_outputs_u64) ||
        !buffer_read_bytes(&dc->read_buffer, st->outputs_root, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return false;
    }
    st->n_outputs = (unsigned int) n_outputs_u64;

    uint8_t wallet_hmac[32];
    uint8_t wallet_id[32];
    if (!buffer_read_bytes(&dc->read_buffer, wallet_id, 32) ||
        !buffer_read_bytes(&dc->read_buffer, wallet_hmac, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return false;
    }

    {  // process global map
        // Check integrity of the global map
        if (call_check_merkle_tree_sorted(dc, global_map.keys_root, (size_t) global_map.size) < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t raw_result[9];  // max size for a varint
        int result_len;

        // Read tx version
        result_len = call_get_merkleized_map_value(dc,
                                                   &global_map,
                                                   (uint8_t[]){PSBT_GLOBAL_TX_VERSION},
                                                   1,
                                                   raw_result,
                                                   sizeof(raw_result));
        if (result_len != 4) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        st->tx_version = read_u32_le(raw_result, 0);

        // Read fallback locktime.
        // Unlike BIP-0370 recommendation, we use the fallback locktime as-is, ignoring each input's
        // preferred height/block locktime. If that's relevant, the client must set the fallback
        // locktime to the appropriate value before calling sign_psbt.
        result_len = call_get_merkleized_map_value(dc,
                                                   &global_map,
                                                   (uint8_t[]){PSBT_GLOBAL_FALLBACK_LOCKTIME},
                                                   1,
                                                   raw_result,
                                                   sizeof(raw_result));
        if (result_len == -1) {
            st->locktime = 0;
        } else if (result_len != 4) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        } else {
            st->locktime = read_u32_le(raw_result, 0);
        }
    }

    st->is_wallet_default = false;

    {
        // Fetch the serialized wallet policy from the client
        uint8_t serialized_wallet_policy[MAX_WALLET_POLICY_SERIALIZED_LENGTH];
        int serialized_wallet_policy_len = call_get_preimage(dc,
                                                             wallet_id,
                                                             serialized_wallet_policy,
                                                             sizeof(serialized_wallet_policy));
        if (serialized_wallet_policy_len < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        buffer_t serialized_wallet_policy_buf =
            buffer_create(serialized_wallet_policy, serialized_wallet_policy_len);

        uint8_t policy_map_descriptor[MAX_DESCRIPTOR_TEMPLATE_LENGTH];

        int desc_temp_len = read_and_parse_wallet_policy(dc,
                                                         st,
                                                         &serialized_wallet_policy_buf,
                                                         &st->wallet_header,
                                                         policy_map_descriptor,
                                                         st->wallet_policy_map_bytes,
                                                         MAX_WALLET_POLICY_BYTES,
                                                         true);
        if (desc_temp_len < 0) {
            PRINTF("Failed to read or parse wallet policy");
            SEND_SW(dc, SW_SECURITY_STATUS_NOT_SATISFIED);
            return false;
        }

        st->wallet_policy_map = (policy_node_t *) st->wallet_policy_map_bytes;
        // chester: to check the policy later
        if (st->is_wallet_default) {
            // No hmac, verify that the policy is indeed a default one
            if (!is_wallet_policy_standard(dc, &st->wallet_header, st->wallet_policy_map)) {
                PRINTF("Non-standard policy, and no hmac provided\n");
                SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_MISSING_HMAC_FOR_NONDEFAULT_POLICY);
                return false;
            }

            if (st->wallet_header.name_len != 0) {
                PRINTF("Name must be zero-length for a standard wallet policy\n");
                SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_NO_NAME_FOR_DEFAULT_POLICY);
                return false;
            }

            // unlike in get_wallet_address, we do not check if the address_index is small:
            // if funds were already sent there, there is no point in preventing to spend them.
        }
    }

    st->master_key_fingerprint = crypto_get_master_key_fingerprint();
    return true;
}

static bool __attribute__((noinline)) get_and_verify_key_info(dispatcher_context_t *dc,
                                                              sign_psbt_state_t *st,
                                                              uint16_t key_index,
                                                              keyexpr_info_t *keyexpr_info) {
    policy_map_key_info_t key_info;
    uint8_t key_info_str[MAX_POLICY_KEY_INFO_LEN];

    int key_info_len = call_get_merkle_leaf_element(dc,
                                                    st->wallet_header.keys_info_merkle_root,
                                                    st->wallet_header.n_keys,
                                                    key_index,
                                                    key_info_str,
                                                    sizeof(key_info_str));
    if (key_info_len < 0) {
        return false;  // should never happen
    }

    // Make a sub-buffer for the pubkey info
    buffer_t key_info_buffer = buffer_create(key_info_str, key_info_len);

    if (parse_policy_map_key_info(&key_info_buffer, &key_info, st->wallet_header.version) == -1) {
        PRINTF("parse_policy_map_key_info fail\n");
        return false;  // should never happen
    }

    keyexpr_info->key_derivation_length = key_info.master_key_derivation_len;
    for (int i = 0; i < key_info.master_key_derivation_len; i++) {
        keyexpr_info->key_derivation[i] = key_info.master_key_derivation[i];
    }

    keyexpr_info->fingerprint = read_u32_be(key_info.master_key_fingerprint, 0);

    memcpy(&keyexpr_info->pubkey, &key_info.ext_pubkey, sizeof(serialized_extended_pubkey_t));

    // chester
    if (get_fingerprint(key_info.master_key_fingerprint) == FP_FINALITY_PUB) {
        st->psbt_finality_pk_state = FP_FINALITY_PUB;
        memcpy(st->psbt_finality_pk, keyexpr_info->pubkey.compressed_pubkey + 1, 32);
    }
    // to make data in key infos to psbt leaf hash
    if (st->psbt_leafhash_state == BBN_LEAF_HASH_NULL) {
        // only get leafhash when handler not receive yet
        if (get_fingerprint(key_info.master_key_fingerprint) == FP_LEAF_HASH_DISPLY) {
            st->psbt_leafhash_state = BBN_LEAF_HASH_DISPALY;

        } else if (get_fingerprint(key_info.master_key_fingerprint) == FP_LEAF_HASH_CHECK) {
            st->psbt_leafhash_state = BBN_LEAF_HASH_CHECK;
        }
        if (st->psbt_leafhash_state == BBN_LEAF_HASH_DISPALY ||
            st->psbt_leafhash_state == BBN_LEAF_HASH_CHECK) {
            memcpy(st->psbt_leafhash, keyexpr_info->pubkey.compressed_pubkey + 1, 32);
        }
    }
    if (get_fingerprint(key_info.master_key_fingerprint) == FP_BIP322_MESSAGE) {
        memcpy(st->psbt_leafhash,
               keyexpr_info->pubkey.compressed_pubkey + 1,
               32);  // reuse for save memoroy
        st->psbt_leafhash_state = st->psbt_leafhash[0];
    }
    if (get_fingerprint(key_info.master_key_fingerprint) == FP_BIP322_TAPPUB) {
        memcpy(st->psbt_finality_pk,
               keyexpr_info->pubkey.compressed_pubkey + 1,
               32);  // reuse for save memoroy
    }
    if (get_fingerprint(key_info.master_key_fingerprint) == FP_BIP322_HASH) {
        memcpy(st->psbt_message_hash,
               keyexpr_info->pubkey.compressed_pubkey + 1,
               32);  // reuse for save memoroy
    }

    // it could be a collision on the fingerprint; we verify that we can actually generate
    // the same pubkey
    serialized_extended_pubkey_t derived_pubkey;

    if (0 > get_extended_pubkey_at_path(key_info.master_key_derivation,
                                        key_info.master_key_derivation_len,
                                        BIP32_PUBKEY_VERSION,
                                        &derived_pubkey)) {
        PRINTF("get_extended_pubkey_at_path false\n");
        return false;
    }

    if (memcmp(&key_info.ext_pubkey, &derived_pubkey, sizeof(derived_pubkey)) != 0) {
        // PRINTF_BUF(&keyexpr_info->pubkey.compressed_pubkey, 33);
        // PRINTF_BUF(&derived_pubkey.compressed_pubkey, 33);
        return false;
    }

    return true;
}

static bool fill_keyexpr_info_if_internal(dispatcher_context_t *dc,
                                          sign_psbt_state_t *st,
                                          keyexpr_info_t *keyexpr_info) {
    keyexpr_info_t tmp_keyexpr_info;
    // preserve the fields that are already computed outside of this function
    memcpy(&tmp_keyexpr_info, keyexpr_info, sizeof(keyexpr_info_t));

    if (keyexpr_info->key_expression_ptr->type == KEY_EXPRESSION_NORMAL) {
        bool result = get_and_verify_key_info(dc,
                                              st,
                                              keyexpr_info->key_expression_ptr->k.key_index,
                                              &tmp_keyexpr_info);
        if (result) {
            memcpy(keyexpr_info, &tmp_keyexpr_info, sizeof(keyexpr_info_t));
            memcpy(&keyexpr_info->internal_pubkey,
                   &keyexpr_info->pubkey,
                   sizeof(serialized_extended_pubkey_t));
            keyexpr_info->psbt_root_key_derivation_length = keyexpr_info->key_derivation_length;
        }
        return result;
    } else {
        LEDGER_ASSERT(false, "Unsupported key expression type");
        return false;
    }
}

typedef struct {
    sign_psbt_state_t *state;
    input_info_t *input;
} input_keys_callback_data_t;

/**
 * Callback to process all the keys of the current input map.
 * Keeps track if the current input has a witness_utxo and/or a redeemScript.
 */
static void input_keys_callback(dispatcher_context_t *dc,
                                input_keys_callback_data_t *callback_data,
                                const merkleized_map_commitment_t *map_commitment,
                                int index,
                                buffer_t *data) {
    size_t data_len = data->size - data->offset;
    if (data_len >= 1) {
        uint8_t key_type;
        buffer_read_u8(data, &key_type);
        if (key_type == PSBT_IN_WITNESS_UTXO) {
            callback_data->input->has_witnessUtxo = true;
        } else if (key_type == PSBT_IN_NON_WITNESS_UTXO) {
            callback_data->input->has_nonWitnessUtxo = true;
        } else if (key_type == PSBT_IN_REDEEM_SCRIPT) {
            callback_data->input->has_redeemScript = true;
        } else if (key_type == PSBT_IN_SIGHASH_TYPE) {
            callback_data->input->has_sighash_type = true;
        } else if (key_type == PSBT_IN_BIP32_DERIVATION ||
                   key_type == PSBT_IN_TAP_BIP32_DERIVATION) {
            derivation_info_t derivation_info;
            int res = read_change_and_index_from_psbt_bip32_derivation(dc,
                                                                       key_type,
                                                                       data,
                                                                       map_commitment,
                                                                       index,
                                                                       &derivation_info);
            if (res < 0) {
                // there was an error; we keep track of it so an error SW is sent later
                callback_data->input->in_out.unexpected_pubkey_error = true;
            } else if (res == 0) {
                // nothing to do
            } else if (res == 1) {
                in_out_info_t *in_out = &callback_data->input->in_out;
                for (size_t i = 0; i < callback_data->state->n_internal_key_expressions; i++) {
                    keyexpr_info_t *key_expr = &callback_data->state->internal_key_expressions[i];
                    if (is_keyexpr_compatible_with_derivation_info(key_expr, &derivation_info)) {
                        key_expr->to_sign = true;

                        bool is_change =
                            key_expr->key_expression_ptr->num_second ==
                            derivation_info.key_origin[derivation_info.derivation_len - 2];

                        in_out->key_expression_found = true;
                        in_out->is_change = is_change;
                        in_out->address_index =
                            derivation_info.key_origin[derivation_info.derivation_len - 1];
                    }
                }
            } else {
                LEDGER_ASSERT(false, "Unreachable code");
            }
        } else if (key_type == PSBT_IN_MUSIG2_PUB_NONCE) {
            callback_data->state->has_musig2_pub_nonces = true;
        }
    }
}

static bool fill_internal_key_expressions(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    size_t cur_index = 0;

    st->n_internal_key_expressions = 0;
    memset(st->internal_key_expressions, 0, sizeof(st->internal_key_expressions));

    // find and parse our registered key info in the wallet
    keyexpr_info_t keyexpr_info;
    memset(&keyexpr_info, 0, sizeof(keyexpr_info_t));
    while (true) {
        keyexpr_info.index = cur_index;
        const policy_node_t *tapleaf_ptr = NULL;
        int n_key_expressions = get_keyexpr_by_index(st->wallet_policy_map,
                                                     cur_index,
                                                     &tapleaf_ptr,
                                                     &keyexpr_info.key_expression_ptr);
        if (tapleaf_ptr != NULL) {
            // get_keyexpr_by_index returns the pointer to the tapleaf only if the key being
            // spent is indeed in a tapleaf
            keyexpr_info.tapleaf_ptr = tapleaf_ptr;
            keyexpr_info.is_tapscript = true;
        }
        if (n_key_expressions < 0) {
            SEND_SW(dc, SW_BAD_STATE);  // should never happen
            return false;
        }

        if (cur_index >= (size_t) n_key_expressions) {
            // all keys have been processed
            break;
        }
        // chester
        if (fill_keyexpr_info_if_internal(dc, st, &keyexpr_info)) {
            if (st->n_internal_key_expressions >= MAX_INTERNAL_KEY_EXPRESSIONS) {
                PRINTF("Too many internal key expressions. The maximum supported is %d\n",
                       MAX_INTERNAL_KEY_EXPRESSIONS);
                SEND_SW_EC(dc, SW_NOT_SUPPORTED, EC_SIGN_PSBT_WALLET_POLICY_TOO_MANY_INTERNAL_KEYS);
                return false;
            }

            // store this key info, as it's internal
            memcpy(&st->internal_key_expressions[st->n_internal_key_expressions],
                   &keyexpr_info,
                   sizeof(keyexpr_info_t));
            ++st->n_internal_key_expressions;
        }

        ++cur_index;
    }

    if (st->n_internal_key_expressions == 0) {
        PRINTF("No internal key found in wallet policy");
        SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_WALLET_POLICY_HAS_NO_INTERNAL_KEY);
        return false;
    }

    return true;
}

static bool __attribute__((noinline))
preprocess_inputs(dispatcher_context_t *dc,
                  sign_psbt_state_t *st,
                  uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    memset(internal_inputs, 0, BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN));

    if (!fill_internal_key_expressions(dc, st)) return false;

    // process each input
    for (unsigned int cur_input_index = 0; cur_input_index < st->n_inputs; cur_input_index++) {
        input_info_t input;
        memset(&input, 0, sizeof(input));

        input_keys_callback_data_t callback_data = {.input = &input, .state = st};
        int res = call_get_merkleized_map_with_callback(
            dc,
            (void *) &callback_data,
            st->inputs_root,
            st->n_inputs,
            cur_input_index,
            (merkle_tree_elements_callback_t) input_keys_callback,
            &input.in_out.map);
        if (res < 0) {
            PRINTF("Failed to process input map\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (input.in_out.unexpected_pubkey_error) {
            PRINTF("Unexpected pubkey length\n");  // only compressed pubkeys are supported
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        // either witness utxo or non-witness utxo (or both) must be present.
        if (!input.has_nonWitnessUtxo && !input.has_witnessUtxo) {
            PRINTF("No witness utxo nor non-witness utxo present in input.\n");
            SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_MISSING_NONWITNESSUTXO_AND_WITNESSUTXO);
            return false;
        }

        // validate non-witness utxo (if present) and witness utxo (if present)

        if (input.has_nonWitnessUtxo) {
            uint8_t prevout_hash[32];
            // check if the prevout_hash of the transaction matches the computed one from the
            // non-witness utxo
            if (0 > call_get_merkleized_map_value(dc,
                                                  &input.in_out.map,
                                                  (uint8_t[]){PSBT_IN_PREVIOUS_TXID},
                                                  1,
                                                  prevout_hash,
                                                  sizeof(prevout_hash))) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }
            // request non-witness utxo, and get the prevout's value and scriptpubkey
            // Also checks that the recomputed transaction hash matches with prevout_hash.
            if (0 > get_amount_scriptpubkey_from_psbt_nonwitness(dc,
                                                                 &input.in_out.map,
                                                                 &input.prevout_amount,
                                                                 input.in_out.scriptPubKey,
                                                                 &input.in_out.scriptPubKey_len,
                                                                 prevout_hash)) {
                SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_NONWITNESSUTXO_CHECK_FAILED);
                return false;
            }

            st->inputs_total_amount += input.prevout_amount;
        }

        if (input.has_witnessUtxo) {
            size_t wit_utxo_scriptPubkey_len;
            uint8_t wit_utxo_scriptPubkey[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
            uint64_t wit_utxo_prevout_amount;
            if (0 > get_amount_scriptpubkey_from_psbt_witness(dc,
                                                              &input.in_out.map,
                                                              &wit_utxo_prevout_amount,
                                                              wit_utxo_scriptPubkey,
                                                              &wit_utxo_scriptPubkey_len)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            };
            if (input.has_nonWitnessUtxo) {
                // we already know the scriptPubKey, but we double check that it matches
                if (input.in_out.scriptPubKey_len != wit_utxo_scriptPubkey_len ||
                    memcmp(input.in_out.scriptPubKey,
                           wit_utxo_scriptPubkey,
                           wit_utxo_scriptPubkey_len) != 0 ||
                    input.prevout_amount != wit_utxo_prevout_amount) {
                    PRINTF(
                        "scriptPubKey or amount in non-witness utxo doesn't match with witness "
                        "utxo\n");
                    SEND_SW_EC(dc,
                               SW_INCORRECT_DATA,
                               EC_SIGN_PSBT_NONWITNESSUTXO_AND_WITNESSUTXO_MISMATCH);
                    return false;
                }
            } else {
                // we extract the scriptPubKey and prevout amount from the witness utxo
                st->inputs_total_amount += wit_utxo_prevout_amount;

                input.prevout_amount = wit_utxo_prevout_amount;
                input.in_out.scriptPubKey_len = wit_utxo_scriptPubkey_len;
                memcpy(input.in_out.scriptPubKey, wit_utxo_scriptPubkey, wit_utxo_scriptPubkey_len);
            }
        }

        bitvector_set(internal_inputs, cur_input_index, 1);

        int segwit_version = get_policy_segwit_version(st->wallet_policy_map);

        // For legacy inputs, the non-witness utxo must be present
        // and the witness utxo must be absent.
        // (This assumption is later relied on when signing).
        if (segwit_version == -1) {
            if (!input.has_nonWitnessUtxo || input.has_witnessUtxo) {
                PRINTF("Legacy inputs must have the non-witness utxo, but no witness utxo.\n");
                SEND_SW_EC(
                    dc,
                    SW_INCORRECT_DATA,
                    EC_SIGN_PSBT_MISSING_NONWITNESSUTXO_OR_UNEXPECTED_WITNESSUTXO_FOR_LEGACY);
                return false;
            }
        }

        // For segwitv0 inputs, the non-witness utxo _should_ be present; we show a warning
        // to the user otherwise, but we continue nonetheless on approval
        if (segwit_version == 0 && !input.has_nonWitnessUtxo) {
            PRINTF("Non-witness utxo missing for segwitv0 input. Will show a warning.\n");
            st->warnings.missing_nonwitnessutxo = true;
        }

        // For all segwit transactions, the witness utxo must be present
        if (segwit_version >= 0 && !input.has_witnessUtxo) {
            PRINTF("Witness utxo missing for segwit input\n");
            SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_MISSING_WITNESSUTXO_FOR_SEGWIT);
            return false;
        }

        // If any of the internal inputs has a sighash type that is not SIGHASH_DEFAULT or
        // SIGHASH_ALL, we show a warning

        if (!input.has_sighash_type) {
            continue;
        }

        // get the sighash_type
        if (4 != call_get_merkleized_map_value_u32_le(dc,
                                                      &input.in_out.map,
                                                      (uint8_t[]){PSBT_IN_SIGHASH_TYPE},
                                                      1,
                                                      &input.sighash_type)) {
            PRINTF("Malformed PSBT_IN_SIGHASH_TYPE for input %d\n", cur_input_index);

            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        if (((segwit_version > 0) && (input.sighash_type == SIGHASH_DEFAULT)) ||
            (input.sighash_type == SIGHASH_ALL)) {
            PRINTF("Sighash type is SIGHASH_DEFAULT or SIGHASH_ALL\n");

        } else if ((segwit_version >= 0) &&
                   ((input.sighash_type == SIGHASH_NONE) ||
                    (input.sighash_type == SIGHASH_SINGLE) ||
                    (input.sighash_type == (SIGHASH_ANYONECANPAY | SIGHASH_ALL)) ||
                    (input.sighash_type == (SIGHASH_ANYONECANPAY | SIGHASH_NONE)) ||
                    (input.sighash_type == (SIGHASH_ANYONECANPAY | SIGHASH_SINGLE)))) {
            PRINTF("Sighash type is non-default, will show a warning.\n");
            st->warnings.non_default_sighash = true;
        } else {
            PRINTF("Unsupported sighash\n");
            SEND_SW(dc, SW_NOT_SUPPORTED);
            return false;
        }

        if (((input.sighash_type & SIGHASH_SINGLE) == SIGHASH_SINGLE) &&
            (cur_input_index >= st->n_outputs)) {
            PRINTF("SIGHASH_SINGLE with input idx >= n_output is not allowed \n");
            SEND_SW_EC(dc, SW_NOT_SUPPORTED, EC_SIGN_PSBT_UNALLOWED_SIGHASH_SINGLE);
            return false;
        }
    }
    return true;
}

typedef struct {
    sign_psbt_state_t *state;
    output_info_t *output;
} output_keys_callback_data_t;

/**
 * Callback to process all the keys of the current input map.
 * Keeps track if the current input has a witness_utxo and/or a redeemScript.
 */
static void output_keys_callback(dispatcher_context_t *dc,
                                 output_keys_callback_data_t *callback_data,
                                 const merkleized_map_commitment_t *map_commitment,
                                 int index,
                                 buffer_t *data) {
    size_t data_len = data->size - data->offset;
    if (data_len >= 1) {
        uint8_t key_type;
        buffer_read_u8(data, &key_type);

        if ((key_type == PSBT_OUT_BIP32_DERIVATION || key_type == PSBT_OUT_TAP_BIP32_DERIVATION) &&
            !callback_data->output->in_out.key_expression_found) {
            derivation_info_t derivation_info;
            int res = read_change_and_index_from_psbt_bip32_derivation(dc,
                                                                       key_type,
                                                                       data,
                                                                       map_commitment,
                                                                       index,
                                                                       &derivation_info);
            if (res < 0) {
                // there was an error; we keep track of it so an error SW is sent later
                callback_data->output->in_out.unexpected_pubkey_error = true;
            } else if (res == 1) {
                in_out_info_t *in_out = &callback_data->output->in_out;
                for (size_t i = 0; i < callback_data->state->n_internal_key_expressions; i++) {
                    const keyexpr_info_t *key_expr =
                        &callback_data->state->internal_key_expressions[i];
                    if (is_keyexpr_compatible_with_derivation_info(key_expr, &derivation_info)) {
                        bool is_change =
                            key_expr->key_expression_ptr->num_second ==
                            derivation_info.key_origin[derivation_info.derivation_len - 2];

                        in_out->key_expression_found = true;
                        in_out->is_change = is_change;
                        in_out->address_index =
                            derivation_info.key_origin[derivation_info.derivation_len - 1];
                        // unlike for inputs, where we want to keep track of all the key expressions
                        // we want to sign for, here we only care about finding the relevant info
                        // for this output. Therefore, we're done as soon as we have a match.
                        break;
                    }
                }
            }
        }
    }
}

static bool __attribute__((noinline))
preprocess_outputs(dispatcher_context_t *dc,
                   sign_psbt_state_t *st,
                   sign_psbt_cache_t *sign_psbt_cache,
                   uint8_t internal_outputs[static BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)]) {
    /** OUTPUTS VERIFICATION FLOW
     *
     *  For each output, check if it's internal (that is, a change address).
     *  Also computes the total amount of change outputs, and the total of all outputs.
     */

    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    memset(&st->outputs, 0, sizeof(st->outputs));

    // the counter used when showing outputs to the user, which ignores change outputs
    // (0-indexed here, although the UX starts with 1)
    int external_outputs_count = 0;
    for (unsigned int cur_output_index = 0; cur_output_index < st->n_outputs; cur_output_index++) {
        output_info_t output;
        memset(&output, 0, sizeof(output));

        output_keys_callback_data_t callback_data = {.output = &output, .state = st};
        int res = call_get_merkleized_map_with_callback(
            dc,
            (void *) &callback_data,
            st->outputs_root,
            st->n_outputs,
            cur_output_index,
            (merkle_tree_elements_callback_t) output_keys_callback,
            &output.in_out.map);

        if (res < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        if (output.in_out.unexpected_pubkey_error) {
            PRINTF("Unexpected pubkey length\n");  // only compressed pubkeys are supported
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        // Read output amount
        uint8_t raw_result[8];

        // Read the output's amount
        int result_len = call_get_merkleized_map_value(dc,
                                                       &output.in_out.map,
                                                       (uint8_t[]){PSBT_OUT_AMOUNT},
                                                       1,
                                                       raw_result,
                                                       sizeof(raw_result));
        if (result_len != 8) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        uint64_t value = read_u64_le(raw_result, 0);

        output.value = value;
        st->outputs.total_amount += value;

        // Read the output's scriptPubKey
        result_len = call_get_merkleized_map_value(dc,
                                                   &output.in_out.map,
                                                   (uint8_t[]){PSBT_OUT_SCRIPT},
                                                   1,
                                                   output.in_out.scriptPubKey,
                                                   sizeof(output.in_out.scriptPubKey));
        if (result_len == -1 || result_len > (int) sizeof(output.in_out.scriptPubKey)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        output.in_out.scriptPubKey_len = result_len;

        int is_internal = is_in_out_internal(dc, st, sign_psbt_cache, &output.in_out, false);
        if (is_internal < 0) {
            PRINTF("Error checking if output %d is internal\n", cur_output_index);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        } else if (is_internal == 0) {
            // external output, user needs to validate
            bitvector_set(internal_outputs, cur_output_index, 0);

            // cache external output scripts
            if (external_outputs_count < N_CACHED_EXTERNAL_OUTPUTS) {
                st->outputs.output_script_lengths[external_outputs_count] =
                    output.in_out.scriptPubKey_len;
                memcpy(st->outputs.output_scripts[external_outputs_count],
                       output.in_out.scriptPubKey,
                       output.in_out.scriptPubKey_len);
                st->outputs.output_amounts[external_outputs_count] = value;
            }

            ++external_outputs_count;
        } else {
            // valid change address, nothing to show to the user

            bitvector_set(internal_outputs, cur_output_index, 1);

            st->outputs.change_total_amount += output.value;
            ++st->outputs.n_change;
        }
    }

    st->n_external_outputs = external_outputs_count;

    if (st->inputs_total_amount < st->outputs.total_amount) {
        PRINTF("Negative fee is invalid\n");
        // negative fee transaction is invalid
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    if (st->outputs.n_change > 10) {
        // As the information regarding change outputs is aggregated, we want to prevent the user
        // from unknowingly signing a transaction that sends the change to too many outputs
        // (possibly economically not worth spending).
        PRINTF("Too many change outputs: %d\n", st->outputs.n_change);
        SEND_SW_EC(dc, SW_NOT_SUPPORTED, EC_SIGN_PSBT_TOO_MANY_CHANGE_OUTPUTS);
        return false;
    }

    return true;
}

static bool __attribute__((noinline))
display_output(dispatcher_context_t *dc,
               sign_psbt_state_t *st,
               int cur_output_index,
               int external_outputs_count,
               const uint8_t out_scriptPubKey[static MAX_OUTPUT_SCRIPTPUBKEY_LEN],
               size_t out_scriptPubKey_len,
               uint64_t out_amount) {
    (void) cur_output_index;

    // show this output's address
    char output_description[MAX_OUTPUT_SCRIPT_DESC_SIZE];

    // chester
    // if it is the sign message in BIP322
    // to avoid it is mis-used(attacked) for normal transaction
    // we check amount=0, address=OP_RETURN
    if (st->bbn_action_type == BBN_POLICY_BIP322) {
        if (!is_opreturn(out_scriptPubKey, out_scriptPubKey_len) || out_amount != 0) {
            SEND_SW(dc, SW_NOT_SUPPORTED);
            return false;
        }
    }

    if (!format_script(out_scriptPubKey, out_scriptPubKey_len, output_description)) {
        PRINTF("Invalid or unsupported script for output %d\n", cur_output_index);
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return false;
    }

    // Show address to the user
    if (!ui_validate_output(dc,
                            external_outputs_count,
                            st->n_external_outputs,
                            output_description,
                            COIN_COINID_SHORT,
                            out_amount)) {
        SEND_SW(dc, SW_DENY);
        return false;
    }
    return true;
}

static bool get_output_script_and_amount(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    size_t output_index,
    uint8_t out_scriptPubKey[static MAX_OUTPUT_SCRIPTPUBKEY_LEN],
    size_t *out_scriptPubKey_len,
    uint64_t *out_amount) {
    if (out_scriptPubKey == NULL || out_amount == NULL) {
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    merkleized_map_commitment_t map;

    // TODO: This might be too slow, as it checks the integrity of the map;
    //       Refactor so that the map key ordering is checked all at the beginning of sign_psbt.
    int res = call_get_merkleized_map(dc, st->outputs_root, st->n_outputs, output_index, &map);

    if (res < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    // Read output amount
    uint8_t raw_result[8];

    // Read the output's amount
    int result_len = call_get_merkleized_map_value(dc,
                                                   &map,
                                                   (uint8_t[]){PSBT_OUT_AMOUNT},
                                                   1,
                                                   raw_result,
                                                   sizeof(raw_result));
    if (result_len != 8) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint64_t value = read_u64_le(raw_result, 0);
    *out_amount = value;

    // Read the output's scriptPubKey
    result_len = call_get_merkleized_map_value(dc,
                                               &map,
                                               (uint8_t[]){PSBT_OUT_SCRIPT},
                                               1,
                                               out_scriptPubKey,
                                               MAX_OUTPUT_SCRIPTPUBKEY_LEN);

    if (result_len == -1 || result_len > MAX_OUTPUT_SCRIPTPUBKEY_LEN) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    *out_scriptPubKey_len = result_len;

    return true;
}

static bool __attribute__((noinline)) display_external_outputs(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    const uint8_t internal_outputs[static BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)]) {
    /**
     *  Display all the non-change outputs
     */

    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    // the counter used when showing outputs to the user, which ignores change outputs
    // (0-indexed here, although the UX starts with 1)
    int external_outputs_count = 0;

    for (unsigned int cur_output_index = 0; cur_output_index < st->n_outputs; cur_output_index++) {
        if (!bitvector_get(internal_outputs, cur_output_index)) {
            // external output, user needs to validate
            uint8_t out_scriptPubKey[MAX_OUTPUT_SCRIPTPUBKEY_LEN];
            size_t out_scriptPubKey_len;
            uint64_t out_amount;

            if (external_outputs_count < N_CACHED_EXTERNAL_OUTPUTS) {
                // we have the output cached, no need to fetch it again
                out_scriptPubKey_len = st->outputs.output_script_lengths[external_outputs_count];
                memcpy(out_scriptPubKey,
                       st->outputs.output_scripts[external_outputs_count],
                       out_scriptPubKey_len);
                out_amount = st->outputs.output_amounts[external_outputs_count];
            } else if (!get_output_script_and_amount(dc,
                                                     st,
                                                     cur_output_index,
                                                     out_scriptPubKey,
                                                     &out_scriptPubKey_len,
                                                     &out_amount)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            ++external_outputs_count;

            // displays the output. It fails if the output is invalid or not supported
            if (!display_output(dc,
                                st,
                                cur_output_index,
                                external_outputs_count,
                                out_scriptPubKey,
                                out_scriptPubKey_len,
                                out_amount)) {
                return false;
            }
        }
    }

    return true;
}

static bool __attribute__((noinline))
display_bbn_pk(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    if (0 < st->psbt_finality_pk_state && !ui_confirm_finality_pk(dc, st->psbt_finality_pk)) {
        SEND_SW(dc, SW_DENY);
        return false;
    }

    unsigned int cov_count = count_psbt_covenant_pk_state(st->psbt_covenant_pk_state);
    if (cov_count < 2) {
        return false;
    } else {
        if (st->bbn_action_type == BBN_POLICY_SLASHING ||
            st->bbn_action_type == BBN_POLICY_SLASHING_UNBONDING)
            cov_count = cov_count - 2;
        if (st->bbn_action_type == BBN_POLICY_UNBOND) cov_count = cov_count - 1;
    }

    for (unsigned int i = 0; i < cov_count; i++) {
        for (unsigned int j = i + 1; j < cov_count; j++) {
            if (memcmp(st->psbt_covenant_pk[i], st->psbt_covenant_pk[j], 32) == 0) {
                PRINTF("Duplicate covenant pk\n");
                SEND_SW(dc, SW_DENY);
                return false;
            }
        }
    }

    if (st->psbt_quorum > 0 && st->psbt_quorum < BBN_MIN_QUORUM) {
        PRINTF("Invalid quorum %d\n", st->psbt_quorum);
        SEND_SW(dc, SW_DENY);
        return false;
    }

    if (!ui_confirm_cov_pks(dc, st->psbt_covenant_pk, cov_count, st->psbt_quorum)) {
        SEND_SW(dc, SW_DENY);
        return false;
    }
    return true;
}

static bool __attribute__((noinline))
display_bbn_timelock(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    char timelock_str[12];  // Enough to hold the maximum 32-bit integer value in decimal
    if (st->psbt_timelock_state > 0) {
        if (st->bbn_action_type == BBN_POLICY_STAKE_TRANSFER) {
            snprintf(timelock_str, sizeof(timelock_str), "%u", st->psbt_timelock);
            if (!ui_confirm_bbn_timelock(dc, timelock_str, "BTC blocks timelock")) {
                // PRINTF_BUF(timelock_str, 12);
                SEND_SW(dc, SW_DENY);
                return false;
            }
        } else if (st->bbn_action_type == BBN_POLICY_UNBOND) {
            snprintf(timelock_str, sizeof(timelock_str), "%u", st->psbt_timelock);
            if (!ui_confirm_bbn_timelock_unbonding(dc, timelock_str, "BTC blocks timelock")) {
                // PRINTF_BUF(timelock_str, 12);
                SEND_SW(dc, SW_DENY);
                return false;
            }
        }
    }
    return true;
}

static bool __attribute__((noinline))
display_warnings(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    // If any input has non-default sighash, we deny to sign
    if (st->warnings.non_default_sighash) {
        SEND_SW(dc, SW_DENY);
        return false;
    }
    // If any segwitv0 input is missing the non-witness-utxo, we warn the user and ask for
    // confirmation
    if (st->warnings.missing_nonwitnessutxo && !ui_warn_unverified_segwit_inputs(dc)) {
        SEND_SW(dc, SW_DENY);
        return false;
    }

    return true;
}

static bool __attribute__((noinline)) display_transaction(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    const uint8_t internal_outputs[static BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);
    uint64_t fee = st->inputs_total_amount - st->outputs.total_amount;

    /** INPUT VERIFICATION ALERTS
     *
     * Show warnings and allow users to abort in any of the following conditions:
     * - pre-taproot transaction with unverified inputs (missing non-witness-utxo)
     * - external inputs
     * - non-default sighash types
     */

    // if the value of fees is 10% or more of the amount, and it's more than 100000
    st->warnings.high_fee = 10 * fee >= st->inputs_total_amount && st->inputs_total_amount > 100000;

    if (!display_warnings(dc, st)) {
        PRINTF("display_warnings fail \n");
        return false;
    }

    /** OUTPUTS CONFIRMATION
     *
     *  Display each non-change output, and transaction fees, and acquire user confirmation,
     */
    // chester
    // not sure if it is necessary for step1 and step2 to show output
    // seems useless

    if (!display_external_outputs(dc, st, internal_outputs)) {
        PRINTF("display_external_outputs fail \n");
        return false;
    }

    if (st->warnings.high_fee && !ui_warn_high_fee(dc)) {
        PRINTF("ui_warn_high_fee fail \n");
        SEND_SW(dc, SW_DENY);
        return false;
    }

    /** TRANSACTION CONFIRMATION
     *
     *  Show summary info to the user (transaction fees), ask for final confirmation
     */
    // Show final user validation UI
    if (!ui_validate_transaction(dc, COIN_COINID_SHORT, fee, false)) {
        PRINTF("ui_validate_transaction fail \n");
        SEND_SW(dc, SW_DENY);
        return false;
    }
    return true;
}

static bool __attribute__((noinline)) compute_sighash_legacy(dispatcher_context_t *dc,
                                                             sign_psbt_state_t *st,
                                                             input_info_t *input,
                                                             unsigned int cur_input_index,
                                                             uint8_t sighash[static 32]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    cx_sha256_t sighash_context;
    cx_sha256_init(&sighash_context);

    uint8_t tmp[4];
    write_u32_le(tmp, 0, st->tx_version);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    crypto_hash_update_varint(&sighash_context.header, st->n_inputs);

    for (unsigned int i = 0; i < st->n_inputs; i++) {
        // get this input's map
        merkleized_map_commitment_t ith_map;

        if (i != cur_input_index) {
            int res = call_get_merkleized_map(dc, st->inputs_root, st->n_inputs, i, &ith_map);
            if (res < 0) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }
        } else {
            // Avoid requesting the same map unnecessarily
            // (might be removed once a caching mechanism is implemented)
            memcpy(&ith_map, &input->in_out.map, sizeof(input->in_out.map));
        }

        // get prevout hash and output index for the i-th input
        uint8_t ith_prevout_hash[32];
        if (32 != call_get_merkleized_map_value(dc,
                                                &ith_map,
                                                (uint8_t[]){PSBT_IN_PREVIOUS_TXID},
                                                1,
                                                ith_prevout_hash,
                                                32)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        crypto_hash_update(&sighash_context.header, ith_prevout_hash, 32);

        uint8_t ith_prevout_n_raw[4];
        if (4 != call_get_merkleized_map_value(dc,
                                               &ith_map,
                                               (uint8_t[]){PSBT_IN_OUTPUT_INDEX},
                                               1,
                                               ith_prevout_n_raw,
                                               4)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        crypto_hash_update(&sighash_context.header, ith_prevout_n_raw, 4);

        if (i != cur_input_index) {
            // empty scriptcode
            crypto_hash_update_u8(&sighash_context.header, 0x00);
        } else {
            if (!input->has_redeemScript) {
                // P2PKH, the script_code is the prevout's scriptPubKey
                crypto_hash_update_varint(&sighash_context.header, input->in_out.scriptPubKey_len);
                crypto_hash_update(&sighash_context.header,
                                   input->in_out.scriptPubKey,
                                   input->in_out.scriptPubKey_len);
            } else {
                // P2SH, the script_code is the redeemScript

                // update sighash_context with the length-prefixed redeem script
                int redeemScript_len =
                    update_hashes_with_map_value(dc,
                                                 &input->in_out.map,
                                                 (uint8_t[]){PSBT_IN_REDEEM_SCRIPT},
                                                 1,
                                                 NULL,
                                                 &sighash_context.header);

                if (redeemScript_len < 0) {
                    PRINTF("Error fetching redeemScript\n");
                    SEND_SW(dc, SW_INCORRECT_DATA);
                    return false;
                }
            }
        }

        uint8_t ith_nSequence_raw[4];
        if (4 != call_get_merkleized_map_value(dc,
                                               &ith_map,
                                               (uint8_t[]){PSBT_IN_SEQUENCE},
                                               1,
                                               ith_nSequence_raw,
                                               4)) {
            // if no PSBT_IN_SEQUENCE is present, we must assume nSequence 0xFFFFFFFF
            memset(ith_nSequence_raw, 0xFF, 4);
        }

        crypto_hash_update(&sighash_context.header, ith_nSequence_raw, 4);
    }

    // outputs
    crypto_hash_update_varint(&sighash_context.header, st->n_outputs);
    if (hash_outputs(dc, st, &sighash_context.header) == -1) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    // nLocktime
    write_u32_le(tmp, 0, st->locktime);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    // hash type
    write_u32_le(tmp, 0, input->sighash_type);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    // compute sighash
    crypto_hash_digest(&sighash_context.header, sighash, 32);
    cx_hash_sha256(sighash, 32, sighash, 32);

    return true;
}

static bool __attribute__((noinline)) compute_sighash_segwitv0(dispatcher_context_t *dc,
                                                               sign_psbt_state_t *st,
                                                               const tx_hashes_t *hashes,
                                                               input_info_t *input,
                                                               unsigned int cur_input_index,
                                                               uint8_t sighash[static 32]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    cx_sha256_t sighash_context;
    cx_sha256_init(&sighash_context);

    uint8_t tmp[8];
    uint8_t sighash_byte = (uint8_t) (input->sighash_type & 0xFF);

    // nVersion
    write_u32_le(tmp, 0, st->tx_version);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    {
        uint8_t dbl_hash[32];

        memset(dbl_hash, 0, 32);
        // add to hash: hashPrevouts = sha256(sha_prevouts)
        if (!(sighash_byte & SIGHASH_ANYONECANPAY)) {
            cx_hash_sha256(hashes->sha_prevouts, 32, dbl_hash, 32);
        }

        crypto_hash_update(&sighash_context.header, dbl_hash, 32);

        memset(dbl_hash, 0, 32);
        // add to hash: hashSequence sha256(sha_sequences)
        if (!(sighash_byte & SIGHASH_ANYONECANPAY) && (sighash_byte & 0x1f) != SIGHASH_SINGLE &&
            (sighash_byte & 0x1f) != SIGHASH_NONE) {
            cx_hash_sha256(hashes->sha_sequences, 32, dbl_hash, 32);
        }
        crypto_hash_update(&sighash_context.header, dbl_hash, 32);
    }

    {
        // outpoint (32-byte prevout hash, 4-byte index)

        // get prevout hash and output index for the current input
        uint8_t prevout_hash[32];
        if (32 != call_get_merkleized_map_value(dc,
                                                &input->in_out.map,
                                                (uint8_t[]){PSBT_IN_PREVIOUS_TXID},
                                                1,
                                                prevout_hash,
                                                32)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        crypto_hash_update(&sighash_context.header, prevout_hash, 32);

        uint8_t prevout_n_raw[4];
        if (4 != call_get_merkleized_map_value(dc,
                                               &input->in_out.map,
                                               (uint8_t[]){PSBT_IN_OUTPUT_INDEX},
                                               1,
                                               prevout_n_raw,
                                               4)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        crypto_hash_update(&sighash_context.header, prevout_n_raw, 4);
    }

    // scriptCode
    if (is_p2wpkh(input->script, input->script_len)) {
        // P2WPKH(script[2:22])
        crypto_hash_update_u32(&sighash_context.header, 0x1976a914);
        crypto_hash_update(&sighash_context.header, input->script + 2, 20);
        crypto_hash_update_u16(&sighash_context.header, 0x88ac);
    } else if (is_p2wsh(input->script, input->script_len)) {
        // P2WSH

        // update sighash_context.header with the length-prefixed witnessScript,
        // and also compute sha256(witnessScript)
        cx_sha256_t witnessScript_hash_context;
        cx_sha256_init(&witnessScript_hash_context);

        int witnessScript_len = update_hashes_with_map_value(dc,
                                                             &input->in_out.map,
                                                             (uint8_t[]){PSBT_IN_WITNESS_SCRIPT},
                                                             1,
                                                             &witnessScript_hash_context.header,
                                                             &sighash_context.header);

        if (witnessScript_len < 0) {
            PRINTF("Error fetching witnessScript\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t witnessScript_hash[32];
        crypto_hash_digest(&witnessScript_hash_context.header, witnessScript_hash, 32);

        // check that script == P2WSH(witnessScript)
        if (input->script_len != 2 + 32 || input->script[0] != 0x00 || input->script[1] != 0x20 ||
            memcmp(input->script + 2, witnessScript_hash, 32) != 0) {
            PRINTF("Mismatching witnessScript\n");

            SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_MISMATCHING_WITNESS_SCRIPT);
            return false;
        }
    } else {
        PRINTF("Invalid or unsupported script in segwit transaction\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    {
        // input value, taken from the WITNESS_UTXO field
        uint8_t witness_utxo[8 + 1 + MAX_PREVOUT_SCRIPTPUBKEY_LEN];

        int witness_utxo_len = call_get_merkleized_map_value(dc,
                                                             &input->in_out.map,
                                                             (uint8_t[]){PSBT_IN_WITNESS_UTXO},
                                                             1,
                                                             witness_utxo,
                                                             sizeof(witness_utxo));
        if (witness_utxo_len < 8) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        crypto_hash_update(&sighash_context.header,
                           witness_utxo,
                           8);  // only the first 8 bytes (amount)
    }

    // nSequence
    {
        uint8_t nSequence_raw[4];
        if (4 != call_get_merkleized_map_value(dc,
                                               &input->in_out.map,
                                               (uint8_t[]){PSBT_IN_SEQUENCE},
                                               1,
                                               nSequence_raw,
                                               4)) {
            // if no PSBT_IN_SEQUENCE is present, we must assume nSequence 0xFFFFFFFF
            memset(nSequence_raw, 0xFF, 4);
        }
        crypto_hash_update(&sighash_context.header, nSequence_raw, 4);
    }

    {
        // compute hashOutputs = sha256(sha_outputs)

        uint8_t hashOutputs[32];
        memset(hashOutputs, 0, 32);

        if ((sighash_byte & 0x1f) != SIGHASH_SINGLE && (sighash_byte & 0x1f) != SIGHASH_NONE) {
            cx_hash_sha256(hashes->sha_outputs, 32, hashOutputs, 32);

        } else if ((sighash_byte & 0x1f) == SIGHASH_SINGLE && cur_input_index < st->n_outputs) {
            cx_sha256_t sha_output_context;
            cx_sha256_init(&sha_output_context);
            if (hash_output_n(dc, st, &sha_output_context.header, cur_input_index) == -1) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }
            crypto_hash_digest(&sha_output_context.header, hashOutputs, 32);
            cx_hash_sha256(hashOutputs, 32, hashOutputs, 32);
        }
        crypto_hash_update(&sighash_context.header, hashOutputs, 32);
    }

    // nLocktime
    write_u32_le(tmp, 0, st->locktime);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    // sighash type
    write_u32_le(tmp, 0, input->sighash_type);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    // compute sighash
    crypto_hash_digest(&sighash_context.header, sighash, 32);
    cx_hash_sha256(sighash, 32, sighash, 32);

    return true;
}

static bool __attribute__((noinline)) compute_sighash_segwitv1(dispatcher_context_t *dc,
                                                               sign_psbt_state_t *st,
                                                               const tx_hashes_t *hashes,
                                                               input_info_t *input,
                                                               unsigned int cur_input_index,
                                                               keyexpr_info_t *keyexpr_info,
                                                               uint8_t sighash[static 32]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    cx_sha256_t sighash_context;

    crypto_tr_tagged_hash_init(&sighash_context, BIP0341_sighash_tag, sizeof(BIP0341_sighash_tag));
    // the first 0x00 byte is not part of SigMsg
    crypto_hash_update_u8(&sighash_context.header, 0x00);

    uint8_t tmp[MAX(32, 8 + 1 + MAX_PREVOUT_SCRIPTPUBKEY_LEN)];

    // hash type
    uint8_t sighash_byte = (uint8_t) (input->sighash_type & 0xFF);
    crypto_hash_update_u8(&sighash_context.header, sighash_byte);

    // nVersion
    write_u32_le(tmp, 0, st->tx_version);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    // nLocktime
    write_u32_le(tmp, 0, st->locktime);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    if ((sighash_byte & 0x80) != SIGHASH_ANYONECANPAY) {
        crypto_hash_update(&sighash_context.header, hashes->sha_prevouts, 32);
        crypto_hash_update(&sighash_context.header, hashes->sha_amounts, 32);
        crypto_hash_update(&sighash_context.header, hashes->sha_scriptpubkeys, 32);
        crypto_hash_update(&sighash_context.header, hashes->sha_sequences, 32);
    }

    if ((sighash_byte & 3) != SIGHASH_NONE && (sighash_byte & 3) != SIGHASH_SINGLE) {
        crypto_hash_update(&sighash_context.header, hashes->sha_outputs, 32);
    }
    // chester
    // also change here
    // not script spend for stake transaction

    // ext_flag
    if (st->bbn_action_type == BBN_POLICY_STAKE_TRANSFER ||
        st->bbn_action_type == BBN_POLICY_BIP322) {
        keyexpr_info->is_tapscript = 0;
    }
    // ext_flag
    uint8_t ext_flag = keyexpr_info->is_tapscript ? 1 : 0;
    // annex is not supported
    const uint8_t annex_present = 0;
    uint8_t spend_type = ext_flag * 2 + annex_present;
    crypto_hash_update_u8(&sighash_context.header, spend_type);

    if ((sighash_byte & 0x80) == SIGHASH_ANYONECANPAY) {
        // outpoint (hash)
        if (32 != call_get_merkleized_map_value(dc,
                                                &input->in_out.map,
                                                (uint8_t[]){PSBT_IN_PREVIOUS_TXID},
                                                1,
                                                tmp,
                                                32)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        crypto_hash_update(&sighash_context.header, tmp, 32);

        // outpoint (output index)
        if (4 != call_get_merkleized_map_value(dc,
                                               &input->in_out.map,
                                               (uint8_t[]){PSBT_IN_OUTPUT_INDEX},
                                               1,
                                               tmp,
                                               4)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        crypto_hash_update(&sighash_context.header, tmp, 4);

        if (8 > call_get_merkleized_map_value(dc,
                                              &input->in_out.map,
                                              (uint8_t[]){PSBT_IN_WITNESS_UTXO},
                                              1,
                                              tmp,
                                              8 + 1 + MAX_PREVOUT_SCRIPTPUBKEY_LEN)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        // amount
        crypto_hash_update(&sighash_context.header, tmp, 8);

        // scriptPubKey
        crypto_hash_update_varint(&sighash_context.header, input->in_out.scriptPubKey_len);

        crypto_hash_update(&sighash_context.header,
                           input->in_out.scriptPubKey,
                           input->in_out.scriptPubKey_len);

        // nSequence
        if (4 != call_get_merkleized_map_value(dc,
                                               &input->in_out.map,
                                               (uint8_t[]){PSBT_IN_SEQUENCE},
                                               1,
                                               tmp,
                                               4)) {
            // if no PSBT_IN_SEQUENCE is present, we must assume nSequence 0xFFFFFFFF
            memset(tmp, 0xFF, 4);
        }
        crypto_hash_update(&sighash_context.header, tmp, 4);
    } else {
        // input_index
        write_u32_le(tmp, 0, cur_input_index);
        crypto_hash_update(&sighash_context.header, tmp, 4);
    }

    // no annex

    if ((sighash_byte & 3) == SIGHASH_SINGLE) {
        // compute sha_output
        cx_sha256_t sha_output_context;
        cx_sha256_init(&sha_output_context);

        if (hash_output_n(dc, st, &sha_output_context.header, cur_input_index) == -1) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        crypto_hash_digest(&sha_output_context.header, tmp, 32);

        crypto_hash_update(&sighash_context.header, tmp, 32);
    }
    // chester
    // if for staking transaction
    // ignore tanpscript part for hash
    // just check the address
    if (keyexpr_info->is_tapscript) {
        // If spending a tapscript, append the Common Signature Message Extension per BIP-0342
        if (st->psbt_leafhash_state != BBN_LEAF_HASH_NULL) {
            // just copy to buffer
            // will check later before display
            memcpy(keyexpr_info->tapleaf_hash, st->psbt_leafhash, 32);
        } else {
            PRINTF("check leaf_hash not provided\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        crypto_hash_update(&sighash_context.header, keyexpr_info->tapleaf_hash, 32);
        crypto_hash_update_u8(&sighash_context.header, 0x00);         // key_version
        crypto_hash_update_u32(&sighash_context.header, 0xffffffff);  // no OP_CODESEPARATOR
    }

    crypto_hash_digest(&sighash_context.header, sighash, 32);

    return true;
}

static bool __attribute__((noinline)) yield_signature(dispatcher_context_t *dc,
                                                      sign_psbt_state_t *st,
                                                      unsigned int cur_input_index,
                                                      uint8_t *pubkey,
                                                      uint8_t pubkey_len,
                                                      uint8_t *tapleaf_hash,
                                                      uint8_t *sig,
                                                      size_t sig_len) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    // yield signature
    uint8_t cmd = CCMD_YIELD;
    dc->add_to_response(&cmd, 1);

    uint8_t buf[9];
    int input_index_varint_len = varint_write(buf, 0, cur_input_index);
    dc->add_to_response(&buf, input_index_varint_len);

    // for tapscript signatures, we concatenate the (x-only) pubkey with the tapleaf hash
    uint8_t augm_pubkey_len = pubkey_len + (tapleaf_hash != NULL ? 32 : 0);

    // the pubkey is not output in version 0 of the protocol
    if (st->protocol_version >= 1) {
        dc->add_to_response(&augm_pubkey_len, 1);
        dc->add_to_response(pubkey, pubkey_len);

        if (tapleaf_hash != NULL) {
            dc->add_to_response(tapleaf_hash, 32);
        }
    }

    dc->add_to_response(sig, sig_len);
    dc->finalize_response(SW_INTERRUPTED_EXECUTION);
    if (dc->process_interruption(dc) < 0) {
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }
    return true;
}

static bool __attribute__((noinline))
sign_sighash_ecdsa_and_yield(dispatcher_context_t *dc,
                             sign_psbt_state_t *st,
                             const keyexpr_info_t *keyexpr_info,
                             input_info_t *input,
                             unsigned int cur_input_index,
                             uint8_t sighash[static 32]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    uint32_t sign_path[MAX_BIP32_PATH_STEPS];
    for (int i = 0; i < keyexpr_info->key_derivation_length; i++) {
        sign_path[i] = keyexpr_info->key_derivation[i];
    }
    sign_path[keyexpr_info->key_derivation_length] =
        input->in_out.is_change ? keyexpr_info->key_expression_ptr->num_second
                                : keyexpr_info->key_expression_ptr->num_first;
    sign_path[keyexpr_info->key_derivation_length + 1] = input->in_out.address_index;

    int sign_path_len = keyexpr_info->key_derivation_length + 2;

    uint8_t sig[MAX_DER_SIG_LEN + 1];  // extra byte for the appended sighash-type

    uint8_t pubkey[33];

    int sig_len = crypto_ecdsa_sign_sha256_hash_with_key(sign_path,
                                                         sign_path_len,
                                                         sighash,
                                                         pubkey,
                                                         sig,
                                                         NULL);
    if (sig_len < 0) {
        // unexpected error when signing
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    // append the sighash type byte
    uint8_t sighash_byte = (uint8_t) (input->sighash_type & 0xFF);
    sig[sig_len++] = sighash_byte;

    if (!yield_signature(dc, st, cur_input_index, pubkey, 33, NULL, sig, sig_len)) return false;

    return true;
}

static bool __attribute__((noinline)) sign_sighash_schnorr_and_yield(dispatcher_context_t *dc,
                                                                     sign_psbt_state_t *st,
                                                                     keyexpr_info_t *keyexpr_info,
                                                                     input_info_t *input,
                                                                     unsigned int cur_input_index,
                                                                     uint8_t sighash[static 32]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    if (st->wallet_policy_map->type != TOKEN_TR) {
        SEND_SW(dc, SW_BAD_STATE);  // should never happen
        return false;
    }

    uint8_t sig[64 + 1];  // extra byte for the appended sighash-type, possibly
    size_t sig_len = 0;

    cx_ecfp_public_key_t pubkey_tweaked;  // Pubkey corresponding to the key used for signing

    uint8_t *tapleaf_hash = NULL;

    bool error = false;
    cx_ecfp_private_key_t private_key = {0};

    // IMPORTANT: Since we do not use any syscall that might throw an exception, it is safe to avoid
    // using the TRY/CATCH block to ensure zeroing sensitive data.

    do {  // block executed once, only to allow safely breaking out on error

        uint8_t *seckey =
            private_key.d;  // convenience alias (entirely within the private_key struct)

        uint32_t sign_path[MAX_BIP32_PATH_STEPS];

        for (int i = 0; i < keyexpr_info->key_derivation_length; i++) {
            sign_path[i] = keyexpr_info->key_derivation[i];
        }

        sign_path[keyexpr_info->key_derivation_length] =
            input->in_out.is_change ? keyexpr_info->key_expression_ptr->num_second
                                    : keyexpr_info->key_expression_ptr->num_first;
        sign_path[keyexpr_info->key_derivation_length + 1] = input->in_out.address_index;

        int sign_path_len = keyexpr_info->key_derivation_length + 2;

        if (bip32_derive_init_privkey_256(CX_CURVE_256K1,
                                          sign_path,
                                          sign_path_len,
                                          &private_key,
                                          NULL) != CX_OK) {
            error = true;
            break;
        }

        policy_node_tr_t *policy = (policy_node_tr_t *) st->wallet_policy_map;

        if (!keyexpr_info->is_tapscript) {
            if (isnull_policy_node_tree(&policy->tree) ||
                st->bbn_action_type == BBN_POLICY_STAKE_TRANSFER ||
                st->bbn_action_type == BBN_POLICY_BIP322) {
                // tweak as specified in BIP-86 and BIP-386
                crypto_tr_tweak_seckey(seckey, (uint8_t[]){}, 0, seckey);
            } else {
                // tweak with the taptree hash, per BIP-341
                // The taptree hash is computed in sign_transaction_input in order to
                // reduce stack usage.
                crypto_tr_tweak_seckey(seckey, input->taptree_hash, 32, seckey);
            }
        } else {
            // tapscript, we need to yield the tapleaf hash together with the pubkey
            tapleaf_hash = keyexpr_info->tapleaf_hash;
        }

        // generate corresponding public key
        unsigned int err =
            cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1, &pubkey_tweaked, &private_key, 1);
        if (err != CX_OK) {
            error = true;
            break;
        }
        err = cx_ecschnorr_sign_no_throw(&private_key,
                                         CX_ECSCHNORR_BIP0340 | CX_RND_TRNG,
                                         CX_SHA256,
                                         sighash,
                                         32,
                                         sig,
                                         &sig_len);
        if (err != CX_OK) {
            error = true;
        }
    } while (false);

    explicit_bzero(&private_key, sizeof(private_key));

    if (error) {
        // unexpected error when signing
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    if (sig_len != 64) {
        PRINTF("SIG LEN: %d\n", sig_len);
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    // only append the sighash type byte if it is non-zero
    uint8_t sighash_byte = (uint8_t) (input->sighash_type & 0xFF);
    if (sighash_byte != 0x00) {
        // only add the sighash byte if not 0
        sig[sig_len++] = sighash_byte;
    }

    if (!yield_signature(dc,
                         st,
                         cur_input_index,
                         pubkey_tweaked.W + 1,  // x-only pubkey, hence take only the x-coordinate
                         32,
                         tapleaf_hash,
                         sig,
                         sig_len))
        return false;

    return true;
}

static bool __attribute__((noinline))
compute_tx_hashes(dispatcher_context_t *dc, sign_psbt_state_t *st, tx_hashes_t *hashes) {
    {
        // compute sha_prevouts and sha_sequences
        cx_sha256_t sha_prevouts_context, sha_sequences_context;

        // compute hashPrevouts and hashSequence
        cx_sha256_init(&sha_prevouts_context);
        cx_sha256_init(&sha_sequences_context);

        for (unsigned int i = 0; i < st->n_inputs; i++) {
            // get this input's map
            merkleized_map_commitment_t ith_map;
            int res = call_get_merkleized_map(dc, st->inputs_root, st->n_inputs, i, &ith_map);
            if (res < 0) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            // get prevout hash and output index for the i-th input
            uint8_t ith_prevout_hash[32];
            if (32 != call_get_merkleized_map_value(dc,
                                                    &ith_map,
                                                    (uint8_t[]){PSBT_IN_PREVIOUS_TXID},
                                                    1,
                                                    ith_prevout_hash,
                                                    32)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }
            // chester
            // get txid for bip322 message
            if (st->bbn_action_type == BBN_POLICY_BIP322) {
                memcpy(st->psbt_staker_pk, ith_prevout_hash, 32);  // to save memory
            }

            crypto_hash_update(&sha_prevouts_context.header, ith_prevout_hash, 32);

            uint8_t ith_prevout_n_raw[4];
            if (4 != call_get_merkleized_map_value(dc,
                                                   &ith_map,
                                                   (uint8_t[]){PSBT_IN_OUTPUT_INDEX},
                                                   1,
                                                   ith_prevout_n_raw,
                                                   4)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }
            crypto_hash_update(&sha_prevouts_context.header, ith_prevout_n_raw, 4);

            uint8_t ith_nSequence_raw[4];
            if (4 != call_get_merkleized_map_value(dc,
                                                   &ith_map,
                                                   (uint8_t[]){PSBT_IN_SEQUENCE},
                                                   1,
                                                   ith_nSequence_raw,
                                                   4)) {
                // if no PSBT_IN_SEQUENCE is present, we must assume nSequence 0xFFFFFFFF
                memset(ith_nSequence_raw, 0xFF, 4);
            }

            crypto_hash_update(&sha_sequences_context.header, ith_nSequence_raw, 4);
        }

        crypto_hash_digest(&sha_prevouts_context.header, hashes->sha_prevouts, 32);
        crypto_hash_digest(&sha_sequences_context.header, hashes->sha_sequences, 32);
    }

    {
        // compute sha_outputs
        cx_sha256_t sha_outputs_context;
        cx_sha256_init(&sha_outputs_context);

        if (hash_outputs(dc, st, &sha_outputs_context.header) == -1) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        crypto_hash_digest(&sha_outputs_context.header, hashes->sha_outputs, 32);
    }

    {
        // compute sha_amounts and sha_scriptpubkeys
        // TODO: could be skipped if there are no segwitv1 inputs to sign

        cx_sha256_t sha_amounts_context, sha_scriptpubkeys_context;

        cx_sha256_init(&sha_amounts_context);
        cx_sha256_init(&sha_scriptpubkeys_context);

        for (unsigned int i = 0; i < st->n_inputs; i++) {
            // get this input's map
            merkleized_map_commitment_t ith_map;

            int res = call_get_merkleized_map(dc, st->inputs_root, st->n_inputs, i, &ith_map);
            if (res < 0) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            uint64_t in_amount;
            uint8_t in_scriptPubKey[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
            size_t in_scriptPubKey_len;
            if (0 > get_amount_scriptpubkey_from_psbt(dc,
                                                      &ith_map,
                                                      &in_amount,
                                                      in_scriptPubKey,
                                                      &in_scriptPubKey_len)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }
            uint8_t in_amount_le[8];
            write_u64_le(in_amount_le, 0, in_amount);
            crypto_hash_update(&sha_amounts_context.header, in_amount_le, 8);

            crypto_hash_update_varint(&sha_scriptpubkeys_context.header, in_scriptPubKey_len);
            crypto_hash_update(&sha_scriptpubkeys_context.header,
                               in_scriptPubKey,
                               in_scriptPubKey_len);
        }

        crypto_hash_digest(&sha_amounts_context.header, hashes->sha_amounts, 32);
        crypto_hash_digest(&sha_scriptpubkeys_context.header, hashes->sha_scriptpubkeys, 32);
    }
    return true;
}

static bool __attribute__((noinline)) sign_transaction_input(dispatcher_context_t *dc,
                                                             sign_psbt_state_t *st,
                                                             sign_psbt_cache_t *sign_psbt_cache,
                                                             signing_state_t *signing_state,
                                                             keyexpr_info_t *keyexpr_info,
                                                             input_info_t *input,
                                                             unsigned int cur_input_index) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    // if the psbt does not specify the sighash flag for this input, the default
    // changes depending on the type of spend; therefore, we set it later.
    if (input->has_sighash_type) {
        // Get sighash type
        if (4 != call_get_merkleized_map_value_u32_le(dc,
                                                      &input->in_out.map,
                                                      (uint8_t[]){PSBT_IN_SIGHASH_TYPE},
                                                      1,
                                                      &input->sighash_type)) {
            PRINTF("Malformed PSBT_IN_SIGHASH_TYPE for input %d\n", cur_input_index);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    // Sign as segwit input iff it has a witness utxo
    if (!input->has_witnessUtxo) {
        LEDGER_ASSERT(keyexpr_info->key_expression_ptr->type == KEY_EXPRESSION_NORMAL,
                      "Only plain key expressions are valid for legacy inputs");
        // sign legacy P2PKH or P2SH

        // sign_non_witness(non_witness_utxo.vout[psbt.tx.input_[i].prevout.n].scriptPubKey, i)

        uint64_t tmp;  // unused
        if (0 > get_amount_scriptpubkey_from_psbt_nonwitness(dc,
                                                             &input->in_out.map,
                                                             &tmp,
                                                             input->in_out.scriptPubKey,
                                                             &input->in_out.scriptPubKey_len,
                                                             NULL)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        if (!input->has_sighash_type) {
            // legacy input default to SIGHASH_ALL
            input->sighash_type = SIGHASH_ALL;
        }

        uint8_t sighash[32];
        if (!compute_sighash_legacy(dc, st, input, cur_input_index, sighash)) return false;

        if (!sign_sighash_ecdsa_and_yield(dc, st, keyexpr_info, input, cur_input_index, sighash))
            return false;
    } else {
        {
            uint64_t amount;
            if (0 > get_amount_scriptpubkey_from_psbt_witness(dc,
                                                              &input->in_out.map,
                                                              &amount,
                                                              input->in_out.scriptPubKey,
                                                              &input->in_out.scriptPubKey_len)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            if (input->has_redeemScript) {
                // Get redeemScript
                // The redeemScript cannot be longer than standard scriptPubKeys for
                // wrapped segwit transactions that we support
                uint8_t redeemScript[MAX_PREVOUT_SCRIPTPUBKEY_LEN];

                int redeemScript_length =
                    call_get_merkleized_map_value(dc,
                                                  &input->in_out.map,
                                                  (uint8_t[]){PSBT_IN_REDEEM_SCRIPT},
                                                  1,
                                                  redeemScript,
                                                  sizeof(redeemScript));
                if (redeemScript_length < 0) {
                    PRINTF("Error fetching redeem script\n");
                    SEND_SW(dc, SW_INCORRECT_DATA);
                    return false;
                }

                uint8_t p2sh_redeemscript[2 + 20 + 1];
                p2sh_redeemscript[0] = 0xa9;
                p2sh_redeemscript[1] = 0x14;
                crypto_hash160(redeemScript, redeemScript_length, p2sh_redeemscript + 2);
                p2sh_redeemscript[22] = 0x87;

                if (input->in_out.scriptPubKey_len != 23 ||
                    memcmp(input->in_out.scriptPubKey, p2sh_redeemscript, 23) != 0) {
                    PRINTF("witnessUtxo's scriptPubKey does not match redeemScript\n");
                    SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_MISMATCHING_REDEEM_SCRIPT);
                    return false;
                }

                input->script_len = redeemScript_length;
                memcpy(input->script, redeemScript, redeemScript_length);
            } else {
                input->script_len = input->in_out.scriptPubKey_len;
                memcpy(input->script, input->in_out.scriptPubKey, input->in_out.scriptPubKey_len);
            }
        }

        int segwit_version = get_policy_segwit_version(st->wallet_policy_map);
        uint8_t sighash[32];
        if (segwit_version == 0) {
            LEDGER_ASSERT(keyexpr_info->key_expression_ptr->type == KEY_EXPRESSION_NORMAL,
                          "Only plain key expressions are valid for SegwitV0 inputs");
            if (!input->has_sighash_type) {
                // segwitv0 inputs default to SIGHASH_ALL
                input->sighash_type = SIGHASH_ALL;
            }

            if (!compute_sighash_segwitv0(dc,
                                          st,
                                          &signing_state->tx_hashes,
                                          input,
                                          cur_input_index,
                                          sighash))
                return false;

            if (!sign_sighash_ecdsa_and_yield(dc,
                                              st,
                                              keyexpr_info,
                                              input,
                                              cur_input_index,
                                              sighash))
                return false;
        } else if (segwit_version == 1) {
            if (!input->has_sighash_type) {
                // segwitv0 inputs default to SIGHASH_DEFAULT
                input->sighash_type = SIGHASH_DEFAULT;
            }

            if (!compute_sighash_segwitv1(dc,
                                          st,
                                          &signing_state->tx_hashes,
                                          input,
                                          cur_input_index,
                                          keyexpr_info,
                                          sighash))
                return false;

            policy_node_tr_t *policy = (policy_node_tr_t *) st->wallet_policy_map;
            if (!keyexpr_info->is_tapscript && !isnull_policy_node_tree(&policy->tree)) {
                // keypath spend, we compute the taptree hash so that we find it ready
                // later in sign_sighash_schnorr_and_yield (which has less available stack).
                if (0 > compute_taptree_hash(
                            dc,
                            st,
                            &(wallet_derivation_info_t){
                                .address_index = input->in_out.address_index,
                                .change = input->in_out.is_change ? 1 : 0,
                                .keys_merkle_root = st->wallet_header.keys_info_merkle_root,
                                .n_keys = st->wallet_header.n_keys,
                                .wallet_version = st->wallet_header.version,
                                .sign_psbt_cache = sign_psbt_cache},
                            r_policy_node_tree(&policy->tree),
                            input->taptree_hash)) {
                    PRINTF("Error while computing taptree hash\n");
                    SEND_SW(dc, SW_BAD_STATE);
                    return false;
                }
            }
            if (keyexpr_info->key_expression_ptr->type == KEY_EXPRESSION_NORMAL) {
                if (!sign_sighash_schnorr_and_yield(dc,
                                                    st,
                                                    keyexpr_info,
                                                    input,
                                                    cur_input_index,
                                                    sighash))
                    return false;
            } else {
                LEDGER_ASSERT(false, "unexpected key expression type");
                SEND_SW(dc, SW_BAD_STATE);  // can't happen
                return false;
            }

        } else {
            SEND_SW(dc, SW_BAD_STATE);  // can't happen
            return false;
        }
    }
    return true;
}

static bool __attribute__((noinline))
fill_taproot_keyexpr_info(dispatcher_context_t *dc,
                          sign_psbt_state_t *st,
                          const input_info_t *input,
                          const policy_node_t *tapleaf_ptr,
                          keyexpr_info_t *keyexpr_info,
                          sign_psbt_cache_t *sign_psbt_cache) {
    cx_sha256_t hash_context;
    crypto_tr_tapleaf_hash_init(&hash_context);

    wallet_derivation_info_t wdi = {.wallet_version = st->wallet_header.version,
                                    .keys_merkle_root = st->wallet_header.keys_info_merkle_root,
                                    .n_keys = st->wallet_header.n_keys,
                                    .change = input->in_out.is_change,
                                    .address_index = input->in_out.address_index,
                                    .sign_psbt_cache = sign_psbt_cache};

    // we compute the tapscript once just to compute its length
    // this avoids having to store it
    int tapscript_len = get_wallet_internal_script_hash(dc,
                                                        st,
                                                        tapleaf_ptr,
                                                        &wdi,
                                                        WRAPPED_SCRIPT_TYPE_TAPSCRIPT,
                                                        NULL);
    if (tapscript_len < 0) {
        PRINTF("Failed to compute tapleaf script\n");
        return false;
    }

    crypto_hash_update_u8(&hash_context.header, 0xC0);
    crypto_hash_update_varint(&hash_context.header, tapscript_len);

    // we compute it again to get add the actual script code to the hash computation
    if (0 > get_wallet_internal_script_hash(dc,
                                            st,
                                            tapleaf_ptr,
                                            &wdi,
                                            WRAPPED_SCRIPT_TYPE_TAPSCRIPT,
                                            &hash_context.header)) {
        PRINTF("get_wallet_internal_script_hash fail\n");
        return false;  // should never happen!
    }
    crypto_hash_digest(&hash_context.header, keyexpr_info->tapleaf_hash, 32);

    return true;
}

static bool __attribute__((noinline)) sign_transaction(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    sign_psbt_cache_t *sign_psbt_cache,
    signing_state_t *signing_state,
    const uint8_t internal_outputs[static BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);
    int key_expression_index = 0;
    // Iterate over all the key expressions that correspond to keys owned by us
    for (size_t i_keyexpr = 0; i_keyexpr < st->n_internal_key_expressions; i_keyexpr++) {
        keyexpr_info_t *keyexpr_info = &st->internal_key_expressions[i_keyexpr];
        if (!fill_keyexpr_info_if_internal(dc, st, keyexpr_info) == true) {
            PRINTF("fill_keyexpr_info_if_internal XX\n");
            continue;
        }
        for (unsigned int i = 0; i < st->n_inputs; i++) {
            input_info_t input;
            memset(&input, 0, sizeof(input));

            input_keys_callback_data_t callback_data = {.input = &input, .state = st};
            int res = call_get_merkleized_map_with_callback(
                dc,
                (void *) &callback_data,
                st->inputs_root,
                st->n_inputs,
                i,
                (merkle_tree_elements_callback_t) input_keys_callback,
                &input.in_out.map);
            if (res < 0) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }
            if (keyexpr_info->tapleaf_ptr != NULL &&
                !fill_taproot_keyexpr_info(dc,
                                           st,
                                           &input,
                                           keyexpr_info->tapleaf_ptr,
                                           keyexpr_info,
                                           sign_psbt_cache)) {
                return false;
            }
            // check if the name in list, if not deny
            // then display it to user for confirmation
            if (!st->is_wallet_default) {
                if (st->psbt_display_once == 0) {
                    if (!ui_authorize_wallet_spend(dc, st->wallet_header.name)) {
                        PRINTF("ui_authorize_wallet_spend fail \n");
                        SEND_SW(dc, SW_DENY);
                        return false;
                    }
                }
            }
            if (st->bbn_action_type == BBN_POLICY_SLASHING ||
                st->bbn_action_type == BBN_POLICY_SLASHING_UNBONDING) {
                uint8_t slashing_leafhash[32];
                // BAP-010
                compute_bbn_leafhash_slasing(st, slashing_leafhash);
                if (memcmp(st->psbt_leafhash, slashing_leafhash, 32) != 0) {
                    PRINTF_BUF(st->psbt_leafhash, 32);
                    PRINTF_BUF(slashing_leafhash, 32);
                    PRINTF("bbn_check_slashing leafhash fail\n");
                    SEND_SW(dc, SW_DENY);
                    return false;
                }
                if (!bbn_check_slashing(st)) {
                    PRINTF("bbn_check_slashing fail\n");
                    SEND_SW(dc, SW_DENY);
                    return false;
                }
            }
            // chester
            // BAP-008
            // for the most important operation, staking
            // we re-compute the address by all the informaiton
            // three taproot script in babylon protocol
            // get the merkle root and tweak the pubkey
            // to VALIDATION to address is right
            // if the address checked, then it means all the information
            // including the slashing script, timelock script and
            // unbonding script is right
            // the confirmation task for users is quite normal
            // to confirm the value like amount they input from front-end
            if (st->bbn_action_type == BBN_POLICY_STAKE_TRANSFER) {
                if (!bbn_check_address(st)) {
                    PRINTF("bbn_check_address fail\n");
                    SEND_SW(dc, SW_DENY);
                    return false;
                }
            }
            if (st->bbn_action_type == BBN_POLICY_UNBOND) {
                if (!bbn_check_unbond(st)) {
                    PRINTF("bbn_check_unbond fail\n");
                    SEND_SW(dc, SW_DENY);
                    return false;
                }
                uint8_t unbond_leafhash[32];
                // BAP-010
                compute_bbn_leafhash_unbonding(st, unbond_leafhash);
                if (memcmp(st->psbt_leafhash, unbond_leafhash, 32) != 0) {
                    PRINTF("bbn_check_unbond leafhash fail\n");
                    SEND_SW(dc, SW_DENY);
                    return false;
                }
                memcpy(st->psbt_leafhash, unbond_leafhash, 32);
                st->psbt_leafhash_state = BBN_LEAF_HASH_CHECK;
            }

            if (st->psbt_display_once == 0) {
                if (st->bbn_action_type == BBN_POLICY_BIP322 &&
                    !bbn_check_and_display_message(dc, st)) {
                    SEND_SW(dc, SW_DENY);
                    PRINTF("bbn_check_and_display_message fail\n");
                    return false;
                }
                if (st->bbn_action_type == BBN_POLICY_SLASHING ||
                    st->bbn_action_type == BBN_POLICY_SLASHING_UNBONDING ||
                    st->bbn_action_type == BBN_POLICY_STAKE_TRANSFER ||
                    st->bbn_action_type == BBN_POLICY_UNBOND) {
                    if (!display_bbn_pk(dc, st)) {
                        PRINTF("display_bbn_pk fail \n");
                        return false;
                    }
                }
                if (st->bbn_action_type == BBN_POLICY_STAKE_TRANSFER ||
                    st->bbn_action_type == BBN_POLICY_UNBOND) {
                    if (!display_bbn_timelock(dc, st)) {
                        PRINTF("display_bbn_timelock fail \n");
                        return false;
                    }
                }

                if (!display_transaction(dc, st, internal_outputs)) return false;
                io_show_processing_screen();
                st->psbt_display_once = 1;
            }
            if (!sign_transaction_input(dc,
                                        st,
                                        sign_psbt_cache,
                                        signing_state,
                                        keyexpr_info,
                                        &input,
                                        i)) {
                // we do not send a status word, since sign_transaction_input
                // already does it on failure
                return false;
            }
        }
        ++key_expression_index;
    }

    return true;
}

// We declare this in the global space in order to use less stack space, since BOLOS enforces on
// some devices an 8kb stack limit.
// Once this is resolved in BOLOS, we should move this to the function scope to avoid unnecessarily
// reserving RAM that can only be used for the signing flow (which, at time of writing, is the most
// RAM-intensive operation command of the app).
sign_psbt_cache_t G_sign_psbt_cache;

void handler_sign_psbt(dispatcher_context_t *dc, uint8_t protocol_version) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);
    sign_psbt_state_t st;
    memset(&st, 0, sizeof(st));
    st.protocol_version = protocol_version;

    // read APDU inputs, intialize global state and read global PSBT map
    if (!init_global_state(dc, &st)) return;
    sign_psbt_cache_t *cache = &G_sign_psbt_cache;
    init_sign_psbt_cache(cache);
    // bitmap to keep track of which inputs are internal
    uint8_t internal_inputs[BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)];
    memset(internal_inputs, 0, sizeof(internal_inputs));

    // bitmap to keep track of which inputs are internal
    uint8_t internal_outputs[BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)];
    memset(internal_outputs, 0, sizeof(internal_outputs));

    /** Inputs verification flow
     *
     *  Go though all the inputs:
     *  - verify the non_witness_utxo
     *  - compute value spent
     *  - detect internal inputs that should be signed, and if there are external inputs or unusual
     * sighashes
     */
    if (!preprocess_inputs(dc, &st, internal_inputs)) return;
    /** OUTPUTS VERIFICATION FLOW
     *
     *  For each output, check if it's a change address.
     *  Check if it's an acceptable output.
     */
    if (!preprocess_outputs(dc, &st, cache, internal_outputs)) return;
    signing_state_t signing_state;
    memset(&signing_state, 0, sizeof(signing_state));

    if (!compute_tx_hashes(dc, &st, &signing_state.tx_hashes)) {
        return;
    }

    /** SIGNING FLOW
     *
     * For each internal key expression, and for each internal input, sign using the
     * appropriate algorithm.
     */
    int sign_result = sign_transaction(dc, &st, cache, &signing_state, internal_outputs);
    ui_post_processing_confirm_transaction(dc, sign_result);
    if (!sign_result) {
        return;
    }
    SEND_SW(dc, SW_OK);
}

static inline unsigned int count_psbt_covenant_pk_state(
    const uint32_t state_array[BBN_COV_PUBKEY_MAX_COUNT]) {
    int count = 0;
    for (unsigned int i = 0; i < BBN_COV_PUBKEY_MAX_COUNT; i++) {
        if (state_array[i] == 1) {
            count++;
        }
    }
    return count;
}
