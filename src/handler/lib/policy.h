#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/wallet.h"
#include "../../handler/sign_psbt/sign_psbt_cache.h"
#include "../sign_psbt.h"

/**
 * Parses a serialized wallet policy, saving the wallet header, the policy map descriptor and the
 * policy descriptor. Then, it parses the descriptor into the Abstract Syntax Tree into the
 * policy_map_bytes array.
 *
 * It returns -1 if any error occurs.
 *
 * @param dispatcher_context Pointer to the dispatcher content
 * @param buf Pointer to the buffer from which the serialized policy is read from
 * @param wallet_header Pointer to policy_map_wallet_header_t that will receive the policy map
 * header
 * @param policy_map_descriptor_template Pointer to a buffer of MAX_DESCRIPTOR_TEMPLATE_LENGTH bytes
 * that will contain the descriptor template as a string
 * @param policy_map_bytes Pointer to an array of bytes that will be used for the parsed abstract
 * syntax tree
 * @param policy_map_bytes_len Length of policy_map_bytes in bytes.
 * @return The memory size of the parsed descriotor template on success, a negative number in case
 * of error.
 */
// TODO: we should distinguish actual errors from just "policy too big to fit in memory"
__attribute__((warn_unused_result)) int read_and_parse_wallet_policy(
    dispatcher_context_t *dispatcher_context,
    sign_psbt_state_t *st,
    buffer_t *buf,
    policy_map_wallet_header_t *wallet_header,
    uint8_t policy_map_descriptor[static MAX_DESCRIPTOR_TEMPLATE_LENGTH],
    uint8_t *policy_map_bytes,
    size_t policy_map_bytes_len,
    bool is_sign);

typedef enum {
    WRAPPED_SCRIPT_TYPE_SH,
    WRAPPED_SCRIPT_TYPE_WSH,
    WRAPPED_SCRIPT_TYPE_SH_WSH,
    WRAPPED_SCRIPT_TYPE_TAPSCRIPT
} internal_script_type_e;

// Bundles together some parameters relative to a call to
// get_wallet_script or get_wallet_internal_script_hash
typedef struct {
    int wallet_version;  // The wallet policy version, either WALLET_POLICY_VERSION_V1 or
                         // WALLET_POLICY_VERSION_V2
    const uint8_t
        *keys_merkle_root;  // The Merkle root of the tree of key informations in the policy
    uint32_t n_keys;        // The number of key information elements in the policy
    size_t address_index;   // The address index to use in the derivation
    bool change;            // whether a change address or a receive address is derived
    sign_psbt_cache_t
        *sign_psbt_cache;  // If not NULL, the cache for key derivations used during signing
} wallet_derivation_info_t;

/**
 * Requests and parses the serialized extended public key from the client.
 *
 * @param[in] dispatcher_context Pointer to the dispatcher content
 * @param[in] wdi Pointer to a `wallet_derivation_info_t` struct with the details of the
 * necessary details of the wallet policy. The change/addr_index pairs are not
 * @param[in] key_index Index of the pubkey in the vector of keys of the wallet policy.
 * @param[out] out Pointer to a `serialized_extended_pubkey_t` that will contain the requested
 * extended pubkey.
 *
 * @return // returns: -1 on error, 0 if the Fingerprint is known,l en of the derivation path if the
 * fingerprint is unknown
 */
__attribute__((warn_unused_result)) int get_extended_pubkey_from_client(
    dispatcher_context_t *dispatcher_context,
    const wallet_derivation_info_t *wdi,
    int key_index,
    serialized_extended_pubkey_t *out);

/**
 * Computes the hash of a taptree, to be used as tweak for the internal key per BIP-0341;
 * The returned hash is the second value in the tuple returned by taproot_tree_helper in
 * BIP-0341, assuming leaf_version 0xC0.
 *
 * @param[in] dispatcher_context
 *   Pointer to the dispatcher context
 * @param[in] wdi
 *   Pointer to a wallet_derivation_info_t structure containing multiple other parameters
 * @param[in] tree
 *   Pointer to the root of the taptree
 * @param[out] out
 *   A buffer of 32 bytes to receive the output
 *
 * @return 0 on success, a negative number on failure.
 */
__attribute__((warn_unused_result)) int compute_taptree_hash(
    dispatcher_context_t *dispatcher_context,
    sign_psbt_state_t *st,
    const wallet_derivation_info_t *wdi,
    const policy_node_tree_t *tree,
    uint8_t out[static 32]);

/**
 * Computes the script corresponding to a wallet policy, for a certain change and address index.
 *
 * @param[in] dispatcher_context
 *   Pointer to the dispatcher context
 * @param[in] policy
 *   Pointer to the root node of the policy
 * @param[in] wdi
 *   Pointer to a wallet_derivation_info_t structure containing multiple other parameters
 * @param[out] out
 *   A buffer of at least 34 bytes to contain the script. The actual length of the output might be
 * smaller.
 *
 * @return The length of the output on success; -1 in case of error.
 *
 */
__attribute__((warn_unused_result)) int get_wallet_script(dispatcher_context_t *dispatcher_context,
                                                          const policy_node_t *policy,
                                                          const wallet_derivation_info_t *wdi,
                                                          uint8_t out[static 34]);

/**
 * Computes the script corresponding to a wallet policy, for a certain change and address index.
 *
 * @param[in] dispatcher_context
 *   Pointer to the dispatcher context
 * @param[in] policy
 *   Pointer to the root node of the policy
 * @param[in] wdi
 *   Pointer to a wallet_derivation_info_t structure containing multiple other parameters
 * @param[out] hash_context
 *   A pointer to an already initialized hash context that will be updated with the bytes from the
 * produced script. If NULL, it is ignored.
 *
 * @return the length of the script on success; a negative number in case of error.
 *
 */
__attribute__((warn_unused_result)) int get_wallet_internal_script_hash(
    dispatcher_context_t *dispatcher_context,
    sign_psbt_state_t *st,
    const policy_node_t *policy,
    const wallet_derivation_info_t *wdi,
    internal_script_type_e script_type,
    cx_hash_t *hash_context);

/**
 * Returns the address type constant corresponding to a standard policy type.
 *
 * @param[in] policy
 *   Pointer to the root node of the policy
 *
 * @return One of, ADDRESS_TYPE_LEGACY, ADDRESS_TYPE_WIT, ADDRESS_TYPE_SH_WIT, ADDRESS_TYPE_TR if
 * the policy pattern is one of the expected types; -1 otherwise.
 */
int get_policy_address_type(const policy_node_t *policy);

/**
 * Returns true if the descriptor template is a standard one.
 * Standard wallet policies are single-signature policies as per the following standards:
 *  - BIP-44 (legacy, P2PKH)
 *  - BIP-84 (native segwit, P2WPKH)
 *  - BIP-49 (wrapped segwit, P2SH-P2WPKH)
 *  - BIP-86 (standard single key P2TR)
 * with the standard derivations for the key placeholders, and unhardened steps for the
 * change / address_index steps (using 0 for non-change, 1 for change addresses).
 *
 * @param[in] dispatcher_context
 *   Pointer to the dispatcher context
 * @param[in] wallet_policy_header
 *   Pointer the wallet policy header
 * @param[in] descriptor_template
 *   Pointer to the root node of the policy
 *
 * @return true if the descriptor_template is not standard; false if not, or in case of error.
 */
__attribute__((warn_unused_result)) bool is_wallet_policy_standard(
    dispatcher_context_t *dispatcher_context,
    const policy_map_wallet_header_t *wallet_policy_header,
    const policy_node_t *descriptor_template);

/**
 * Computes and returns the wallet_hmac, using the symmetric key derived
 * with the WALLET_SLIP0021_LABEL label according to SLIP-0021.
 *
 * @param[in] wallet_id
 *   Pointer to the a 32-bytes array containing the 32-byte wallet policy id.
 * @param[out] wallet_hmac
 *   Pointer to the a 32-bytes array containing the wallet policy registration hmac.
 * @return true if the given hmac is valid, false otherwise.
 */
bool compute_wallet_hmac(const uint8_t wallet_id[static 32], uint8_t wallet_hmac[static 32]);

/**
 * Verifies if the wallet_hmac is correct for the given wallet_id, using the symmetric key derived
 * with the WALLET_SLIP0021_LABEL label according to SLIP-0021.
 *
 * @param[in] wallet_id
 *   Pointer to the a 32-bytes array containing the 32-byte wallet policy id.
 * @param[in] wallet_hmac
 *   Pointer to the a 32-bytes array containing the expected wallet policy registration hmac.
 * @return true if the given hmac is valid, false otherwise.
 */
bool check_wallet_hmac(const uint8_t wallet_id[static 32], const uint8_t wallet_hmac[static 32]);

/**
 * Copies the i-th key expression (indexing from 0) of the given policy into `out_keyexpr` (if not
 * null).
 *
 * @param[in] policy
 *   Pointer to the root node of the policy
 * @param[in] i
 *   Index of the wanted key expression. Ignored if out_keyexpr is NULL.
 * @param[out] out_tapleaf_ptr
 *   If not NULL, and if the i-th key expression is in a tapleaf of the policy, receives the pointer
 * to the tapleaf's script.
 * @param[out] out_keyexpr
 *   If not NULL, it is a pointer that will receive a pointer to the i-th key expression of the
 * policy.
 * @return the number of key expressions in the policy on success; -1 in case of error.
 */
__attribute__((warn_unused_result)) int get_keyexpr_by_index(const policy_node_t *policy,
                                                             unsigned int i,
                                                             const policy_node_t **out_tapleaf_ptr,
                                                             policy_node_keyexpr_t **out_keyexpr);

/**
 * Determines the expected number of unique keys in the provided policy's key information.
 * The function calculates this by finding the maximum key index from key expressions and increments
 * it by 1. For instance, if the maximum key index found in the key expressions is `n`, then the
 * result would be `n + 1`.
 *
 * @param[in] policy
 *   Pointer to the root node of the policy
 * @return the expected number of items in the keys information vector; -1 in case of error.
 */
__attribute__((warn_unused_result)) int count_distinct_keys_info(const policy_node_t *policy);

/**
 * Checks if a wallet policy is sane, verifying that pubkeys are never repeated and (if miniscript)
 * that the miniscript is "sane".
 * @param[in] dispatcher_context
 *   Pointer to the dispatcher context
 * @param[in] policy
 *   Pointer to the root node of the policy
 * @param[in] wallet_version
 *   The version of the wallet policy (since it affects the format of keys in the vector of keys)
 * @param[in] keys_merkle_root
 *   The root of the Merkle tree of the vector of keys information in the wallet policy
 * @param[in] n_keys
 *   The number of keys in the vector of keys
 * @return 0 on success; -1 in case of error.
 */
__attribute__((warn_unused_result)) int is_policy_sane(dispatcher_context_t *dispatcher_context,
                                                       const policy_node_t *policy,
                                                       int wallet_version,
                                                       const uint8_t keys_merkle_root[static 32],
                                                       uint32_t n_keys);


#ifdef BBN_PRT_BUF
#define PRINTF_BUF(ptr, len) \
    do {                     \
    } while (0)
#else
#define PRINTF_BUF(ptr, len)                              \
    do {                                                  \
        PRINTF("Buffer: ");                               \
        for (uint32_t i = 0; i < (uint32_t) (len); i++) { \
            PRINTF("%02X", (ptr)[i]);                     \
        }                                                 \
        PRINTF("\n");                                     \
    } while (0)
#endif

#define BBN_NULL_FP             ((uint8_t[]){0x00, 0x00, 0x00, 0x00})
#define BBN_LEAFHASH_DISPLAY_FP ((uint8_t[]){0x69, 0x84, 0x6d, 0x00})
#define BBN_LEAFHASH_CHECK_FP   ((uint8_t[]){0x3b, 0x9f, 0x96, 0x80})
#define BBN_FINALITY_PUB_FP     ((uint8_t[]){0xff, 0x11, 0x94, 0x73})
#define BBN_BIP322_MESSAGE      ((uint8_t[]){0x83, 0x87, 0x16, 0x19})
#define BBN_BIP322_TAPPUB       ((uint8_t[]){0x25, 0x27, 0x04, 0x17})
typedef enum {
    FP_NULL,
    FP_LEAF_HASH_DISPLY,
    FP_LEAF_HASH_CHECK,
    FP_FINALITY_PUB,
    FP_BIP322_MESSAGE,
    FP_BIP322_TAPPUB,
    FP_OTHER

} BBN_FingerPrintType;

#define BBN_POLICY_NAME_MAX_LEN 128

#define BBN_POLICY_NAME_SLASHING           "Consent to slashing"
#define BBN_POLICY_NAME_SLASHING_UNBONDING "Consent to unbonding slashing"
#define BBN_POLICY_NAME_STAKE_TRANSFER     "Staking transaction"
#define BBN_POLICY_NAME_UNBOND             "Unbonding"
#define BBN_POLICY_NAME_WITHDRAW           "Withdraw"
#define BBN_POLICY_NAME_BIP322_MESSAGE     "Sign message"

typedef enum {
    BBN_POLICY_UNKNOWN = -1,
    BBN_POLICY_SLASHING,
    BBN_POLICY_SLASHING_UNBONDING,
    BBN_POLICY_STAKE_TRANSFER,
    BBN_POLICY_UNBOND,
    BBN_POLICY_WITHDRAW,
    BBN_POLICY_BIP322,
} bbn_policy_type_t;

BBN_FingerPrintType get_fingerprint(const uint8_t fingerprint[static 4]);

int get_action_type(const char *str);
#define BBN_DESCRIPTOR_MAX_LEN            512
#define BBN_DESCRIPTOR_SLASHING "tr(@0/**,and_v(and_v(pk_k(@1/**),and_v(pk_k(@2/**),multi_a("
#define BBN_DESCRIPTOR_SLASHING_UNBONDING \
    "tr(@0/**,and_v(and_v(pk_k(@1/**),and_v(pk_k(@2/**),multi_a("
#define BBN_DESCRIPTOR_STAKE_TRANSFER "tr(@0/**,and_v(and_v(pk_k(@1/**),and_v(pk_k(@2/**),multi_a("
#define BBN_DESCRIPTOR_UNBOND         "tr(@0/**,and_v(and_v(pk_k(@1/**),and_v(pk_k(@2/**),multi_a("
#define BBN_DESCRIPTOR_WITHDRAW       "tr(@0/**,and_v(pk_k(@1/**),older"
#define BBN_DESCRIPTOR_BIP322         "tr(@0/**,and_v(pk_k(@1/**),pk_k(@2/**)))"

#define isdigit(c) ((unsigned) ((c) - '0') < 10)
#define isalpha(c) ((((c) >= 'A' && (c) <= 'Z')) || (((c) >= 'a' && (c) <= 'z')))

#define BBN_UNBONDING_MAX_FEE_CONST 9000
#define BBN_UNBONDING_MIN_FEE_CONST 1000
#define BBN_SLASHING_MAX_FEE_CONST  9000
#define BBN_SLASHING_MIN_FEE_CONST  1000

bool check_descriptor(const char *s, bbn_policy_type_t type);
