#ifndef MASTER_PROJECT_HIBE_H
#define MASTER_PROJECT_HIBE_H

#include <relic/relic.h>

typedef struct _hibe_system_params_t {
    struct {
        ep_t g1_g;
        ep2_t g2_g;
    } g[3];
    int hLen;
    struct {
        ep_t g1_h;
        ep2_t g2_h;
    } h[];
} hibe_system_params_t;

typedef struct _hibe_setup_pair_t {
    ep_t masterKey;
    hibe_system_params_t *systemParams;
} hibe_setup_pair_t;

typedef struct _hibe_private_key_t {
    ep_t a0;
    ep_t a1;
    size_t bLen;
    ep_t b[];
} hibe_private_key_t;

typedef struct _hibe_ciphertext_t {
    ep2_t b;
    ep2_t c;
    int aLen;
    uint8_t a[];
} hibe_ciphertext_t;

/**
 * Sets up the Boneh-Boyen-Goy Hierarchical Identity Based Encryption (hibe) scheme.
 *
 * @param setupPair                 - the hibe setup pair containing system parameters and master key.
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
int hibe_setup(hibe_setup_pair_t *setupPair);

/**
 * Generates a private key for a specific node id using the master key.
 *
 * @param privateKey[out]           - the private key for the given node id.
 * @param systemParams[in]          - system parameters.
 * @param masterKey[in]             - master key.
 * @param id[in]                    - node id for which a key should be generated.
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
int hibe_extract(hibe_private_key_t *privateKey, hibe_system_params_t *systemParams, ep_t masterKey, const char *id);

/**
 * Generates a private key for a specific node id using the private key of a direct parent. Private keys of deeper
 * descendants can be generated by using this function incrementally.
 *
 * @param privateKey[out]           - the private key for the given node id.
 * @param systemParams[in]          - system parameters.
 * @param parentPrivateKey[in]      - private key of the parent.
 * @param id[in]                    - node id for which a key should be generated, has to be a direct child of the parent (e.g. if the given private key is for a node "01", possible values are "010" or "011").
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
int hibe_derive(hibe_private_key_t *privateKey, hibe_system_params_t *systemParams, hibe_private_key_t *parentPrivateKey, const char *id);

/**
 * Encrypts a given message under the specific node id.
 *
 * @param ciphertext[out]           - the ciphertext in form of CT = (A, B, C).
 * @param systemParams[in]          - system parameters.
 * @param id[in]                    - node id in the binary form (e.g. "001" to represent the second node on the 3rd level of the tree).
 * @param message[in]               - message to be encrypted.
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
int hibe_encrypt(hibe_ciphertext_t *ciphertext, hibe_system_params_t *systemParams, const char *id, uint8_t *message);

/**
 * Decrypts a given ciphertext. Private key is to be generated by calling hibe_extract() or hibe_derive() functions.
 *
 * @param message[out]              - the returned decrypted message.
 * @param ciphertext[in]            - ciphertext.
 * @param privateKey[in]            - private key to be used for decrypting, has to be of the same node under which the message was originally encrypted.
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
int hibe_decrypt(uint8_t *message, hibe_ciphertext_t *ciphertext, hibe_private_key_t *privateKey);

/**
 * Frees the memory allocated by the hibe system parameters. This method has to be called after the system parameters
 * are no longer needed to avoid memory leaks.
 *
 * @param systemParams              - the corresponding system parameters.
 */
void hibe_free_system_params(hibe_system_params_t *systemParams);

/**
 * Allocates the memory for the hibe setup pair.
 *
 * @param depth                     - depth of the full private keys tree.
 * @return Hibe setup pair struct.
 */
hibe_setup_pair_t *hibe_init_setup_pair(int depth);

/**
 * Frees the memory allocated by the hibe setup pair. This method has to be called after the setup pair is no longer
 * needed to avoid memory leaks.
 *
 * @param setupPair                 - the corresponding setup pair.
 */
void hibe_free_setup_pair(hibe_setup_pair_t *setupPair);

/**
 * Allocates the memory for the hibe private key.
 *
 * @param systemParams              - system parameters.
 * @param id                        - node id for which a key should be generated.
 * @return The hibe private key struct.
 */
hibe_private_key_t *hibe_init_private_key(hibe_system_params_t *systemParams, const char *id);

/**
 * Frees the memory allocated by the hibe private key. This method has to be called after the private key is no longer
 * needed to avoid memory leaks.
 *
 * @param privateKey                - the corresponding private key.
 */
void hibe_free_private_key(hibe_private_key_t *privateKey);

/**
 * Allocates the memory for the hibe ciphertext.
 *
 * @param messageLen                - length of message in bytes.
 * @return The hibe ciphertext struct.
 */
hibe_ciphertext_t *hibe_init_ciphertext(int messageLen);

/**
 * Frees the memory allocated by the hibe ciphertext. This method has to be called after the ciphertext is no longer
 * needed to avoid memory leaks.
 *
 * @param ciphertext                - the corresponding ciphertext.
 */
void hibe_free_ciphertext(hibe_ciphertext_t *ciphertext);

#endif //MASTER_PROJECT_HIBE_H