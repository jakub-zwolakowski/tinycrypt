
#include <tis_builtin.h>

#include <tinycrypt/ecc.h>
#include <tinycrypt/ecc_dh.h>
#include <tinycrypt/ecc_platform_specific.h>
#include <test_ecc_utils.h>
#include <test_utils.h>
#include <tinycrypt/constants.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

int TIS_test(void) {

	unsigned int native[NUM_ECC_BYTES];
	uint8_t input_bytes[NUM_ECC_BYTES];
	uint8_t output_bytes[NUM_ECC_BYTES];

	const struct uECC_Curve_t * curve = uECC_secp256r1();

	/* Setup of the Cryptographically Secure PRNG. */
	uECC_set_rng(&default_CSPRNG);

	tis_make_unknown(input_bytes, sizeof(input_bytes));

	uECC_vli_bytesToNative (native, input_bytes, NUM_ECC_BYTES);

	/*
	* @brief Converts an integer in uECC native format to big-endian bytes.
	* @param bytes OUT -- bytes representation
	* @param num_bytes IN -- number of bytes
	* @param native IN -- uECC native representation
	*/
	uECC_vli_nativeToBytes(output_bytes, NUM_ECC_BYTES, native);

	/*
	* @brief Check if a public key is valid.
	* @param public_key IN -- The public key to be checked.
	* @return returns 0 if the public key is valid
	* @exception returns -1 if it is a point at infinity
	* @exception returns -2 if x or y is smaller than p,
	* @exception returns -3 if y^2 != x^3 + ax + b.
	* @exception returns -4 if public key is the group generator.
	*
	* @note Note that you are not required to check for a valid public key before
	* using any other uECC functions. However, you may wish to avoid spending CPU
	* time computing a shared secret or verifying a signature using an invalid
	* public key.
	*/
	uECC_word_t public_key[2 * NUM_ECC_WORDS];
	tis_make_unknown(public_key, sizeof(public_key));

	uECC_valid_public_key(public_key, curve);

	/*
	* @brief check if it is a valid point in the curve
	* @param point IN -- point to be checked
	* @param curve IN -- elliptic curve
	* @return 0 if point is valid
	* @exception returns -1 if it is a point at infinity
	* @exception returns -2 if x or y is smaller than p,
	* @exception returns -3 if y^2 != x^3 + ax + b.
	*/
	uECC_valid_point(public_key, curve);

	/*
	* @brief Compute the corresponding public key for a private key.
	* @param private_key IN -- The private key to compute the public key for
	* @param public_key OUT -- Will be filled in with the corresponding public key
	* @param curve
	* @return Returns 1 if key was computed successfully, 0 if an error occurred.
	*/
	uECC_word_t private[NUM_ECC_WORDS];
	uECC_word_t public[2 * NUM_ECC_WORDS];

	tis_make_unknown(private, sizeof(private));

	uECC_compute_public_key(private, public, curve);

	/*
	* @brief Generates a random integer in the range 0 < random < top.
	* Both random and top have num_words words.
	* @param random OUT -- random integer in the range 0 < random < top
	* @param top IN -- upper limit
	* @param num_words IN -- number of words
	* @return a random integer in the range 0 < random < top
	*/
	uECC_word_t tmp1[NUM_ECC_WORDS];
	uECC_word_t tmp2[NUM_ECC_WORDS];
	uECC_word_t index;
	uECC_word_t *p_tmp[2] = {tmp1, tmp2};

	wordcount_t num_n_words = BITS_TO_WORDS(curve->num_n_bits);

	tis_make_unknown(tmp1, sizeof(tmp1));
	tis_make_unknown(tmp2, sizeof(tmp2));

	index = tis_interval (0,1);
	uECC_generate_random_int(p_tmp[index], curve->p, num_n_words);

	uECC_curve_private_key_size(curve);
	uECC_curve_public_key_size(curve);

	/*
	* @brief Regularize the bitcount for the private key so that attackers cannot
	* use a side channel attack to learn the number of leading zeros.
	* @return Regularized k
	* @param k IN -- private-key
	* @param k0 IN/OUT -- regularized k
	* @param k1 IN/OUT -- regularized k
	* @param curve IN -- elliptic curve
	*/
	uECC_word_t private[NUM_ECC_WORDS];

	tis_make_unknown(private, sizeof(private));
	tis_make_unknown(tmp1, sizeof(tmp1));
	tis_make_unknown(tmp2, sizeof(tmp2));

	regularize_k(private, tmp1, tmp2, curve);

	return TC_PASS;
}
