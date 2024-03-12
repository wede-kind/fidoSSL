#include <openssl/ssl.h>
#include "types.h"

/**
 * Encodes a binary input into a Base64 encoded string.
 * 
 * @param input Pointer to the input buffer containing binary data to encode.
 * @param input_len Length of the input buffer in bytes.
 * @param output Pointer to a char pointer where the Base64 encoded string will be stored.
 *               The function allocates memory for the encoded string, which should be
 *               freed by the caller.
 * @return int Returns 0 on success, non-zero error code otherwise.
 */
int base64_encode(const u8 *input, size_t input_len, char** output);

/**
 * Decodes a Base64 encoded string back into binary data.
 * 
 * @param input Pointer to the null-terminated Base64 encoded string to decode.
 * @param output Pointer to a pointer to an unsigned char buffer where the decoded
 *               binary data will be stored. The function allocates memory for the
 *               decoded data, which should be freed by the caller.
 * @param output_len Pointer to a size_t variable where the length of the decoded
 *                   data will be stored.
 * @return int Returns 0 on success, non-zero error code otherwise.
 */
int base64_decode(const char *input, u8 **output, size_t *output_len);

/**
 * Encodes a binary input into a Base64url encoded string.
 * Base64url is a URL-safe version of Base64 encoding, which uses different characters
 * for padding and does not include line breaks.
 * 
 * @param input Pointer to the input buffer containing binary data to encode.
 * @param input_len Length of the input buffer in bytes.
 * @param output Pointer to a char pointer where the Base64url encoded string will be stored.
 *               The function allocates memory for the encoded string, which should be
 *               freed by the caller.
 * @return int Returns 0 on success, non-zero error code otherwise.
 */
int base64url_encode(const u8 *input, size_t input_len, char** output);

/**
 * Decodes a Base64url encoded string back into binary data.
 * 
 * @param input Pointer to the null-terminated Base64url encoded string to decode.
 * @param output Pointer to a pointer to an unsigned char buffer where the decoded
 *               binary data will be stored. The function allocates memory for the
 *               decoded data, which should be freed by the caller.
 * @param output_len Pointer to a size_t variable where the length of the decoded
 *                   data will be stored.
 * @return int Returns 0 on success, non-zero error code otherwise.
 */
int base64url_decode(const char *input, u8 **output, size_t *output_len);
