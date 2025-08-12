#include "common.h"
#include "types.h"
#include "debug.h"
#include "rp.h"

int test_parse_authdata() {
    debug_printf(DEBUG_LEVEL_VERBOSE, "TEST: parse_authdata");

    char *hex = "c46cef82ad1b546477591d008b08759ec3e6d2ecb4f39474bfea6969925d03b74100000002000000000000000000000000000000000030e6e5eee103907ac2f44f60c7997970c147db201d5c83efde152af2bb9532ddad186baae36f883ff579c174d4998e2311a4010103272006215820e6e5eee103907ac2f44f60c799147414dbef7e8a6b01dc1960726bea573202d3";
    u8 *data = NULL;
    size_t data_len;

    hex_to_u8(hex, &data, &data_len);
    if (data == NULL) {
        printf("Error: hex_to_u8\n");
        return -1;
    }
    struct authdata *ad = parse_authdata(data, data_len);
    if (ad == NULL) {
        printf("Error: parse_authdata\n");
        return -1;
    }
    debug_print_hex(DEBUG_LEVEL_VERBOSE, "rp_id_hash: ", ad->rp_id_hash, ad->rp_id_hash_len);
    debug_printf(DEBUG_LEVEL_VERBOSE, "flags: %d", ad->flags);
    debug_printf(DEBUG_LEVEL_VERBOSE, "sign_count: %d", ad->sign_count);
    debug_print_hex(DEBUG_LEVEL_VERBOSE, "aaguid: ", ad->aaguid, ad->aaguid_len);
    debug_print_hex(DEBUG_LEVEL_VERBOSE, "cred_id: ", ad->cred_id, ad->cred_id_len);
    debug_print_hex(DEBUG_LEVEL_VERBOSE, "pubkey: ", ad->pubkey, ad->pubkey_len);
    puts("");
    return 0;
}

int test_parse_cose_key() {
    char *hex = "2b662ac619c2e71c3ef2af752bb757180bebe21ef288588f277f656f9eec007f47d00a9054f4f44b7efab2fd9796f63c64cfcab25e891a65508d06ed7b77d0ee";
    u8 *data = NULL;
    size_t data_len;

    hex_to_u8(hex, &data, &data_len);
    if (data == NULL) {
        printf("Error: hex_to_u8\n");
        return -1;
    }
    printf("data_len: %zu\n", data_len);
    PublicKey *pk = parse_cose_key(data, data_len);
    if (pk == NULL) {
        printf("Error: parse_cose_key\n");
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    debug_initialize();
    set_debug_level(DEBUG_LEVEL_MORE_VERBOSE);

    if (test_parse_authdata() != 0) {
        printf("Error: test_parse_authdata\n");
        return -1;
    }

    if (test_parse_cose_key() != 0) {
        printf("Error: test_parse_cose_key\n");
        return -1;
    }

    return 0;
}
