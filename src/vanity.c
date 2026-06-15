#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <process.h>
#include <secp256k1.h>
#include "Keccak.c"
#include "base58check.c"

enum {
    PRIVKEY_LEN = 32,
    PUBKEY_LEN = 65,
    ADDRESS_LEN = 21,
    B58CHECK_ADDRESS_LEN = 34,
};
static const char HELP_TEXT[] = "Usage:\n"
                                "  %s [-i] pattern\n"
                                "\n"
                                "Options:\n"
                                "  -i            Case-insensitive search\n"
                                "  -h, --help    Print help\n";

secp256k1_context* ctx;

void error_exit(const char* message) {
    fprintf(stderr, "%s\n", message);
    if (ctx) secp256k1_context_destroy(ctx);
    exit(EXIT_FAILURE);
}

void print_hex(size_t len, const uint8_t data[static len]) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    putchar('\n');
}

bool privkey_to_pubkey(const uint8_t privkey[static PRIVKEY_LEN], secp256k1_pubkey* out_pub) {
    return secp256k1_ec_pubkey_create(ctx, out_pub, privkey);
}

bool increment_pubkey(secp256k1_pubkey* pub) {
    static const uint8_t tweak[32] = { [31] = 1 };
    return secp256k1_ec_pubkey_tweak_add(ctx, pub, tweak);
}

void pubkey_to_tron_address(const secp256k1_pubkey* pub, uint8_t address[static ADDRESS_LEN]) {
    uint8_t pubkey_bytes[PUBKEY_LEN];
    size_t pubkey_len = PUBKEY_LEN;
    secp256k1_ec_pubkey_serialize(ctx, pubkey_bytes, &pubkey_len, pub, SECP256K1_EC_UNCOMPRESSED);

    uint8_t hash[32];
    Keccak_256(pubkey_bytes + 1, PUBKEY_LEN - 1, hash);

    address[0] = 0x41;
    memcpy(address + 1, hash + 12, 20);
}

void pubkey_to_b58check_address(const secp256k1_pubkey* pub, char address[static B58CHECK_ADDRESS_LEN + 1]) {
    uint8_t tron_address[ADDRESS_LEN];
    pubkey_to_tron_address(pub, tron_address);
    base58check(ADDRESS_LEN, tron_address, B58CHECK_ADDRESS_LEN, address);
    address[B58CHECK_ADDRESS_LEN] = 0;
}

bool generate_private_key(uint8_t buf[static PRIVKEY_LEN]) {
    return BCRYPT_SUCCESS(BCryptGenRandom(NULL, buf, PRIVKEY_LEN, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

void print_address_info(const char* b58check_address, const uint8_t privkey[static PRIVKEY_LEN], unsigned long long count) {
    printf("\nAddress: %s\nPrivate Key: ", b58check_address);
    print_hex(PRIVKEY_LEN, privkey);
    printf("Count: %llu\n", count);
}

bool matches_pattern(const char* address, const char* pattern, bool case_sensitive) {
    if (address[0] != 'T') return false;

    const char* addr_pos = address + 1;
    const char* pat_pos = pattern;

    while (*pat_pos) {
        if (!*addr_pos) return false;

        char addr_char = *addr_pos;
        char pat_char = *pat_pos;

        if (!case_sensitive) {
            addr_char = toupper((unsigned char)addr_char);
            pat_char = toupper((unsigned char)pat_char);
        }

        if (addr_char != pat_char) return false;
        addr_pos++;
        pat_pos++;
    }

    return true;
}

bool validate_pattern(const char* pattern) {
    return strchr("9ABCDEFGHJKLMNPQRSTUVWXYZ", pattern[0])
        && strspn(pattern, BASE58_ALPHABET) == strlen(pattern);
}

char* parse_args(int argc, char* argv[], bool* cs) {
    if (argc > 3) {
        error_exit("Too many arguments.");
    }

    if (argc == 1) {
        printf(HELP_TEXT, argv[0]);
        exit(EXIT_SUCCESS);
    }

    *cs = true;
    char* pattern = NULL;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf(HELP_TEXT, argv[0]);
            exit(EXIT_SUCCESS);
        } else if (strcmp(argv[i], "-i") == 0) {
            *cs = false;
        } else if (*argv[i] == '-') {
            error_exit("Unrecognized option.");
        } else if (pattern != NULL) {
            error_exit("Only one pattern can be specified.");
        } else if (!validate_pattern(pattern = argv[i])) {
            error_exit("Pattern must be a subset of Base58 alphabet. The first character must be 9 or an uppercase letter.");
        }
    }

    if (pattern == NULL) {
        error_exit("You must specify a pattern to look for.");
    }

    return pattern;
}

bool reconstruct_privkey(uint8_t privkey[static PRIVKEY_LEN], unsigned long long num_increments) {
    if (num_increments == 0) return true;
    const uint8_t tweak[32] = {
        [24] = (num_increments >> 56) & 0xFF,
        [25] = (num_increments >> 48) & 0xFF,
        [26] = (num_increments >> 40) & 0xFF,
        [27] = (num_increments >> 32) & 0xFF,
        [28] = (num_increments >> 24) & 0xFF,
        [29] = (num_increments >> 16) & 0xFF,
        [30] = (num_increments >>  8) & 0xFF,
        [31] =  num_increments        & 0xFF,
    };
    return secp256k1_ec_seckey_tweak_add(ctx, privkey, tweak);
}

typedef struct {
    const char* pattern;
    bool case_sensitive;
    atomic_ullong* total_count;
    atomic_bool* found;
    bool did_find;
    uint8_t privkey[PRIVKEY_LEN];
    char b58check_address[B58CHECK_ADDRESS_LEN + 1];
} ThreadData;

unsigned __stdcall worker(void* arg) {
    ThreadData* td = (ThreadData*)arg;

    uint8_t start_privkey[PRIVKEY_LEN];
    if (!generate_private_key(start_privkey)) return false;

    secp256k1_pubkey pub;
    if (!privkey_to_pubkey(start_privkey, &pub)) return false;

    char b58check_address[B58CHECK_ADDRESS_LEN + 1];
    pubkey_to_b58check_address(&pub, b58check_address);

    unsigned long long local_count = 0;
    unsigned long long batch = 0;

    while (!atomic_load_explicit(td->found, memory_order_relaxed)) {
        local_count++;
        batch++;

        if (matches_pattern(b58check_address, td->pattern, td->case_sensitive)) {
            bool expected = false;
            if (atomic_compare_exchange_strong(td->found, &expected, true)) {
                uint8_t privkey[PRIVKEY_LEN];
                memcpy(privkey, start_privkey, PRIVKEY_LEN);
                reconstruct_privkey(privkey, local_count - 1);
                memcpy(td->privkey, privkey, PRIVKEY_LEN);
                memcpy(td->b58check_address, b58check_address, B58CHECK_ADDRESS_LEN + 1);
                td->did_find = true;
            }
            break;
        }

        if (!increment_pubkey(&pub)) {
            if (!generate_private_key(start_privkey)) return false;
            if (!privkey_to_pubkey(start_privkey, &pub)) return false;
            local_count = 0;
        }

        pubkey_to_b58check_address(&pub, b58check_address);

        if (batch == 65536) {
            atomic_fetch_add(td->total_count, batch);
            batch = 0;
        }
    }

    atomic_fetch_add(td->total_count, batch);
    return true;
}

int main(int argc, char* argv[]) {
    bool case_sensitive;
    char* pattern = parse_args(argc, argv, &case_sensitive);

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    DWORD num_threads = sysinfo.dwNumberOfProcessors;

    atomic_ullong total_count = 0;
    atomic_bool found = false;

    ThreadData* td = calloc(num_threads, sizeof(ThreadData));
    HANDLE* threads = malloc(num_threads * sizeof(HANDLE));

    for (DWORD i = 0; i < num_threads; i++) {
        td[i].pattern = pattern;
        td[i].case_sensitive = case_sensitive;
        td[i].total_count = &total_count;
        td[i].found = &found;
        threads[i] = (HANDLE)_beginthreadex(NULL, 0, worker, &td[i], 0, NULL);
    }

    while (!atomic_load(&found)) {
        Sleep(100);
        printf("\r%llu addresses checked", atomic_load(&total_count));
        fflush(stdout);
    }

    WaitForMultipleObjects(num_threads, threads, TRUE, INFINITE);

    for (DWORD i = 0; i < num_threads; i++) {
        CloseHandle(threads[i]);
        if (td[i].did_find) {
            print_address_info(td[i].b58check_address, td[i].privkey, atomic_load(&total_count));
        }
    }

    free(td);
    free(threads);
    secp256k1_context_destroy(ctx);
}
