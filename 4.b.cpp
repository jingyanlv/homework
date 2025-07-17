#ifdef SM3_LENEXT_MAIN
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

void sm3_hash(const uint8_t *msg, size_t len, uint8_t hash[32]);
void sm3_compress(uint32_t digest[8], const uint8_t block[64]);

uint64_t pad_len(uint64_t msg_len) {
    uint64_t l = msg_len * 8;
    uint64_t k = (448 - (l + 1) % 512 + 512) % 512;
    return (l + 1 + k + 64) / 8;
}

std::vector<uint8_t> sm3_padding(uint64_t len) {
    uint64_t l = len * 8;
    size_t k = (448 - (l + 1) % 512 + 512) % 512;
    size_t total = (l + 1 + k + 64) / 8;
    std::vector<uint8_t> pad(total - len);
    pad[0] = 0x80;
    uint64_t blen = len * 8;
    for (int i = 0; i < 8; ++i)
        pad[pad.size() - 1 - i] = (blen >> (8 * i)) & 0xFF;
    return pad;
}

std::string hex(const uint8_t *buf, size_t len) {
    static const char *hex = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < len; ++i)
        s += hex[buf[i] >> 4], s += hex[buf[i] & 15];
    return s;
}

void print_digest(const char *title, const uint8_t h[32]) {
    printf("%s: %s\n", title, hex(h, 32).c_str());
}

int main() {
    const std::string secret = "secret";
    const std::string suffix = ";admin=true";

    uint8_t H_orig[32];
    sm3_hash((const uint8_t*)secret.data(), secret.size(), H_orig);
    print_digest("Original hash", H_orig);

    std::vector<uint8_t> glue = sm3_padding(secret.size());
    std::vector<uint8_t> attack(glue);
    attack.insert(attack.end(), suffix.begin(), suffix.end());

    uint32_t IV[8];
    for (int i = 0; i < 8; ++i)
        IV[i] = (H_orig[i * 4] << 24) | (H_orig[i * 4 + 1] << 16) |
                (H_orig[i * 4 + 2] << 8) | H_orig[i * 4 + 3];

    uint64_t fake_len = secret.size() + glue.size();
    std::vector<uint8_t> full = attack;
    full.insert(full.end(), sm3_padding(fake_len + suffix.size()).begin(),
                              sm3_padding(fake_len + suffix.size()).end());

    for (size_t i = 0; i + 64 <= full.size(); i += 64)
        sm3_compress(IV, full.data() + i);

    uint8_t forged[32];
    for (int i = 0; i < 8; ++i) {
        forged[i * 4 + 0] = IV[i] >> 24;
        forged[i * 4 + 1] = IV[i] >> 16;
        forged[i * 4 + 2] = IV[i] >> 8;
        forged[i * 4 + 3] = IV[i];
    }

    print_digest("Forged hash", forged);

    std::string real = secret + std::string(glue.begin(), glue.end()) + suffix;
    uint8_t H_true[32];
    sm3_hash((const uint8_t*)real.data(), real.size(), H_true);
    print_digest("Real hash", H_true);

    bool ok = std::memcmp(forged, H_true, 32) == 0;
    printf("Length-extension attack %s!\n", ok ? "SUCCESS" : "FAIL");
    return 0;
}
#endif
