#include <map>
#include <set>
#include <chrono>
#include <cassert>

#ifdef SM3_MERKLE_MAIN

using Hash = std::vector<uint8_t>;  // 32-byte digest

static Hash sm3(const std::string &msg) {
    Hash h(32); sm3_hash((const uint8_t*)msg.data(), msg.size(), h.data()); return h;
}

static Hash sm3_concat(const Hash &a, const Hash &b) {
    Hash h(32); std::vector<uint8_t> data(a); data.insert(data.end(), b.begin(), b.end());
    sm3_hash(data.data(), data.size(), h.data()); return h;
}

// ========== Merkle Tree ==========
class MerkleTree {
public:
    std::vector<Hash> leaves;
    std::map<size_t, std::vector<Hash>> levels; // level -> hashes
    Hash root;

    void build(size_t n) {
        leaves.resize(n);
        for(size_t i = 0; i < n; ++i)
            leaves[i] = sm3("leaf#" + std::to_string(i));
        build_from_leaves();
    }

    void build_from_leaves() {
        levels.clear();
        levels[0] = leaves;
        size_t level = 0;
        while(levels[level].size() > 1) {
            const auto &cur = levels[level];
            std::vector<Hash> next;
            for(size_t i = 0; i < cur.size(); i += 2) {
                if(i+1 < cur.size()) next.push_back(sm3_concat(cur[i], cur[i+1]));
                else next.push_back(cur[i]); // odd case
            }
            levels[++level] = next;
        }
        root = levels[level][0];
    }

    std::vector<Hash> gen_proof(size_t idx) const {
        std::vector<Hash> proof;
        for(size_t level = 0; levels.count(level); ++level) {
            size_t sibling = idx ^ 1;
            if(sibling < levels.at(level).size())
                proof.push_back(levels.at(level)[sibling]);
            idx /= 2;
        }
        return proof;
    }

    static Hash verify_proof(size_t idx, const Hash &leaf, const std::vector<Hash> &proof) {
        Hash h = leaf;
        for(const auto &sibling : proof) {
            if(idx % 2 == 0) h = sm3_concat(h, sibling);
            else             h = sm3_concat(sibling, h);
            idx /= 2;
        }
        return h;
    }
};

int main() {
    constexpr size_t N = 100000;
    MerkleTree tree;
    printf("Building Merkle Tree with %zu leaves...\n", N);
    auto t0 = std::chrono::high_resolution_clock::now();
    tree.build(N);
    auto t1 = std::chrono::high_resolution_clock::now();
    printf("Done. Root = %s\n", bytes_to_hex(tree.root.data(), 32).c_str());

    // Test existence proof
    size_t target = 12345;
    auto proof = tree.gen_proof(target);
    auto leaf = sm3("leaf#" + std::to_string(target));
    auto calc = MerkleTree::verify_proof(target, leaf, proof);
    printf("Existence proof for leaf[%zu]: %s\n", target, calc == tree.root ? "OK" : "FAIL");

    // Fake non-existence: use a non-existent leaf
    std::string fake = "not_in_tree";
    auto fake_hash = sm3(fake);
    auto fake_calc = MerkleTree::verify_proof(0, fake_hash, proof); // wrong index
    printf("Non-existence check: %s\n", fake_calc == tree.root ? "FAIL (collision!)" : "OK");
    return 0;
}

#endif
