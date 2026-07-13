#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include "lib/bip39_wordlist.hpp"

#include <sqlite3.h>
#include <ctime>
#include <algorithm>
#include <atomic>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

constexpr char BASE58[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
constexpr char BASE64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

struct Args {
    std::string db;
    std::string prefix;
    std::string suffix;
    std::string contains;
    bool case_sensitive = false;
    bool benchmark = false;
    uint64_t max = 1;
    uint64_t max_tries = 0;
    uint64_t progress = 100000;
    uint32_t threads = 0;
    std::string out;
    bool force = false;
    bool quiet = false;
    std::string rpc = "https://octra.network/rpc";
};

struct Wallet {
    std::array<uint8_t, 32> seed{};
    std::array<uint8_t, 32> pub{};
    std::string address;
};

struct SearchResult {
    Wallet wallet;
    std::string mnemonic;
    uint64_t attempts = 0;
    bool found = false;
};

Wallet wallet_from_seed(const std::array<uint8_t, 32>& seed);

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool is_base58_text(const std::string& s) {
    for (char c : s) {
        if (!std::strchr(BASE58, c)) return false;
    }
    return true;
}

std::string hex_encode(const uint8_t* data, size_t len) {
    static constexpr char H[] = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[i * 2] = H[data[i] >> 4];
        out[i * 2 + 1] = H[data[i] & 0x0f];
    }
    return out;
}

std::array<uint8_t, 64> mnemonic_to_seed(const std::string& mnemonic) {
    std::array<uint8_t, 64> seed{};
    const std::string salt = "mnemonic";
    if (PKCS5_PBKDF2_HMAC(
            mnemonic.c_str(),
            (int)mnemonic.size(),
            reinterpret_cast<const uint8_t*>(salt.data()),
            (int)salt.size(),
            2048,
            EVP_sha512(),
            64,
            seed.data()) != 1) {
        throw std::runtime_error("mnemonic_to_seed failed");
    }
    return seed;
}

std::array<uint8_t, 32> derive_octra_hd_seed(const std::array<uint8_t, 64>& master_seed) {
    std::array<uint8_t, 32> out{};
    unsigned int out_len = 64;
    std::array<uint8_t, 64> mac{};
    const char* key = "Octra seed";
    HMAC(
        EVP_sha512(),
        key,
        10,
        master_seed.data(),
        master_seed.size(),
        mac.data(),
        &out_len
    );
    std::copy(mac.begin(), mac.begin() + 32, out.begin());
    return out;
}
std::string generate_mnemonic_12() {
    uint8_t entropy[16];
    if (RAND_bytes(entropy, sizeof(entropy)) != 1) {
        throw std::runtime_error("RAND_bytes mnemonic entropy failed");
    }
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(entropy, sizeof(entropy), hash);
    uint8_t bits[17];
    std::memcpy(bits, entropy, 16);
    bits[16] = hash[0];
    std::string mnemonic;
    for (int i = 0; i < 12; ++i) {
        int bit_pos = i * 11;
        int byte_idx = bit_pos / 8;
        int bit_off = bit_pos % 8;
        uint32_t val = ((uint32_t)bits[byte_idx] << 16)
                     | ((uint32_t)bits[byte_idx + 1] << 8);
        if (byte_idx + 2 < 17) val |= bits[byte_idx + 2];
        val = (val >> (24 - 11 - bit_off)) & 0x7ff;
        if (i) mnemonic += " ";
        mnemonic += bip39::wordlist[val];
    }
    return mnemonic;
}
Wallet wallet_from_mnemonic(std::string& mnemonic_out) {
    mnemonic_out = generate_mnemonic_12();
    auto master_seed = mnemonic_to_seed(mnemonic_out);
    auto hd_seed = derive_octra_hd_seed(master_seed);
    return wallet_from_seed(hd_seed);
}

std::string base64_encode(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);
        out.push_back(BASE64[(n >> 18) & 63]);
        out.push_back(BASE64[(n >> 12) & 63]);
        out.push_back((i + 1 < len) ? BASE64[(n >> 6) & 63] : '=');
        out.push_back((i + 2 < len) ? BASE64[n & 63] : '=');
    }
    return out;
}

std::string base58_encode(const uint8_t* data, size_t len) {
    size_t zeroes = 0;
    while (zeroes < len && data[zeroes] == 0) ++zeroes;

    std::vector<uint8_t> buf(data, data + len);
    std::string result;
    while (!buf.empty()) {
        int carry = 0;
        std::vector<uint8_t> next;
        next.reserve(buf.size());
        for (uint8_t b : buf) {
            int val = carry * 256 + b;
            int digit = val / 58;
            carry = val % 58;
            if (!next.empty() || digit > 0) next.push_back(static_cast<uint8_t>(digit));
        }
        result.push_back(BASE58[carry]);
        buf = std::move(next);
    }

    for (size_t i = 0; i < zeroes; ++i) result.push_back('1');
    if (result.empty()) result.push_back('1');
    std::reverse(result.begin(), result.end());
    return result;
}

std::string derive_address(const std::array<uint8_t, 32>& pub) {
    std::array<uint8_t, SHA256_DIGEST_LENGTH> digest{};
    SHA256(pub.data(), pub.size(), digest.data());
    std::string body = base58_encode(digest.data(), digest.size());
    if (body.size() < 44) body.insert(body.begin(), 44 - body.size(), '1');
    return "oct" + body;
}

std::array<uint8_t, 32> public_from_seed(const std::array<uint8_t, 32>& seed) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size());
    if (!pkey) throw std::runtime_error("EVP_PKEY_new_raw_private_key failed");

    std::array<uint8_t, 32> pub{};
    size_t pub_len = pub.size();
    if (EVP_PKEY_get_raw_public_key(pkey, pub.data(), &pub_len) != 1 || pub_len != pub.size()) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_get_raw_public_key failed");
    }
    EVP_PKEY_free(pkey);
    return pub;
}

Wallet wallet_from_seed(const std::array<uint8_t, 32>& seed) {
    Wallet w;
    w.seed = seed;
    w.pub = public_from_seed(seed);
    w.address = derive_address(w.pub);
    return w;
}

bool matches(const std::string& address, const Args& args) {
    std::string hay = args.case_sensitive ? address : lower(address);
    std::string pre = args.case_sensitive ? args.prefix : lower(args.prefix);
    std::string suf = args.case_sensitive ? args.suffix : lower(args.suffix);
    std::string con = args.case_sensitive ? args.contains : lower(args.contains);

    if (!pre.empty() && hay.rfind(pre, 0) != 0) return false;
    if (!suf.empty() && (hay.size() < suf.size() || hay.compare(hay.size() - suf.size(), suf.size(), suf) != 0)) return false;
    if (!con.empty() && hay.find(con) == std::string::npos) return false;
    return true;
}

std::string target_summary(const Args& args) {
    std::string target;
    if (!args.prefix.empty()) target += "prefix=" + args.prefix;
    if (!args.suffix.empty()) {
        if (!target.empty()) target += ",";
        target += "suffix=" + args.suffix;
    }
    if (!args.contains.empty()) {
        if (!target.empty()) target += ",";
        target += "contains=" + args.contains;
    }
    return target.empty() ? "any" : target;
}

std::string json_escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '"' || c == '\\') {
            out.push_back('\\');
            out.push_back(c);
        } else if (c == '\n') {
            out += "\\n";
        } else {
            out.push_back(c);
        }
    }
    return out;
}

void write_wallet_json(const std::string& path, const Wallet& w, const Args& args) {
    if (std::filesystem::exists(path) && !args.force) {
        throw std::runtime_error(path + " already exists; use --force to overwrite");
    }
    std::ofstream f(path);
    if (!f) throw std::runtime_error("cannot write " + path);
    f << "{\n"
      << "  \"priv\": \"" << base64_encode(w.seed.data(), w.seed.size()) << "\",\n"
      << "  \"addr\": \"" << w.address << "\",\n"
      << "  \"rpc\": \"" << json_escape(args.rpc) << "\"\n"
      << "}\n";
}

void write_wallets_json(const std::string& path, const std::vector<SearchResult>& results, const Args& args) {
    if (std::filesystem::exists(path) && !args.force) {
        throw std::runtime_error(path + " already exists; use --force to overwrite");
    }
    std::ofstream f(path);
    if (!f) throw std::runtime_error("cannot write " + path);
    f << "{\n"
      << "  \"wallets\": [\n";
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        f << "    {\n"
          << "      \"priv\": \"" << base64_encode(r.wallet.seed.data(), r.wallet.seed.size()) << "\",\n"
          << "      \"addr\": \"" << r.wallet.address << "\",\n"
          << "      \"rpc\": \"" << json_escape(args.rpc) << "\"\n"
          << "    }" << (i + 1 == results.size() ? "\n" : ",\n");
    }
    f << "  ]\n"
      << "}\n";
}

std::string utc_now_iso8601() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

void sqlite_check(int rc, sqlite3* db, const char* what) {
      if (rc == SQLITE_OK || rc == SQLITE_DONE || rc == SQLITE_ROW) return;
      std::string msg = what;
      msg += ": ";
      msg += sqlite3_errmsg(db);
      throw std::runtime_error(msg);
  }

void save_wallet_db(const std::string& path, const Wallet& w, const std::string& mnemonic) {
    sqlite3* db = nullptr;
    sqlite_check(sqlite3_open(path.c_str(), &db), db, "sqlite3_open");

    try {
        const char* schema =
            "CREATE TABLE IF NOT EXISTS vanity_wallets ("
            "address TEXT PRIMARY KEY,"
            "private_key TEXT NOT NULL,"
            "mnemonic TEXT NOT NULL DEFAULT '',"
            "created_at TEXT NOT NULL"
            ")";
        sqlite_check(sqlite3_exec(db, schema, nullptr, nullptr, nullptr), db, "create table");

        const char* sql =
            "INSERT OR REPLACE INTO vanity_wallets(address, private_key, mnemonic, created_at) "
            "VALUES (?, ?, ?, ?)";
        sqlite3_stmt* stmt = nullptr;
        sqlite_check(sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr), db, "prepare insert");

        const std::string priv = base64_encode(w.seed.data(), w.seed.size());
        const std::string created_at = utc_now_iso8601();

        sqlite_check(sqlite3_bind_text(stmt, 1, w.address.c_str(), -1, SQLITE_TRANSIENT), db, "bind address");
        sqlite_check(sqlite3_bind_text(stmt, 2, priv.c_str(), -1, SQLITE_TRANSIENT), db, "bind private_key");
        sqlite_check(sqlite3_bind_text(stmt, 3, mnemonic.c_str(), -1, SQLITE_TRANSIENT), db, "bind mnemonic");
        sqlite_check(sqlite3_bind_text(stmt, 4, created_at.c_str(), -1, SQLITE_TRANSIENT), db, "bind created_at");
        sqlite_check(sqlite3_step(stmt), db, "insert wallet");
        sqlite_check(sqlite3_finalize(stmt), db, "finalize insert");
        sqlite_check(sqlite3_close(db), db, "sqlite3_close");
    } catch (...) {
        sqlite3_close(db);
        throw;
    }
}

void usage(const char* argv0) {
    std::cerr
        << "usage: " << argv0 << " [--prefix P] [--suffix S] [--contains X]\n"
        << "       [--max N] [--benchmark] [--threads N]\n"
        << "       [--case-sensitive] [--max-tries N] [--progress N]\n"
        << "       [--out wallet.json] [--db vanity.db]\n"
        << "       [--rpc URL] [--force] [--quiet]\n";
}

Args parse_args(int argc, char** argv) {
    Args args;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto need = [&](const char* name) -> std::string {
            if (++i >= argc) throw std::runtime_error(std::string("missing value for ") + name);
            return argv[i];
        };

        if (a == "--prefix") args.prefix = need("--prefix");
        else if (a == "--max") args.max = std::stoull(need("--max"));
        else if (a == "--benchmark") args.benchmark = true;
        else if (a == "--threads") args.threads = static_cast<uint32_t>(std::stoul(need("--threads")));
        else if (a == "--db") args.db = need("--db");
        else if (a == "--suffix") args.suffix = need("--suffix");
        else if (a == "--contains") args.contains = need("--contains");
        else if (a == "--case-sensitive") args.case_sensitive = true;
        else if (a == "--max-tries") args.max_tries = std::stoull(need("--max-tries"));
        else if (a == "--progress") args.progress = std::stoull(need("--progress"));
        else if (a == "--out") args.out = need("--out");
        else if (a == "--force") args.force = true;
        else if (a == "--quiet") args.quiet = true;
        else if (a == "--rpc") args.rpc = need("--rpc");
        else if (a == "-h" || a == "--help") {
            usage(argv[0]);
            std::exit(0);
        } else {
            throw std::runtime_error("unknown argument: " + a);
        }
    }

    if (!args.prefix.empty() && args.prefix.rfind("oct", 0) != 0) args.prefix = "oct" + args.prefix;
    if (!args.prefix.empty() && !is_base58_text(args.prefix.substr(3))) {
        throw std::runtime_error("--prefix contains non-base58 characters");
    }
    if (!args.suffix.empty() && !is_base58_text(args.suffix)) {
        throw std::runtime_error("--suffix contains non-base58 characters");
    }
    if (!args.contains.empty() && !is_base58_text(args.contains)) {
        throw std::runtime_error("--contains contains non-base58 characters");
    }
    if (args.max == 0) {
        throw std::runtime_error("--max must be greater than 0");
    }
    if (args.threads == 0) {
        args.threads = std::max<uint32_t>(1, std::thread::hardware_concurrency());
    }
    return args;
}

} // namespace

int main(int argc, char** argv) {
    try {
        Args args = parse_args(argc, argv);
        std::vector<SearchResult> results;
        uint64_t attempts = 0;
        auto start = std::chrono::steady_clock::now();
        const std::string target = target_summary(args);

        std::atomic<bool> stop{false};
        std::atomic<uint64_t> generated{0};
        std::mutex result_mu;
        std::string last_address;

        auto worker = [&]() {
            while (!stop.load(std::memory_order_relaxed)) {
                uint64_t n = generated.load(std::memory_order_relaxed);
                for (;;) {
                    if (args.max_tries && n >= args.max_tries) {
                        stop.store(true, std::memory_order_relaxed);
                        return;
                    }
                    if (generated.compare_exchange_weak(
                            n,
                            n + 1,
                            std::memory_order_relaxed,
                            std::memory_order_relaxed)) {
                        ++n;
                        break;
                    }
                }

                std::string mnemonic;
                Wallet candidate = wallet_from_mnemonic(mnemonic);

                if ((n & 0xff) == 0) {
                    std::lock_guard<std::mutex> lock(result_mu);
                    last_address = candidate.address;
                }

                bool hit = !args.benchmark && matches(candidate.address, args);
                if (hit) {
                    std::lock_guard<std::mutex> lock(result_mu);
                    if (results.size() < args.max) {
                        SearchResult result;
                        result.wallet = std::move(candidate);
                        result.mnemonic = std::move(mnemonic);
                        result.attempts = n;
                        result.found = true;
                        last_address = result.wallet.address;
                        results.push_back(std::move(result));
                    }
                    if (results.size() >= args.max) {
                        stop.store(true, std::memory_order_relaxed);
                        break;
                    }
                    continue;
                }
                if (args.max_tries && n >= args.max_tries) {
                    stop.store(true, std::memory_order_relaxed);
                    break;
                }
            }
        };

        std::vector<std::thread> workers;
        workers.reserve(args.threads);
        for (uint32_t i = 0; i < args.threads; ++i) workers.emplace_back(worker);

        uint64_t last_report = 0;
        for (;;) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            uint64_t n = generated.load(std::memory_order_relaxed);
            bool should_report = args.progress && !args.quiet && (n >= last_report + args.progress);
            if (should_report) {
                last_report = n;
                auto now = std::chrono::steady_clock::now();
                double elapsed = std::chrono::duration<double>(now - start).count();
                double rate = elapsed > 0.0 ? n / elapsed : 0.0;
                std::string last;
                {
                    std::lock_guard<std::mutex> lock(result_mu);
                    last = last_address;
                }
                std::cerr << "generated=" << n
                          << " elapsed=" << std::fixed << std::setprecision(1) << elapsed << "s"
                          << " rate=" << std::fixed << std::setprecision(1) << rate << "/s"
                          << " threads=" << args.threads
                          << " target=" << (args.benchmark ? "benchmark" : target)
                          << " last=" << last << "\n";
            }
            if (stop.load(std::memory_order_relaxed)) break;
        }

        for (auto& t : workers) t.join();
        attempts = generated.load(std::memory_order_relaxed);

        if (results.size() < args.max && !args.benchmark) {
            throw std::runtime_error(
                "found " + std::to_string(results.size()) + " match(es) after " +
                std::to_string(attempts) + " attempts"
            );
        }
        std::sort(results.begin(), results.end(), [](const SearchResult& a, const SearchResult& b) {
            return a.attempts < b.attempts;
        });

        auto end = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(end - start).count();
        if (!args.quiet) {
            double rate = elapsed > 0.0 ? attempts / elapsed : 0.0;
            std::cerr << "matched=" << results.size()
                      << " generated=" << attempts
                      << " elapsed=" << std::fixed << std::setprecision(1) << elapsed << "s"
                      << " rate=" << std::fixed << std::setprecision(1) << rate << "/s"
                      << " threads=" << args.threads
                      << " target=" << (args.benchmark ? "benchmark" : target);
            if (!results.empty()) {
                std::cerr << " address=" << results.back().wallet.address;
            }
            std::cerr << "\n";
        }
        if (!args.out.empty()) {
            if (results.size() == 1) {
                write_wallet_json(args.out, results.front().wallet, args);
            } else {
                write_wallets_json(args.out, results, args);
            }
        }
        if (!args.db.empty()) {
            for (const auto& result : results) {
                save_wallet_db(args.db, result.wallet, result.mnemonic);
            }
        }

        const std::string indent = args.quiet ? "" : "  ";
        const std::string nl = args.quiet ? "" : "\n";
        const std::string sep = args.quiet ? "" : " ";
        if (results.size() == 1) {
            const auto& result = results.front();
            std::cout << "{" << nl
                << indent << "\"address\":" << sep << "\"" << result.wallet.address << "\"," << nl
                << indent << "\"priv\":" << sep << "\"" << base64_encode(result.wallet.seed.data(), result.wallet.seed.size()) << "\"," <<
                nl
                << indent << "\"pub\":" << sep << "\"" << base64_encode(result.wallet.pub.data(), result.wallet.pub.size()) << "\"," << nl
                << indent << "\"seed_hex\":" << sep << "\"" << hex_encode(result.wallet.seed.data(), result.wallet.seed.size()) << "\","
                << nl
                << indent << "\"mnemonic\":" << sep << "\"" << json_escape(result.mnemonic) << "\"," << nl
                << indent << "\"attempts\":" << sep << result.attempts << "," << nl
                << indent << "\"threads\":" << sep << args.threads << "," << nl
                << indent << "\"matched\":" << sep << (result.found ? "true" : "false") << "," << nl
                << indent << "\"elapsed_seconds\":" << sep << std::fixed << std::setprecision(3) << elapsed;

            if (!args.out.empty()) {
                std::cout << "," << nl << indent << "\"wallet_file\":" << sep << "\"" << json_escape(args.out) << "\"";
            }
            if (!args.db.empty()) {
                std::cout << "," << nl << indent << "\"db_file\":" << sep << "\"" << json_escape(args.db) << "\"";
            }
            std::cout << nl << "}\n";
        } else {
            std::cout << "{" << nl
                << indent << "\"matched\":" << sep << results.size() << "," << nl
                << indent << "\"attempts\":" << sep << attempts << "," << nl
                << indent << "\"threads\":" << sep << args.threads << "," << nl
                << indent << "\"elapsed_seconds\":" << sep << std::fixed << std::setprecision(3) << elapsed << "," << nl
                << indent << "\"wallets\":" << sep << "[" << nl;
            const std::string item_indent = args.quiet ? "" : "    ";
            const std::string item_sep = args.quiet ? "" : " ";
            for (size_t i = 0; i < results.size(); ++i) {
                const auto& result = results[i];
                std::cout << item_indent << "{" << nl
                    << item_indent << indent << "\"address\":" << item_sep << "\"" << result.wallet.address << "\"," << nl
                    << item_indent << indent << "\"priv\":" << item_sep << "\"" << base64_encode(result.wallet.seed.data(), result.wallet.seed.size()) << "\"," << nl
                    << item_indent << indent << "\"pub\":" << item_sep << "\"" << base64_encode(result.wallet.pub.data(), result.wallet.pub.size()) << "\"," << nl
                    << item_indent << indent << "\"seed_hex\":" << item_sep << "\"" << hex_encode(result.wallet.seed.data(), result.wallet.seed.size()) << "\"," << nl
                    << item_indent << indent << "\"mnemonic\":" << item_sep << "\"" << json_escape(result.mnemonic) << "\"," << nl
                    << item_indent << indent << "\"attempts\":" << item_sep << result.attempts << nl
                    << item_indent << "}" << (i + 1 == results.size() ? "" : ",") << nl;
            }
            std::cout << indent << "]";
            if (!args.out.empty()) {
                std::cout << "," << nl << indent << "\"wallet_file\":" << sep << "\"" << json_escape(args.out) << "\"";
            }
            if (!args.db.empty()) {
                std::cout << "," << nl << indent << "\"db_file\":" << sep << "\"" << json_escape(args.db) << "\"";
            }
            std::cout << nl << "}\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
