#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <random>
#include <thread>
#include <filesystem>
#include <asio.hpp>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif

using asio::ip::tcp;
using json = nlohmann::json;
namespace fs = std::filesystem;

struct Config {
    std::string network_secret;
    int hydra_port;
    int socks_port;
    int desync_ms;
    int onion_layers;
    std::vector<std::string> reflect_domains;
    std::vector<std::string> seeds;
};

Config cfg;

fs::path get_base_path() {
#ifdef _WIN32
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    return fs::path(path).parent_path();
#else
    char result[1024];
    ssize_t count = readlink("/proc/self/exe", result, 1024);
    return fs::path(std::string(result, (count > 0) ? count : 0)).parent_path();
#endif
}

void load_config() {
    fs::path p = get_base_path() / "config.json";
    std::ifstream f(p);
    if (!f.is_open()) {
        cfg = {"Proprietary_Mesh_Key_V7_Genius", 25000, 1080, 5, 3, {"yandex.ru", "gosuslugi.ru", "vk.com", "max.ru"}, {}};
        json j = {
            {"network_secret", cfg.network_secret}, {"hydra_port", cfg.hydra_port},
            {"socks_port", cfg.socks_port}, {"desync_ms", cfg.desync_ms},
            {"onion_layers", cfg.onion_layers}, {"reflect_domains", cfg.reflect_domains},
            {"seeds", cfg.seeds}
        };
        std::ofstream out(p);
        out << j.dump(4);
        return;
    }
    json j; f >> j;
    cfg.network_secret = j.at("network_secret");
    cfg.hydra_port = j.at("hydra_port");
    cfg.socks_port = j.at("socks_port");
    cfg.desync_ms = j.at("desync_ms");
    cfg.onion_layers = j.at("onion_layers");
    cfg.reflect_domains = j.at("reflect_domains").get<std::vector<std::string>>();
    cfg.seeds = j.at("seeds").get<std::vector<std::string>>();
}

class CryptoContext {
    EVP_PKEY *local_priv = nullptr;
    EVP_CIPHER_CTX *en_ctx = nullptr;
    EVP_CIPHER_CTX *de_ctx = nullptr;
    uint8_t tx_iv[12] = {0}, rx_iv[12] = {0};
    uint64_t tx_cnt = 0, rx_cnt = 0;

public:
    CryptoContext() {
        local_priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, (uint8_t*)cfg.network_secret.data(), 32);
        en_ctx = EVP_CIPHER_CTX_new();
        de_ctx = EVP_CIPHER_CTX_new();
    }
    ~CryptoContext() {
        if (local_priv) EVP_PKEY_free(local_priv);
        EVP_CIPHER_CTX_free(en_ctx);
        EVP_CIPHER_CTX_free(de_ctx);
    }

    std::vector<uint8_t> get_public_key() {
        std::vector<uint8_t> pub(32);
        size_t len = 32;
        EVP_PKEY_get_raw_public_key(local_priv, pub.data(), &len);
        return pub;
    }

    void derive_session(const uint8_t* peer_pub, bool init) {
        EVP_PKEY *peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, 32);
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(local_priv, NULL);
        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_derive_set_peer(ctx, peer_key);
        size_t secret_len = 32;
        uint8_t secret[32];
        EVP_PKEY_derive(ctx, secret, &secret_len);

        uint8_t derived[64];
        PKCS5_PBKDF2_HMAC(cfg.network_secret.c_str(), cfg.network_secret.length(), secret, 32, 1, EVP_sha256(), 64, derived);

        if (init) {
            EVP_EncryptInit_ex(en_ctx, EVP_chacha20_poly1305(), NULL, derived, NULL);
            EVP_DecryptInit_ex(de_ctx, EVP_chacha20_poly1305(), NULL, derived + 32, NULL);
        } else {
            EVP_EncryptInit_ex(en_ctx, EVP_chacha20_poly1305(), NULL, derived + 32, NULL);
            EVP_DecryptInit_ex(de_ctx, EVP_chacha20_poly1305(), NULL, derived, NULL);
        }
        EVP_PKEY_free(peer_key);
        EVP_PKEY_CTX_free(ctx);
    }

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> out(data.size());
        int len;
        memcpy(tx_iv, &tx_cnt, 8);
        EVP_EncryptInit_ex(en_ctx, NULL, NULL, NULL, tx_iv);
        EVP_EncryptUpdate(en_ctx, out.data(), &len, data.data(), data.size());
        uint8_t tag[16];
        EVP_CIPHER_CTX_ctrl(en_ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
        out.insert(out.end(), tag, tag + 16);
        tx_cnt++;
        return out;
    }

    std::vector<uint8_t> decrypt(uint8_t* data, size_t size) {
        if (size < 16) return {};
        std::vector<uint8_t> out(size - 16);
        int len;
        memcpy(rx_iv, &rx_cnt, 8);
        EVP_DecryptInit_ex(de_ctx, NULL, NULL, NULL, rx_iv);
        EVP_DecryptUpdate(de_ctx, out.data(), &len, data, size - 16);
        EVP_CIPHER_CTX_ctrl(de_ctx, EVP_CTRL_AEAD_SET_TAG, 16, data + size - 16);
        rx_cnt++;
        if (EVP_DecryptFinal_ex(de_ctx, out.data() + len, &len) <= 0) return {};
        return out;
    }
};

class Session : public std::enable_shared_from_this<Session> {
    tcp::socket src;
    tcp::socket dst;
    CryptoContext crypto;
    uint8_t buf_in[16384], buf_out[16384];

public:
    Session(tcp::socket s, asio::io_context& ctx) : src(std::move(s)), dst(ctx) {}

    void start_inbound() {
        auto self = shared_from_this();
        src.async_read_some(asio::buffer(buf_in), [self](std::error_code ec, size_t n) {
            if (ec) return;
            std::string domain = cfg.reflect_domains[rand() % cfg.reflect_domains.size()];
            std::string headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: nginx\r\nConnection: keep-alive\r\n\r\n";
            self->desync_write(self->src, headers, [self]() { self->handle_tunnel(); });
        });
    }

    void desync_write(tcp::socket& s, const std::string& data, std::function<void()> cb) {
        auto self = shared_from_this();
        asio::async_write(s, asio::buffer(data.data(), 1), [self, &s, data, cb](std::error_code ec, size_t) {
            if (ec) return;
            auto timer = std::make_shared<asio::steady_timer>(self->src.get_executor());
            timer->expires_after(std::chrono::milliseconds(cfg.desync_ms));
            timer->async_wait([self, &s, data, cb, timer](std::error_code) {
                asio::async_write(s, asio::buffer(data.data() + 1, data.size() - 1), [cb](std::error_code ec, size_t) {
                    if (!ec) cb();
                });
            });
        });
    }

    void handle_tunnel() {
        auto self = shared_from_this();
        src.async_read_some(asio::buffer(buf_in), [self](std::error_code ec, size_t n) {
            if (ec) return;
            self->handle_tunnel();
        });
    }
};

class SOCKS5Server : public std::enable_shared_from_this<SOCKS5Server> {
    tcp::socket client;
    asio::io_context& ctx;
    uint8_t buf[1024];

public:
    SOCKS5Server(tcp::socket s, asio::io_context& i) : client(std::move(s)), ctx(i) {}

    void start() {
        auto self = shared_from_this();
        client.async_read_some(asio::buffer(buf), [self](std::error_code ec, size_t n) {
            if (ec || n < 2 || self->buf[0] != 0x05) return;
            uint8_t resp[] = {0x05, 0x00};
            asio::async_write(self->client, asio::buffer(resp, 2), [self](std::error_code ec, size_t) {
                self->handle_request();
            });
        });
    }

    void handle_request() {
        auto self = shared_from_this();
        client.async_read_some(asio::buffer(buf), [self](std::error_code ec, size_t n) {
            if (ec || n < 4 || self->buf[1] != 0x01) return;
            uint8_t resp[] = {0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            asio::async_write(self->client, asio::buffer(resp, 10), [self](std::error_code, size_t) {
                // Pipe logic here
            });
        });
    }
};

class Node {
    tcp::acceptor acc_tunnel;
    tcp::acceptor acc_socks;
    asio::io_context& ctx;

public:
    Node(asio::io_context& i) : ctx(i), 
        acc_tunnel(i, tcp::endpoint(tcp::v4(), cfg.hydra_port)),
        acc_socks(i, tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), cfg.socks_port)) {
        accept_tunnel();
        accept_socks();
    }

    void accept_tunnel() {
        acc_tunnel.async_accept([this](std::error_code ec, tcp::socket s) {
            if (!ec) std::make_shared<Session>(std::move(s), ctx)->start_inbound();
            accept_tunnel();
        });
    }

    void accept_socks() {
        acc_socks.async_accept([this](std::error_code ec, tcp::socket s) {
            if (!ec) std::make_shared<SOCKS5Server>(std::move(s), ctx)->start();
            accept_socks();
        });
    }
};

#ifdef _WIN32
void setup_autostart() {
    fs::path p = get_base_path() / "hydra7.exe";
    std::string v = "\"" + p.string() + "\" -d";
    HKEY h;
    RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &h);
    RegSetValueExA(h, "Hydra7", 0, REG_SZ, (const BYTE*)v.c_str(), v.length());
    RegCloseKey(h);
}
#endif

int main(int argc, char** argv) {
    load_config();
    bool daemon = false;
    for (int i = 1; i < argc; i++) if (std::string(argv[i]) == "-d") daemon = true;

    if (daemon) {
#ifdef _WIN32
        setup_autostart();
        ShowWindow(GetConsoleWindow(), SW_HIDE);
#else
        if (fork() > 0) exit(0);
        setsid();
#endif
    }

    try {
        asio::io_context ctx;
        Node n(ctx);
        ctx.run();
    } catch (...) {}
    return 0;
}