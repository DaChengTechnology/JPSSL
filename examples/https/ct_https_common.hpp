#pragma once
/**
 * ct_https_common.hpp -- HTTPS + 国际 CT 示例的公共辅助
 *
 * 提供：
 *   - hex / base64 编解码
 *   - 极简 JSON 键值提取（示例自用，不做完整 JSON 解析）
 *   - 基于 tls_connection 的 HTTP GET / 请求读取 / 响应构造
 */
#include "base64.hpp"
#include "ct.hpp"
#include "tls_socket.hpp"

#include <cstdlib>
#include <string>
#include <vector>

namespace jpssl_https {

inline std::string hex_encode(const uint8_t* d, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(H[d[i] >> 4]);
        s.push_back(H[d[i] & 0xF]);
    }
    return s;
}

inline bool hex_decode(const std::string& h, std::vector<uint8_t>& out) {
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    if (h.size() % 2 != 0) return false;
    out.clear();
    out.reserve(h.size() / 2);
    for (size_t i = 0; i < h.size(); i += 2) {
        int hi = val(h[i]), lo = val(h[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back((uint8_t)((hi << 4) | lo));
    }
    return true;
}

/// 极简 JSON：提取 "key":"value"
inline std::string json_get_string(const std::string& json, const std::string& key) {
    std::string pat = "\"" + key + "\":\"";
    size_t p = json.find(pat);
    if (p == std::string::npos) return {};
    p += pat.size();
    size_t q = json.find('"', p);
    return q == std::string::npos ? std::string() : json.substr(p, q - p);
}

/// 极简 JSON：提取 "key":<整数>
inline uint64_t json_get_u64(const std::string& json, const std::string& key) {
    std::string pat = "\"" + key + "\":";
    size_t p = json.find(pat);
    if (p == std::string::npos) return 0;
    return std::strtoull(json.c_str() + p + pat.size(), nullptr, 10);
}

/// 发送 HTTP GET 并读取完整响应体（服务器每个响应后关闭连接）
inline std::string http_get(jpssl::tls::tls_connection& conn, const std::string& host,
                            const std::string& path) {
    conn.send("GET " + path + " HTTP/1.1\r\nHost: " + host +
              "\r\nConnection: close\r\n\r\n");
    std::vector<uint8_t> acc, chunk;
    std::string err;
    while (conn.recv(chunk, &err)) acc.insert(acc.end(), chunk.begin(), chunk.end());
    std::string resp(acc.begin(), acc.end());
    size_t pos = resp.find("\r\n\r\n");
    if (pos == std::string::npos) return resp;
    return resp.substr(pos + 4);
}

/// 读取完整 HTTP 请求头（直到 \r\n\r\n），供服务器使用
inline bool read_http_request(jpssl::tls::tls_connection& conn, std::string& out,
                              std::string* err) {
    std::string acc;
    std::vector<uint8_t> chunk;
    while (acc.find("\r\n\r\n") == std::string::npos) {
        if (!conn.recv(chunk, err)) return false;
        acc.append((const char*)chunk.data(), chunk.size());
    }
    out = acc;
    return true;
}

/// 从请求行提取 GET 路径（含 query）
inline std::string request_path(const std::string& req) {
    size_t a = req.find(' ');
    size_t b = (a == std::string::npos) ? std::string::npos : req.find(' ', a + 1);
    if (a == std::string::npos || b == std::string::npos) return "/";
    return req.substr(a + 1, b - a - 1);
}

/// 构造 200 响应
inline std::string http_respond(const std::string& content_type, const std::string& body) {
    std::string r = "HTTP/1.1 200 OK\r\nContent-Type: " + content_type +
                    "\r\nContent-Length: " + std::to_string(body.size()) +
                    "\r\nConnection: close\r\n\r\n";
    return r + body;
}

inline std::string http_404() {
    std::string body = "Not Found";
    return "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n"
           "Content-Length: " + std::to_string(body.size()) +
           "\r\nConnection: close\r\n\r\n" + body;
}

} // namespace jpssl_https
