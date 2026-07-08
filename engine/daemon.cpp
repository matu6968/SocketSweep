// ============================================================================
// daemon.cpp — Anti-MTP Android Storage Analyzer Engine
// ============================================================================

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <cerrno>
#include <fstream>
#include <filesystem>
#include <iostream>

// ── Configuration ───────────────────────────────────────────────────────────
namespace cfg {
    constexpr uint16_t    PORT              = 5050;
    constexpr const char* BIND_ADDR         = "127.0.0.1";
    constexpr const char* DEFAULT_ROOT      = "/sdcard";
    constexpr int         LISTEN_BACKLOG    = 4;
    constexpr int         MAX_DEPTH         = 64;
    constexpr int         RECV_TIMEOUT_SEC  = 30;
}

// ── Globals ─────────────────────────────────────────────────────────────────
static volatile sig_atomic_t g_running = 1;
static void on_signal(int) { g_running = 0; }

// ── Network & Streaming Helpers ─────────────────────────────────────────────
class JsonStream {
    int fd;
    std::string buf;
public:
    JsonStream(int fd) : fd(fd) {
        buf.reserve(64 * 1024);
    }
    ~JsonStream() { flush(); }
    
    bool write(const char* data, size_t len) {
        if (buf.size() + len > buf.capacity()) {
            if (!flush()) return false;
        }
        if (len >= buf.capacity()) {
            return send_all(fd, data, len);
        } else {
            buf.append(data, len);
            return true;
        }
    }
    
    bool write(const std::string& s) { return write(s.data(), s.size()); }
    
    bool flush() {
        if (!buf.empty()) {
            bool ok = send_all(fd, buf.data(), buf.size());
            buf.clear();
            return ok;
        }
        return true;
    }

    static bool send_all(int fd, const char* p, size_t left) {
        while (left > 0) {
            ssize_t n = ::send(fd, p, left, MSG_NOSIGNAL);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) return false;
            p    += n;
            left -= static_cast<size_t>(n);
        }
        return true;
    }
};

static std::string recv_line(int fd) {
    std::string line;
    char c;
    while (true) {
        ssize_t n = ::recv(fd, &c, 1, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        if (c == '\n') break;
        if (c != '\r') line += c;
    }
    return line;
}

static std::string trim(std::string s) {
    while (!s.empty() && s.back()  == ' ') s.pop_back();
    size_t start = s.find_first_not_of(' ');
    return (start == std::string::npos) ? "" : s.substr(start);
}

static bool recv_all(int fd, char* p, size_t left) {
    while (left > 0) {
        ssize_t n = ::recv(fd, p, left, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        p    += n;
        left -= static_cast<size_t>(n);
    }
    return true;
}

static int upload_timeout_sec(int64_t size_bytes) {
    int64_t sec = 60 + (size_bytes / (1024 * 1024)) * 5;
    if (sec > 3600) sec = 3600;
    return static_cast<int>(sec);
}

static bool is_allowed_path(const std::string& path) {
    if (path.rfind("/sdcard", 0) == 0) {
        if (path.size() == 7 || path[7] == '/') return true;
    }
    if (path.rfind("/storage/emulated/0", 0) == 0) {
        if (path.size() == 21 || path[21] == '/') return true;
    }
    return false;
}

static void set_recv_timeout(int fd, int sec) {
    struct timeval tv { sec, 0 };
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

static std::vector<std::string> tokenize(const std::string& s) {
    std::vector<std::string> tokens;
    std::string cur;
    for (char c : s) {
        if (c == ' ') {
            if (!cur.empty()) {
                tokens.push_back(cur);
                cur.clear();
            }
        } else {
            cur += c;
        }
    }
    if (!cur.empty()) tokens.push_back(cur);
    return tokens;
}

static void apply_file_times(const std::string& path,
                             int64_t mtime_sec, int64_t mtime_nsec,
                             int64_t atime_sec, int64_t atime_nsec)
{
    if (mtime_sec <= 0) return;

    struct timespec ts[2]{};
    if (atime_sec > 0) {
        ts[0].tv_sec  = atime_sec;
        ts[0].tv_nsec = atime_nsec;
    } else {
        ts[0].tv_sec  = mtime_sec;
        ts[0].tv_nsec = mtime_nsec;
    }
    ts[1].tv_sec  = mtime_sec;
    ts[1].tv_nsec = mtime_nsec;

    if (::utimensat(AT_FDCWD, path.c_str(), ts, 0) != 0) {
        std::fprintf(stderr, "[engine] utimensat failed for \"%s\": %s\n",
                     path.c_str(), std::strerror(errno));
    }
}

static void stat_times_to_json(JsonStream& out, const struct stat& info) {
    int64_t mtime_sec  = info.st_mtim.tv_sec;
    int64_t mtime_nsec = info.st_mtim.tv_nsec;
    int64_t atime_sec  = info.st_atim.tv_sec;
    int64_t atime_nsec = info.st_atim.tv_nsec;

    out.write(",\"mtime_sec\":");
    out.write(std::to_string(mtime_sec));
    out.write(",\"mtime_nsec\":");
    out.write(std::to_string(mtime_nsec));
    out.write(",\"atime_sec\":");
    out.write(std::to_string(atime_sec));
    out.write(",\"atime_nsec\":");
    out.write(std::to_string(atime_nsec));
}

// ── Data Model ──────────────────────────────────────────────────────────────
struct FileNode {
    std::string              name;
    std::string              path;
    bool                     is_dir = false;
    int64_t                  size   = 0;
    std::vector<FileNode>    children;
};

struct ScanStats {
    int64_t files      = 0;
    int64_t dirs       = 0;
    int64_t total_size = 0;
    int64_t errors     = 0;
};

// ── JSON helpers ────────────────────────────────────────────────────────────
static void json_escape_into(JsonStream& out, const std::string& s) {
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out.write("\\\"", 2); break;
            case '\\': out.write("\\\\", 2); break;
            case '\b': out.write("\\b", 2); break;
            case '\f': out.write("\\f", 2); break;
            case '\n': out.write("\\n", 2); break;
            case '\r': out.write("\\r", 2); break;
            case '\t': out.write("\\t", 2); break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    int len = std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out.write(buf, len);
                } else {
                    char b = static_cast<char>(c);
                    out.write(&b, 1);
                }
        }
    }
}

static void serialize_node(JsonStream& out, const FileNode& node) {
    out.write("{\"name\":\"");
    json_escape_into(out, node.name);
    out.write("\",\"path\":\"");
    json_escape_into(out, node.path);
    out.write("\",\"type\":");
    out.write(node.is_dir ? "\"directory\"" : "\"file\"");
    out.write(",\"size\":");
    out.write(std::to_string(node.size));

    if (node.is_dir) {
        out.write(",\"children\":[");
        for (size_t i = 0; i < node.children.size(); ++i) {
            if (i > 0) out.write(",");
            serialize_node(out, node.children[i]);
        }
        out.write("]");
    }
    out.write("}");
}

// ── Recursive Scanner ───────────────────────────────────────────────────────
static FileNode scan(const std::string& path, const std::string& name,
                     ScanStats& st, int depth)
{
    FileNode node;
    node.name = name;
    node.path = path;

    struct stat info{};
    int stat_res = (depth == 0) ? ::stat(path.c_str(), &info) : ::lstat(path.c_str(), &info);
    if (stat_res != 0) {
        ++st.errors;
        return node;
    }

    if (depth > 0 && S_ISLNK(info.st_mode)) return node;

    if (S_ISREG(info.st_mode)) {
        node.size = info.st_size;
        ++st.files;
        st.total_size += info.st_size;
        return node;
    }

    if (!S_ISDIR(info.st_mode)) return node;

    node.is_dir = true;
    ++st.dirs;

    if (depth >= cfg::MAX_DEPTH) { ++st.errors; return node; }

    DIR* dir = ::opendir(path.c_str());
    if (!dir) { ++st.errors; return node; }

    struct dirent* ent;
    while ((ent = ::readdir(dir)) != nullptr) {
        if (ent->d_name[0] == '.') {
            if (ent->d_name[1] == '\0') continue;
            if (ent->d_name[1] == '.' && ent->d_name[2] == '\0') continue;
        }

        #ifdef DT_LNK
        if (ent->d_type == DT_LNK) continue;
        #endif

        std::string child_path = path + '/' + ent->d_name;

        FileNode child = scan(child_path, ent->d_name, st, depth + 1);
        node.size += child.size;
        node.children.push_back(std::move(child));
    }
    ::closedir(dir);

    std::sort(node.children.begin(), node.children.end(),
              [](const FileNode& a, const FileNode& b) {
                  return a.size > b.size;
              });

    return node;
}

// ── Upload handler ──────────────────────────────────────────────────────────
static void handle_put(int fd, JsonStream& out, const std::string& dest_path,
                       int64_t size_bytes,
                       int64_t mtime_sec, int64_t mtime_nsec,
                       int64_t atime_sec, int64_t atime_nsec)
{
    if (!is_allowed_path(dest_path)) {
        out.write("{\"status\":\"error\",\"message\":\"Path not allowed\"}\n");
        return;
    }
    if (size_bytes < 0) {
        out.write("{\"status\":\"error\",\"message\":\"Invalid size\"}\n");
        return;
    }

    set_recv_timeout(fd, upload_timeout_sec(size_bytes));

    std::error_code ec;
    std::filesystem::path dest(dest_path);
    auto parent = dest.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            out.write("{\"status\":\"error\",\"message\":\"");
            json_escape_into(out, ec.message());
            out.write("\"}\n");
            return;
        }
    }

    std::ofstream file(dest_path, std::ios::binary | std::ios::trunc);
    if (!file) {
        out.write("{\"status\":\"error\",\"message\":\"Failed to open destination file\"}\n");
        return;
    }

    std::vector<char> buf(256 * 1024);
    int64_t remaining = size_bytes;
    int64_t written   = 0;

    while (remaining > 0) {
        size_t chunk = static_cast<size_t>(
            remaining > static_cast<int64_t>(buf.size()) ? buf.size() : remaining);
        if (!recv_all(fd, buf.data(), chunk)) {
            file.close();
            std::filesystem::remove(dest_path, ec);
            out.write("{\"status\":\"error\",\"message\":\"Upload interrupted\"}\n");
            return;
        }
        file.write(buf.data(), static_cast<std::streamsize>(chunk));
        if (!file) {
            file.close();
            std::filesystem::remove(dest_path, ec);
            out.write("{\"status\":\"error\",\"message\":\"Failed to write file\"}\n");
            return;
        }
        remaining -= static_cast<int64_t>(chunk);
        written   += static_cast<int64_t>(chunk);
    }
    file.close();

    apply_file_times(dest_path, mtime_sec, mtime_nsec, atime_sec, atime_nsec);

    std::fprintf(stderr, "[engine] PUT \"%s\" (%lld bytes)\n",
                 dest_path.c_str(), (long long)written);

    out.write("{\"status\":\"ok\",\"bytes_written\":");
    out.write(std::to_string(written));
    out.write(",\"path\":\"");
    json_escape_into(out, dest_path);
    out.write("\"}\n");
}

// ── Download handler ────────────────────────────────────────────────────────
static void handle_get(int fd, const std::string& source_path) {
    JsonStream out(fd);

    if (!is_allowed_path(source_path)) {
        out.write("{\"status\":\"error\",\"message\":\"Path not allowed\"}\n");
        return;
    }

    struct stat info{};
    if (::stat(source_path.c_str(), &info) != 0) {
        out.write("{\"status\":\"error\",\"message\":\"File not found\"}\n");
        return;
    }
    if (!S_ISREG(info.st_mode)) {
        out.write("{\"status\":\"error\",\"message\":\"Not a file\"}\n");
        return;
    }

    int64_t size_bytes = info.st_size;
    if (size_bytes < 0) {
        out.write("{\"status\":\"error\",\"message\":\"Invalid file size\"}\n");
        return;
    }

    std::ifstream file(source_path, std::ios::binary);
    if (!file) {
        out.write("{\"status\":\"error\",\"message\":\"Failed to open source file\"}\n");
        return;
    }

    out.write("{\"status\":\"ok\",\"size\":");
    out.write(std::to_string(size_bytes));
    out.write(",\"path\":\"");
    json_escape_into(out, source_path);
    out.write("\"");
    stat_times_to_json(out, info);
    out.write("}\n");
    if (!out.flush()) {
        return;
    }

    std::vector<char> buf(256 * 1024);
    int64_t remaining = size_bytes;
    int64_t sent      = 0;

    while (remaining > 0) {
        size_t chunk = static_cast<size_t>(
            remaining > static_cast<int64_t>(buf.size()) ? buf.size() : remaining);
        file.read(buf.data(), static_cast<std::streamsize>(chunk));
        if (!file && !file.eof()) {
            std::fprintf(stderr, "[engine] GET read error for \"%s\"\n", source_path.c_str());
            return;
        }
        std::streamsize got = file.gcount();
        if (got <= 0) break;
        if (!JsonStream::send_all(fd, buf.data(), static_cast<size_t>(got))) {
            std::fprintf(stderr, "[engine] GET send interrupted for \"%s\"\n", source_path.c_str());
            return;
        }
        remaining -= got;
        sent      += got;
    }

    std::fprintf(stderr, "[engine] GET \"%s\" (%lld bytes)\n",
                 source_path.c_str(), (long long)sent);
}

// ── Command dispatch ────────────────────────────────────────────────────────
static void handle_client(int fd) {
    set_recv_timeout(fd, cfg::RECV_TIMEOUT_SEC);

    std::string cmd = trim(recv_line(fd));
    if (cmd.empty()) return;

    JsonStream out(fd);

    if (cmd == "PING") {
        out.write("{\"status\":\"ok\",\"message\":\"pong\"}\n");
    }
    else if (cmd == "SHUTDOWN") {
        out.write("{\"status\":\"ok\",\"message\":\"shutting down\"}\n");
        out.flush();
        g_running = 0;
        return;
    }
    else if (cmd.rfind("DELETE ", 0) == 0) {
        std::string target = trim(cmd.substr(7));
        std::error_code ec;
        std::uintmax_t removed = std::filesystem::remove_all(target, ec);
        if (ec) {
            out.write("{\"status\":\"error\",\"message\":\"");
            json_escape_into(out, ec.message());
            out.write("\"}\n");
        } else {
            out.write("{\"status\":\"ok\",\"message\":\"Deleted ");
            out.write(std::to_string(removed));
            out.write(" items\"}\n");
        }
    }
    else if (cmd.rfind("SCAN", 0) == 0) {
        std::string root = cfg::DEFAULT_ROOT;
        if (cmd.size() > 4) {
            std::string arg = trim(cmd.substr(4));
            if (!arg.empty()) root = arg;
        }
        while (root.size() > 1 && root.back() == '/') root.pop_back();

        std::string root_name = root;
        auto pos = root.rfind('/');
        if (pos != std::string::npos && pos + 1 < root.size())
            root_name = root.substr(pos + 1);

        std::fprintf(stderr, "[engine] SCAN \"%s\" ...\n", root.c_str());

        auto t0 = std::chrono::steady_clock::now();
        ScanStats stats{};
        FileNode tree = scan(root, root_name, stats, 0);
        auto t1 = std::chrono::steady_clock::now();
        int64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

        std::fprintf(stderr, "[engine] Done: %lld files, %lld dirs, "
                     "%lld bytes, %lld errors, %lld ms\n",
                     (long long)stats.files, (long long)stats.dirs,
                     (long long)stats.total_size, (long long)stats.errors,
                     (long long)ms);

        out.write("{\"status\":\"ok\",\"scan_time_ms\":");
        out.write(std::to_string(ms));
        out.write(",\"total_files\":");
        out.write(std::to_string(stats.files));
        out.write(",\"total_dirs\":");
        out.write(std::to_string(stats.dirs));
        out.write(",\"total_size\":");
        out.write(std::to_string(stats.total_size));
        out.write(",\"errors\":");
        out.write(std::to_string(stats.errors));
        out.write(",\"tree\":");
        serialize_node(out, tree);
        out.write("}\n");
    }
    else if (cmd.rfind("GET ", 0) == 0) {
        std::string source_path = trim(cmd.substr(4));
        handle_get(fd, source_path);
    }
    else if (cmd.rfind("PUT ", 0) == 0) {
        auto tokens = tokenize(trim(cmd.substr(4)));
        if (tokens.size() < 2) {
            out.write("{\"status\":\"error\",\"message\":\"Usage: PUT <path> <size> [mtime_sec mtime_nsec atime_sec atime_nsec]\"}\n");
        } else {
            int64_t mtime_sec = 0, mtime_nsec = 0, atime_sec = 0, atime_nsec = 0;
            int64_t size_bytes = 0;
            std::string dest_path;

            if (tokens.size() >= 6) {
                atime_nsec = std::strtoll(tokens.back().c_str(), nullptr, 10); tokens.pop_back();
                atime_sec  = std::strtoll(tokens.back().c_str(), nullptr, 10); tokens.pop_back();
                mtime_nsec = std::strtoll(tokens.back().c_str(), nullptr, 10); tokens.pop_back();
                mtime_sec  = std::strtoll(tokens.back().c_str(), nullptr, 10); tokens.pop_back();
                size_bytes = std::strtoll(tokens.back().c_str(), nullptr, 10); tokens.pop_back();
            } else {
                size_bytes = std::strtoll(tokens.back().c_str(), nullptr, 10); tokens.pop_back();
            }

            dest_path = tokens[0];
            for (size_t i = 1; i < tokens.size(); ++i) {
                dest_path += " ";
                dest_path += tokens[i];
            }

            handle_put(fd, out, dest_path, size_bytes,
                         mtime_sec, mtime_nsec, atime_sec, atime_nsec);
        }
    }
    else {
        out.write("{\"status\":\"error\",\"message\":\"Unknown command\"}\n");
    }
    out.flush();
}

// ── Main ────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    std::ios_base::sync_with_stdio(false);

    uint16_t port = cfg::PORT;
    if (argc > 1) port = static_cast<uint16_t>(std::atoi(argv[1]));

    ::signal(SIGINT,  on_signal);
    ::signal(SIGTERM, on_signal);
    ::signal(SIGPIPE, SIG_IGN);

    int srv = ::socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { std::perror("[engine] socket"); return 1; }

    int yes = 1;
    ::setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    ::inet_pton(AF_INET, cfg::BIND_ADDR, &addr.sin_addr);

    if (::bind(srv, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::perror("[engine] bind");
        ::close(srv);
        return 1;
    }
    if (::listen(srv, cfg::LISTEN_BACKLOG) < 0) {
        std::perror("[engine] listen");
        ::close(srv);
        return 1;
    }

    std::fprintf(stderr, "[engine] Listening on %s:%u  (pid %d)\n",
                 cfg::BIND_ADDR, port, static_cast<int>(::getpid()));

    while (g_running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(srv, &fds);
        struct timeval tv { 1, 0 };
        int sel = ::select(srv + 1, &fds, nullptr, nullptr, &tv);
        if (sel <= 0) continue;

        struct sockaddr_in peer{};
        socklen_t peer_len = sizeof(peer);
        int client = ::accept(srv, reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (client < 0) continue;

        std::fprintf(stderr, "[engine] Client connected\n");
        handle_client(client);
        ::close(client);
        std::fprintf(stderr, "[engine] Client disconnected\n");
    }

    ::close(srv);
    std::fprintf(stderr, "[engine] Shutdown complete.\n");
    return 0;
}
