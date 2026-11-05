// netsentry — real-time socket audit
// (c) spek_ofc
// build: cl /std:c++20 /EHsc netsentry.cpp

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <wintrust.h>
#include <softpub.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <future>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <thread>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

// console
static void enable_ansi() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    SetConsoleOutputCP(CP_UTF8);
}
static int console_width() {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi))
        return csbi.srWindow.Right - csbi.srWindow.Left + 1;
    return 100;
}
static const char* col(int s) {
    if (s >= 50) return "\x1b[1;31m";
    if (s >= 25) return "\x1b[1;33m";
    return "\x1b[1;32m";
}
static const char* dim()  { return "\x1b[2m"; }
static const char* rst()  { return "\x1b[0m"; }
static const char* risk_label(int s) {
    if (s >= 50) return "HIGH";
    if (s >= 25) return "MED ";
    return "LOW ";
}
static int visible_len(const std::string& s) {
    int n = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\x1b' && i + 1 < s.size() && s[i + 1] == '[') {
            i += 2;
            while (i < s.size() && !(s[i] >= '@' && s[i] <= '~')) ++i;
        } else n++;
    }
    return n;
}
static std::string pad_right(std::string s, size_t w) {
    if (s.size() >= w) return s.substr(0, w);
    s.append(w - s.size(), ' '); return s;
}
static std::string pad_left(std::string s, size_t w) {
    if (s.size() >= w) return s.substr(0, w);
    return std::string(w - s.size(), ' ') + s;
}
static void box_top(const std::string& title, int W) {
    std::string line = "┌─ " + title + " ";
    if ((int)line.size() < W - 1) line.append(W - 1 - line.size(), '─');
    line += "┐";
    std::cout << dim() << line << rst() << "\n";
}
static void box_line(const std::string& content, int W) {
    std::string s = "│ " + content;
    int vis = 2 + visible_len(content);
    if (vis < W - 1) s.append(W - 1 - vis, ' ');
    s += "│";
    std::cout << dim() << s << rst() << "\n";
}
static void box_bottom(int W) {
    std::string s = "└";
    s.append(W - 2, '─');
    s += "┘";
    std::cout << dim() << s << rst() << "\n";
}
static void spin_show(const std::string& body, int W, int frames, int ms) {
    static const char* a = "|/-\\";
    std::string padded = body;
    if ((int)padded.size() + 6 < W) padded.append(W - padded.size() - 6, ' ');
    for (int i = 0; i < frames; ++i) {
        std::cout << "\r" << dim() << padded << " " << a[i & 3] << " " << rst() << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(ms));
    }
}
static void commit_line(const std::string& line, int W) {
    std::cout << "\r" << line;
    int vis = visible_len(line);
    if (vis < W - 1) std::cout << std::string(W - 1 - vis, ' ');
    std::cout << "\n";
}

// model
struct connection {
    std::string proto, local_addr, remote_addr, state, process_name, process_path, rdns;
    uint16_t    local_port = 0, remote_port = 0;
    DWORD       pid = 0;
    bool        signed_bin = false, rdns_resolved = false;
    int         score = 0;
    std::vector<std::string> reasons;
};

// process
static std::string get_process_path(DWORD pid) {
    if (pid == 0 || pid == 4) return {};
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return {};
    wchar_t buf[MAX_PATH * 2]{};
    DWORD sz = sizeof(buf) / sizeof(wchar_t);
    std::string out;
    if (QueryFullProcessImageNameW(h, 0, buf, &sz)) {
        int n = WideCharToMultiByte(CP_UTF8, 0, buf, -1, nullptr, 0, nullptr, nullptr);
        if (n > 0) { out.resize(n - 1); WideCharToMultiByte(CP_UTF8, 0, buf, -1, out.data(), n, nullptr, nullptr); }
    }
    CloseHandle(h);
    return out;
}
static bool is_signed(const std::string& path) {
    if (path.empty()) return false;
    std::wstring w(path.begin(), path.end());
    WINTRUST_FILE_INFO fi{};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = w.c_str();
    WINTRUST_DATA wd{};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG st = WinVerifyTrust(nullptr, &policy, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policy, &wd);
    return st == ERROR_SUCCESS;
}
static std::string base_name(const std::string& p) {
    size_t s = p.find_last_of("\\/");
    return s == std::string::npos ? p : p.substr(s + 1);
}

// rdns
static std::string reverse_dns(const std::string& ip, int timeout_ms, bool& ok) {
    ok = false;
    sockaddr_storage ss{};
    int len = 0;
    if (inet_pton(AF_INET, ip.c_str(), &reinterpret_cast<sockaddr_in*>(&ss)->sin_addr) == 1) {
        auto* sin = reinterpret_cast<sockaddr_in*>(&ss);
        sin->sin_family = AF_INET;
        len = sizeof(sockaddr_in);
    } else if (inet_pton(AF_INET6, ip.c_str(), &reinterpret_cast<sockaddr_in6*>(&ss)->sin6_addr) == 1) {
        auto* s6 = reinterpret_cast<sockaddr_in6*>(&ss);
        s6->sin6_family = AF_INET6;
        len = sizeof(sockaddr_in6);
    } else return {};

    auto fut = std::async(std::launch::async, [&]() -> std::string {
        char host[NI_MAXHOST]{};
        if (getnameinfo(reinterpret_cast<sockaddr*>(&ss), len, host, NI_MAXHOST,
                        nullptr, 0, NI_NAMEREQD) == 0) {
            ok = true; return host;
        }
        return {};
    });
    if (fut.wait_for(std::chrono::milliseconds(timeout_ms)) == std::future_status::ready)
        return fut.get();
    return {};
}

// ip helpers
static bool is_private_or_loopback(const std::string& ip) {
    in_addr a{};
    if (inet_pton(AF_INET, ip.c_str(), &a) != 1) {
        if (ip == "::1") return true;
        unsigned char b[16]{};
        if (inet_pton(AF_INET6, ip.c_str(), b) == 1) {
            if ((b[0] & 0xfe) == 0xfc) return true;
            if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return true;
        }
        return false;
    }
    uint32_t h = ntohl(a.s_addr);
    if ((h & 0xff000000u) == 0x0a000000u) return true;
    if ((h & 0xfff00000u) == 0xac100000u) return true;
    if ((h & 0xffff0000u) == 0xc0a80000u) return true;
    if ((h & 0xff000000u) == 0x7f000000u) return true;
    if ((h & 0xffff0000u) == 0xa9fe0000u) return true;
    if ((h & 0xffc00000u) == 0x64400000u) return true;
    return false;
}
static bool path_is_suspicious(const std::string& p) {
    if (p.empty()) return false;
    std::string low = p;
    std::transform(low.begin(), low.end(), low.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    const char* marks[] = {
        "\\temp\\", "\\tmp\\", "\\downloads\\", "\\appdata\\local\\temp\\",
        "\\appdata\\roaming\\", "\\programdata\\", "\\public\\", "\\perflogs\\"
    };
    for (auto m : marks) if (low.find(m) != std::string::npos) return true;
    return false;
}
static bool port_suspicious(uint16_t p) {
    switch (p) {
        case 4444: case 1337: case 31337: case 6667: case 2222:
        case 51820: case 1080: case 9001: case 9050: case 8888:
            return true;
        default: return false;
    }
}

// scoring
static void score(connection& c) {
    c.reasons.clear(); c.score = 0;
    bool pub = !is_private_or_loopback(c.remote_addr);

    if (port_suspicious(c.remote_port)) {
        c.score += 40;
        c.reasons.push_back("remote port " + std::to_string(c.remote_port) + " matches C2/backdoor list");
    }
    if (pub && path_is_suspicious(c.process_path)) {
        c.score += 30;
        c.reasons.push_back("process in temp/download path talking to public IP");
    }
    if (pub && !c.signed_bin && !c.process_path.empty()) {
        c.score += 25;
        c.reasons.push_back("unsigned process outbound to public IP");
    }
    if (pub && !c.rdns_resolved && c.remote_port > 1024) {
        c.score += 15;
        c.reasons.push_back("no reverse DNS and non-standard high port");
    }
    std::string pn = base_name(c.process_path);
    if ((pn == "svchost.exe" || pn == "explorer.exe" || pn == "lsass.exe") &&
        pub && c.remote_port > 10000) {
        c.score += 20;
        c.reasons.push_back("system process outbound to high port (possible injection)");
    }
    if (c.proto.rfind("UDP", 0) == 0 && pub && c.remote_port != 53 && c.remote_port != 123) {
        c.score += 15;
        c.reasons.push_back("UDP to public IP outside DNS/NTP");
    }
}

// collect
static std::string ipv4_str(DWORD a) {
    in_addr x{}; x.s_addr = a;
    char b[INET_ADDRSTRLEN]{}; inet_ntop(AF_INET, &x, b, sizeof(b)); return b;
}
static std::string ipv6_str(const UCHAR a[16]) {
    char b[INET6_ADDRSTRLEN]{}; inet_ntop(AF_INET6, a, b, sizeof(b)); return b;
}
static std::vector<connection> collect_tcp() {
    std::vector<connection> out;
    for (int af : {AF_INET, AF_INET6}) {
        DWORD sz = 0;
        if (GetExtendedTcpTable(nullptr, &sz, FALSE, af, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) continue;
        std::vector<BYTE> buf(sz);
        if (GetExtendedTcpTable(buf.data(), &sz, FALSE, af, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) continue;
        if (af == AF_INET) {
            auto* t = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                auto& r = t->table[i];
                connection c;
                c.proto = "TCP";
                c.local_addr = ipv4_str(r.dwLocalAddr);
                c.local_port = ntohs((uint16_t)r.dwLocalPort);
                c.remote_addr = ipv4_str(r.dwRemoteAddr);
                c.remote_port = ntohs((uint16_t)r.dwRemotePort);
                c.state = std::to_string(r.dwState);
                c.pid = r.dwOwningPid;
                out.push_back(std::move(c));
            }
        } else {
            auto* t = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buf.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                auto& r = t->table[i];
                connection c;
                c.proto = "TCP6";
                c.local_addr = ipv6_str(r.ucLocalAddr);
                c.local_port = ntohs((uint16_t)r.dwLocalPort);
                c.remote_addr = ipv6_str(r.ucRemoteAddr);
                c.remote_port = ntohs((uint16_t)r.dwRemotePort);
                c.state = std::to_string(r.dwState);
                c.pid = r.dwOwningPid;
                out.push_back(std::move(c));
            }
        }
    }
    return out;
}
static std::vector<connection> collect_udp() {
    std::vector<connection> out;
    for (int af : {AF_INET, AF_INET6}) {
        DWORD sz = 0;
        if (GetExtendedUdpTable(nullptr, &sz, FALSE, af, UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER) continue;
        std::vector<BYTE> buf(sz);
        if (GetExtendedUdpTable(buf.data(), &sz, FALSE, af, UDP_TABLE_OWNER_PID, 0) != NO_ERROR) continue;
        if (af == AF_INET) {
            auto* t = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buf.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                auto& r = t->table[i];
                connection c;
                c.proto = "UDP";
                c.local_addr = ipv4_str(r.dwLocalAddr);
                c.local_port = ntohs((uint16_t)r.dwLocalPort);
                c.remote_addr = "0.0.0.0";
                c.remote_port = 0;
                c.state = "UDP";
                c.pid = r.dwOwningPid;
                out.push_back(std::move(c));
            }
        } else {
            auto* t = reinterpret_cast<MIB_UDP6TABLE_OWNER_PID*>(buf.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                auto& r = t->table[i];
                connection c;
                c.proto = "UDP6";
                c.local_addr = ipv6_str(r.ucLocalAddr);
                c.local_port = ntohs((uint16_t)r.dwLocalPort);
                c.remote_addr = "::";
                c.remote_port = 0;
                c.state = "UDP";
                c.pid = r.dwOwningPid;
                out.push_back(std::move(c));
            }
        }
    }
    return out;
}

// output
static void print_json(const std::vector<connection>& v) {
    std::cout << "[\n";
    for (size_t i = 0; i < v.size(); ++i) {
        auto& c = v[i];
        std::cout << "  {\"proto\":\"" << c.proto
                  << "\",\"remote\":\"" << c.remote_addr << "\",\"port\":" << c.remote_port
                  << ",\"pid\":" << c.pid
                  << ",\"process\":\"" << base_name(c.process_path) << "\""
                  << ",\"path\":\"" << c.process_path << "\""
                  << ",\"signed\":" << (c.signed_bin ? "true" : "false")
                  << ",\"rdns\":\"" << c.rdns << "\""
                  << ",\"score\":" << c.score
                  << ",\"reasons\":[";
        for (size_t j = 0; j < c.reasons.size(); ++j)
            std::cout << (j ? "," : "") << "\"" << c.reasons[j] << "\"";
        std::cout << "]}";
        if (i + 1 < v.size()) std::cout << ",";
        std::cout << "\n";
    }
    std::cout << "]\n";
}

// main
int main(int argc, char** argv) {
    enable_ansi();
    bool json = false, fast = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--json") json = true;
        else if (a == "--fast") fast = true;
    }

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { std::cerr << "WSAStartup failed\n"; return 1; }

    auto conns = collect_tcp();
    auto udps  = collect_udp();
    conns.insert(conns.end(), udps.begin(), udps.end());
    std::sort(conns.begin(), conns.end(), [](auto& a, auto& b) {
        if (a.pid != b.pid) return a.pid < b.pid;
        if (a.remote_addr != b.remote_addr) return a.remote_addr < b.remote_addr;
        return a.remote_port < b.remote_port;
    });
    conns.erase(std::unique(conns.begin(), conns.end(), [](auto& a, auto& b) {
        return a.pid == b.pid && a.remote_addr == b.remote_addr && a.remote_port == b.remote_port;
    }), conns.end());

    size_t total = conns.size();

    if (json) {
        size_t budget = 64;
        for (auto& c : conns) {
            c.process_path = get_process_path(c.pid);
            c.signed_bin = is_signed(c.process_path);
            c.process_name = base_name(c.process_path);
            if (budget > 0 && c.remote_addr != "0.0.0.0" && c.remote_addr != "::") {
                bool ok = false;
                c.rdns = reverse_dns(c.remote_addr, 800, ok);
                c.rdns_resolved = ok;
                --budget;
            }
            score(c);
        }
        print_json(conns);
        WSACleanup();
        return 0;
    }

    int W = console_width();
    if (W < 80) W = 80;
    if (W > 140) W = 140;

    auto t_start = std::chrono::steady_clock::now();

    box_top("netsentry — real-time socket audit", W);
    box_line("endpoints   " + std::to_string(total), W);
    box_line("rdns budget 64  ·  timeout 800ms  ·  mode " + std::string(fast ? "fast" : "live"), W);
    box_line("pipeline    process image  ·  Authenticode  ·  reverse dns  ·  heuristic", W);
    box_line("(c) spek_ofc", W);
    box_bottom(W);
    std::cout << "\n";

    std::cout << dim()
              << pad_left("#", 11) << "  "
              << pad_right("proto", 5) << " "
              << pad_right("remote", 24) << " "
              << pad_right("process", 22) << "  "
              << pad_right("risk", 4) << " " << pad_left("score", 4)
              << rst() << "\n";
    std::cout << dim() << std::string(77, '─') << rst() << "\n";

    size_t rdns_budget = 64;
    int digits = (int)std::to_string(total).size();
    if (digits < 3) digits = 3;

    for (size_t i = 0; i < conns.size(); ++i) {
        auto& c = conns[i];

        c.process_path = get_process_path(c.pid);
        c.signed_bin   = is_signed(c.process_path);
        c.process_name = base_name(c.process_path);

        char tagbuf[32];
        snprintf(tagbuf, sizeof(tagbuf), "[%*zu/%zu]", digits, i + 1, total);
        std::string tag = tagbuf;

        std::string proto    = pad_right(c.proto, 5);
        std::string remote   = pad_right(c.remote_addr + ":" + std::to_string(c.remote_port), 24);
        std::string procname = pad_right(c.process_name.empty()
                                         ? "<pid " + std::to_string(c.pid) + ">"
                                         : c.process_name, 22);

        if (!fast) {
            std::string body = "  " + tag + "  " + proto + " " + remote + " " + procname;
            spin_show(body, W, 3, 15);
        }

        if (rdns_budget > 0 && c.remote_addr != "0.0.0.0" && c.remote_addr != "::") {
            bool ok = false;
            c.rdns = reverse_dns(c.remote_addr, 800, ok);
            c.rdns_resolved = ok;
            --rdns_budget;
        }
        score(c);

        char line[512];
        snprintf(line, sizeof(line), "  %s  %-5s %-24s %-22s  %s%-4s %4d%s",
                 tag.c_str(), c.proto.c_str(), remote.c_str(), procname.c_str(),
                 col(c.score), risk_label(c.score), c.score, rst());
        commit_line(line, W);

        if (!c.reasons.empty()) {
            std::string joined;
            for (size_t j = 0; j < c.reasons.size(); ++j)
                joined += (j ? "  ·  " : "") + c.reasons[j];
            int room = W - 18;
            if (room < 20) room = 20;
            if ((int)joined.size() > room) joined = joined.substr(0, room - 3) + "...";
            std::cout << dim() << "             \\_ " << joined << rst() << "\n";
        }
    }

    auto t_end = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();

    std::cout << "\n";

    int high = 0, med = 0, low = 0;
    long long total_score = 0;
    for (auto& c : conns) {
        if (c.score >= 50) high++;
        else if (c.score >= 25) med++;
        else low++;
        total_score += c.score;
    }
    box_top("summary", W);
    box_line("scanned  " + std::to_string(total) +
             "   high " + std::to_string(high) +
             "   med  " + std::to_string(med) +
             "   low  " + std::to_string(low), W);
    box_line("total risk " + std::to_string(total_score) +
             "   avg " + std::to_string(total ? total_score / (long long)total : 0) +
             "   elapsed " + std::to_string(ms) + "ms", W);
    box_bottom(W);

    std::sort(conns.begin(), conns.end(), [](auto& a, auto& b) { return a.score > b.score; });
    std::cout << "\n";
    box_top("top offenders", W);
    int shown = 0;
    for (auto& c : conns) {
        if (c.score < 25) break;
        if (shown++ >= 8) break;
        std::string pn = c.process_name.empty() ? "<pid " + std::to_string(c.pid) + ">" : c.process_name;
        char line[512];
        snprintf(line, sizeof(line), "%s%-4s %4d%s   %s:%d   %s",
                 col(c.score), risk_label(c.score), c.score, rst(),
                 c.remote_addr.c_str(), c.remote_port, pn.c_str());
        box_line(line, W);
    }
    if (shown == 0) box_line("no endpoints scored above threshold", W);
    box_bottom(W);

    WSACleanup();
    return 0;
}