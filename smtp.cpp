#include <arpa/inet.h>
#include <cstring>
#include <netdb.h>
#include <openssl/ssl.h>
#include <stdexcept>
#include <unistd.h>
#include <vector>

std::string base64_encode(const std::string &in) {
    static const std::string base64_chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/";
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

class SMTP {
    int fd;
    SSL_CTX *ctx;
    SSL *ssl;

    void send(const char *msg) {
#ifdef DEBUG
        printf("%s", msg);
#endif
        if (ssl != nullptr)
            SSL_write(ssl, msg, strlen(msg));
        else
            ::send(fd, msg, strlen(msg), 0);
    }

    std::string recv() {
        char buf[16384];
        int r;
        if (ssl != nullptr)
            r = SSL_read(ssl, buf, sizeof(buf));
        else
            r = ::recv(fd, buf, sizeof(buf), 0);
        buf[r] = '\0';
#ifdef DEBUG
        printf("%s", buf);
#endif
        return buf;
    }

    void recv(int code) {
        std::string s = recv();
        char a[16], b[16];
        sprintf(a, "%u ", code);
        sprintf(b, "%u-", code);
        const char *t = s.c_str();
        for (;;) {
            if (strncmp(t, a, strlen(a)) == 0)
                return;
            if (strncmp(t, b, strlen(b)) != 0)
                throw std::runtime_error(s);
            t = strchr(t, '\n');
            if (t == nullptr)
                throw std::runtime_error(s);
            ++t;
        }
    }

public:
    SMTP(const char *host, int port, bool useSsl = false, const char *user = nullptr, const char *pass = nullptr) {
        if (port == 0)
            port = useSsl ? 465 : 25;
        union {
            sockaddr sa;
            sockaddr_in in;
            sockaddr_in6 in6;
        } sa = {0};
        socklen_t sa_len;
        if (inet_pton(AF_INET, host, &sa.in.sin_addr) == 1) {
            sa.sa.sa_family = AF_INET;
            sa.in.sin_port = htons(port);
            sa_len = sizeof(sa.in);
        } else if (inet_pton(AF_INET6, host, &sa.in6.sin6_addr) == 1) {
            sa.sa.sa_family = AF_INET6;
            sa.in6.sin6_port = htons(port);
            sa_len = sizeof(sa.in6);
        } else {
            addrinfo hints = {0}, *res;
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_flags |= AI_CANONNAME;
            int r = getaddrinfo(host, nullptr, &hints, &res);
            if (r == 0)
                for (; res; res = res->ai_next) {
                    if (res->ai_family == AF_INET) {
                        sa.sa.sa_family = AF_INET;
                        sa.in.sin_addr = ((sockaddr_in *) res->ai_addr)->sin_addr;
                        sa.in.sin_port = htons(port);
                        sa_len = sizeof(sa.in);
                        break;
                    } else if (res->ai_family == AF_INET6) {
                        sa.sa.sa_family = AF_INET6;
                        sa.in6.sin6_addr = ((sockaddr_in6 *) res->ai_addr)->sin6_addr;
                        sa.in6.sin6_port = htons(port);
                        sa_len = sizeof(sa.in6);
                    }
                }
            if (sa.sa.sa_family == 0)
                throw std::runtime_error("Unable to resolve host name");
#ifdef DEBUG
            char t[40];
            if (sa.sa.sa_family == AF_INET)
                inet_ntop(sa.sa.sa_family, &sa.in.sin_addr, t, sizeof(t));
            else
                inet_ntop(sa.sa.sa_family, &sa.in6.sin6_addr, t, sizeof(t));
            printf("%s --> %s\n", host, t);
#endif
        }
        if (useSsl) {
            SSL_library_init();
            SSL_load_error_strings();
            OpenSSL_add_all_algorithms();
            ctx = SSL_CTX_new(TLS_client_method());
            if (ctx == nullptr)
                throw std::runtime_error("Unable to create SSL context");
        } else {
            ctx = nullptr;
        }
        fd = socket(sa.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
        int r = connect(fd, &sa.sa, sa_len);
        if (r != 0)
            throw std::runtime_error("Cannot connect to server");
        if (useSsl) {
            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, fd);
            if (SSL_connect(ssl) != 1)
                throw std::runtime_error("Unable to shake hands");
        } else {
            ssl = nullptr;
        }
        recv(220);
        send("EHLO 51myabc.com\r\n");
        recv(250);
        if (user && pass) {
            send("AUTH LOGIN\r\n");
            recv(334);
            send((base64_encode(user) + "\r\n").c_str());
            recv(334);
            send((base64_encode(pass) + "\r\n").c_str());
            recv(235);
        }
    }

    ~SMTP() {
        if (ssl != nullptr) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        close(fd);
        if (ctx != nullptr)
            SSL_CTX_free(ctx);
    }

    void from(const char *from) {
        char buf[16384];
        sprintf(buf, "MAIL FROM:<%s>\r\n", from);
        send(buf);
        recv(250);
    }

    void to(const char *to) {
        char buf[16384];
        sprintf(buf, "RCPT TO:<%s>\r\n", to);
        send(buf);
        recv(250);
    }

    void data(const char *data) {
        send("DATA\r\n");
        recv(354);
        send(data);
        recv(250);
    }
};

std::string decodeMailAddr(const char *s) {
    const char *a = strchr(s, '<');
    if (a != nullptr) {
        const char *b = strchr(++a, '>');
        if (b != nullptr)
            return std::string(a, b - a);
    }
    return s;
}

std::vector<std::string> decodeMailAddrList(const char *s) {
    std::vector<std::string> list;
    const char *a = s, *b;
    while ((b = strchr(a, ',')) != nullptr) {
        list.emplace_back(decodeMailAddr(std::string(a, b - a).c_str()));
        a = b + 1;
        while ((uint8_t) *a <= (uint8_t) ' ')
            ++a;
    }
    list.emplace_back(decodeMailAddr(a));
    return list;
}

int main(int argc, char *argv[]) {
    const char *server = nullptr, *user = nullptr, *pass = nullptr, *file = nullptr;
    int port = 0;
    bool ssl = false;
    for (int i = 1; i < argc; ++i) {
        if (strncmp(argv[i], "--port=", 7) == 0)
            port = (int) strtol(argv[i] + 7, nullptr, 10);
        else if (strcmp(argv[i], "--ssl") == 0)
            ssl = true;
        else if (strncmp(argv[i], "--user=", 7) == 0)
            user = argv[i] + 7;
        else if (strncmp(argv[i], "--pass=", 7) == 0)
            pass = argv[i] + 7;
        else if (strncmp(argv[i], "--file=", 7) == 0)
            file = argv[i] + 7;
        else
            server = argv[i];
    }
    if (server == nullptr) {
        printf("Usage: smtp <server> [options]\n"
               "    <server>            The SMTP server address. It can be a host name, an IPv4 address or an IPv6 address.\n"
               "    --port=<port>       The SMTP server port. Default is 25 or 465 (for SSL).\n"
               "    --ssl               Indicate if SSL is used to connect. Default is false.\n"
               "    --user=<username>   Indicate user name.\n"
               "    --pass=<password>   Indicate password. Auth only if user name and password are both given.\n"
               "    --file=<path>       Indicate mail data file. If not indicated, stdin will be used.\n");
        return 0;
    }
    FILE *fp = file != nullptr ? fopen(file, "rt") : stdin;
    if (fp == nullptr) {
        fprintf(stderr, "ERROR: Unable to open file.\n");
        return -1;
    }
    bool head = true;
    char line[16384];
    std::string data, from;
    std::vector<std::string> to;
    while (fgets(line, sizeof(line), fp)) {
        char *p = line + strlen(line);
        while (p > line && (uint8_t) p[-1] <= (uint8_t) ' ')
            --p;
        *p = '\0';
        data.append(line).append("\r\n");
        if (p == line)
            head = false;
        if (head) {
            if (strncmp(line, "From: ", 6) == 0) {
                from = decodeMailAddr(line + 6);
#ifdef DEBUG
                printf("From: %s\n", from.c_str());
#endif
            } else if (strncmp(line, "To: ", 4) == 0) {
                for (std::string &mailAddr:decodeMailAddrList(line + 4)) {
#ifdef DEBUG
                    printf("To: %s\n", mailAddr.c_str());
#endif
                    to.emplace_back(mailAddr);
                }
            } else if (strncmp(line, "Cc: ", 4) == 0 || strncmp(line, "CC: ", 4) == 0) {
                for (std::string &mailAddr:decodeMailAddrList(line + 4)) {
#ifdef DEBUG
                    printf("CC: %s\n", mailAddr.c_str());
#endif
                    to.emplace_back(mailAddr);
                }
            }
        } else {
            if (strcmp(line, ".") == 0)
                break;
        }
    }
    try {
        if (from.empty())
            throw std::runtime_error("No 'From' in mail.");
        if (to.empty())
            throw std::runtime_error("No 'To' and 'CC' in mail.");
        SMTP smtp(server, port, ssl, user, pass);
        smtp.from(from.c_str());
        for (std::string &addr : to)
            smtp.to(addr.c_str());
        smtp.data(data.c_str());
        if (file != nullptr)
            fclose(fp);
        return 0;
    } catch (const std::exception &e) {
        fprintf(stderr, "ERROR: %s\n", e.what());
        if (file != nullptr)
            fclose(fp);
        return -1;
    }
}
