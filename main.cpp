//
// Created by Calvin Oats on 4/7/2024.
//

#ifdef _WIN32
    #include <winsock2.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>

SSL* ssl;
#endif

int SendPacket(const char* buf) {
    int len = SSL_write(ssl, buf, (int)strlen(buf));
    if (len < 0) {
        int err = SSL_get_error(ssl, len);
        switch (err) {
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_READ:
                return 0;
            case SSL_ERROR_ZERO_RETURN:
            case SSL_ERROR_SYSCALL:
            case SSL_ERROR_SSL:
            default:
                return -1;
        }
    }
    return len;
}

int RecvPacket(char** buf) {
    int len;
    do {
        len = SSL_read(ssl, reinterpret_cast<void *>(buf), 100);
        buf[len] = nullptr;
        printf("%s\n", *buf);
//        fprintf(fp, "%s",buf);
    } while (len > 0);
    if (len < 0) {
        int err = SSL_get_error(ssl, len);
        switch (err) {
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_READ:
                return 1;
            case SSL_ERROR_ZERO_RETURN:
            case SSL_ERROR_SYSCALL:
            case SSL_ERROR_SSL:
            default:
                return -1;
        }
    }
    return len;
}

void log_ssl()
{
    unsigned long err;
    while ((err = ERR_get_error())) {
        char *str = ERR_error_string(err, nullptr);
        if (!str)
            return;
        printf("%s", str);
        printf("\n");
        fflush(stdout);
    }
}

//int sendall(int s, const char *buf, int *len) {
//    int total = 0;        // how many bytes we've sent
//    int bytesleft = *len; // how many we have left to send
//    int n;
//
//    while(total < *len) {
//        n = send(s, buf+total, bytesleft, 0);
//        if (n == -1) { break; }
//        total += n;
//        bytesleft -= n;
//    }
//
//    *len = total; // return number actually sent here
//
//    return n==-1?-1:0; // return -1 on failure, 0 on success
//}

int main() {
    int                     _buffer_size = 1000000;

    int                     s, sock, cur_con, ssl_sock, sp, rp;
//    int                     send_success;
//    ssize_t                 byte_c;
    struct addrinfo         hints{};
    struct addrinfo*        result;
    char*                   buf[_buffer_size];
//    const char*             header;

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_CANONNAME;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

/** Get Address and Connect Socket for Address */
    s = getaddrinfo("xkcd.com", "https", &hints, &result);
    if(s != 0) {
        std::cerr << "Failed to get address information" << std::endl;
        return 1;
    } else {
//        char ip[INET6_ADDRSTRLEN];
//        for(addrinfo* addr = result; addr; addr = addr->ai_next) {
//            std::cout << "Output for each addr info from address: ";
//            std::cout << inet_ntop(addr->ai_family, &reinterpret_cast<sockaddr_in*>(addr->ai_addr)->sin_addr, ip, sizeof(ip)) << "\n";
//        }
        sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        cur_con = connect(sock, result->ai_addr, result->ai_addrlen);
        if(cur_con != 0) {
            std::cerr << "Failed to connect to socket" << std::endl;
            return 2;
        }

/** SSL  Socket and Connection */
//  Set SSL initial variables
        SSL_library_init();
        SSLeay_add_ssl_algorithms();
        SSL_load_error_strings();

//  Set the SSL method
        const SSL_METHOD *ssl_meth = TLS_client_method();
        SSL_CTX *ctx = SSL_CTX_new (ssl_meth);
        ssl = SSL_new (ctx);
        if (!ssl) {
            printf("Error creating SSL.\n");
            log_ssl();
            return -1;
        }

//  Set the SSL socket and start the connection
        ssl_sock = SSL_get_fd(ssl);
        SSL_set_fd(ssl, ssl_sock);
        int ssl_ret = SSL_connect(ssl);
        if (ssl_ret <= 0) {
            int err = SSL_get_error(ssl, ssl_ret);
            char* err_buf = ERR_error_string(errno, nullptr);
            int fatal = ERR_FATAL_ERROR(errno);
            printf("Error creating SSL connection.  err=%d\n"
                   "%s\n"
                   "Is fatal: %s\n", err, err_buf, fatal?"True":"False");
            log_ssl();
            fflush(stdout);
            return -1;
        }
        printf ("SSL connection using %s\n", SSL_get_cipher (ssl));

//  Send the header request and receive the response
        const char* request = "GET https://xkcd.com/rss.xml HTTP/1.1\n"
                              "\n";
        do {
            sp = SendPacket(request);
        } while(sp <= 0);
        do {
            rp = RecvPacket(buf);
        } while(rp != 0);

/** HTTP Socket and Connection */
//        header = "GET /rss.xml HTTP/1.1\n"
//                 "Host: xkcd.com\n"
//                 "\n";
//        send_success = SendPacket(header);
//        if(send_success == -1) {
//            return 3;
//        }
//
//        byte_c = recv(sock, buf, sizeof buf, 0);
//        buf[byte_c] = 0;
//        if(byte_c == 0) {
//            std::cerr << "Failed to receive data" << std::endl;
//            return 4;
//        }
        std::cout << buf << std::endl;
    }

    freeaddrinfo(result);
    return 0;
}