#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/certs_test.h>
#include <wolfssl/wolfcrypt/port/iotsafe/iotsafe.h>

#include <stdio.h>
#include <string.h>

static int client_state;
static int server_state;

static WOLFSSL_CTX *srv_ctx;
static WOLFSSL *srv_ssl;
static WOLFSSL_CTX *cli_ctx;
static WOLFSSL *cli_ssl;

#define CLIENT_AUTH

#define TLS_BUFFERS_SZ (1024 * 8)
static unsigned char to_server[TLS_BUFFERS_SZ];
static int server_bytes;
static int server_write_idx;
static int server_read_idx;

static unsigned char to_client[TLS_BUFFERS_SZ];
static int client_bytes;
static int client_write_idx;
static int client_read_idx;

static int mem_send(unsigned char *dst, int *write_idx, int *bytes,
    const char *buf, int sz)
{
    int available;

    if (buf == NULL || dst == NULL || write_idx == NULL || bytes == NULL || sz <= 0) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    available = TLS_BUFFERS_SZ - *write_idx;
    if (available <= 0) {
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    }
    if (sz > available) {
        sz = available;
    }

    memcpy(&dst[*write_idx], buf, (size_t)sz);
    *write_idx += sz;
    *bytes += sz;

    return sz;
}

static int mem_recv(char *buf, int sz, unsigned char *src, int *read_idx,
    int *write_idx, int *bytes)
{
    int available;

    if (buf == NULL || src == NULL || read_idx == NULL || write_idx == NULL ||
        bytes == NULL || sz <= 0) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    available = *write_idx - *read_idx;
    if (available <= 0) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    if (sz > available) {
        sz = available;
    }

    memcpy(buf, &src[*read_idx], (size_t)sz);
    *read_idx += sz;
    *bytes -= sz;

    if (*read_idx == *write_idx) {
        *read_idx = 0;
        *write_idx = 0;
    }

    return sz;
}

static int ServerSend(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    (void)ssl;
    (void)ctx;
    return mem_send(to_client, &client_write_idx, &client_bytes, buf, sz);
}

static int ServerRecv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    (void)ssl;
    (void)ctx;
    return mem_recv(buf, sz, to_server, &server_read_idx, &server_write_idx,
        &server_bytes);
}

static int ClientSend(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    (void)ssl;
    (void)ctx;
    return mem_send(to_server, &server_write_idx, &server_bytes, buf, sz);
}

static int ClientRecv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    (void)ssl;
    (void)ctx;
    return mem_recv(buf, sz, to_client, &client_read_idx, &client_write_idx,
        &client_bytes);
}

static int client_loop(void)
{
    int ret;
    const char *hello = "hello iotsafe over m33mu";
    uint16_t privkey_id = PRIVKEY_ID;
    uint16_t keypair_id = ECDH_KEYPAIR_ID;
    uint16_t peer_pubkey_id = PEER_PUBKEY_ID;
    uint16_t peer_cert_id = PEER_CERT_ID;
    uint16_t cert_file_id = CRT_CLIENT_FILE_ID;
    uint16_t serv_cert_id = CRT_SERVER_FILE_ID;
    unsigned char cert_buffer[2048];
    int cert_buffer_size;

    if (client_state == 0) {
        cli_ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
        if (cli_ctx == NULL) {
            printf("client ctx alloc failed\r\n");
            return -1;
        }

        ret = wolfSSL_CTX_iotsafe_enable(cli_ctx);
        if (ret != 0) {
            printf("iotsafe enable failed: %d\r\n", ret);
            return -1;
        }

        ret = wolfSSL_CTX_load_verify_buffer(cli_ctx, ca_ecc_cert_der_256,
            sizeof_ca_ecc_cert_der_256, WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            printf("client CA load failed: %d\r\n", ret);
            return -1;
        }

        cert_buffer_size = wolfIoTSafe_GetCert_ex((byte *)&cert_file_id,
            IOTSAFE_ID_SIZE, cert_buffer, sizeof(cert_buffer));
        if (cert_buffer_size < 1) {
            printf("client cert read failed: %d\r\n", cert_buffer_size);
            return -1;
        }

        ret = wolfSSL_CTX_use_certificate_buffer(cli_ctx, cert_buffer,
            cert_buffer_size, WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            printf("client cert use failed: %d\r\n", ret);
            return -1;
        }

        cert_buffer_size = wolfIoTSafe_GetCert_ex((byte *)&serv_cert_id,
            IOTSAFE_ID_SIZE, cert_buffer, sizeof(cert_buffer));
        if (cert_buffer_size < 1) {
            printf("server cert read failed: %d\r\n", cert_buffer_size);
            return -1;
        }
        ret = wolfSSL_CTX_load_verify_buffer(cli_ctx, cert_buffer,
            cert_buffer_size, WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            printf("server cert verify load failed: %d\r\n", ret);
            return -1;
        }

        wolfSSL_CTX_set_verify(cli_ctx, WOLFSSL_VERIFY_PEER, NULL);
        wolfSSL_CTX_SetIOSend(cli_ctx, ClientSend);
        wolfSSL_CTX_SetIORecv(cli_ctx, ClientRecv);

        cli_ssl = wolfSSL_new(cli_ctx);
        if (cli_ssl == NULL) {
            printf("client ssl alloc failed\r\n");
            return -1;
        }

        ret = wolfSSL_iotsafe_on_ex(cli_ssl, (byte *)&privkey_id,
            (byte *)&keypair_id, (byte *)&peer_pubkey_id,
            (byte *)&peer_cert_id, IOTSAFE_ID_SIZE);
        if (ret != 0) {
            printf("iotsafe session enable failed: %d\r\n", ret);
            return -1;
        }

        client_state = 1;
    }

    if (client_state == 1) {
        ret = wolfSSL_connect(cli_ssl);
        if (ret != WOLFSSL_SUCCESS) {
            if (wolfSSL_want_read(cli_ssl) || wolfSSL_want_write(cli_ssl)) {
                return 0;
            }
            printf("client connect failed: %d\r\n", wolfSSL_get_error(cli_ssl, ret));
            return -1;
        }
        printf("client connected\r\n");
        client_state = 2;
    }

    if (client_state == 2) {
        ret = wolfSSL_write(cli_ssl, hello, (int)strlen(hello));
        if (ret >= 0) {
            printf("client write ok\r\n");
            wolfSSL_free(cli_ssl);
            cli_ssl = NULL;
            wolfSSL_CTX_free(cli_ctx);
            cli_ctx = NULL;
            client_state = 3;
            return 0;
        }
        if (wolfSSL_get_error(cli_ssl, ret) != WOLFSSL_ERROR_WANT_WRITE) {
            printf("client write failed: %d\r\n", wolfSSL_get_error(cli_ssl, ret));
            return -1;
        }
    }

    return 0;
}

static int server_loop(void)
{
    int ret;
    unsigned char buf[96];

    if (server_state == 0) {
        srv_ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
        if (srv_ctx == NULL) {
            printf("server ctx alloc failed\r\n");
            return -1;
        }

        ret = wolfSSL_CTX_load_verify_buffer(srv_ctx, ca_ecc_cert_der_256,
            sizeof_ca_ecc_cert_der_256, WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            printf("server CA load failed: %d\r\n", ret);
            return -1;
        }
        ret = wolfSSL_CTX_load_verify_buffer(srv_ctx, cliecc_cert_der_256,
            sizeof_cliecc_cert_der_256, WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            printf("server client-cert trust load failed: %d\r\n", ret);
            return -1;
        }
        wolfSSL_CTX_set_verify(srv_ctx,
            WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

        ret = wolfSSL_CTX_use_PrivateKey_buffer(srv_ctx, ecc_key_der_256,
            sizeof_ecc_key_der_256, WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            printf("server key load failed: %d\r\n", ret);
            return -1;
        }
        ret = wolfSSL_CTX_use_certificate_buffer(srv_ctx, serv_ecc_der_256,
            sizeof_serv_ecc_der_256, WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            printf("server cert load failed: %d\r\n", ret);
            return -1;
        }

        wolfSSL_CTX_SetIOSend(srv_ctx, ServerSend);
        wolfSSL_CTX_SetIORecv(srv_ctx, ServerRecv);

        srv_ssl = wolfSSL_new(srv_ctx);
        if (srv_ssl == NULL) {
            printf("server ssl alloc failed\r\n");
            return -1;
        }

        server_state = 1;
    }

    if (server_state == 1) {
        ret = wolfSSL_accept(srv_ssl);
        if (ret != WOLFSSL_SUCCESS) {
            if (wolfSSL_want_read(srv_ssl) || wolfSSL_want_write(srv_ssl)) {
                return 0;
            }
            printf("server accept failed: %d\r\n", wolfSSL_get_error(srv_ssl, ret));
            return -1;
        }
        printf("server accepted\r\n");
        server_state = 2;
    }

    if (server_state == 2) {
        ret = wolfSSL_read(srv_ssl, buf, (int)sizeof(buf) - 1);
        if (ret < 0 && wolfSSL_get_error(srv_ssl, ret) == WOLFSSL_ERROR_WANT_READ) {
            return 0;
        }
        if (ret < 0) {
            printf("server read failed: %d\r\n", wolfSSL_get_error(srv_ssl, ret));
            return -1;
        }
        buf[ret] = '\0';
        printf("server rx: %s\r\n", buf);

        wolfSSL_free(srv_ssl);
        srv_ssl = NULL;
        wolfSSL_CTX_free(srv_ctx);
        srv_ctx = NULL;
        server_state = 3;
        return 1;
    }

    return 0;
}

int memory_tls_test(void)
{
    int ret_s;
    int ret_c;
    unsigned limit = 0;

    printf("starting in-memory TLS test\r\n");
    do {
        ret_s = server_loop();
        ret_c = (ret_s >= 0) ? client_loop() : -1;
        limit++;
        if (limit > 10000u) {
            printf("loop timeout\r\n");
            return -1;
        }
    } while (ret_s == 0 && ret_c >= 0);

    wolfSSL_free(cli_ssl);
    wolfSSL_CTX_free(cli_ctx);
    wolfSSL_free(srv_ssl);
    wolfSSL_CTX_free(srv_ctx);

    return (ret_s > 0 && ret_c >= 0) ? 0 : -1;
}
