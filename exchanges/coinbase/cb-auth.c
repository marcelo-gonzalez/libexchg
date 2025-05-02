// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Marcelo Diop-Gonzalez

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include "b64.h"
#include "compiler.h"
#include "json-helpers.h"
#include "time-helpers.h"

#include "cb-auth.h"
#include "cb-client.h"

static int __jwt_b64_push_str(struct b64_state *state, const unsigned char *s,
                              size_t len)
{
        if (b64url_step(state, (unsigned char *)"\"", 1))
                return -1;
        if (b64url_step(state, s, len))
                return -1;
        return b64url_step(state, (unsigned char *)"\"", 1);
}

static int __jwt_b64_push_key(struct b64_state *state, const char *key)
{
        if (__jwt_b64_push_str(state, (unsigned char *)key, strlen(key)))
                return -1;
        return b64url_step(state, (unsigned char *)":", 1);
}

// TODO: redundant with jwt_b64_add_key_str()
static int jwt_b64_add_key(struct b64_state *state, const char *key,
                           const char *value)
{
        if (b64url_step(state, (unsigned char *)",", 1))
                return -1;
        if (__jwt_b64_push_key(state, key))
                return -1;
        return b64url_step(state, (unsigned char *)value, strlen(value));
}

static int __jwt_b64_add_key_ustr(struct b64_state *state, const char *key,
                                  const unsigned char *value, size_t value_len)
{
        if (__jwt_b64_push_key(state, key))
                return -1;
        return __jwt_b64_push_str(state, value, value_len);
}

static int jwt_b64_add_key_ustr(struct b64_state *state, const char *key,
                                const unsigned char *value, size_t value_len)
{
        if (b64url_step(state, (unsigned char *)",", 1))
                return -1;
        return __jwt_b64_add_key_ustr(state, key, value, value_len);
}

static int jwt_b64_add_key_str(struct b64_state *state, const char *key,
                               const char *value)
{
        return jwt_b64_add_key_ustr(state, key, (unsigned char *)value,
                                    strlen(value));
}

static int jwt_b64_json_start(struct b64_state *state, const char *key,
                              const char *value)
{
        if (b64url_step(state, (unsigned char *)"{", 1))
                return -1;
        return __jwt_b64_add_key_ustr(state, key, (unsigned char *)value,
                                      strlen(value));
}

static int jwt_b64_end_json(struct b64_state *state)
{
        return b64url_step(state, (unsigned char *)"}", 1);
}

static int jwt_next_section(struct b64_state *state)
{
        return b64_putc(state, '.');
}

static int add_jwt_protected_headers(struct exchg_client *cl,
                                     struct b64_state *state)
{
        uint64_t nonce;
        if (RAND_bytes((unsigned char *)&nonce, sizeof(nonce)) != 1) {
                exchg_log("%s: RAND_bytes() failed\n", __func__);
                ERR_print_errors_fp(stderr);
                return -1;
        }
        char nonce_str[22];
        size_t nonce_len =
            snprintf(nonce_str, sizeof(nonce_str), "%" PRIu64, nonce);
        if (unlikely(nonce_len >= sizeof(nonce_str))) {
                exchg_log("coinbase: unexpected length %zu of nonce string??\n",
                          nonce_len);
                return -1;
        }

        if (jwt_b64_json_start(state, "alg", "ES256"))
                return -1;
        if (jwt_b64_add_key_str(state, "typ", "JWT"))
                return -1;
        if (jwt_b64_add_key_ustr(state, "kid", cl->apikey_public,
                                 cl->apikey_public_len))
                return -1;
        if (jwt_b64_add_key_ustr(state, "nonce", (unsigned char *)nonce_str,
                                 nonce_len))
                return -1;
        if (jwt_b64_end_json(state))
                return -1;
        return b64url_close(state);
}

static int add_jwt_unprotected_headers(struct exchg_client *cl,
                                       struct b64_state *state, const char *uri)
{
        int64_t not_before = current_seconds() - 1;
        int64_t not_after = not_before + 120;

        char nbf[22];
        snprintf(nbf, sizeof(nbf), "%" PRId64, not_before);
        char exp[22];
        snprintf(exp, sizeof(exp), "%" PRId64, not_after);

        if (jwt_b64_json_start(state, "iss", "cdp"))
                return -1;
        if (jwt_b64_add_key(state, "nbf", nbf))
                return -1;
        if (jwt_b64_add_key(state, "exp", exp))
                return -1;
        if (jwt_b64_add_key_ustr(state, "sub", cl->apikey_public,
                                 cl->apikey_public_len))
                return -1;
        if (uri && jwt_b64_add_key_str(state, "uri", uri))
                return -1;
        if (jwt_b64_end_json(state))
                return -1;
        return b64url_close(state);
}

static int add_jwt_headers(struct exchg_client *cl, struct b64_state *state,
                           const char *uri)
{
        if (add_jwt_protected_headers(cl, state))
                return -1;
        if (jwt_next_section(state))
                return -1;
        return add_jwt_unprotected_headers(cl, state, uri);
}

static int do_sign(struct exchg_client *cl, unsigned char *sig, size_t *sig_len,
                   unsigned char *data, size_t data_len)
{
        struct coinbase_client *cb = client_private(cl);

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) {
                exchg_log("%s: EVP_MD_CTX_new() failed\n", __func__);
                goto out_err;
        }
        EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_FINALISE);
        if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, cb->pkey) != 1) {
                exchg_log("%s: EVP_DigestSignInit() failed\n", __func__);
                goto out_err;
        }
        if (EVP_DigestSign(ctx, sig, sig_len, data, data_len) != 1) {
                exchg_log("%s: EVP_DigestSign() failed\n", __func__);
                goto out_err;
        }
        EVP_MD_CTX_free(ctx);
        return 0;

out_err:
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        return -1;
}

static int jwt_format_sig(unsigned char *jwt_sig, size_t jwt_sig_len,
                          const unsigned char *sig, size_t sig_len)
{
        // paranoid check
        if (jwt_sig_len < 64) {
                exchg_log("%s: internal error\n", __func__);
                return -1;
        }

        ECDSA_SIG *esig = NULL;
        const unsigned char *sigp = sig;

        esig = d2i_ECDSA_SIG(NULL, &sigp, sig_len);
        if (!esig) {
                exchg_log("%s: d2i_ECDSA_SIG() failed\n", __func__);
                goto out_err;
        }

        const BIGNUM *r, *s;
        ECDSA_SIG_get0(esig, &r, &s);

        int r_len = BN_num_bytes(r);
        int s_len = BN_num_bytes(s);

        if (r_len < 1 || r_len > 32 || s_len < 1 || s_len > 32) {
                exchg_log(
                    "%s: bad num bytes in ecdsa sig (r,s) pair: (%d, %d)\n",
                    __func__, r_len, s_len);
                goto out_err;
        }

        if (BN_bn2binpad(r, jwt_sig, 32) < 1) {
                exchg_log("%s: BN_bn2binpad() failed\n", __func__);
                goto out_err;
        }
        if (BN_bn2binpad(s, jwt_sig + 32, 32) < 1) {
                exchg_log("%s: BN_bn2binpad() failed\n", __func__);
                goto out_err;
        }
        ECDSA_SIG_free(esig);
        return 64;

out_err:
        ECDSA_SIG_free(esig);
        ERR_print_errors_fp(stderr);
        return -1;
}

static int add_jwt_signature(struct exchg_client *cl, struct b64_state *state,
                             size_t auth_str_start)
{
        unsigned char sig[128];
        size_t sig_len = sizeof(sig);

        char *to_auth = &state->encoding[auth_str_start];
        size_t to_auth_len = state->len - auth_str_start;
        if (do_sign(cl, sig, &sig_len, (unsigned char *)to_auth, to_auth_len))
                return -1;

        unsigned char jwt_sig[64];
        int jwt_sig_len =
            jwt_format_sig(jwt_sig, sizeof(jwt_sig), sig, sig_len);
        if (jwt_sig_len < 0)
                return -1;
        if (jwt_next_section(state))
                return -1;
        if (b64url_step(state, jwt_sig, jwt_sig_len))
                return -1;
        return b64url_close(state);
}

static int write_jwt(struct exchg_client *cl, const char *uri,
                     struct b64_state *state)
{
        struct coinbase_client *cb = client_private(cl);
        if (!cb->pkey) {
                exchg_log("%s called without a private key set\n", __func__);
                return -1;
        }

        size_t auth_str_start = state->len;
        if (add_jwt_headers(cl, state, uri))
                return -1;
        if (add_jwt_signature(cl, state, auth_str_start))
                return -1;
        return 0;
}

char *coinbase_ws_jwt(struct exchg_client *cl)
{
        struct b64_state state = {};
        if (b64_init(&state, 1024))
                goto out_bad;

        if (write_jwt(cl, NULL, &state)) {
                goto out_bad;
        }
        return state.encoding;

out_bad:
        free(state.encoding);
        return NULL;
}

int coinbase_http_auth(struct exchg_client *cl, struct http *http)
{
        struct http_data *data = http_private(http);

        char *uri =
            malloc(strlen(http_method(http)) + 1 + strlen(http_host(http)) +
                   strlen(http_path(http)) + 1);
        if (!uri) {
                exchg_log("%s: OOM\n", __func__);
                return -1;
        }

        char *p = stpcpy(uri, http_method(http));
        *p = ' ';
        p++;
        p = stpcpy(p, http_host(http));
        stpcpy(p, http_path(http));

        struct b64_state state = {};
        if (b64_init(&state, 1024))
                goto out_bad;

        if (b64_puts(&state, "Bearer "))
                goto out_bad;
        if (write_jwt(cl, uri, &state)) {
                goto out_bad;
        }
        data->jwt = state.encoding;
        data->jwt_len = state.len;

        free(uri);
        return 0;

out_bad:
        free(uri);
        free(state.encoding);
        return -1;
}

static int new_private_key(struct exchg_client *cl, BIO *bio)
{
        struct coinbase_client *cb = client_private(cl);

        EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (!pkey) {
                exchg_log("%s: PEM_read_bio_PrivateKey failed\n", __func__);
                goto bad;
        }

        int id = EVP_PKEY_base_id(pkey);
        if (id != EVP_PKEY_EC) {
                exchg_log("%s: expected key base ID EVP_PKEY_EC. got %d\n",
                          __func__, id);
                goto bad;
        }

        char curve_name[80];
        if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                           curve_name, sizeof(curve_name),
                                           NULL) != 1) {
                exchg_log("%s: EVP_PKEY_get_utf8_string_param() failed\n",
                          __func__);
                goto bad;
        }
        int curve_id = OBJ_txt2nid(curve_name);
        if (curve_id != NID_X9_62_prime256v1) {
                exchg_log("%s: Unexpected curve type: %d\n", __func__,
                          curve_id);
                goto bad;
        }
        cb->pkey = pkey;
        return 0;

bad:
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        return -1;
}

static void private_key_free(struct exchg_client *cl)
{
        struct coinbase_client *cb = client_private(cl);

        EVP_PKEY_free(cb->pkey);
        cb->pkey = NULL;
}

int coinbase_new_keypair(struct exchg_client *cl, const unsigned char *key,
                         size_t len)
{
        private_key_free(cl);
        BIO *bio = BIO_new_mem_buf(key, len);
        if (!bio) {
                exchg_log("%s: BIO_new_mem_buf failed\n", __func__);
                ERR_print_errors_fp(stderr);
                return -1;
        }
        return new_private_key(cl, bio);
}

static BIO *convert_newlines(const char *key, size_t len)
{
        BIO *b = NULL;
        b = BIO_new(BIO_s_secmem());
        if (!b)
                goto bad;

        for (size_t pos = 0; pos < len;) {
                int newline_pos = -1;
                for (size_t p = pos; p < len - 1; p++) {
                        if (key[p] == '\\' && key[p + 1] == 'n') {
                                newline_pos = p;
                                break;
                        }
                }
                if (newline_pos == -1) {
                        if (BIO_write(b, &key[pos], len - pos) < 1)
                                goto bad;
                        break;
                }
                // BIO_write(.., 0) is fine
                if (BIO_write(b, &key[pos], newline_pos - pos) < 1)
                        goto bad;
                if (BIO_write(b, "\n", 1) < 1)
                        goto bad;
                pos = newline_pos + 2;
        }
        return b;
bad:
        exchg_log("%s: Failed writing key to BIO\n", __func__);
        BIO_free(b);
        return NULL;
}

int coinbase_new_keypair_from_file(struct exchg_client *cl, const char *path)
{
        char *json;
        int num_toks;
        jsmntok_t *toks;
        const char *problem = "";

        client_apikey_pub_free(cl);
        private_key_free(cl);

        int json_len = json_from_file(path, &json, &num_toks, &toks);
        if (json_len < 0)
                return -1;

        if (toks[0].type != JSMN_OBJECT) {
                problem = "non-object data";
                goto bad;
        }

        jsmntok_t *name = NULL;
        jsmntok_t *privateKey = NULL;

        int key_idx = 1;
        for (int i = 0; i < toks[0].size; i++) {
                jsmntok_t *key = &toks[key_idx];
                jsmntok_t *value = key + 1;

                if (json_streq(json, key, "name")) {
                        if (value->type != JSMN_STRING) {
                                problem = "\"name\" not a string";
                                goto bad;
                        }
                        name = value;
                        key_idx += 2;
                } else if (json_streq(json, key, "privateKey")) {
                        if (value->type != JSMN_STRING) {
                                problem = "\"privateKey\" not a string";
                                goto bad;
                        }
                        privateKey = value;
                        key_idx += 2;
                } else {
                        key_idx = json_skip(num_toks, toks, key_idx + 1);
                }
        }
        if (!name || !privateKey) {
                problem = "should have \"name\" and \"privateKey\" set";
                goto bad;
        }

        BIO *key_data = convert_newlines(&json[privateKey->start],
                                         privateKey->end - privateKey->start);
        if (!key_data)
                goto bad;

        if (new_private_key(cl, key_data))
                goto bad;

        int len = json_strdup((char **)&cl->apikey_public, json, name);
        if (len < 0) {
                problem = "OOM";
                goto bad;
        }
        cl->apikey_public_len = len;

        OPENSSL_cleanse(json, json_len);
        free(toks);
        free(json);
        return 0;

bad:
        exchg_log("Bad Coinbase key at %s: %s:\n", path, problem);
        client_apikey_pub_free(cl);
        private_key_free(cl);
        free(toks);
        free(json);
        return -1;
}

void coinbase_auth_free(struct exchg_client *cl)
{
        struct coinbase_client *cb = client_private(cl);

        EVP_PKEY_free(cb->pkey);
}
