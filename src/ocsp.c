#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/ocsp.h>
#include <curl/curl.h>

size_t get_data(void *buffer, size_t size, size_t nmemb, void *userp);

static gnutls_x509_crt_t load_cert(char *cert);

static void _generate_request(gnutls_datum_t * rdata, gnutls_x509_crt_t cert,
                              gnutls_x509_crt_t issuer, gnutls_datum_t *nonce);
static int _verify_response(gnutls_datum_t * data, gnutls_x509_crt_t cert,
                            gnutls_x509_crt_t signer, gnutls_datum_t *nonce);

int ocsp_check(char *cert_buf, char *issuer_buf, char *signer_buf)
{

  gnutls_x509_crt_t cert, issuer, signer;

  cert = load_cert(cert_buf);
  issuer = load_cert(issuer_buf);
  signer = load_cert(signer_buf);

  gnutls_datum_t ud, tmp;
  int ret;
  gnutls_datum_t req;
  CURL *handle;
  struct curl_slist *headers = NULL;
  int v, seq;
  char *hostname = NULL;
  unsigned char noncebuf[23];
  gnutls_datum_t nonce = { noncebuf, sizeof(noncebuf) };

  gnutls_global_init();

  ret = gnutls_rnd(GNUTLS_RND_NONCE, nonce.data, nonce.size);
  if (ret < 0)
    exit(1);

  for (seq = 0;; seq++) {
    ret = gnutls_x509_crt_get_authority_info_access(cert,
                                                    seq,
                                                    GNUTLS_IA_OCSP_URI,
                                                    &tmp,
                                                    NULL);
    if (ret == GNUTLS_E_UNKNOWN_ALGORITHM)
      continue;
    if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
      return(1);
    }
    if (ret < 0) {
      return(1);
    }

    hostname = malloc(tmp.size + 1);
    memcpy(hostname, tmp.data, tmp.size);
    hostname[tmp.size] = 0;
    gnutls_free(tmp.data);
    break;
  }

  memset(&ud, 0, sizeof(ud));
  _generate_request(&req, cert, issuer, &nonce);

  curl_global_init(CURL_GLOBAL_ALL);

  handle = curl_easy_init();
  if (handle == NULL) {
    // @TODO deinit stuff here...
    return(1);
  }
  headers =
    curl_slist_append(headers,
                      "Content-Type: application/ocsp-request");

  curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(handle, CURLOPT_POSTFIELDS, (void *) req.data);
  curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, req.size);
  curl_easy_setopt(handle, CURLOPT_URL, hostname);
  curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, get_data);
  curl_easy_setopt(handle, CURLOPT_WRITEDATA, &ud);

  ret = curl_easy_perform(handle);
  if (ret != 0) {
    // @TODO deinit stuff here
    curl_easy_cleanup(handle);
    return(1);
  }

  curl_easy_cleanup(handle);

  v = _verify_response(&ud, cert, signer, &nonce);

  gnutls_x509_crt_deinit(cert);
  gnutls_x509_crt_deinit(issuer);
  gnutls_x509_crt_deinit(signer);
  gnutls_global_deinit();

  return v;
}

static void
_generate_request(gnutls_datum_t * rdata, gnutls_x509_crt_t cert,
                  gnutls_x509_crt_t issuer, gnutls_datum_t *nonce)
{
  gnutls_ocsp_req_t req;
  int ret;

  ret = gnutls_ocsp_req_init(&req);
  if (ret < 0)
    exit(1);

  ret = gnutls_ocsp_req_add_cert(req, GNUTLS_DIG_SHA1, issuer, cert);
  if (ret < 0)
    exit(1);


  ret = gnutls_ocsp_req_set_nonce(req, 0, nonce);
  if (ret < 0)
    exit(1);

  ret = gnutls_ocsp_req_export(req, rdata);
  if (ret != 0)
    exit(1);

  gnutls_ocsp_req_deinit(req);

  return;
}

static int
_verify_response(gnutls_datum_t * data, gnutls_x509_crt_t cert,
                 gnutls_x509_crt_t signer, gnutls_datum_t *nonce)
{
  gnutls_ocsp_resp_t resp;
  int ret;
  unsigned verify;
  gnutls_datum_t rnonce;

  ret = gnutls_ocsp_resp_init(&resp);
  if (ret < 0) {
    return 1;
  }
  ret = gnutls_ocsp_resp_import(resp, data);
  if (ret < 0) {
    return 1;
  }
  ret = gnutls_ocsp_resp_check_crt(resp, 0, cert);
  if (ret < 0) {
    return 1;
  }

  ret = gnutls_ocsp_resp_get_nonce(resp, NULL, &rnonce);
  if (ret < 0) {
    return 1;
  }

  if (rnonce.size != nonce->size || memcmp(nonce->data, rnonce.data,nonce->size) != 0) {
    return 1;
  }

  ret = gnutls_ocsp_resp_verify_direct(resp, signer, &verify, 0);
  if (ret < 0) {
    return 1;
  }

  gnutls_free(rnonce.data);
  gnutls_ocsp_resp_deinit(resp);
  return verify;
}

size_t get_data(void *buffer, size_t size, size_t nmemb, void *userp)
{
  gnutls_datum_t *ud = userp;

  size *= nmemb;

  ud->data = realloc(ud->data, size + ud->size);
  if (ud->data == NULL) {
    exit(1);
  }

  memcpy(&ud->data[ud->size], buffer, size);
  ud->size += size;

  return size;
}

static gnutls_x509_crt_t load_cert(char *cert)
{

  gnutls_x509_crt_t crt;
  int ret;
  gnutls_datum_t data;

  if (gnutls_x509_crt_init(&crt) < 0) {
    return NULL;
  }

  data.data = (void *) cert;
  data.size = strlen(cert);

  ret = gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_PEM);
  free(data.data);
  if (ret < 0) {
    return NULL;
  }
  return crt;
}
