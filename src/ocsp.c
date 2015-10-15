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
  char *ocsp_url = NULL;
  unsigned char noncebuf[23];
  gnutls_datum_t nonce = { noncebuf, sizeof(noncebuf) };

  gnutls_global_init();

  ret = gnutls_rnd(GNUTLS_RND_NONCE, nonce.data, nonce.size);
  if (ret < 0) {
    goto cleanup;
  }
  ret = gnutls_x509_crt_get_authority_info_access(cert,
                                                  0,
                                                  GNUTLS_IA_OCSP_URI,
                                                  &tmp,
                                                  NULL);

  if (ret != 0) {
    goto cleanup;
  }

  ocsp_url = malloc(tmp.size + 1);
  memcpy(ocsp_url, tmp.data, tmp.size);
  ocsp_url[tmp.size] = 0;

  memset(&ud, 0, sizeof(ud));

  _generate_request(&req, cert, issuer, &nonce);

  curl_global_init(CURL_GLOBAL_ALL);
  handle = curl_easy_init();
  if (handle == NULL) {
    goto cleanup;
  }

  headers =
    curl_slist_append(headers,
                      "Content-Type: application/ocsp-request");

  curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(handle, CURLOPT_POSTFIELDS, (void *) req.data);
  curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, req.size);
  curl_easy_setopt(handle, CURLOPT_URL, ocsp_url);
  curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, get_data);
  curl_easy_setopt(handle, CURLOPT_WRITEDATA, &ud);
  ret = curl_easy_perform(handle);

  if (ret != 0) {
    goto cleanup;
  }

  v = _verify_response(&ud, cert, signer, &nonce);

 cleanup:
  free(ocsp_url);
  curl_slist_free_all(headers);
  curl_easy_cleanup(handle);
  gnutls_free(tmp.data);
  gnutls_free(ud.data);
  gnutls_free(req.data);
  gnutls_x509_crt_deinit(cert);
  gnutls_x509_crt_deinit(issuer);
  gnutls_x509_crt_deinit(signer);
  gnutls_global_deinit();
  return v;
}

static int
_verify_response(gnutls_datum_t * data, gnutls_x509_crt_t cert,
                 gnutls_x509_crt_t signer, gnutls_datum_t *nonce)
{
  gnutls_ocsp_resp_t resp;
  int ret;
  unsigned verify = -1;
  gnutls_datum_t rnonce;

  ret = gnutls_ocsp_resp_init(&resp);
  if (ret < 0) {
    goto cleanup;
  }
  ret = gnutls_ocsp_resp_import(resp, data);
  if (ret < 0) {
    goto cleanup;
  }
  ret = gnutls_ocsp_resp_check_crt(resp, 0, cert);
  if (ret < 0) {
    goto cleanup;
  }

  ret = gnutls_ocsp_resp_get_nonce(resp, NULL, &rnonce);
  if (ret < 0) {
    goto cleanup;
  }

  if (rnonce.size != nonce->size || memcmp(nonce->data, rnonce.data,nonce->size) != 0) {
    goto cleanup;
  }

  ret = gnutls_ocsp_resp_verify_direct(resp, signer, &verify, 0);
  if (ret < 0) {
    goto cleanup;
  }

 cleanup:
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
    return 0;
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
  if (ret < 0) {
    gnutls_free(data.data);
    return NULL;
  }
  gnutls_free(data.data);
  return crt;
}

static void _generate_request(gnutls_datum_t * rdata, gnutls_x509_crt_t cert,
                              gnutls_x509_crt_t issuer, gnutls_datum_t *nonce)
{
  gnutls_ocsp_req_t req;
  int ret;

  ret = gnutls_ocsp_req_init(&req);
  if (ret < 0)
    goto cleanup;

  ret = gnutls_ocsp_req_add_cert(req, GNUTLS_DIG_SHA1, issuer, cert);
  if (ret < 0)
    goto cleanup;

  ret = gnutls_ocsp_req_set_nonce(req, 0, nonce);
  if (ret < 0)
    goto cleanup;

  ret = gnutls_ocsp_req_export(req, rdata);
  if (ret != 0)
    goto cleanup;

 cleanup:
  gnutls_ocsp_req_deinit(req);
  return;
}
