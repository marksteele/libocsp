#ifndef ocsp_h__
#define ocsp_h__

extern int ocsp_check(gnutls_x509_crt_t cert, gnutls_x509_crt_t issuer, gnutls_x509_crt_t signer);

#endif

