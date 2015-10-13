/* This example code is placed in the public domain. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include "../lib/read-file.h"
#include "ocsp.h"

static gnutls_x509_crt_t load_cert(const char *cert_file);

int main(int argc, char *argv[])
{
        int ret;
        gnutls_x509_crt_t cert, issuer, signer;

        const char *cert_file = argv[1];
        const char *issuer_file = argv[2];
        const char *signer_file = argv[3];

        cert = load_cert(cert_file);
        issuer = load_cert(issuer_file);
        signer = load_cert(signer_file);

	ret = ocsp_check(cert, issuer, signer);
        return ret;
}

static gnutls_x509_crt_t load_cert(const char *cert_file)
{
        gnutls_x509_crt_t crt;
        int ret;
        gnutls_datum_t data;
        size_t size;

        ret = gnutls_x509_crt_init(&crt);
        if (ret < 0)
                exit(1);

        data.data = (void *) read_binary_file(cert_file, &size);
        data.size = size;

        if (!data.data) {
                fprintf(stderr, "Cannot open file: %s\n", cert_file);
                exit(1);
        }

        ret = gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_PEM);
        free(data.data);
        if (ret < 0) {
                fprintf(stderr, "Cannot import certificate in %s: %s\n",
                        cert_file, gnutls_strerror(ret));
                exit(1);
        }

        return crt;
}

