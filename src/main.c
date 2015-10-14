/* This example code is placed in the public domain. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../lib/read-file.h"
#include "ocsp.h"

char *load_cert(const char *cert_file);

int main(int argc, char *argv[])
{
  int ret;
  char *cert, *issuer, *signer;

  const char *cert_file = argv[1];
  const char *issuer_file = argv[2];
  const char *signer_file = argv[3];

  cert = load_cert(cert_file);
  issuer = load_cert(issuer_file);
  signer = load_cert(signer_file);

  if (!cert || !issuer || !signer) {
    fprintf(stderr,"Error loading cert\n");
    exit(1);
  }

  ret = ocsp_check(cert, issuer, signer);
  if (ret == 0) {
    fprintf(stdout,"Check success\n");
  } else {
    fprintf(stdout,"Check failed\n");
  }
  return ret;
}

char *load_cert(const char *cert_file)
{
  size_t size;
  char *cert = read_binary_file(cert_file, &size);
  return cert;
}
