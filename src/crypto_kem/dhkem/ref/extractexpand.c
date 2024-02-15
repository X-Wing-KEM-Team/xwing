
#include <lib25519.h>
#include <stdlib.h>
#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "params.h"

unsigned char l[2] = {0, 32};
unsigned char hpkelabel[7] = {72, 80, 75, 69, 45, 118, 49};
unsigned char suiteID[5] = {75, 69, 77, 0, 32};

void labeledExtract(unsigned char *out, unsigned char *label, const unsigned char *ikm)
{
    unsigned char *labeled_ikm = malloc(51);
    memcpy(labeled_ikm, hpkelabel, 7);
    labeled_ikm += 7;
    memcpy(labeled_ikm, suiteID, 5);
    labeled_ikm += 5;
    memcpy(labeled_ikm, label, 7);
    labeled_ikm += 7;
    memcpy(labeled_ikm, ikm, 32);
    labeled_ikm -= 19;

    crypto_kdf_hkdf_sha256_extract(out, NULL, 0, labeled_ikm, 51);

    free(labeled_ikm);
}

void labeledExpand(unsigned char *out, unsigned char *label, unsigned char *prk, unsigned char *info, int infoLength, int labelLength)
{
    int inputLength;
    inputLength = 14 + infoLength + labelLength;

    unsigned char *labeled_info = malloc(inputLength);
    memcpy(labeled_info, l, 2);
    labeled_info += 2;
    memcpy(labeled_info, hpkelabel, 7);
    labeled_info += 7;
    memcpy(labeled_info, suiteID, 5);
    labeled_info += 5;

    memcpy(labeled_info, label, labelLength);
    labeled_info += labelLength;
    memcpy(labeled_info, info, infoLength);
    labeled_info -= 14;
    labeled_info -= labelLength;

    // int i;
    // i = 0;
    // printf("input ");
    // while (i < inputLength)
    // {
    //     printf("%02x", labeled_info[i]);
    //     i++;
    // }
    // printf("\n");

    crypto_kdf_hkdf_sha256_expand(out, 32, (char *)labeled_info, inputLength, prk);
    free(labeled_info);
}

void extractAndExpand(unsigned char *sharedSecret, unsigned char *dh, unsigned char *kemContext)
{
    unsigned char eaePrkLabel[7] = {101, 97, 101, 95, 112, 114, 107};
    unsigned char ssLabel[13] = {115, 104, 97, 114, 101, 100, 95, 115, 101, 99, 114, 101, 116};

    unsigned char *eaePrk = malloc(DH_BYTES);
    labeledExtract(eaePrk, eaePrkLabel, dh);
    labeledExpand(sharedSecret, ssLabel, eaePrk, kemContext, 64, 13);
    free(eaePrk);
}