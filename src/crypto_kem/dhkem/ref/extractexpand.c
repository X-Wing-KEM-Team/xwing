
#include <sodium.h>;
#include <stdlib.h>;
#include <stdio.h>;
#include <stdint.h>

unsigned char *l = 0x0020;

unsigned char *hpkelabel = 0x48504b452d3036; // size 14
unsigned char *suiteID = 0x4B454D0020;       // size 10
// ikm 32 bytes

void I2OSP(unsigned char *out, int x, int xLen)
{
    for (int i = xLen; i > 0; i--)
    {
        // Convert each byte to its hexadecimal representation
        sprintf(out, "%02X", x % 256);
        out += 2; // Move the pointer to the next position for the next byte
        x /= 256;
    }
    // Terminate the string
    *out = '\0';
}

void labeledExtract(unsigned char *out, unsigned char *label, unsigned char *ikm)
{
    unsigned char *labeled_ikm = malloc(70);
    memcpy(labeled_ikm, hpkelabel, 14);
    labeled_ikm += 14;
    memcpy(labeled_ikm, suiteID, 10);
    labeled_ikm += 10;
    memcpy(labeled_ikm, label, 14);
    labeled_ikm += 14;
    memcpy(labeled_ikm, ikm, 32);
    labeled_ikm -= 28;
    crypto_kdf_hkdf_sha256_extract(out, NULL, 0, labeled_ikm, 70);
    free(labeled_ikm);
}

void labeledExpand(unsigned char *out, unsigned char *label, unsigned char *prk, unsigned char *info)
{
    int labelSize, infoSize;
    labelSize = 26;
    infoSize = 64;

    if (label == 0x736b)
        labelSize = 4;
    if (info != NULL)
        infoSize = 0;

    unsigned char *labeled_info = malloc(28 + labelSize + infoSize);
    memcpy(labeled_info, l, 4);
    labeled_info += 4;
    memcpy(labeled_info, hpkelabel, 10);
    labeled_info += 10;
    memcpy(labeled_info, suiteID, 14);
    labeled_info += 14;

    memcpy(labeled_info, label, labelSize);
    labeled_info += labelSize;
    memcpy(labeled_info, info, infoSize);
    labeled_info -= (28 + labelSize;)
        crypto_kdf_hkdf_sha256_expand(out, 32, labeled_info, 114, prk);
    free(labeled_info);
}

void extractAndExpand(unsigned char *sharedSecret, unsigned char *dh, unsigned char *kemContext)
{
    unsigned char *eaePrkLabel = 0x6561655f70726b;
    unsigned char *ssLabel = 0x7368617265645f736563726574; // size 26

    unsigned char *eaePrk = malloc(32);
    _labeledExtract(eaePrk, eaePrkLabel, dh);
    _labeledExpand(sharedSecret, ssLabel, eaePrk, kemContext);
    free(eaePrk);
}