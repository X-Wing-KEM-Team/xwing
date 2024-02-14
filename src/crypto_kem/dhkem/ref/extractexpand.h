void I2OSP(unsigned char *out, int x, int xLen);
void labeledExtract(unsigned char *out, unsigned char *label, unsigned char *ikm);
void labeledExpand(unsigned char *out, unsigned char *label, unsigned char *prk, unsigned char *info);
void extractAndExpand(unsigned char *sharedSecret, unsigned char *dh, unsigned char *kemContext);
