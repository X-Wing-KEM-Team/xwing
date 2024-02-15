void labeledExtract(unsigned char *out, unsigned char *label, const unsigned char *ikm);
void labeledExpand(unsigned char *out, unsigned char *label, unsigned char *prk, unsigned char *info, int infoLength, int labelLength);
void extractAndExpand(unsigned char *sharedSecret, unsigned char *dh, unsigned char *kemContext);
