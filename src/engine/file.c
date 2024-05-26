#include <stdio.h>
#include <string.h>

long write_content_to_file(const char *path, unsigned char *content) {
    FILE *fp = fopen(path, "w");
    if (fp == NULL) {
        return -1;
    }
    fputs((char *) content, fp);

    (void) fclose(fp);
    return 1;
}
