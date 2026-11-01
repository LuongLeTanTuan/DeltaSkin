/* Host-side driver for patcher/macho.c.
 *
 * Used by CI twice: to sign the patcher app itself with its entitlements (the
 * iOS toolchain here has no ldid), and to exercise the injector against a real
 * arm64 Mach-O built on the runner, so the signing path is verified off-device.
 *
 *   patcher_cli sign   <file> [entitlements.plist]
 *   patcher_cli inject <exe> <dylib-install-path> [entitlements.plist]
 *   patcher_cli ents   <file>
 */
#include "../patcher/macho.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    rewind(f);
    if (n <= 0) { fclose(f); return NULL; }
    uint8_t *b = (uint8_t *)malloc((size_t)n);
    if (!b) { fclose(f); return NULL; }
    if (fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); fclose(f); return NULL; }
    fclose(f);
    *len = (size_t)n;
    return b;
}

static void die(const char *what, const char *err) {
    fprintf(stderr, "%s: %s\n", what, err && err[0] ? err : "unknown error");
    exit(1);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s sign <file> [ents] | inject <exe> <dylib> [ents] | ents <file>\n", argv[0]);
        return 2;
    }

    const char *cmd = argv[1];

    uint8_t *ent = NULL;
    size_t entLen = 0;
    const char *entPath = NULL;
    if (!strcmp(cmd, "sign") && argc >= 4) entPath = argv[3];
    if (!strcmp(cmd, "inject") && argc >= 5) entPath = argv[4];
    if (entPath) {
        ent = slurp(entPath, &entLen);
        if (!ent) die("cannot read entitlements", entPath);
    }

    char err[256] = {0};

    if (!strcmp(cmd, "sign")) {
        int rc = mo_adhoc_sign_file(argv[2], ent, entLen, err, sizeof(err));
        if (rc != 0) die("sign failed", err);
        printf("signed %s (%zu bytes of entitlements)\n", argv[2], entLen);
        return 0;
    }

    if (!strcmp(cmd, "inject")) {
        int rc = mo_inject_and_sign(argv[2], argv[3], ent, entLen, err, sizeof(err));
        if (rc != 0) die("inject failed", err);
        printf("injected %s\n", argv[3]);
        return 0;
    }

    if (!strcmp(cmd, "ents")) {
        uint8_t *out = NULL;
        uint32_t n = 0;
        if (mo_copy_entitlements(argv[2], &out, &n) != 0) {
            printf("no entitlements\n");
            return 1;
        }
        fwrite(out, 1, n, stdout);
        printf("\n");
        free(out);
        return 0;
    }

    fprintf(stderr, "unknown command %s\n", cmd);
    return 2;
}
