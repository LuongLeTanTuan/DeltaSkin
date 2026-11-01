/* Minimal Mach-O 64 reader/editor and ad-hoc code signer.
 *
 * The structs are redeclared instead of pulled from <mach-o/loader.h> so the
 * exact same translation unit builds on the Linux CI runner (where the file is
 * exercised against a real arm64 Mach-O) and inside the iOS app (where it does
 * the actual work). One implementation, tested off-device. */
#ifndef DS_MACHO_H
#define DS_MACHO_H

#include <stddef.h>
#include <stdint.h>

/* Injects LC_LOAD_DYLIB(dylibPath) into the executable and re-signs it ad-hoc
 * with SHA-256 page hashes. Everything is computed in memory and written in one
 * go at the end, so a failure leaves the binary untouched.
 *
 * Returns 0 on success. On failure returns non-zero and fills err. */
int mo_inject_and_sign(const char *exePath, const char *dylibPath,
                       const uint8_t *entitlements, size_t entitlementsLen,
                       char *err, size_t errCap);

/* Ad-hoc signs an existing Mach-O in place (adds LC_CODE_SIGNATURE if absent). */
int mo_adhoc_sign_file(const char *path, const uint8_t *entitlements,
                       size_t entitlementsLen, char *err, size_t errCap);

/* Copies the entitlements XML out of the binary's current signature, malloc'd,
 * so they can be carried through a re-sign. Returns 0 and sets *out/*outLen on
 * success, -1 when the binary carries no entitlements. */
int mo_copy_entitlements(const char *path, uint8_t **out, uint32_t *outLen);

/* True when the file at path is a thin arm64 Mach-O executable/dylib. */
int mo_is_arm64_macho(const char *path);

#endif
