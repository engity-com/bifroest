/* Test-only PAM account module: no authentication or session entry point. */
#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <string.h>

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags;
    const void *remote = NULL;
    if (argc != 1 || pam_get_item(pamh, PAM_RHOST, &remote) != PAM_SUCCESS ||
        remote == NULL || strcmp((const char *)remote, "127.0.0.1") != 0) {
        return PAM_PERM_DENIED;
    }
    FILE *source = fopen(argv[0], "r");
    if (source == NULL) return PAM_SYSTEM_ERR;
    char value[256];
    int read_ok = fgets(value, sizeof(value), source) != NULL;
    int closed = fclose(source);
    if (!read_ok || closed != 0) return PAM_SYSTEM_ERR;
    value[strcspn(value, "\n")] = '\0';
    if (strncmp(value, "PAM_NATIVE_FRESH=", 17) != 0) return PAM_SYSTEM_ERR;
    return pam_putenv(pamh, value);
}
