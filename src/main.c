#include <stdio.h>
#include <sys/resource.h>
#include <sys/stat.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

#include "auth.h"
#include "utils.h"
#include "paths.h"

/* Process-level protection for secrets held in memory. */
static void harden_process(void)
{
    /* New files (users, vaults, log, backups) are readable only by the owner. */
    umask(077);

    /* No core dumps: a crash must not write keys or passwords to disk. */
    struct rlimit no_core = {0, 0};
    setrlimit(RLIMIT_CORE, &no_core);

#if defined(__linux__) && !defined(PM_KEEP_DUMPABLE)
    /* Other processes of the same user cannot attach to read our memory. */
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif

    /* No stdio input buffer, so typed passwords are not kept in a second
     * copy inside the C library. */
    setvbuf(stdin, NULL, _IONBF, 0);
}

int main(void) {
    harden_process();

    if (init_data_dirs() != 0) {
        printf("Could not create the data directory.\n");
        return 1;
    }

    while (1) {
    printf("\n=== Password Manager ===\n");
    printf("1. Register\n");
    printf("2. Login\n");
    printf("3. Exit\n");
    printf("Choice: ");

        int choice = read_choice();

        if (choice == -2) { /* EOF */
            printf("\n\nGoodbye.\n");
            return 0;
        }

        switch (choice) {
            case 1:
                create_user();
                break;

            case 2:
                login_user();
                break;

            case 3:
                printf("\n\nGoodbye.\n");
                return 0;

            default:
                printf("\n\nInvalid option.\n\n");
        }
    }
}