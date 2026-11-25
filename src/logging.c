#include <stdio.h>
#include <time.h>

#include "logging.h"

void log_event(const char *event)
{
    FILE *file = fopen("password_manager.log", "a");

    if (file == NULL) {
        return;
    }

    time_t now = time(NULL);

   char time_string[64];

    strftime(time_string,
         sizeof(time_string),
         "%Y-%m-%d %H:%M:%S UTC",
         gmtime(&now));

    fprintf(file,
        "%s | %s\n",
        time_string,
        event);

    fclose(file);
}