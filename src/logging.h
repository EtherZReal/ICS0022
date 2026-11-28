#ifndef LOGGING_H
#define LOGGING_H

/* Append one line "<UTC time> | <event>" to password_manager.log in the data
 * directory.  Callers must never pass secrets (passwords, keys, hashes). */
void log_event(const char *event, const char *user, const char *target);

#endif