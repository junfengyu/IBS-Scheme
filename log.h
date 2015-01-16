#ifndef LOG_H
#define LOG_H

void     fatal(const char *, ...) __attribute__((noreturn))
    __attribute__((format(printf, 1, 2)));
void     error(const char *, ...) __attribute__((format(printf, 1, 2)));

#endif
