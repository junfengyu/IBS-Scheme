

void	*xmalloc(size_t);
void	*xcalloc(size_t, size_t);
void	*xrealloc(void *, size_t, size_t);
void     xfree(void *);
char	*xstrdup(const char *);
int	 xasprintf(char **, const char *, ...)
                __attribute__((__format__ (printf, 2, 3)))
                __attribute__((__nonnull__ (2)));
