/*
 * Copyright (c) 2015 Kazuho Oku, DeNA Co., Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "khash.h"
#include "openfilecache.h"

KHASH_MAP_INIT_STR(filemap, openfilecache_t *);

struct st_openfilecache_map_t {
    khash_t(filemap) * filemap;
    time_t last_open_at;
};

static void release_from_cache(struct st_openfilecache_map_t *cache, khiter_t iter)
{
    const char *path = kh_key(cache->filemap, iter);
    openfilecache_t *ref = kh_val(cache->filemap, iter);

    assert(path == ref->_path);

    kh_del(filemap, cache->filemap, iter);
    free((void *)path);
    ref->_path = NULL;
}

static void release_all(struct st_openfilecache_map_t *cache)
{
    khiter_t iter;

    for (iter = kh_begin(cache->filemap); iter != kh_end(cache->filemap); ++iter) {
        if (kh_exist(cache->filemap, iter))
            release_from_cache(cache, iter);
    }
}

static struct st_openfilecache_map_t *create_cache(void)
{
    struct st_openfilecache_map_t *cache = malloc(sizeof(*cache));
    cache->filemap = kh_init(filemap);
    return cache;
}

static struct st_openfilecache_map_t *get_cache(void)
{
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    static pthread_key_t *key = NULL;
    struct st_openfilecache_map_t *cache;

    /* fast path */
    if (key != NULL && ((cache = pthread_getspecific(*key))) != NULL)
        goto Exit;

    pthread_mutex_lock(&mutex);
    if (key == NULL) {
        key = malloc(sizeof(*key));
        pthread_key_create(key, NULL);
    }
    if ((cache = pthread_getspecific(*key)) == NULL) {
        cache = create_cache();
        pthread_setspecific(*key, cache);
    }
    pthread_mutex_unlock(&mutex);

Exit:
    return cache;
}

openfilecache_t *openfilecache_open(const char *path, int oflag)
{
    struct st_openfilecache_map_t *cache = get_cache();
    time_t now = time(NULL);
    khiter_t iter;
    openfilecache_t *ref;

    if (cache->last_open_at != now) {
        cache->last_open_at = now;
        release_all(cache);
    }

    iter = kh_get(filemap, cache->filemap, path);
    if (iter != kh_end(cache->filemap)) {
        ref = kh_val(cache->filemap, iter);
        ++ref->_refcnt;
    } else {
        int fd = open(path, oflag), dummy;
        if (fd == -1)
            return NULL;
        ref = malloc(sizeof(*ref));
        ref->fd = fd;
        ref->_path = strdup(path);
        ref->_refcnt = 1;
        if (fstat(ref->fd, &ref->st) != 0) {
            close(fd);
            free(ref);
            return NULL;
        }
        iter = kh_put(filemap, cache->filemap, ref->_path, &dummy);
        kh_val(cache->filemap, iter) = ref;
    }

    return ref;
}

#include <stdio.h>

void openfilecache_close(openfilecache_t *ref)
{
    if (--ref->_refcnt != 0)
        return;
    if (ref->_path != NULL) {
        struct st_openfilecache_map_t *cache = get_cache();
        khiter_t iter = kh_get(filemap, cache->filemap, ref->_path);
        assert(iter != kh_end(cache->filemap));
        assert(kh_val(cache->filemap, iter) == ref);
        release_from_cache(cache, iter);
    }
    close(ref->fd);
    ref->fd = -1;
    free(ref);
}
