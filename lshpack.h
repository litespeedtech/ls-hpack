/*
MIT License

Copyright (c) 2018 - 2020 LiteSpeed Technologies Inc

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#ifndef LITESPEED_HPACK_H
#define LITESPEED_HPACK_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include <limits.h>
#include <stdint.h>

#ifndef LSXPACK_MAX_STRLEN
#define LSXPACK_MAX_STRLEN UINT_MAX
#endif

#if UINT_MAX == 65535
typedef uint16_t lsxpack_strlen_t;
#elif UINT_MAX == 4294967295
typedef uint32_t lsxpack_strlen_t;
#elif UINT_MAX == 18446744073709551615ULL
typedef uint64_t lsxpack_strlen_t;
#else
#error unexpected UINT_MAX
#endif

enum lsxpack_flag
{
    LSXPACK_HPACK_IDX       = 1 << 0,
    LSXPACK_QPACK_IDX       = 1 << 1,
    LSXPACK_APP_IDX         = 1 << 2,
    LSXPACK_NAME_HASH       = 1 << 3,
    LSXPACK_NAMEVAL_HASH    = 1 << 4,
    LSXPACK_VAL_MATCHED     = 1 << 5,
    LSXPACK_NEVER_INDEX     = 1 << 6,
    /* TODO: qpack flags */
};

/**
 * When header are decoded, it should be stored to @buf starting from @name_offset,
 *    <name>: <value>\r\n
 * So, it can be used directly as HTTP/1.1 header. there are 4 extra characters
 * added.
 *
 * limitation: we currently does not support total header size > 64KB.
 */

struct lsxpack_header
{
    char               *buf;          /* the buffer for headers */
    uint32_t            name_hash;    /* hash value for name */
    uint32_t            nameval_hash; /* hash value for name + value */
    lsxpack_strlen_t    name_offset;  /* the offset for name in the buffer */
    lsxpack_strlen_t    name_len;     /* the length of name */
    lsxpack_strlen_t    val_offset;   /* the offset for value in the buffer */
    lsxpack_strlen_t    val_len;      /* the length of value */
    uint8_t             hpack_index;  /* HPACK static table index [1,61] */
    uint8_t             qpack_index;  /* QPACK static table index [0,98] */
    uint8_t             app_index;    /* APP header index (user-defined) */
    enum lsxpack_flag   flags:8;      /* Bitmask of lsxpack_flag */
};

typedef struct lsxpack_header lsxpack_header_t;

struct lshpack_enc;
struct lshpack_dec;

enum lshpack_static_hdr_idx
{
    LSHPACK_HDR_UNKNOWN,
    LSHPACK_HDR_AUTHORITY,
    LSHPACK_HDR_METHOD_GET,
    LSHPACK_HDR_METHOD_POST,
    LSHPACK_HDR_PATH,
    LSHPACK_HDR_PATH_INDEX_HTML,
    LSHPACK_HDR_SCHEME_HTTP,
    LSHPACK_HDR_SCHEME_HTTPS,
    LSHPACK_HDR_STATUS_200,
    LSHPACK_HDR_STATUS_204,
    LSHPACK_HDR_STATUS_206,
    LSHPACK_HDR_STATUS_304,
    LSHPACK_HDR_STATUS_400,
    LSHPACK_HDR_STATUS_404,
    LSHPACK_HDR_STATUS_500,
    LSHPACK_HDR_ACCEPT_CHARSET,
    LSHPACK_HDR_ACCEPT_ENCODING,
    LSHPACK_HDR_ACCEPT_LANGUAGE,
    LSHPACK_HDR_ACCEPT_RANGES,
    LSHPACK_HDR_ACCEPT,
    LSHPACK_HDR_ACCESS_CONTROL_ALLOW_ORIGIN,
    LSHPACK_HDR_AGE,
    LSHPACK_HDR_ALLOW,
    LSHPACK_HDR_AUTHORIZATION,
    LSHPACK_HDR_CACHE_CONTROL,
    LSHPACK_HDR_CONTENT_DISPOSITION,
    LSHPACK_HDR_CONTENT_ENCODING,
    LSHPACK_HDR_CONTENT_LANGUAGE,
    LSHPACK_HDR_CONTENT_LENGTH,
    LSHPACK_HDR_CONTENT_LOCATION,
    LSHPACK_HDR_CONTENT_RANGE,
    LSHPACK_HDR_CONTENT_TYPE,
    LSHPACK_HDR_COOKIE,
    LSHPACK_HDR_DATE,
    LSHPACK_HDR_ETAG,
    LSHPACK_HDR_EXPECT,
    LSHPACK_HDR_EXPIRES,
    LSHPACK_HDR_FROM,
    LSHPACK_HDR_HOST,
    LSHPACK_HDR_IF_MATCH,
    LSHPACK_HDR_IF_MODIFIED_SINCE,
    LSHPACK_HDR_IF_NONE_MATCH,
    LSHPACK_HDR_IF_RANGE,
    LSHPACK_HDR_IF_UNMODIFIED_SINCE,
    LSHPACK_HDR_LAST_MODIFIED,
    LSHPACK_HDR_LINK,
    LSHPACK_HDR_LOCATION,
    LSHPACK_HDR_MAX_FORWARDS,
    LSHPACK_HDR_PROXY_AUTHENTICATE,
    LSHPACK_HDR_PROXY_AUTHORIZATION,
    LSHPACK_HDR_RANGE,
    LSHPACK_HDR_REFERER,
    LSHPACK_HDR_REFRESH,
    LSHPACK_HDR_RETRY_AFTER,
    LSHPACK_HDR_SERVER,
    LSHPACK_HDR_SET_COOKIE,
    LSHPACK_HDR_STRICT_TRANSPORT_SECURITY,
    LSHPACK_HDR_TRANSFER_ENCODING,
    LSHPACK_HDR_USER_AGENT,
    LSHPACK_HDR_VARY,
    LSHPACK_HDR_VIA,
    LSHPACK_HDR_WWW_AUTHENTICATE
};


/**
 * Initialization routine allocates memory.  -1 is returned if memory
 * could not be allocated.  0 is returned on success.
 */
int
lshpack_enc_init (struct lshpack_enc *);

/**
 * Clean up HPACK encoder, freeing all allocated memory.
 */
void
lshpack_enc_cleanup (struct lshpack_enc *);

unsigned char *
lshpack_enc_encode (struct lshpack_enc *henc, unsigned char *dst,
                unsigned char *dst_end, lsxpack_header_t *hdr);

void
lshpack_enc_set_max_capacity (struct lshpack_enc *, unsigned);

/**
 * Turn history on or off.  Turning history on may fail (malloc), in
 * which case -1 is returned.
 */
int
lshpack_enc_use_hist (struct lshpack_enc *, int on);

/**
 * Return true if history is used, false otherwise.  By default,
 * history is off.
 */
int
lshpack_enc_hist_used (const struct lshpack_enc *);

/**
 * Initialize HPACK decoder structure.
 */
void
lshpack_dec_init (struct lshpack_dec *);

/**
 * Clean up HPACK decoder structure, freeing all allocated memory.
 */
void
lshpack_dec_cleanup (struct lshpack_dec *);

int
lshpack_dec_decode (struct lshpack_dec *dec,
    const unsigned char **src, const unsigned char *src_end,
    lsxpack_header_t *output);

void
lshpack_dec_set_max_capacity (struct lshpack_dec *, unsigned);

/* Some internals follow.  Struct definitions are exposed to save a malloc.
 * These structures are not very complicated.
 */

#include <sys/queue.h>

struct lshpack_enc_table_entry;

STAILQ_HEAD(lshpack_enc_head, lshpack_enc_table_entry);
struct lshpack_double_enc_head;

struct lshpack_enc
{
    unsigned            hpe_cur_capacity;
    unsigned            hpe_max_capacity;

    /* Each new dynamic table entry gets the next number.  It is used to
     * calculate the entry's position in the decoder table without having
     * to maintain an actual array.
     */
    unsigned            hpe_next_id;

    /* Dynamic table entries (struct enc_table_entry) live in two hash
     * tables: name/value hash table and name hash table.  These tables
     * are the same size.
     */
    unsigned            hpe_nelem;
    unsigned            hpe_nbits;
    struct lshpack_enc_head
                        hpe_all_entries;
    struct lshpack_double_enc_head
                       *hpe_buckets;

    uint32_t           *hpe_hist_buf;
    unsigned            hpe_hist_size, hpe_hist_idx;
    int                 hpe_hist_wrapped;
    enum {
        LSHPACK_ENC_USE_HIST    = 1 << 0,
    }                   hpe_flags;
};

struct lshpack_arr
{
    unsigned        nalloc,
                    nelem,
                    off;
    uintptr_t      *els;
};

struct lshpack_dec
{
    unsigned           hpd_max_capacity;       /* Maximum set by caller */
    unsigned           hpd_cur_max_capacity;   /* Adjusted at runtime */
    unsigned           hpd_cur_capacity;
    unsigned           hpd_state;
    struct lshpack_arr hpd_dyn_table;
};

unsigned
lshpack_enc_get_stx_tab_id (struct lsxpack_header *);

#ifdef __cplusplus
}
#endif

#endif
