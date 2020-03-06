#ifndef LSXPACK_HEADER_H
#define LSXPACK_HEADER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stdint.h>
#include <string.h>

#ifndef LSXPACK_MAX_STRLEN
#define LSXPACK_MAX_STRLEN UINT16_MAX
#endif

#if LSXPACK_MAX_STRLEN == 65535
typedef uint16_t lsxpack_strlen_t;
#elif LSXPACK_MAX_STRLEN == 4294967295
typedef uint32_t lsxpack_strlen_t;
#elif LSXPACK_MAX_STRLEN == 18446744073709551615ULL
typedef uint64_t lsxpack_strlen_t;
#else
#error unexpected UINT_MAX
#endif

enum lsxpack_flag
{
    LSXPACK_HPACK_IDX = 1,
    LSXPACK_QPACK_IDX = 2,
    LSXPACK_APP_IDX   = 4,
    LSXPACK_NAME_HASH = 8,
    LSXPACK_NAMEVAL_HASH = 16,
    LSXPACK_VAL_MATCHED = 32,
    LSXPACK_NEVER_INDEX = 64,
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
    char       *buf;                /* the buffer for headers */
    const char *name_ptr;           /* the name pointer can be optionally set for encoding */
    uint32_t    name_hash;          /* hash value for name */
    uint32_t    nameval_hash;       /* hash value for name + value */
    lsxpack_strlen_t    name_offset;/* the offset for name in the buffer */
    lsxpack_strlen_t    name_len;   /* the length of name */
    lsxpack_strlen_t    val_offset; /* the offset for value in the buffer */
    uint16_t    val_len;            /* the length of value */
    uint8_t     hpack_index;        /* HPACK static table index */
    uint8_t     qpack_index;        /* QPACK static table index */
    uint8_t     app_index;          /* APP header index */
    enum lsxpack_flag flags:8;      /* combination of lsxpack_flag */
};

typedef struct lsxpack_header lsxpack_header_t;


static inline void lsxpack_header_set_idx(lsxpack_header_t *hdr, int hpack_idx,
                               const char *val, int val_len)
{
    memset(hdr, 0, sizeof(*hdr));
    hdr->buf = (char *)val;
    hdr->hpack_index = hpack_idx;
    assert(hpack_idx != 0);
    hdr->flags = LSXPACK_HPACK_IDX;
    hdr->val_len = val_len;
}


static inline void lsxpack_header_set_ptr(lsxpack_header_t *hdr,
                               const char *name, int name_len,
                               const char *val, int val_len)
{
    memset(hdr, 0, sizeof(*hdr));
    hdr->buf = (char *)val;
    hdr->val_len = val_len;
    hdr->name_ptr = name;
    hdr->name_len = name_len;
}


static inline void lsxpack_header_set_offset(lsxpack_header_t *hdr, const char *buf,
                               int name_offset, int name_len,
                               int val_len)
{
    memset(hdr, 0, sizeof(*hdr));
    hdr->buf = (char *)buf;
    hdr->name_offset = name_offset;
    hdr->name_len = name_len;
    hdr->val_offset = name_offset + name_len + 2;
    hdr->val_len = val_len;
}


static inline void lsxpack_header_set_offset2(lsxpack_header_t *hdr, const char *buf,
                               int name_offset, int name_len,
                               int val_offset, int val_len)
{
    memset(hdr, 0, sizeof(*hdr));
    hdr->buf = (char *)buf;
    hdr->name_offset = name_offset;
    hdr->name_len = name_len;
    hdr->val_offset = val_offset;
    hdr->val_len = val_len;
}


#ifdef __cplusplus
}
#endif

#endif //LSXPACK_HEADER_H
