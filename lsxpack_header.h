
#ifndef LSXPACK_HEADER_H
#define LSXPACK_HEADER_H

#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

enum LSXPACK_FLAG
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
    uint32_t    name_hash;          /* hash value for name */
    uint32_t    nameval_hash;       /* hash value for name + value */
    uint16_t    name_offset;        /* the offset for name in the buffer */
    uint16_t    name_len;           /* the length of name */
    uint16_t    val_offset;         /* the offset for value in the buffer */
    uint16_t    val_len;            /* the length of value */
    uint8_t     hpack_index;        /* HPACK static table index */
    uint8_t     qpack_index;        /* QPACK static table index */
    uint8_t     app_index;          /* APP header index */
    uint8_t     flags;              /* combination of LSXPACK_FLAG */
};

typedef struct lsxpack_header lsxpack_header_t;

#ifdef __cplusplus
}
#endif

#endif //LSXPACK_HEADER_H

