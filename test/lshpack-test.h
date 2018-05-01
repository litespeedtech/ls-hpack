#ifndef LITESPEED_HPACK_TEST_H
#define LITESPEED_HPACK_TEST_H 1

struct enc_dyn_table_entry
{
    const char *name,       /* Not NUL-terminated */
               *value;      /* Not NUL-terminated */
    unsigned    name_len,
                value_len;
    unsigned    entry_id;
};

unsigned
lshpack_enc_get_stx_tab_id (const char *name, lshpack_strlen_t name_len,
                const char *val, lshpack_strlen_t val_len, int *val_matched);

int
lshpack_enc_push_entry (struct lshpack_enc *enc, const char *name,
    lshpack_strlen_t name_len, const char *value, lshpack_strlen_t value_len);

int
lshpack_enc_enc_str (unsigned char *const dst, size_t dst_len,
                     const unsigned char *str, lshpack_strlen_t str_len);

typedef void * enc_iter_t;

void
lshpack_enc_iter_init (struct lshpack_enc *enc, void **iter);

/* Returns 0 if entry is found */
int
lshpack_enc_iter_next (struct lshpack_enc *enc, void **iter,
                                            struct enc_dyn_table_entry *);

int
lshpack_dec_dec_int (const unsigned char **src, const unsigned char *src_end,
                                        uint8_t prefix_bits, uint32_t *value);
int
lshpack_dec_push_entry (struct lshpack_dec *dec, const char *name,
                        lshpack_strlen_t name_len, const char *val,
                        lshpack_strlen_t val_len);

#endif
