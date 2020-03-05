#ifndef LITESPEED_HPACK_TEST_H
#define LITESPEED_HPACK_TEST_H 1

#define LSHPACK_XXH_SEED 39378473

struct enc_dyn_table_entry
{
    const char *name,       /* Not NUL-terminated */
               *value;      /* Not NUL-terminated */
    unsigned    name_len,
                value_len;
    unsigned    entry_id;
};

unsigned
lshpack_enc_get_static_name (uint32_t name_hash, const char *name,
                                            unsigned name_len);

unsigned
lshpack_enc_get_static_nameval (uint32_t nameval_hash, const char *name,
        unsigned name_len, const char *val, unsigned val_len);

int
lshpack_enc_push_entry (struct lshpack_enc *enc, uint32_t name_hash,
    uint32_t nameval_hash, const char *name, unsigned name_len,
    const char *value, unsigned value_len);

int
lshpack_enc_enc_str (unsigned char *const dst, size_t dst_len,
                     const unsigned char *str, unsigned str_len);

typedef void * enc_iter_t;

void
lshpack_enc_iter_init (struct lshpack_enc *enc, void **iter);

/* Returns 0 if entry is found */
int
lshpack_enc_iter_next (struct lshpack_enc *enc, void **iter,
                                            struct enc_dyn_table_entry *);

int
lshpack_dec_dec_int (const unsigned char **src, const unsigned char *src_end,
                                        unsigned prefix_bits, uint32_t *value);
int
lshpack_dec_push_entry (struct lshpack_dec *dec, const char *name,
                        unsigned name_len, const char *val,
                        unsigned val_len);

unsigned char *
lshpack_enc_enc_int (unsigned char *dst, unsigned char *const end, uint32_t value,
                                                       uint8_t prefix_bits);


#endif
