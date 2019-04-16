add_executable(encode-qif encode-qif.c ../deps/xxhash/xxhash.c)
target_link_libraries(encode-qif PRIVATE ls-hpack)
