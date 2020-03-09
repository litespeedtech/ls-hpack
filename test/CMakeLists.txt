ENABLE_TESTING()

ADD_EXECUTABLE(test_hpack test_hpack.c ../deps/xxhash/xxhash.c)
TARGET_LINK_LIBRARIES(test_hpack ls-hpack)
ADD_TEST(hpack test_hpack 0)
ADD_TEST(hpack-http1x test_hpack 1)

ADD_EXECUTABLE(test_int test_int.c ../deps/xxhash/xxhash.c)
TARGET_LINK_LIBRARIES(test_int ls-hpack)
ADD_TEST(int test_int)
