idf_component_register(
    SRCS "smartkey_proto.c" "smartkey_crypto.c" "smartkey_proximity.c" "smartkey_rearm.c"
    INCLUDE_DIRS "include"
    REQUIRES mbedtls esp_hw_support
)

