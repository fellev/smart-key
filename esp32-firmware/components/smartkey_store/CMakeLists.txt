idf_component_register(
    SRCS "smartkey_store.c"
    INCLUDE_DIRS "include"
    REQUIRES smartkey_proto nvs_flash
)
