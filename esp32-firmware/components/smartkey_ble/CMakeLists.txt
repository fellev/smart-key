idf_component_register(
    SRCS "smartkey_ble.c" "smartkey_pairing.c" "pseudonym_table.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "."
    REQUIRES smartkey_proto smartkey_store bt esp_timer
)
