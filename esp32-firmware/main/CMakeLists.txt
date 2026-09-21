idf_component_register(
    SRCS "smartkey_main.c" "smartkey_console.c"
    INCLUDE_DIRS "."
    REQUIRES smartkey_proto smartkey_store smartkey_io smartkey_ble smartkey_zigbee
             console esp_timer
)
