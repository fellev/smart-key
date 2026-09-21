# ESP-IDF v5.3+ split the monolithic "driver" component into per-peripheral
# components, and from v6.0 "driver" no longer re-exports their headers. Depend
# on esp_driver_gpio directly; this also builds on 5.x, where the component
# already exists.
idf_component_register(
    SRCS "smartkey_io.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_driver_gpio esp_timer
)
