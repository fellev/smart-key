# esp-zigbee-lib / esp-zboss-lib are pulled in by idf_component.yml in this
# directory (guarded by a target rule), so they do not need to be listed here:
# the component manager adds them to the requirements automatically.
idf_component_register(
    SRCS "smartkey_zigbee.c"
    INCLUDE_DIRS "include"
    REQUIRES ieee802154
)


