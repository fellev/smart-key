# esp-zigbee-lib / esp-zboss-lib are pulled in by idf_component.yml in this
# directory (guarded by a target rule), so they do not need to be listed here:
# the component manager adds them to the requirements automatically.
# ieee802154 only exists on targets with an 802.15.4 radio, so requiring it
# unconditionally breaks the build on e.g. the ESP32-C3. On those targets
# smartkey_zigbee compiles to its logging stub and needs no dependency.
set(zigbee_requires "")
if(CONFIG_SOC_IEEE802154_SUPPORTED)
    list(APPEND zigbee_requires ieee802154)
endif()

idf_component_register(
    SRCS "smartkey_zigbee.c"
    INCLUDE_DIRS "include"
    REQUIRES ${zigbee_requires}
)


