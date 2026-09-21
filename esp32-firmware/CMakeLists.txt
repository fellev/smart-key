cmake_minimum_required(VERSION 3.16)

# The door unit targets the ESP32-C5 (BLE 5 + 802.15.4 for Zigbee).
#   idf.py set-target esp32c5 && idf.py build
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(smartkey-door)

