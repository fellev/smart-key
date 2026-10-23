/**
 * @file smartkey_console.h
 * @brief Serial console commands for provisioning and diagnostics.
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Register the SmartKey commands and start the REPL on the USB/UART console.
 *
 * Commands: status, users, open, mqtt-open, pair, revoke, enable, forget, reset.
 */
typedef void (*smartkey_console_open_button_fn_t)(void);

void smartkey_console_start(smartkey_console_open_button_fn_t open_button);

#ifdef __cplusplus
}
#endif
