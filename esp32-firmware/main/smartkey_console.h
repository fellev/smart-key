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
 * Commands: status, users, pair, revoke, enable, forget, reset.
 */
void smartkey_console_start(void);

#ifdef __cplusplus
}
#endif
