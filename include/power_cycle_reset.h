#ifndef POWER_CYCLE_RESET_H
#define POWER_CYCLE_RESET_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Power-cycle factory reset check. Call once at boot, after NVS init.
 *
 * Only power-on and EN-pin resets are counted. When CONFIG_POWER_CYCLE_RESET_COUNT
 * consecutive power-ups each last less than CONFIG_POWER_CYCLE_RESET_TIMEOUT_SEC,
 * factory_reset_settings() is called and the device restarts. Otherwise a one-shot
 * timer clears the counter once the device has been up for the timeout.
 * No-op when CONFIG_POWER_CYCLE_RESET_ENABLED is not set.
 */
void check_power_cycle_factory_reset(void);

#ifdef __cplusplus
}
#endif

#endif // POWER_CYCLE_RESET_H
