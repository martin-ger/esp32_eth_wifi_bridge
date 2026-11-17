#ifndef POWER_CYCLE_RESET_H
#define POWER_CYCLE_RESET_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Checks NVS for 5 consecutive rapid power cycles (within 5s of boot).
 *        Triggers built-in factory_reset() if threshold is reached.
 *        Otherwise starts a 5-second timer to reset count to 0 on stable run.
 */
void check_power_cycle_factory_reset(void);

#ifdef __cplusplus
}
#endif

#endif // POWER_CYCLE_RESET_H