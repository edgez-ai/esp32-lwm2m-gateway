#pragma once

#include "esp_err.h"

/* Start the LwM2M client task (creates FreeRTOS task internally). */
void lwm2m_client_start(void);

/* Update the temperature value exposed via test object (before start or anytime). */
void lwm2m_client_set_temperature(float temp_celsius);
