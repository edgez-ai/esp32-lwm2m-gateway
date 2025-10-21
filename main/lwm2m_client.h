#pragma once

#include "esp_err.h"

/* Start the LwM2M client task (creates FreeRTOS task internally). */
void lwm2m_client_start(void);

/* Update the temperature value exposed via test object (before start or anytime). */
void lwm2m_client_set_temperature(float temp_celsius);

/* Read factory partition and parse data into provided buffers */
esp_err_t read_factory_and_parse(char *pinCode, size_t pinCode_len, char *psk_key, size_t psk_key_len, char *server, size_t server_len);

/* Gateway management functions */
void lwm2m_update_gateway_rx_stats(uint64_t bytes);
void lwm2m_update_gateway_tx_stats(uint64_t bytes);
void lwm2m_set_gateway_status(const char* status);
void lwm2m_update_connected_devices_count(void);
void lwm2m_update_active_sessions(int32_t session_count);

/* Trigger registration update to notify server of changes */
void lwm2m_trigger_registration_update(void);
