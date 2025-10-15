/*
 * Device ring buffer management for LwM2M gateway
 * Provides a ring buffer implementation for managing connected devices
 * When the buffer is full, new devices will replace the oldest ones
 */

#pragma once

#include "lwm2m.pb.h"
#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LWM2M_MAX_DEVICES 100

/* Device ring buffer structure */
typedef struct {
    lwm2m_LwM2MDevice devices[LWM2M_MAX_DEVICES];
    uint32_t head;          /* Next position to insert */
    uint32_t count;         /* Current number of devices */
    uint32_t capacity;      /* Maximum capacity (LWM2M_MAX_DEVICES) */
} device_ring_buffer_t;

/* Initialize the device ring buffer */
esp_err_t device_ring_buffer_init(void);

/* Add a device to the ring buffer (replaces oldest if full) */
esp_err_t device_ring_buffer_add(const lwm2m_LwM2MDevice *device);

/* Find a device by serial number */
lwm2m_LwM2MDevice* device_ring_buffer_find_by_serial(uint32_t serial);

/* Find a device by MAC address */
lwm2m_LwM2MDevice* device_ring_buffer_find_by_mac(const uint8_t *mac_address, size_t mac_len);

/* Get device by index (0 to count-1) */
lwm2m_LwM2MDevice* device_ring_buffer_get_by_index(uint32_t index);

/* Remove a device by serial number */
esp_err_t device_ring_buffer_remove_by_serial(uint32_t serial);

/* Get current count of devices */
uint32_t device_ring_buffer_get_count(void);

/* Check if buffer is full */
bool device_ring_buffer_is_full(void);

/* Clear all devices from buffer */
void device_ring_buffer_clear(void);

/* Get the underlying ring buffer (for advanced operations) */
device_ring_buffer_t* device_ring_buffer_get_handle(void);

/* Print device buffer status for debugging */
void device_ring_buffer_print_status(void);

/* Utility: Create a device structure from basic parameters */
esp_err_t device_create(lwm2m_LwM2MDevice *device, int32_t model, uint32_t serial, 
                       const uint8_t *public_key, size_t pub_key_len,
                       const uint8_t *aes_key, int32_t instance_id, bool banned);

#ifdef __cplusplus
}
#endif