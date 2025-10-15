/*
 * Device ring buffer implementation for LwM2M gateway
 * Provides a ring buffer implementation for managing connected devices
 * When the buffer is full, new devices will replace the oldest ones
 */

#include "device.h"
#include "esp_log.h"
#include <string.h>

static const char *TAG = "DEVICE_RING_BUFFER";

/* Global ring buffer instance */
static device_ring_buffer_t g_device_buffer;
static bool g_initialized = false;

/* Initialize the device ring buffer */
esp_err_t device_ring_buffer_init(void)
{
    if (g_initialized) {
        ESP_LOGW(TAG, "Device ring buffer already initialized");
        return ESP_OK;
    }

    memset(&g_device_buffer, 0, sizeof(g_device_buffer));
    g_device_buffer.capacity = LWM2M_MAX_DEVICES;
    g_device_buffer.head = 0;
    g_device_buffer.count = 0;

    g_initialized = true;
    ESP_LOGI(TAG, "Device ring buffer initialized with capacity %d", LWM2M_MAX_DEVICES);
    
    return ESP_OK;
}

/* Add a device to the ring buffer (replaces oldest if full) */
esp_err_t device_ring_buffer_add(const lwm2m_LwM2MDevice *device)
{
    if (!g_initialized) {
        ESP_LOGE(TAG, "Device ring buffer not initialized");
        return ESP_ERR_INVALID_STATE;
    }

    if (device == NULL) {
        ESP_LOGE(TAG, "Device pointer is NULL");
        return ESP_ERR_INVALID_ARG;
    }

    // Check if device already exists (by serial number)
    lwm2m_LwM2MDevice *existing = device_ring_buffer_find_by_serial(device->serial);
    if (existing != NULL) {
        // Update existing device
        memcpy(existing, device, sizeof(lwm2m_LwM2MDevice));
        ESP_LOGI(TAG, "Updated existing device with serial %ld", device->serial);
        return ESP_OK;
    }

    // Add new device at head position
    memcpy(&g_device_buffer.devices[g_device_buffer.head], device, sizeof(lwm2m_LwM2MDevice));

    // Advance head pointer (circular)
    g_device_buffer.head = (g_device_buffer.head + 1) % g_device_buffer.capacity;

    // Update count (max is capacity)
    if (g_device_buffer.count < g_device_buffer.capacity) {
        g_device_buffer.count++;
        ESP_LOGI(TAG, "Added new device with serial %ld (count: %ld/%ld)", 
                 device->serial, g_device_buffer.count, g_device_buffer.capacity);
    } else {
        ESP_LOGI(TAG, "Ring buffer full, replaced oldest device with serial %ld", device->serial);
    }

    return ESP_OK;
}

/* Find a device by serial number */
lwm2m_LwM2MDevice* device_ring_buffer_find_by_serial(uint32_t serial)
{
    if (!g_initialized) {
        ESP_LOGE(TAG, "Device ring buffer not initialized");
        return NULL;
    }

    for (uint32_t i = 0; i < g_device_buffer.count; i++) {
        if (g_device_buffer.devices[i].serial == serial) {
            return &g_device_buffer.devices[i];
        }
    }

    return NULL;
}

/* Find a device by MAC address */
lwm2m_LwM2MDevice* device_ring_buffer_find_by_mac(const uint8_t *mac_address, size_t mac_len)
{
    if (!g_initialized) {
        ESP_LOGE(TAG, "Device ring buffer not initialized");
        return NULL;
    }

    if (mac_address == NULL || mac_len == 0) {
        ESP_LOGE(TAG, "Invalid MAC address parameters");
        return NULL;
    }

    for (uint32_t i = 0; i < g_device_buffer.count; i++) {
        lwm2m_LwM2MDevice *device = &g_device_buffer.devices[i];
        
        // Check if MAC address callback is set and compare
        if (device->mac_address.funcs.decode != NULL) {
            // For protobuf callback fields, we'd need to decode the MAC address
            // This is a simplified comparison assuming MAC is stored directly
            // In a real implementation, you'd need to properly decode the callback data
            ESP_LOGW(TAG, "MAC address comparison with callback fields not fully implemented");
        }
    }

    return NULL;
}

/* Get device by index (0 to count-1) */
lwm2m_LwM2MDevice* device_ring_buffer_get_by_index(uint32_t index)
{
    if (!g_initialized) {
        ESP_LOGE(TAG, "Device ring buffer not initialized");
        return NULL;
    }

    if (index >= g_device_buffer.count) {
        ESP_LOGE(TAG, "Index %ld out of range (count: %ld)", index, g_device_buffer.count);
        return NULL;
    }

    return &g_device_buffer.devices[index];
}

/* Remove a device by serial number */
esp_err_t device_ring_buffer_remove_by_serial(uint32_t serial)
{
    if (!g_initialized) {
        ESP_LOGE(TAG, "Device ring buffer not initialized");
        return ESP_ERR_INVALID_STATE;
    }

    // Find the device
    for (uint32_t i = 0; i < g_device_buffer.count; i++) {
        if (g_device_buffer.devices[i].serial == serial) {
            // Shift all devices after this one forward
            for (uint32_t j = i; j < g_device_buffer.count - 1; j++) {
                memcpy(&g_device_buffer.devices[j], &g_device_buffer.devices[j + 1], 
                       sizeof(lwm2m_LwM2MDevice));
            }
            
            // Clear the last device and decrement count
            memset(&g_device_buffer.devices[g_device_buffer.count - 1], 0, sizeof(lwm2m_LwM2MDevice));
            g_device_buffer.count--;
            
            // Adjust head pointer if necessary
            if (g_device_buffer.head > 0) {
                g_device_buffer.head--;
            } else {
                g_device_buffer.head = g_device_buffer.capacity - 1;
            }

            ESP_LOGI(TAG, "Removed device with serial %ld (count: %ld)", serial, g_device_buffer.count);
            return ESP_OK;
        }
    }

    ESP_LOGW(TAG, "Device with serial %ld not found for removal", serial);
    return ESP_ERR_NOT_FOUND;
}

/* Get current count of devices */
uint32_t device_ring_buffer_get_count(void)
{
    if (!g_initialized) {
        return 0;
    }
    
    return g_device_buffer.count;
}

/* Check if buffer is full */
bool device_ring_buffer_is_full(void)
{
    if (!g_initialized) {
        return false;
    }
    
    return (g_device_buffer.count >= g_device_buffer.capacity);
}

/* Clear all devices from buffer */
void device_ring_buffer_clear(void)
{
    if (!g_initialized) {
        ESP_LOGW(TAG, "Device ring buffer not initialized");
        return;
    }

    memset(&g_device_buffer.devices, 0, sizeof(g_device_buffer.devices));
    g_device_buffer.head = 0;
    g_device_buffer.count = 0;

    ESP_LOGI(TAG, "Device ring buffer cleared");
}

/* Get the underlying ring buffer (for advanced operations) */
device_ring_buffer_t* device_ring_buffer_get_handle(void)
{
    if (!g_initialized) {
        ESP_LOGE(TAG, "Device ring buffer not initialized");
        return NULL;
    }
    
    return &g_device_buffer;
}

/* Print device buffer status for debugging */
void device_ring_buffer_print_status(void)
{
    if (!g_initialized) {
        ESP_LOGW(TAG, "Device ring buffer not initialized");
        return;
    }

    ESP_LOGI(TAG, "Device Ring Buffer Status:");
    ESP_LOGI(TAG, "  Capacity: %ld", g_device_buffer.capacity);
    ESP_LOGI(TAG, "  Count: %ld", g_device_buffer.count);
    ESP_LOGI(TAG, "  Head: %ld", g_device_buffer.head);
    ESP_LOGI(TAG, "  Full: %s", device_ring_buffer_is_full() ? "Yes" : "No");

    if (g_device_buffer.count > 0) {
        ESP_LOGI(TAG, "  Devices:");
        for (uint32_t i = 0; i < g_device_buffer.count; i++) {
            lwm2m_LwM2MDevice *device = &g_device_buffer.devices[i];
            ESP_LOGI(TAG, "    [%ld] Model: %ld, Serial: %ld, Instance: %ld, Banned: %s",
                     i, device->model, device->serial, device->instance_id,
                     device->banned ? "Yes" : "No");
        }
    }
}

/* Utility: Create a device structure from basic parameters */
esp_err_t device_create(lwm2m_LwM2MDevice *device, int32_t model, uint32_t serial, 
                       const uint8_t *public_key, size_t pub_key_len,
                       const uint8_t *aes_key, int32_t instance_id, bool banned)
{
    if (device == NULL) {
        ESP_LOGE(TAG, "Device pointer is NULL");
        return ESP_ERR_INVALID_ARG;
    }

    // Clear the device structure
    memset(device, 0, sizeof(lwm2m_LwM2MDevice));

    // Set basic fields
    device->model = model;
    device->serial = serial;
    device->instance_id = instance_id;
    device->banned = banned;

    // Copy public key if provided
    if (public_key != NULL && pub_key_len > 0) {
        size_t copy_len = (pub_key_len > sizeof(device->public_key.bytes)) ? 
                          sizeof(device->public_key.bytes) : pub_key_len;
        memcpy(device->public_key.bytes, public_key, copy_len);
        device->public_key.size = copy_len;
    }

    // Copy AES key if provided
    if (aes_key != NULL) {
        memcpy(device->aes_key, aes_key, sizeof(device->aes_key));
    }

    ESP_LOGI(TAG, "Created device: Model=%ld, Serial=%ld, Instance=%ld, Banned=%s",
             model, serial, instance_id, banned ? "Yes" : "No");

    return ESP_OK;
}