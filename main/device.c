/*
 * Device ring buffer implementation for LwM2M gateway
 * Provides a ring buffer implementation for managing connected devices
 * When the buffer is full, new devices will replace the oldest ones
 */

#include "device.h"
#include "flash.h"
#include "esp_log.h"
#include <string.h>
#include "liblwm2m.h"
#include "lwm2mclient.h"
#include "object_gateway.h"
extern lwm2m_object_t *lwm2m_obj_array[6];

// Forward declaration for missing gateway function
uint8_t gateway_update_instance_value(lwm2m_object_t * objectP, uint16_t instanceId, uint16_t resourceId, int64_t value);

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

    /* Save to flash after adding/updating device */
    esp_err_t save_err = device_ring_buffer_save_to_flash();
    if (save_err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to save device data to flash: %s", esp_err_to_name(save_err));
        /* Don't return error - device is still added to memory buffer */
    } else {
        ESP_LOGI(TAG, "Device data saved to flash");
    }

    device_add_instance(lwm2m_obj_array[2], g_device_buffer.count-1);
    
    char serial_str[11]; // 10 digits + null terminator
    sprintf(serial_str, "%010lu", device->serial);
    device_update_instance_string(lwm2m_obj_array[2], g_device_buffer.count - 1, 2, serial_str); // Set Power Source to Battery
    
    // Update gateway object instance count (resource 1)
    if (lwm2m_obj_array[5]) {
        gateway_update_instance_value(lwm2m_obj_array[5], 0, 1, g_device_buffer.count);
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
            ESP_LOGI(TAG, "Found device with serial %ld at index %ld, removing...", serial, i);
            
            // Shift all devices after this one forward
            for (uint32_t j = i; j < g_device_buffer.count - 1; j++) {
                memcpy(&g_device_buffer.devices[j], &g_device_buffer.devices[j + 1], 
                       sizeof(lwm2m_LwM2MDevice));
            }
            
            // Clear the last device and decrement count
            memset(&g_device_buffer.devices[g_device_buffer.count - 1], 0, sizeof(lwm2m_LwM2MDevice));
            g_device_buffer.count--;
            
            // Fix head pointer: Only adjust if removal affects the circular head position
            // Since we shift elements forward, if head was pointing beyond the removed element,
            // we need to adjust it back by one position
            if (g_device_buffer.head > 0) {
                g_device_buffer.head--;
            } else if (g_device_buffer.count > 0) {
                g_device_buffer.head = g_device_buffer.count; // Point to next available slot
            } else {
                g_device_buffer.head = 0; // Buffer is empty
            }

            ESP_LOGI(TAG, "Removed device with serial %ld (count: %ld, head: %ld)", 
                     serial, g_device_buffer.count, g_device_buffer.head);
            
            // Update gateway connected devices count
            if (lwm2m_obj_array[5]) {
                gateway_update_instance_value(lwm2m_obj_array[5], 0, 1, g_device_buffer.count);
                ESP_LOGI(TAG, "Updated gateway connected devices count to %ld", g_device_buffer.count);
            }
            
            /* Save to flash after removing device */
            esp_err_t save_err = device_ring_buffer_save_to_flash();
            if (save_err != ESP_OK) {
                ESP_LOGW(TAG, "Failed to save device data to flash: %s", esp_err_to_name(save_err));
            }
            
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
    
    /* Save to flash after clearing */
    esp_err_t save_err = device_ring_buffer_save_to_flash();
    if (save_err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to save cleared device data to flash: %s", esp_err_to_name(save_err));
    }
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

/* ---- Persistence functions ---- */

esp_err_t device_ring_buffer_init_with_persistence(void)
{
    esp_err_t err;
    
    /* Initialize device data partition */
    err = flash_device_data_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize device data partition: %s", esp_err_to_name(err));
        return err;
    }
    
    /* Initialize the ring buffer structure */
    err = device_ring_buffer_init();
    if (err != ESP_OK) {
        return err;
    }
    
    /* Try to load existing device data */
    err = device_ring_buffer_load_from_flash();
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Device data loaded from flash successfully");
        device_ring_buffer_print_status();
    } else if (err == ESP_ERR_INVALID_CRC || err == ESP_ERR_NOT_SUPPORTED || err == ESP_ERR_INVALID_SIZE) {
        ESP_LOGW(TAG, "No valid device data found in flash, starting with empty buffer");
    } else {
        ESP_LOGE(TAG, "Failed to load device data from flash: %s", esp_err_to_name(err));
        return err;
    }
    
    return ESP_OK;
}

esp_err_t device_ring_buffer_save_to_flash(void)
{
    if (!g_initialized) {
        ESP_LOGE(TAG, "Device ring buffer not initialized");
        return ESP_ERR_INVALID_STATE;
    }
    
    return flash_device_data_save(&g_device_buffer);
}

esp_err_t device_ring_buffer_load_from_flash(void)
{
    if (!g_initialized) {
        ESP_LOGE(TAG, "Device ring buffer not initialized");
        return ESP_ERR_INVALID_STATE;
    }
    
    return flash_device_data_load(&g_device_buffer);
}

esp_err_t device_ring_buffer_clear_flash(void)
{
    return flash_device_data_clear();
}

/* Sync gateway statistics with current device count */
void device_ring_buffer_sync_lwm2m_count(void)
{
    if (lwm2m_obj_array[5]) {
        uint32_t device_count = device_ring_buffer_get_count();
        gateway_update_instance_value(lwm2m_obj_array[5], 0, 1, device_count);
        ESP_LOGI(TAG, "Synced gateway device count: %ld", device_count);
    }
}

/* Check if a device with the given public key is already known */
bool device_ring_buffer_is_device_known(const uint8_t *public_key, size_t public_key_len)
{
    if (!g_initialized) {
        ESP_LOGE(TAG, "Device ring buffer not initialized");
        return false;
    }

    if (public_key == NULL || public_key_len == 0) {
        ESP_LOGE(TAG, "Invalid public key parameters");
        return false;
    }

    for (uint32_t i = 0; i < g_device_buffer.count; i++) {
        lwm2m_LwM2MDevice *device = &g_device_buffer.devices[i];
        
        // Compare public keys
        if (device->public_key.size == public_key_len && 
            device->public_key.size > 0 && 
            memcmp(device->public_key.bytes, public_key, public_key_len) == 0) {
            ESP_LOGI(TAG, "Device with public key found (serial: %ld, model: %ld)", 
                     device->serial, device->model);
            return true;
        }
    }

    ESP_LOGI(TAG, "Device with given public key not found");
    return false;
}

lwm2m_LwM2MDevice* device_ring_buffer_find_by_public_key(const uint8_t *public_key, size_t public_key_len)
{
    if (!g_initialized) {
        ESP_LOGE(TAG, "Device ring buffer not initialized");
        return NULL;
    }

    if (public_key == NULL || public_key_len == 0) {
        ESP_LOGE(TAG, "Invalid public key parameters");
        return NULL;
    }

    for (uint32_t i = 0; i < g_device_buffer.count; i++) {
        lwm2m_LwM2MDevice *device = &g_device_buffer.devices[i];
        
        // Compare public keys
        if (device->public_key.size == public_key_len && 
            device->public_key.size > 0 && 
            memcmp(device->public_key.bytes, public_key, public_key_len) == 0) {
            ESP_LOGI(TAG, "Device with public key found (serial: %ld, model: %ld)", 
                     device->serial, device->model);
            return device;
        }
    }

    ESP_LOGI(TAG, "Device with given public key not found");
    return NULL;
}

/* Add a device with public key, model, and serial number */
esp_err_t device_ring_buffer_add_device(const uint8_t *public_key, size_t public_key_len, uint32_t model, uint32_t serial, lwm2m_ConnectionType connection_type)
{
    if (!g_initialized) {
        ESP_LOGE(TAG, "Device ring buffer not initialized");
        return ESP_ERR_INVALID_STATE;
    }

    if (public_key == NULL || public_key_len == 0) {
        ESP_LOGE(TAG, "Invalid public key parameters");
        return ESP_ERR_INVALID_ARG;
    }

    if (public_key_len > sizeof(((lwm2m_LwM2MDevice*)0)->public_key.bytes)) {
        ESP_LOGE(TAG, "Public key too large (%d bytes, max %d)", 
                 (int)public_key_len, (int)sizeof(((lwm2m_LwM2MDevice*)0)->public_key.bytes));
        return ESP_ERR_INVALID_ARG;
    }

    // Check if device with this public key already exists
    if (device_ring_buffer_is_device_known(public_key, public_key_len)) {
        ESP_LOGW(TAG, "Device with this public key already exists");
        return ESP_OK; // Not an error, just already exists
    }

    // Create a new device structure
    lwm2m_LwM2MDevice new_device;
    memset(&new_device, 0, sizeof(new_device));
    
    new_device.model = model;
    new_device.serial = serial;
    new_device.instance_id = g_device_buffer.count; // Use current count as instance ID
    new_device.banned = false;
    new_device.connection_type = connection_type; // Use protobuf enum directly
    
    // Copy public key
    memcpy(new_device.public_key.bytes, public_key, public_key_len);
    new_device.public_key.size = public_key_len;

    ESP_LOGI(TAG, "Adding device - Model: %ld, Serial: %ld, Public key size: %d, Connection type: %d", 
             model, serial, (int)public_key_len, (int)connection_type);

    // Add the device to the ring buffer
    return device_ring_buffer_add(&new_device);
}