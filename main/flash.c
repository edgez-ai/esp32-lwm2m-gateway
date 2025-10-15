/* Implementation of flash helpers (renamed + extended from factory_partition.c) */

#include "flash.h"
#include "device.h"

#include <string.h>
#include "esp_log.h"
#include "esp_partition.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "mbedtls/base64.h"
#include "lwm2m_helpers.h"

static const char *TAG = "flash";
static const esp_partition_t *s_factory_partition = NULL;
static const esp_partition_t *s_device_data_partition = NULL;

/* NVS constants (kept aligned with previous main.c & ble_lwm2m.c expectations) */
#define NVS_AES_NAMESPACE "ble_lwm2m"
#define NVS_AES_KEY       "aes_key"


#define NVS_NAMESPACE "test_storage"
#define NVS_TEST_KEY "boot_count"
#define NVS_AES_KEY "aes_key"
#define NVS_AES_NAMESPACE "ble_lwm2m"  // Must match namespace used in ble_lwm2m.c for AES key persistence

esp_err_t flash_factory_partition_init(void)
{
    if (s_factory_partition) {
        return ESP_OK; /* already */
    }
    s_factory_partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                                                   (esp_partition_subtype_t)0x40,
                                                   "factory_data");
    if (!s_factory_partition) {
        ESP_LOGE(TAG, "Factory data partition not found");
        return ESP_ERR_NOT_FOUND;
    }
    ESP_LOGI(TAG, "Factory data partition: addr=0x%08lx size=0x%08lx",
             s_factory_partition->address, s_factory_partition->size);
    return ESP_OK;
}

esp_err_t flash_factory_partition_read(size_t offset, void* data, size_t size)
{
    if (!s_factory_partition) {
        ESP_LOGE(TAG, "Factory partition not initialized");
        return ESP_ERR_INVALID_STATE;
    }
    if (offset + size > s_factory_partition->size) {
        ESP_LOGE(TAG, "Read exceeds partition boundary");
        return ESP_ERR_INVALID_SIZE;
    }
    esp_err_t err = esp_partition_read(s_factory_partition, offset, data, size);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Partition read failed: %s", esp_err_to_name(err));
    }
    return err;
}

esp_err_t flash_factory_partition_write(size_t offset, const void* data, size_t size)
{
    if (!s_factory_partition) {
        ESP_LOGE(TAG, "Factory partition not initialized");
        return ESP_ERR_INVALID_STATE;
    }
    if (offset + size > s_factory_partition->size) {
        ESP_LOGE(TAG, "Write exceeds partition boundary");
        return ESP_ERR_INVALID_SIZE;
    }
    if (offset % 4096 == 0) {
        size_t erase_size = (size + 4095) & ~4095;
        if (offset + erase_size > s_factory_partition->size) {
            erase_size = s_factory_partition->size - offset;
        }
        esp_err_t err = esp_partition_erase_range(s_factory_partition, offset, erase_size);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Erase failed: %s", esp_err_to_name(err));
            return err;
        }
    }
    esp_err_t err = esp_partition_write(s_factory_partition, offset, data, size);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Write failed: %s", esp_err_to_name(err));
    }
    return err;
}

const esp_partition_t* flash_factory_partition_get_handle(void)
{
    return s_factory_partition;
}

bool flash_check_aes_key_exists(void)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_AES_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        if (err != ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGW(TAG, "AES namespace open failed: %s", esp_err_to_name(err));
        } else {
            ESP_LOGI(TAG, "AES namespace not found");
        }
        return false;
    }
    uint8_t stored_len = 0;
    err = nvs_get_u8(handle, "aes_len", &stored_len);
    if (err != ESP_OK || !(stored_len == 16 || stored_len == 24 || stored_len == 32)) {
        if (err == ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGI(TAG, "AES key length marker missing");
        } else {
            ESP_LOGW(TAG, "AES length read failed: %s", esp_err_to_name(err));
        }
        nvs_close(handle);
        return false;
    }
    size_t len = stored_len;
    uint8_t tmp_key[32];
    err = nvs_get_blob(handle, NVS_AES_KEY, tmp_key, &len);
    nvs_close(handle);
    if (err == ESP_OK && len == stored_len) {
        ESP_LOGI(TAG, "AES key present (len=%u)", (unsigned)len);
        return true;
    }
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGI(TAG, "AES key blob missing");
    } else {
        ESP_LOGW(TAG, "AES blob read error: %s", esp_err_to_name(err));
    }
    return false;
}

static void print_hex_bytes(const char* label, const uint8_t* data, size_t len)
{
    if (len == 0) {
        ESP_LOGI(TAG, "%s: (empty)", label);
        return;
    }
    char buf[len * 2 + 1];
    for (size_t i = 0; i < len; ++i) sprintf(&buf[i*2], "%02x", data[i]);
    buf[len*2] = '\0';
    ESP_LOGI(TAG, "%s: %s", label, buf);
}

void flash_debug_print_factory_partition(const lwm2m_FactoryPartition* p, bool valid)
{
    if (!valid || !p) {
        ESP_LOGI(TAG, "Factory partition invalid or NULL");
        return;
    }
    ESP_LOGI(TAG, "=== LwM2M Factory Partition ===");
    ESP_LOGI(TAG, "Serial: %s", p->serial);
    print_hex_bytes("Public Key", p->public_key.bytes, sizeof(p->public_key.bytes));
    print_hex_bytes("Private Key", p->private_key.bytes, sizeof(p->private_key.bytes));
    if (p->bootstrap_server.size > 0) {
        char server[p->bootstrap_server.size + 1];
        memcpy(server, p->bootstrap_server.bytes, p->bootstrap_server.size);
        server[p->bootstrap_server.size] = '\0';
        ESP_LOGI(TAG, "Bootstrap Server: %s", server);
    }
    ESP_LOGI(TAG, "================================");
}

esp_err_t flash_load_lwm2m_factory_partition(lwm2m_FactoryPartition* out_partition, bool* valid)
{
    if (valid) *valid = false;
    if (!out_partition) return ESP_ERR_INVALID_ARG;

    esp_err_t err = flash_factory_partition_init();
    if (err != ESP_OK) return err;

    /* Read up to 1KB base64 text */
    char b64[1024] = {0};
    err = flash_factory_partition_read(0, b64, sizeof(b64) - 1);
    if (err != ESP_OK) return err;

    /* Determine actual length (stop at first NUL/newline) */
    size_t b64_len = 0;
    while (b64_len < sizeof(b64)-1 && b64[b64_len] && b64[b64_len] != '\n' && b64[b64_len] != '\r') b64_len++;
    if (b64_len == 0) {
        ESP_LOGW(TAG, "Factory data empty");
        return ESP_ERR_INVALID_SIZE;
    }
    ESP_LOGI(TAG, "Factory base64 length: %zu", b64_len);

    uint8_t decoded[512]; size_t decoded_len = 0;
    int mb_ret = mbedtls_base64_decode(decoded, sizeof(decoded), &decoded_len, (const unsigned char*)b64, b64_len);
    if (mb_ret != 0) {
        ESP_LOGE(TAG, "Base64 decode failed (%d)", mb_ret);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Decoded length: %zu", decoded_len);
    if (decoded_len > 0) {
        size_t to_show = decoded_len;
        const size_t kMaxShow = 128; /* avoid overly large dumps */
        if (to_show > kMaxShow) {
            to_show = kMaxShow;
            ESP_LOGI(TAG, "Decoded bytes (hex, first %zu of %zu bytes):", to_show, decoded_len);
        } else {
            ESP_LOGI(TAG, "Decoded bytes (hex):");
        }
        /* Use ESP-IDF provided helper to log a hex dump */
        ESP_LOG_BUFFER_HEX(TAG, decoded, to_show);
    }

    *out_partition = (lwm2m_FactoryPartition)lwm2m_FactoryPartition_init_zero;
    int parse_rc = lwm2m_read_factory_partition(decoded, decoded_len, out_partition);
    if (parse_rc != 0) {
        ESP_LOGE(TAG, "Protobuf parse failed (%d)", parse_rc);
        return ESP_FAIL;
    }
    if (valid) *valid = true;
    return ESP_OK;
}


void test_nvs_functionality(void)
{
    ESP_LOGI(TAG, "=== Testing NVS Functionality ===");
    
    // Initialize NVS
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS partition was truncated and will be erased");
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
    
    nvs_handle_t nvs_handle;
    err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS handle: %s", esp_err_to_name(err));
        return;
    }
    
    // Try to read existing value
    uint32_t boot_count = 0;
    err = nvs_get_u32(nvs_handle, NVS_TEST_KEY, &boot_count);
    
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Previous boot count found: %lu", (unsigned long)boot_count);
    } else if (err == ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGI(TAG, "Boot count not found - this appears to be first boot or after factory reset");
        boot_count = 0;
    } else {
        ESP_LOGE(TAG, "Failed to read boot count: %s", esp_err_to_name(err));
        nvs_close(nvs_handle);
        return;
    }
    
    // Increment and save boot count
    boot_count++;
    err = nvs_set_u32(nvs_handle, NVS_TEST_KEY, boot_count);
    if (err == ESP_OK) {
        err = nvs_commit(nvs_handle);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "✓ Boot count updated to: %lu", (unsigned long)boot_count);
            ESP_LOGI(TAG, "✓ NVS write/read test PASSED");
        } else {
            ESP_LOGE(TAG, "Failed to commit NVS: %s", esp_err_to_name(err));
        }
    } else {
        ESP_LOGE(TAG, "Failed to set NVS value: %s", esp_err_to_name(err));
    }
    
    nvs_close(nvs_handle);
    ESP_LOGI(TAG, "=============================");
}

/* ---- Device data persistence implementation ---- */

#define DEVICE_DATA_MAGIC 0xDEADBE01  /* Magic number to identify valid device data */
#define DEVICE_DATA_VERSION 1         /* Version for future compatibility */

/* Header structure for device data partition */
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t data_size;
    uint32_t crc32;
    uint32_t reserved[4];  /* For future use */
} device_data_header_t;

/* Simple CRC32 implementation */
static uint32_t calculate_crc32(const uint8_t *data, size_t length)
{
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    return ~crc;
}

esp_err_t flash_device_data_init(void)
{
    if (s_device_data_partition) {
        return ESP_OK; /* already initialized */
    }
    
    s_device_data_partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                                                      (esp_partition_subtype_t)0x41,
                                                      "device_data");
    if (!s_device_data_partition) {
        ESP_LOGE(TAG, "Device data partition not found");
        return ESP_ERR_NOT_FOUND;
    }
    
    ESP_LOGI(TAG, "Device data partition: addr=0x%08lx size=0x%08lx",
             s_device_data_partition->address, s_device_data_partition->size);
    
    return ESP_OK;
}

esp_err_t flash_device_data_save(const struct device_ring_buffer_t* buffer)
{
    if (!s_device_data_partition) {
        ESP_LOGE(TAG, "Device data partition not initialized");
        return ESP_ERR_INVALID_STATE;
    }
    
    if (!buffer) {
        ESP_LOGE(TAG, "Buffer pointer is NULL");
        return ESP_ERR_INVALID_ARG;
    }
    
    ESP_LOGI(TAG, "Saving device data (count: %ld, head: %ld)", buffer->count, buffer->head);
    
    /* Calculate required size */
    size_t data_size = sizeof(struct device_ring_buffer_t);
    size_t total_size = sizeof(device_data_header_t) + data_size;
    
    if (total_size > s_device_data_partition->size) {
        ESP_LOGE(TAG, "Device data too large for partition (need %zu, have %ld)", 
                 total_size, s_device_data_partition->size);
        return ESP_ERR_INVALID_SIZE;
    }
    
    /* Prepare header */
    device_data_header_t header = {
        .magic = DEVICE_DATA_MAGIC,
        .version = DEVICE_DATA_VERSION,
        .data_size = data_size,
        .crc32 = calculate_crc32((const uint8_t*)buffer, data_size),
        .reserved = {0}
    };
    
    /* Erase the partition */
    esp_err_t err = esp_partition_erase_range(s_device_data_partition, 0, s_device_data_partition->size);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to erase device data partition: %s", esp_err_to_name(err));
        return err;
    }
    
    /* Write header */
    err = esp_partition_write(s_device_data_partition, 0, &header, sizeof(header));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to write device data header: %s", esp_err_to_name(err));
        return err;
    }
    
    /* Write device data */
    err = esp_partition_write(s_device_data_partition, sizeof(header), buffer, data_size);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to write device data: %s", esp_err_to_name(err));
        return err;
    }
    
    ESP_LOGI(TAG, "Device data saved successfully (size: %zu bytes)", total_size);
    return ESP_OK;
}

esp_err_t flash_device_data_load(struct device_ring_buffer_t* buffer)
{
    if (!s_device_data_partition) {
        ESP_LOGE(TAG, "Device data partition not initialized");
        return ESP_ERR_INVALID_STATE;
    }
    
    if (!buffer) {
        ESP_LOGE(TAG, "Buffer pointer is NULL");
        return ESP_ERR_INVALID_ARG;
    }
    
    /* Read header */
    device_data_header_t header;
    esp_err_t err = esp_partition_read(s_device_data_partition, 0, &header, sizeof(header));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read device data header: %s", esp_err_to_name(err));
        return err;
    }
    
    /* Validate header */
    if (header.magic != DEVICE_DATA_MAGIC) {
        ESP_LOGW(TAG, "Invalid magic number in device data partition (0x%08lx)", header.magic);
        return ESP_ERR_INVALID_CRC;
    }
    
    if (header.version != DEVICE_DATA_VERSION) {
        ESP_LOGW(TAG, "Unsupported device data version (%ld)", header.version);
        return ESP_ERR_NOT_SUPPORTED;
    }
    
    if (header.data_size != sizeof(struct device_ring_buffer_t)) {
        ESP_LOGW(TAG, "Device data size mismatch (expected %zu, got %ld)", 
                 sizeof(struct device_ring_buffer_t), header.data_size);
        return ESP_ERR_INVALID_SIZE;
    }
    
    /* Read device data */
    err = esp_partition_read(s_device_data_partition, sizeof(header), buffer, header.data_size);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read device data: %s", esp_err_to_name(err));
        return err;
    }
    
    /* Validate CRC */
    uint32_t calculated_crc = calculate_crc32((const uint8_t*)buffer, header.data_size);
    if (calculated_crc != header.crc32) {
        ESP_LOGE(TAG, "Device data CRC mismatch (expected 0x%08lx, got 0x%08lx)", 
                 header.crc32, calculated_crc);
        return ESP_ERR_INVALID_CRC;
    }
    
    ESP_LOGI(TAG, "Device data loaded successfully (count: %ld, head: %ld)", 
             buffer->count, buffer->head);
    
    return ESP_OK;
}

esp_err_t flash_device_data_clear(void)
{
    if (!s_device_data_partition) {
        ESP_LOGE(TAG, "Device data partition not initialized");
        return ESP_ERR_INVALID_STATE;
    }
    
    ESP_LOGI(TAG, "Clearing device data partition");
    
    esp_err_t err = esp_partition_erase_range(s_device_data_partition, 0, s_device_data_partition->size);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to clear device data partition: %s", esp_err_to_name(err));
        return err;
    }
    
    ESP_LOGI(TAG, "Device data partition cleared successfully");
    return ESP_OK;
}

const esp_partition_t* flash_device_data_get_handle(void)
{
    return s_device_data_partition;
}