/*
 * Extracted BLE logic from original main2.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_bt.h"

#include "esp_gap_ble_api.h"
#include "esp_gatts_api.h"
#include "esp_bt_defs.h"
#include "esp_bt_main.h"
#include "esp_gatt_common_api.h"
#include "esp_gattc_api.h"

#include "pb_decode.h"
#include "lwm2m.pb.h"

#include "ble.h"

#define LOG_TAG "BLE_CLIENT"
#define EXT_SCAN_DURATION 0
#define EXT_SCAN_PERIOD   0
#define STOP_SCAN_AFTER_HANDSHAKE 1

#define FUNC_SEND_WAIT_SEM(func, sem) do {\
        esp_err_t __err_rc = (func);\
        if (__err_rc != ESP_OK) { \
            ESP_LOGE(LOG_TAG, "%s, message send fail, error = %d", __func__, __err_rc); \
        } \
        xSemaphoreTake(sem, portMAX_DELAY); \
} while(0)

/* ---------------- Internal State ---------------- */
static char s_remote_device_name[ESP_BLE_ADV_NAME_LEN_MAX] = "ESP_EXTENDED_ADV";
static SemaphoreHandle_t s_scan_sem = NULL;
static bool s_initialized = false;
static bool s_handshake_done = false;
static bool s_have_target = false;
static bool s_handshake_started = false;
static bool s_periodic_sync = false;

/* Handshake / GATT client state */
#define GATTC_APP_ID 0x66
static esp_gatt_if_t s_gattc_if = ESP_GATT_IF_NONE;
static uint16_t s_conn_id = 0xFFFF;
static esp_bd_addr_t s_target_addr = {0};
static uint8_t s_target_addr_type = BLE_ADDR_TYPE_PUBLIC;
static uint16_t s_svc_start = 0, s_svc_end = 0;
static uint16_t s_char_handle = 0;
static char s_challenge[16] = {0};

/* Service/Char UUIDs expected on peer */
static const uint16_t RW_SERVICE_UUID16 = 0x00FF;
static const uint16_t RW_CHAR_UUID16    = 0xFF01;

static esp_ble_ext_scan_params_t s_ext_scan_params = {
    .own_addr_type = BLE_ADDR_TYPE_PUBLIC,
    .filter_policy = BLE_SCAN_FILTER_ALLOW_ALL,
    .scan_duplicate = BLE_SCAN_DUPLICATE_ENABLE,
    .cfg_mask = ESP_BLE_GAP_EXT_SCAN_CFG_UNCODE_MASK | ESP_BLE_GAP_EXT_SCAN_CFG_CODE_MASK,
    .uncoded_cfg = {BLE_SCAN_TYPE_ACTIVE, 40, 40},
    .coded_cfg   = {BLE_SCAN_TYPE_ACTIVE, 40, 40},
};

static esp_ble_gap_periodic_adv_sync_params_t s_periodic_adv_sync_params = {
    .filter_policy = 0,
    .sid = 0,
    .addr_type = BLE_ADDR_TYPE_RANDOM,
    .skip = 10,
    .sync_timeout = 1000,
};

/* ------------- Helpers ------------- */
static void generate_challenge(char *out, size_t out_len)
{
    uint32_t r = (uint32_t)xTaskGetTickCount();
    const char alphabet[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    size_t i = 0;
    for (; i < out_len - 1 && r; ++i) {
        out[i] = alphabet[r % 36];
        r /= 36;
    }
    if (i == 0) { out[i++] = 'x'; }
    out[i] = '\0';
}

static void start_gattc_discovery(void);
static void start_gattc_challenge_write(void);
static void start_gattc_readback(void);
static void start_gattc_write_ok(void);
static void maybe_start_handshake_from_appearance(void);

static bool adv_next_element(const uint8_t *data, size_t len, size_t *offset,
                             uint8_t *type, const uint8_t **value, size_t *value_len)
{
    if (!data || !offset || *offset >= len) return false;
    size_t i = *offset;
    uint8_t l = data[i];
    if (l == 0) { *offset = len; return false; }
    if (i + 1 + l > len) { *offset = len; return false; }
    uint8_t t = data[i + 1];
    *type = t;
    *value = &data[i + 2];
    *value_len = (l >= 1) ? (size_t)(l - 1) : 0;
    *offset = i + 1 + l;
    return true;
}

static bool extract_msd_payload(const uint8_t *adv_data, size_t adv_len,
                                const uint8_t **payload, size_t *payload_len,
                                uint16_t *company_id_out)
{
    size_t off = 0; uint8_t type; const uint8_t *val; size_t val_len;
    while (adv_next_element(adv_data, adv_len, &off, &type, &val, &val_len)) {
        if (type == 0xFF && val_len >= 2) {
            uint16_t cid = (uint16_t)val[0] | ((uint16_t)val[1] << 8);
            if (company_id_out) *company_id_out = cid;
            if (payload && payload_len) {
                *payload = (val_len > 2) ? (val + 2) : NULL;
                *payload_len = (val_len > 2) ? (val_len - 2) : 0;
            }
            return true;
        }
    }
    return false;
}

static bool extract_service_data_payload(const uint8_t *adv_data, size_t adv_len,
                                         const uint8_t **payload, size_t *payload_len,
                                         uint16_t *uuid16_out)
{
    size_t off = 0; uint8_t type; const uint8_t *val; size_t val_len;
    while (adv_next_element(adv_data, adv_len, &off, &type, &val, &val_len)) {
        if (type == 0x16 && val_len >= 2) {
            uint16_t uuid16 = (uint16_t)val[0] | ((uint16_t)val[1] << 8);
            if (uuid16_out) *uuid16_out = uuid16;
            if (payload && payload_len) {
                *payload = (val_len > 2) ? (val + 2) : NULL;
                *payload_len = (val_len > 2) ? (val_len - 2) : 0;
            }
            return true;
        }
    }
    return false;
}

static bool decode_lwm2m_appearance(const uint8_t *data, size_t data_len, lwm2m_LwM2MAppearance *appearance)
{
    pb_istream_t stream = pb_istream_from_buffer(data, data_len);
    bool status = pb_decode(&stream, lwm2m_LwM2MAppearance_fields, appearance);
    if (!status) {
        ESP_LOGE(LOG_TAG, "Failed to decode protobuf appearance: %s", PB_GET_ERROR(&stream));
        return false;
    }
    return true;
}

static bool decode_lwm2m_message(const uint8_t *data, size_t data_len, lwm2m_LwM2MMessage *message)
{
    pb_istream_t stream = pb_istream_from_buffer(data, data_len);
    bool status = pb_decode(&stream, lwm2m_LwM2MMessage_fields, message);
    if (!status) {
        ESP_LOGE(LOG_TAG, "Failed to decode protobuf message: %s", PB_GET_ERROR(&stream));
        return false;
    }
    return true;
}

static void process_lwm2m_message(const lwm2m_LwM2MMessage *message)
{
    ESP_LOGI(LOG_TAG, "LwM2M Message decoded - timestamp: %llu", message->timestamp);
    switch (message->which_body) {
        case lwm2m_LwM2MMessage_appearance_tag:
            ESP_LOGI(LOG_TAG, "Device appearance - model: %d, serial: %u", 
                     message->body.appearance.model, 
                     message->body.appearance.serial);
            break;
        default:
            ESP_LOGW(LOG_TAG, "Unknown message type: %d", message->which_body);
            break;
    }
}

/* ------------- GATT Client operations ------------- */
static void start_gattc_discovery(void)
{
    if (s_conn_id == 0xFFFF) return;
    esp_bt_uuid_t uuid = { .len = ESP_UUID_LEN_16, .uuid = { .uuid16 = RW_SERVICE_UUID16 } };
    esp_err_t err = esp_ble_gattc_search_service(s_gattc_if, s_conn_id, &uuid);
    if (err != ESP_OK) {
        ESP_LOGE(LOG_TAG, "search_service failed: %s", esp_err_to_name(err));
    }
}

static void start_gattc_challenge_write(void)
{
    if (s_conn_id == 0xFFFF || s_char_handle == 0) return;
    generate_challenge(s_challenge, sizeof(s_challenge));
    ESP_LOGI(LOG_TAG, "Writing challenge '%s'", s_challenge);
    esp_err_t err = esp_ble_gattc_write_char(s_gattc_if, s_conn_id, s_char_handle,
                                             strlen(s_challenge), (uint8_t*)s_challenge,
                                             ESP_GATT_WRITE_TYPE_RSP, ESP_GATT_AUTH_REQ_NONE);
    if (err != ESP_OK) {
        ESP_LOGE(LOG_TAG, "write_char failed: %s", esp_err_to_name(err));
    }
}

static void start_gattc_readback(void)
{
    if (s_conn_id == 0xFFFF || s_char_handle == 0) return;
    esp_err_t err = esp_ble_gattc_read_char(s_gattc_if, s_conn_id, s_char_handle, ESP_GATT_AUTH_REQ_NONE);
    if (err != ESP_OK) {
        ESP_LOGE(LOG_TAG, "read_char failed: %s", esp_err_to_name(err));
    }
}

static void start_gattc_write_ok(void)
{
    static const char ok[] = "ok";
    if (s_conn_id == 0xFFFF || s_char_handle == 0) return;
    esp_err_t err = esp_ble_gattc_write_char(s_gattc_if, s_conn_id, s_char_handle,
                                             sizeof(ok) - 1, (uint8_t*)ok,
                                             ESP_GATT_WRITE_TYPE_RSP, ESP_GATT_AUTH_REQ_NONE);
    if (err != ESP_OK) {
        ESP_LOGE(LOG_TAG, "write 'ok' failed: %s", esp_err_to_name(err));
    } else {
        s_handshake_done = true;
        ESP_LOGI(LOG_TAG, "Handshake completed successfully");
        esp_ble_gattc_close(s_gattc_if, s_conn_id);
        #if STOP_SCAN_AFTER_HANDSHAKE
        ESP_LOGI(LOG_TAG, "Stopping extended scan (handshake complete)");
        esp_ble_gap_stop_ext_scan();
        #endif
    }
}

static void maybe_start_handshake_from_appearance(void)
{
    if (s_handshake_started || s_handshake_done || !s_have_target) return;
    ESP_LOGI(LOG_TAG, "Opening GATT connection to target addr %02X:%02X:%02X:%02X:%02X:%02X (type %u)",
             s_target_addr[0], s_target_addr[1], s_target_addr[2], s_target_addr[3], s_target_addr[4], s_target_addr[5], (unsigned)s_target_addr_type);
#if CONFIG_BT_BLE_50_FEATURES_SUPPORTED
    esp_err_t err = esp_ble_gattc_aux_open(s_gattc_if, s_target_addr, s_target_addr_type, true);
#else
    esp_err_t err = esp_ble_gattc_open(s_gattc_if, s_target_addr, s_target_addr_type, true);
#endif
    if (err != ESP_OK) {
        ESP_LOGE(LOG_TAG, "gattc_open failed: %s", esp_err_to_name(err));
        return;
    }
    s_handshake_started = true;
}

/* ------------- Event Handlers ------------- */
static void gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if, esp_ble_gattc_cb_param_t *param)
{
    switch (event) {
    case ESP_GATTC_REG_EVT:
        s_gattc_if = gattc_if; break;
    case ESP_GATTC_OPEN_EVT:
        if (param->open.status != ESP_GATT_OK) { s_handshake_started = false; break; }
        s_conn_id = param->open.conn_id; esp_ble_gattc_send_mtu_req(gattc_if, s_conn_id); break;
    case ESP_GATTC_DISCONNECT_EVT:
        s_conn_id = 0xFFFF; s_svc_start = s_svc_end = 0; s_char_handle = 0; s_handshake_started = false; break;
    case ESP_GATTC_CFG_MTU_EVT: start_gattc_discovery(); break;
    case ESP_GATTC_SEARCH_RES_EVT: {
        const esp_gatt_id_t *sid = &param->search_res.srvc_id;
        if (sid->uuid.len == ESP_UUID_LEN_16 && sid->uuid.uuid.uuid16 == RW_SERVICE_UUID16) {
            s_svc_start = param->search_res.start_handle; s_svc_end = param->search_res.end_handle;
        }
        break; }
    case ESP_GATTC_SEARCH_CMPL_EVT: {
        if (param->search_cmpl.status == ESP_GATT_OK && s_svc_start && s_svc_end) {
            uint16_t count = 0; esp_bt_uuid_t uuid = { .len = ESP_UUID_LEN_16, .uuid = { .uuid16 = RW_CHAR_UUID16 } };
            if (esp_ble_gattc_get_attr_count(gattc_if, s_conn_id, ESP_GATT_DB_CHARACTERISTIC, s_svc_start, s_svc_end, 0, &count) == ESP_GATT_OK && count) {
                esp_gattc_char_elem_t *chars = calloc(count, sizeof(*chars));
                if (chars) {
                    uint16_t out_count = count;
                    if (esp_ble_gattc_get_char_by_uuid(gattc_if, s_conn_id, s_svc_start, s_svc_end, uuid, chars, &out_count) == ESP_GATT_OK && out_count) {
                        s_char_handle = chars[0].char_handle; start_gattc_challenge_write();
                    }
                    free(chars);
                }
            }
        }
        break; }
    case ESP_GATTC_WRITE_CHAR_EVT: if (param->write.status == ESP_GATT_OK) start_gattc_readback(); break;
    case ESP_GATTC_READ_CHAR_EVT:
        if (param->read.status == ESP_GATT_OK && param->read.value && param->read.value_len) {
            const char prefix[] = "hello "; size_t pre_len = strlen(prefix);
            if (param->read.value_len >= pre_len && strncmp((const char*)param->read.value, prefix, pre_len) == 0 &&
                strstr((const char*)param->read.value + pre_len, s_challenge) != NULL) { start_gattc_write_ok(); }
        }
        break;
    default: break;
    }
}

static void gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param)
{
    switch (event) {
    case ESP_GAP_BLE_SET_EXT_SCAN_PARAMS_COMPLETE_EVT:
    case ESP_GAP_BLE_EXT_SCAN_START_COMPLETE_EVT:
    case ESP_GAP_BLE_EXT_SCAN_STOP_COMPLETE_EVT:
        if (s_scan_sem) {
            xSemaphoreGive(s_scan_sem);
        }
        break;
    case ESP_GAP_BLE_EXT_ADV_REPORT_EVT: {
        uint8_t *adv_name = NULL; uint8_t adv_name_len = 0;
        adv_name = esp_ble_resolve_adv_data_by_type(param->ext_adv_report.params.adv_data,
                                                    param->ext_adv_report.params.adv_data_len,
                                                    ESP_BLE_AD_TYPE_NAME_CMPL, &adv_name_len);
        if (adv_name && adv_name_len == strlen(s_remote_device_name) &&
            memcmp(adv_name, s_remote_device_name, adv_name_len) == 0 && !s_periodic_sync) {
            s_periodic_sync = true;
            s_periodic_adv_sync_params.sid = param->ext_adv_report.params.sid;
            s_periodic_adv_sync_params.addr_type = param->ext_adv_report.params.addr_type;
            memcpy(s_periodic_adv_sync_params.addr, param->ext_adv_report.params.addr, sizeof(esp_bd_addr_t));
            esp_ble_gap_periodic_adv_create_sync(&s_periodic_adv_sync_params);
        }
        if (adv_name && adv_name_len) {
            static const char connect_name[] = "ESP_CONNECT"; size_t cn_len = strlen(connect_name);
            if (!s_have_target && adv_name_len == cn_len && memcmp(adv_name, connect_name, cn_len) == 0) {
                memcpy(s_target_addr, param->ext_adv_report.params.addr, sizeof(esp_bd_addr_t));
                s_target_addr_type = param->ext_adv_report.params.addr_type; s_have_target = true;
            }
        }
        break; }
    case ESP_GAP_BLE_PERIODIC_ADV_REPORT_EVT: {
        if (param->period_adv_report.params.data_length > 0) {
            const uint8_t *adv_data = param->period_adv_report.params.data; size_t adv_len = param->period_adv_report.params.data_length;
            const uint8_t *protobuf_data = NULL; size_t protobuf_len = 0; uint16_t company_id = 0;
            if (extract_msd_payload(adv_data, adv_len, &protobuf_data, &protobuf_len, &company_id) && protobuf_data && protobuf_len) {
                lwm2m_LwM2MMessage message = lwm2m_LwM2MMessage_init_zero;
                if (decode_lwm2m_message(protobuf_data, protobuf_len, &message)) {
                    process_lwm2m_message(&message);
                    if (message.which_body == lwm2m_LwM2MMessage_appearance_tag) maybe_start_handshake_from_appearance();
                    break;
                }
                lwm2m_LwM2MAppearance appearance = {0};
                if (decode_lwm2m_appearance(protobuf_data, protobuf_len, &appearance)) {
                    if (!s_handshake_started) maybe_start_handshake_from_appearance();
                    break;
                }
            }
            const uint8_t *svc_payload = NULL; size_t svc_len = 0; uint16_t uuid16 = 0;
            if (extract_service_data_payload(adv_data, adv_len, &svc_payload, &svc_len, &uuid16) && svc_payload && svc_len) {
                lwm2m_LwM2MMessage message = lwm2m_LwM2MMessage_init_zero;
                if (decode_lwm2m_message(svc_payload, svc_len, &message)) {
                    process_lwm2m_message(&message);
                    if (message.which_body == lwm2m_LwM2MMessage_appearance_tag) maybe_start_handshake_from_appearance();
                    break;
                }
            }
        }
        break; }
    default: break;
    }
}

/* ------------- Public API ------------- */
esp_err_t ble_client_init_and_start(void)
{
    if (s_initialized) return ESP_OK;
    esp_err_t ret;
    /* Initialize NVS (required for BT stack if not already done). Ignore error if already initialized. */
    ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT));
    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_bt_controller_init(&bt_cfg));
    ESP_ERROR_CHECK(esp_bt_controller_enable(ESP_BT_MODE_BLE));
    ESP_ERROR_CHECK(esp_bluedroid_init());
    ESP_ERROR_CHECK(esp_bluedroid_enable());

    ESP_ERROR_CHECK(esp_ble_gattc_register_callback(gattc_event_handler));
    ESP_ERROR_CHECK(esp_ble_gattc_app_register(GATTC_APP_ID));
    ESP_ERROR_CHECK(esp_ble_gap_register_callback(gap_event_handler));

    vTaskDelay(pdMS_TO_TICKS(200));
    s_scan_sem = xSemaphoreCreateBinary();
    if (!s_scan_sem) return ESP_ERR_NO_MEM;
    FUNC_SEND_WAIT_SEM(esp_ble_gap_set_ext_scan_params(&s_ext_scan_params), s_scan_sem);
    FUNC_SEND_WAIT_SEM(esp_ble_gap_start_ext_scan(EXT_SCAN_DURATION, EXT_SCAN_PERIOD), s_scan_sem);
    s_initialized = true;
    return ESP_OK;
}

esp_err_t ble_client_stop_scan(void)
{
    return esp_ble_gap_stop_ext_scan();
}

bool ble_client_handshake_done(void)
{
    return s_handshake_done;
}
