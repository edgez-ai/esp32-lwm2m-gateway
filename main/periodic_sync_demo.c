/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */

/****************************************************************************
*
* This demo showcases BLE GATT server. It can send adv data, be connected by client.
* Run the gatt_client demo, the client demo will automatically connect to the gatt_server demo.
* Client demo will enable gatt_server's notify after connection. The two devices will then exchange
* data.
*
****************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_bt.h"

#include "esp_gap_ble_api.h"
#include "esp_gatts_api.h"
#include "esp_bt_defs.h"
#include "esp_bt_main.h"
#include "esp_gatt_common_api.h"
#include "esp_gattc_api.h"

#include "sdkconfig.h"

#include "freertos/semphr.h"
#include "pb_decode.h"
#include "lwm2m.pb.h"


#define FUNC_SEND_WAIT_SEM(func, sem) do {\
        esp_err_t __err_rc = (func);\
        if (__err_rc != ESP_OK) { \
            ESP_LOGE(LOG_TAG, "%s, message send fail, error = %d", __func__, __err_rc); \
        } \
        xSemaphoreTake(sem, portMAX_DELAY); \
} while(0);

#define LOG_TAG "PERIODIC_SYNC"
#define EXT_SCAN_DURATION     0
#define EXT_SCAN_PERIOD       0

/* Match the device name from device-example-esp32c6 Extended Advertising */
static char remote_device_name[ESP_BLE_ADV_NAME_LEN_MAX] = "ESP_EXTENDED_ADV";
static SemaphoreHandle_t test_sem = NULL;

static esp_ble_ext_scan_params_t ext_scan_params = {
    .own_addr_type = BLE_ADDR_TYPE_PUBLIC,
    .filter_policy = BLE_SCAN_FILTER_ALLOW_ALL,
    .scan_duplicate = BLE_SCAN_DUPLICATE_ENABLE,
    .cfg_mask = ESP_BLE_GAP_EXT_SCAN_CFG_UNCODE_MASK | ESP_BLE_GAP_EXT_SCAN_CFG_CODE_MASK,
    .uncoded_cfg = {BLE_SCAN_TYPE_ACTIVE, 40, 40},
    .coded_cfg = {BLE_SCAN_TYPE_ACTIVE, 40, 40},
};

static esp_ble_gap_periodic_adv_sync_params_t periodic_adv_sync_params = {
    .filter_policy = 0,
    .sid = 0,
    .addr_type = BLE_ADDR_TYPE_RANDOM,
    .skip = 10,
    .sync_timeout = 1000,
};

bool periodic_sync = false;

/* ---------------- GATT Client state for challenge handshake ---------------- */
#define GATTC_APP_ID 0x66
static esp_gatt_if_t s_gattc_if = ESP_GATT_IF_NONE;
static bool s_gattc_registered = false;
static bool s_handshake_started = false;
static bool s_handshake_done = false;
static uint16_t s_conn_id = 0xFFFF;
static esp_bd_addr_t s_target_addr = {0};
static uint8_t s_target_addr_type = BLE_ADDR_TYPE_PUBLIC;
static bool s_have_target = false;
static uint16_t s_svc_start = 0, s_svc_end = 0;
static uint16_t s_char_handle = 0;
static char s_challenge[16] = {0};

/* Known service/char UUIDs from device-example-esp32c6 */
static const uint16_t RW_SERVICE_UUID16 = 0x00FF;
static const uint16_t RW_CHAR_UUID16 = 0xFF01;

static void start_gattc_discovery(void);
static void start_gattc_challenge_write(void);
static void start_gattc_readback(void);
static void start_gattc_write_ok(void);

static void generate_challenge(char *out, size_t out_len)
{
    /* generate short base36-like token from tick count */
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

static void maybe_start_handshake_from_appearance(void)
{
    if (!s_gattc_registered || s_handshake_started || s_handshake_done) return;
    if (!s_have_target) {
        ESP_LOGW(LOG_TAG, "No target address captured yet, cannot start handshake");
        return;
    }
    ESP_LOGI(LOG_TAG, "Opening GATT connection to target addr %02X:%02X:%02X:%02X:%02X:%02X (type %u)",
             s_target_addr[0], s_target_addr[1], s_target_addr[2], s_target_addr[3], s_target_addr[4], s_target_addr[5], (unsigned)s_target_addr_type);
    
#if CONFIG_BT_BLE_50_FEATURES_SUPPORTED
    /* For BLE 5.0, use aux_open for extended advertising connections */
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

static void gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if, esp_ble_gattc_cb_param_t *param)
{
    switch (event) {
    case ESP_GATTC_REG_EVT:
        s_gattc_if = gattc_if;
        s_gattc_registered = true;
        ESP_LOGI(LOG_TAG, "GATTC registered (app_id=%d, if=%d)", param->reg.app_id, (int)gattc_if);
        break;
    case ESP_GATTC_OPEN_EVT:
        if (param->open.status != ESP_GATT_OK) {
            ESP_LOGE(LOG_TAG, "GATTC open failed status=%d", param->open.status);
            s_handshake_started = false; /* allow retry on next appearance */
            break;
        }
        s_conn_id = param->open.conn_id;
        ESP_LOGI(LOG_TAG, "GATTC connected, conn_id=%u, mtu=%u", (unsigned)s_conn_id, (unsigned)param->open.mtu);
        /* As in gatt_client example, request larger MTU first */
        esp_ble_gattc_send_mtu_req(gattc_if, s_conn_id);
        break;
    case ESP_GATTC_DISCONNECT_EVT:
        ESP_LOGI(LOG_TAG, "GATTC disconnected, reason=0x%X", param->disconnect.reason);
        s_conn_id = 0xFFFF;
        s_svc_start = s_svc_end = 0;
        s_char_handle = 0;
        s_handshake_started = false;
        break;
    case ESP_GATTC_SEARCH_RES_EVT: {
        const esp_gatt_id_t *sid = &param->search_res.srvc_id;
        if (sid->uuid.len == ESP_UUID_LEN_16 && sid->uuid.uuid.uuid16 == RW_SERVICE_UUID16) {
            s_svc_start = param->search_res.start_handle;
            s_svc_end = param->search_res.end_handle;
            ESP_LOGI(LOG_TAG, "Found service 0x%04X: start=0x%04X end=0x%04X", RW_SERVICE_UUID16, s_svc_start, s_svc_end);
        }
        break; }
    case ESP_GATTC_CFG_MTU_EVT:
        ESP_LOGI(LOG_TAG, "MTU updated: %u (status=%d)", (unsigned)param->cfg_mtu.mtu, param->cfg_mtu.status);
        start_gattc_discovery();
        break;
    case ESP_GATTC_SEARCH_CMPL_EVT:
        if (param->search_cmpl.status == ESP_GATT_OK && s_svc_start && s_svc_end) {
            /* find characteristic by UUID */
            uint16_t count = 0;
            esp_bt_uuid_t uuid = { .len = ESP_UUID_LEN_16, .uuid = { .uuid16 = RW_CHAR_UUID16 } };
            esp_gatt_status_t st = esp_ble_gattc_get_attr_count(gattc_if, s_conn_id, ESP_GATT_DB_CHARACTERISTIC, s_svc_start, s_svc_end, 0, &count);
            if (st == ESP_GATT_OK && count > 0) {
                esp_gattc_char_elem_t *chars = calloc(count, sizeof(*chars));
                if (chars) {
                    uint16_t out_count = count;
                    st = esp_ble_gattc_get_char_by_uuid(gattc_if, s_conn_id, s_svc_start, s_svc_end, uuid, chars, &out_count);
                    if (st == ESP_GATT_OK && out_count > 0) {
                        s_char_handle = chars[0].char_handle;
                        ESP_LOGI(LOG_TAG, "Found char 0x%04X handle=0x%04X props=0x%02X", RW_CHAR_UUID16, s_char_handle, (unsigned)chars[0].properties);
                        start_gattc_challenge_write();
                    } else {
                        ESP_LOGW(LOG_TAG, "RW char 0x%04X not found in service", RW_CHAR_UUID16);
                    }
                    free(chars);
                } else {
                    ESP_LOGE(LOG_TAG, "OOM allocating char list");
                }
            } else {
                ESP_LOGW(LOG_TAG, "get_attr_count failed or zero characteristics (st=%d, cnt=%u)", st, (unsigned)count);
            }
        } else {
            ESP_LOGW(LOG_TAG, "Service discovery failed (st=%d)", param->search_cmpl.status);
        }
        break;
    case ESP_GATTC_WRITE_CHAR_EVT:
        if (param->write.status != ESP_GATT_OK) {
            ESP_LOGE(LOG_TAG, "Write failed status=%d", param->write.status);
            break;
        }
        ESP_LOGI(LOG_TAG, "Write complete, now reading back response");
        start_gattc_readback();
        break;
    case ESP_GATTC_READ_CHAR_EVT:
        if (param->read.status != ESP_GATT_OK) {
            ESP_LOGE(LOG_TAG, "Read failed status=%d", param->read.status);
            break;
        }
        if (param->read.value && param->read.value_len > 0) {
            ESP_LOGI(LOG_TAG, "Read value (%u bytes): %.*s", (unsigned)param->read.value_len, (int)param->read.value_len, (const char*)param->read.value);
            const char prefix[] = "hello ";
            size_t pre_len = strlen(prefix);
            if (param->read.value_len >= pre_len && strncmp((const char*)param->read.value, prefix, pre_len) == 0 &&
                strstr((const char*)param->read.value + pre_len, s_challenge) != NULL) {
                ESP_LOGI(LOG_TAG, "Challenge success, writing 'ok'");
                start_gattc_write_ok();
            } else {
                ESP_LOGW(LOG_TAG, "Unexpected readback, challenge failed");
            }
        }
        break;
    case ESP_GATTC_WRITE_DESCR_EVT:
    case ESP_GATTC_NOTIFY_EVT:
    default:
        break;
    }
}

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
        ESP_LOGI(LOG_TAG, "Handshake completed, closing connection");
        esp_ble_gattc_close(s_gattc_if, s_conn_id);
    }
}

/* ---- BLE Advertising helpers (standard AD TLV parser) ---- */
static bool adv_next_element(const uint8_t *data, size_t len, size_t *offset,
                             uint8_t *type, const uint8_t **value, size_t *value_len)
{
    /* Iterate Advertising Data: [Len][Type][Value..] ... */
    if (!data || !offset || *offset >= len) return false;
    size_t i = *offset;
    uint8_t l = data[i];
    if (l == 0) { *offset = len; return false; }
    if (i + 1 + l > len) { *offset = len; return false; }
    uint8_t t = data[i + 1];
    *type = t;
    *value = &data[i + 2];
    *value_len = (l >= 1) ? (size_t)(l - 1) : 0; /* exclude Type byte */
    *offset = i + 1 + l; /* move to next element */
    return true;
}

static bool extract_msd_payload(const uint8_t *adv_data, size_t adv_len,
                                const uint8_t **payload, size_t *payload_len,
                                uint16_t *company_id_out)
{
    /* Manufacturer Specific Data (type 0xFF): value = [CompanyID_L][CompanyID_H][payload...] */
    size_t off = 0; uint8_t type; const uint8_t *val; size_t val_len;
    while (adv_next_element(adv_data, adv_len, &off, &type, &val, &val_len)) {
        if (type == 0xFF && val_len >= 2) {
            uint16_t cid = (uint16_t)val[0] | ((uint16_t)val[1] << 8); /* little-endian per spec */
            if (company_id_out) *company_id_out = cid;
            if (payload && payload_len) {
                *payload = (val_len > 2) ? (val + 2) : NULL; /* skip 2-byte company id */
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
    /* Service Data - 16-bit UUID (type 0x16): value = [UUID16_L][UUID16_H][payload...] */
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

static void process_lwm2m_appearance(const lwm2m_LwM2MAppearance *appearance)
{
    ESP_LOGI(LOG_TAG, "Device appearance - model: %d, serial: %u", 
             appearance->model, 
             appearance->serial);
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

static void gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param)
{
    switch (event) {
    case ESP_GAP_BLE_SET_EXT_SCAN_PARAMS_COMPLETE_EVT:
        xSemaphoreGive(test_sem);
        ESP_LOGI(LOG_TAG, "Extended scanning params set, status %d", param->set_ext_scan_params.status);
        break;
    case ESP_GAP_BLE_EXT_SCAN_START_COMPLETE_EVT:
        xSemaphoreGive(test_sem);
        ESP_LOGI(LOG_TAG, "Extended scanning start, status %d", param->ext_scan_start.status);
        break;
    case ESP_GAP_BLE_EXT_SCAN_STOP_COMPLETE_EVT:
        xSemaphoreGive(test_sem);
        ESP_LOGI(LOG_TAG, "Extended scanning stop, status %d", param->period_adv_stop.status);
        break;
    case ESP_GAP_BLE_PERIODIC_ADV_CREATE_SYNC_COMPLETE_EVT:
        ESP_LOGI(LOG_TAG, "Periodic advertising create sync, status %d", param->period_adv_create_sync.status);
        break;
    case ESP_GAP_BLE_PERIODIC_ADV_SYNC_CANCEL_COMPLETE_EVT:
        ESP_LOGI(LOG_TAG, "Periodic advertising sync cancel, status %d", param->period_adv_sync_cancel.status);
        break;
    case ESP_GAP_BLE_PERIODIC_ADV_SYNC_TERMINATE_COMPLETE_EVT:
        ESP_LOGI(LOG_TAG, "Periodic advertising sync terminate, status %d", param->period_adv_sync_term.status);
        break;
    case ESP_GAP_BLE_PERIODIC_ADV_SYNC_LOST_EVT:
        ESP_LOGI(LOG_TAG, "Periodic advertising sync lost, sync handle %d", param->periodic_adv_sync_lost.sync_handle);
        break;
    case ESP_GAP_BLE_PERIODIC_ADV_SYNC_ESTAB_EVT:
        ESP_LOGI(LOG_TAG, "Periodic advertising sync establish, status %d", param->periodic_adv_sync_estab.status);
        ESP_LOGI(LOG_TAG, "address "ESP_BD_ADDR_STR"", ESP_BD_ADDR_HEX(param->periodic_adv_sync_estab.adv_addr));
        ESP_LOGI(LOG_TAG, "sync handle %d sid %d perioic adv interval %d adv phy %d", param->periodic_adv_sync_estab.sync_handle,
                                                                                      param->periodic_adv_sync_estab.sid,
                                                                                      param->periodic_adv_sync_estab.period_adv_interval,
                                                                                      param->periodic_adv_sync_estab.adv_phy);
        break;
    case ESP_GAP_BLE_EXT_ADV_REPORT_EVT: {
        uint8_t *adv_name = NULL;
        uint8_t adv_name_len = 0;
	    adv_name = esp_ble_resolve_adv_data_by_type(param->ext_adv_report.params.adv_data,
                                            param->ext_adv_report.params.adv_data_len,
                                            ESP_BLE_AD_TYPE_NAME_CMPL,
                                            &adv_name_len);
	    
	    /* Log all advertisements with names for debugging */
	    if (adv_name != NULL && adv_name_len > 0) {
	        char temp_name[ESP_BLE_ADV_NAME_LEN_MAX + 1] = {0};
	        size_t copy_len = adv_name_len < ESP_BLE_ADV_NAME_LEN_MAX ? adv_name_len : ESP_BLE_ADV_NAME_LEN_MAX;
	        memcpy(temp_name, adv_name, copy_len);
	        ESP_LOGI(LOG_TAG, "Adv from %02X:%02X:%02X:%02X:%02X:%02X, name: '%s' (len=%u)",
	                 param->ext_adv_report.params.addr[0], param->ext_adv_report.params.addr[1],
	                 param->ext_adv_report.params.addr[2], param->ext_adv_report.params.addr[3],
	                 param->ext_adv_report.params.addr[4], param->ext_adv_report.params.addr[5],
	                 temp_name, (unsigned)adv_name_len);
	    }
	    
	    /* Check for periodic advertising device */
	    if ((adv_name != NULL) && (adv_name_len == strlen(remote_device_name)) && 
	        (memcmp(adv_name, remote_device_name, adv_name_len) == 0) && !periodic_sync) {
            periodic_sync = true;
	        char adv_temp_name[30] = {'0'};
	        memcpy(adv_temp_name, adv_name, adv_name_len);
	        ESP_LOGI(LOG_TAG, "Create sync with the peer device %s", adv_temp_name);
            periodic_adv_sync_params.sid = param->ext_adv_report.params.sid;
	        periodic_adv_sync_params.addr_type = param->ext_adv_report.params.addr_type;
	        memcpy(periodic_adv_sync_params.addr, param->ext_adv_report.params.addr, sizeof(esp_bd_addr_t));
            esp_ble_gap_periodic_adv_create_sync(&periodic_adv_sync_params);
	    }
	    
	    /* Also check for connectable GATT service advertising (ESP_CONNECT) */
	    if (adv_name != NULL && adv_name_len > 0 && !s_have_target) {
	        static const char connect_name[] = "ESP_CONNECT";
	        size_t connect_name_len = strlen(connect_name);
	        if (adv_name_len == connect_name_len && memcmp(adv_name, connect_name, adv_name_len) == 0) {
	            /* Save target address for GATT connection */
                memcpy(s_target_addr, param->ext_adv_report.params.addr, sizeof(esp_bd_addr_t));
                s_target_addr_type = param->ext_adv_report.params.addr_type;
                s_have_target = true;
                ESP_LOGI(LOG_TAG, "Found ESP_CONNECT device at %02X:%02X:%02X:%02X:%02X:%02X (type %u)",
                         s_target_addr[0], s_target_addr[1], s_target_addr[2], 
                         s_target_addr[3], s_target_addr[4], s_target_addr[5], 
                         (unsigned)s_target_addr_type);
	        }
	    }
    }
        break;
    case ESP_GAP_BLE_PERIODIC_ADV_REPORT_EVT:
        ESP_LOGI(LOG_TAG, "Periodic adv report, sync handle %d, data status %d, data len %d, rssi %d", 
                 param->period_adv_report.params.sync_handle,
                 param->period_adv_report.params.data_status,
                 param->period_adv_report.params.data_length,
                 param->period_adv_report.params.rssi);
        
        // Decode protobuf message from periodic advertising data
        if (param->period_adv_report.params.data_length > 0) {
            // Log raw data for debugging
            ESP_LOG_BUFFER_HEX(LOG_TAG, param->period_adv_report.params.data, param->period_adv_report.params.data_length);
            
            // Parse BLE AD structures; first try Manufacturer Specific Data (type 0xFF)
            const uint8_t *adv_data = param->period_adv_report.params.data;
            size_t adv_len = param->period_adv_report.params.data_length;

            const uint8_t *protobuf_data = NULL;
            size_t protobuf_len = 0;
            uint16_t company_id = 0;

            bool found = extract_msd_payload(adv_data, adv_len, &protobuf_data, &protobuf_len, &company_id);
            if (found && protobuf_data && protobuf_len > 0) {
                ESP_LOGI(LOG_TAG, "MSD company_id=0x%04X, protobuf length: %u", company_id, (unsigned)protobuf_len);
                ESP_LOG_BUFFER_HEX(LOG_TAG, protobuf_data, protobuf_len);
                // First try full LwM2MMessage (sender posts LwM2MMessage with appearance inside)
                lwm2m_LwM2MMessage message = lwm2m_LwM2MMessage_init_zero;
                if (decode_lwm2m_message(protobuf_data, protobuf_len, &message)) {
                    process_lwm2m_message(&message);
                    if (message.which_body == lwm2m_LwM2MMessage_appearance_tag) {
                        /* kick off GATT handshake */
                        maybe_start_handshake_from_appearance();
                    }
                    break;
                }
                // Fallback to bare LwM2MAppearance if some devices send only custom data
                lwm2m_LwM2MAppearance appearance = {0};
                if (decode_lwm2m_appearance(protobuf_data, protobuf_len, &appearance)) {
                    ESP_LOGI(LOG_TAG, "Decoded bare LwM2MAppearance from MSD payload");
                    process_lwm2m_appearance(&appearance);
                    break;
                } else {
                    ESP_LOGW(LOG_TAG, "Failed to decode payload as LwM2MMessage or LwM2MAppearance (from MSD)");
                }
            }

            // Optional: also allow Service Data - 16-bit UUID carrier (type 0x16)
            const uint8_t *svc_payload = NULL; size_t svc_len = 0; uint16_t uuid16 = 0;
            if (extract_service_data_payload(adv_data, adv_len, &svc_payload, &svc_len, &uuid16) && svc_payload && svc_len > 0) {
                ESP_LOGI(LOG_TAG, "ServiceData UUID16=0x%04X, protobuf length: %u", uuid16, (unsigned)svc_len);
                ESP_LOG_BUFFER_HEX(LOG_TAG, svc_payload, svc_len);
                lwm2m_LwM2MMessage message = lwm2m_LwM2MMessage_init_zero;
                if (decode_lwm2m_message(svc_payload, svc_len, &message)) {
                    process_lwm2m_message(&message);
                    if (message.which_body == lwm2m_LwM2MMessage_appearance_tag) {
                        maybe_start_handshake_from_appearance();
                    }
                    break;
                }
            }
            // If neither carrier worked, warn once per report
            ESP_LOGW(LOG_TAG, "No decodable LwM2MAppearance found in periodic adv payload");
        } else {
            ESP_LOGW(LOG_TAG, "No data in periodic advertising report");
        }
        break;

    default:
        break;
    }
}

void app_main(void)
{
    esp_err_t ret;

    // Initialize NVS.
    ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK( ret );

    #if CONFIG_EXAMPLE_CI_PIPELINE_ID
    memcpy(remote_device_name, esp_bluedroid_get_example_name(), sizeof(remote_device_name));
    #endif

    ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT));

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ret = esp_bt_controller_init(&bt_cfg);
    if (ret) {
        ESP_LOGE(LOG_TAG, "%s initialize controller failed: %s", __func__, esp_err_to_name(ret));
        return;
    }

    ret = esp_bt_controller_enable(ESP_BT_MODE_BLE);
    if (ret) {
        ESP_LOGE(LOG_TAG, "%s enable controller failed: %s", __func__, esp_err_to_name(ret));
        return;
    }

    ret = esp_bluedroid_init();
    if (ret) {
        ESP_LOGE(LOG_TAG, "%s init bluetooth failed: %s", __func__, esp_err_to_name(ret));
        return;
    }
    ret = esp_bluedroid_enable();
    if (ret) {
        ESP_LOGE(LOG_TAG, "%s enable bluetooth failed: %s", __func__, esp_err_to_name(ret));
        return;
    }
    /* Register GATT client for handshake */
    ESP_ERROR_CHECK(esp_ble_gattc_register_callback(gattc_event_handler));
    ESP_ERROR_CHECK(esp_ble_gattc_app_register(GATTC_APP_ID));
    ret = esp_ble_gap_register_callback(gap_event_handler);
    if (ret){
        ESP_LOGE(LOG_TAG, "gap register error, error code = %x", ret);
        return;
    }

    vTaskDelay(200 / portTICK_PERIOD_MS);

    test_sem = xSemaphoreCreateBinary();

    FUNC_SEND_WAIT_SEM(esp_ble_gap_set_ext_scan_params(&ext_scan_params), test_sem);
    FUNC_SEND_WAIT_SEM(esp_ble_gap_start_ext_scan(EXT_SCAN_DURATION, EXT_SCAN_PERIOD), test_sem);


    return;
}
