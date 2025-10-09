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
	    if ((adv_name != NULL) && (memcmp(adv_name, remote_device_name, adv_name_len) == 0) && !periodic_sync) {
            // Note: If there are multiple devices with the same device name, the device may sync to an unintended one.
            // It is recommended to change the default device name to ensure it is unique.
            periodic_sync = true;
	        char adv_temp_name[30] = {'0'};
	        memcpy(adv_temp_name, adv_name, adv_name_len);
	        ESP_LOGI(LOG_TAG, "Create sync with the peer device %s", adv_temp_name);
            periodic_adv_sync_params.sid = param->ext_adv_report.params.sid;
	        periodic_adv_sync_params.addr_type = param->ext_adv_report.params.addr_type;
	        memcpy(periodic_adv_sync_params.addr, param->ext_adv_report.params.addr, sizeof(esp_bd_addr_t));
            esp_ble_gap_periodic_adv_create_sync(&periodic_adv_sync_params);
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
                    break;
                }
                lwm2m_LwM2MAppearance appearance = {0};
                if (decode_lwm2m_appearance(svc_payload, svc_len, &appearance)) {
                    ESP_LOGI(LOG_TAG, "Decoded bare LwM2MAppearance from ServiceData");
                    process_lwm2m_appearance(&appearance);
                    break;
                } else {
                    ESP_LOGW(LOG_TAG, "Failed to decode payload as LwM2MMessage or LwM2MAppearance (from ServiceData)");
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
