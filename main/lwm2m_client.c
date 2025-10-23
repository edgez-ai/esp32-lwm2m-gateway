#include "lwm2m_client.h"

#include <string.h>
#include <strings.h>
#include <sys/param.h>
#include <lwip/netdb.h>
#include <lwip/sockets.h>

#include "esp_log.h"
#include "esp_sleep.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "lwm2mclient.h"
#include "dtlsconnection.h"
#include "dtls_debug.h"
#include "object_vendor.h"
#include "object_gateway.h"
#include "object_wot_thing.h"
#include "object_wot_data_feature.h"
#include "object_wot_action.h"
#include "object_wot_event.h"
#include "wot_bootstrap_config.h"
#include "flash.h"
#include "device.h"

/* Keep RTC persisted data across deep sleep resets */
RTC_DATA_ATTR char rtc_lwm2m_server_uri[128] = {0};
RTC_DATA_ATTR char rtc_lwm2m_identity[64] = {0};
RTC_DATA_ATTR char rtc_lwm2m_psk[64] = {0};
RTC_DATA_ATTR client_data_t client_data = {0};
RTC_FAST_ATTR uint8_t proto_buffer[8000]; /* Buffer for lwm2m proto model */

static const char *TAG = "lwm2m_client";
static const char *LOCAL_PORT = "56830";
static float s_temperature_c = 0.0f; /* updated via public setter */
/* serialNumber is referenced by wakaama registration logic, needs external linkage */
char serialNumber[64] = {0};
uint8_t public_key[64] = {0};
uint8_t private_key[64] = {0};
uint8_t vendor_public_key[32] = {0};
size_t public_key_len = 0;
size_t private_key_len = 0;
char pinCode[32] = {0};
char psk_key[64] = {0};
char server[128] = {0};
static lwm2m_object_t *objArray[11] = {0};  // Expanded for WoT objects and connectivity monitoring
static uint8_t rx_buffer[2048];
static RTC_DATA_ATTR struct timeval sleep_enter_time;
static bool wot_model_printed = false;  // Flag to print WoT model only once

// Forward declaration of callback function
static void gateway_device_update_callback(uint32_t device_id, uint16_t new_instance_id);

// Function to print WoT Things model
static void print_wot_things_model(void)
{
    ESP_LOGI(TAG, "==================== W3C WoT THINGS MODEL ====================");
    
    if (objArray[7] == NULL) {
        ESP_LOGW(TAG, "WoT objects not initialized");
        return;
    }
    
    lwm2m_object_t *thing_obj = objArray[7];  // WoT Thing object
    wot_thing_instance_t *thing_instance = (wot_thing_instance_t *)thing_obj->instanceList;
    
    if (thing_instance == NULL) {
        ESP_LOGI(TAG, "No WoT Thing instances found");
        return;
    }
    
    // Print each Thing instance
    while (thing_instance != NULL) {
        ESP_LOGI(TAG, "");
        ESP_LOGI(TAG, "Thing Instance ID: %d", thing_instance->instanceId);
        ESP_LOGI(TAG, "  Identifier: %s", thing_instance->thing_identifier);
        ESP_LOGI(TAG, "  Title: %s", thing_instance->title);
        ESP_LOGI(TAG, "  Description: %s", thing_instance->description);
        ESP_LOGI(TAG, "  Version: %s", thing_instance->version);
        ESP_LOGI(TAG, "  Last Updated: %ld", (long)thing_instance->last_updated);
        
        // Print Property References
        if (thing_instance->property_refs_count > 0) {
            ESP_LOGI(TAG, "  Property References (%d):", thing_instance->property_refs_count);
            for (int i = 0; i < thing_instance->property_refs_count; i++) {
                if (thing_instance->property_refs[i].type == LWM2M_TYPE_OBJECT_LINK) {
                    uint16_t obj_id = thing_instance->property_refs[i].value.asObjLink.objectId;
                    uint16_t inst_id = thing_instance->property_refs[i].value.asObjLink.objectInstanceId;
                    ESP_LOGI(TAG, "    [%d] Object %d, Instance %d", i, obj_id, inst_id);
                }
            }
        } else {
            ESP_LOGI(TAG, "  Property References: None");
        }
        
        // Print Action References
        if (thing_instance->action_refs_count > 0) {
            ESP_LOGI(TAG, "  Action References (%d):", thing_instance->action_refs_count);
            for (int i = 0; i < thing_instance->action_refs_count; i++) {
                if (thing_instance->action_refs[i].type == LWM2M_TYPE_OBJECT_LINK) {
                    uint16_t obj_id = thing_instance->action_refs[i].value.asObjLink.objectId;
                    uint16_t inst_id = thing_instance->action_refs[i].value.asObjLink.objectInstanceId;
                    ESP_LOGI(TAG, "    [%d] Object %d, Instance %d", i, obj_id, inst_id);
                }
            }
        } else {
            ESP_LOGI(TAG, "  Action References: None");
        }
        
        // Print Event References
        if (thing_instance->event_refs_count > 0) {
            ESP_LOGI(TAG, "  Event References (%d):", thing_instance->event_refs_count);
            for (int i = 0; i < thing_instance->event_refs_count; i++) {
                if (thing_instance->event_refs[i].type == LWM2M_TYPE_OBJECT_LINK) {
                    uint16_t obj_id = thing_instance->event_refs[i].value.asObjLink.objectId;
                    uint16_t inst_id = thing_instance->event_refs[i].value.asObjLink.objectInstanceId;
                    ESP_LOGI(TAG, "    [%d] Object %d, Instance %d", i, obj_id, inst_id);
                }
            }
        } else {
            ESP_LOGI(TAG, "  Event References: None");
        }
        
        thing_instance = thing_instance->next;
    }
    
    // Print Data Features
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "Data Features (Object %u):", objArray[8] ? objArray[8]->objID : 0);
    if (objArray[8] && objArray[8]->instanceList) {
        wot_data_feature_instance_t *feature_instance = (wot_data_feature_instance_t *)objArray[8]->instanceList;
        while (feature_instance != NULL) {
            ESP_LOGI(TAG, "  Instance %d: %s", feature_instance->instanceId, feature_instance->feature_identifier);
            ESP_LOGI(TAG, "    Linked Resources: %d", feature_instance->linked_resources_count);
            for (int i = 0; i < feature_instance->linked_resources_count; i++) {
                ESP_LOGI(TAG, "      [%d] %s", i, feature_instance->linked_resources[i]);
            }
            if (feature_instance->has_owning_thing) {
                ESP_LOGI(TAG, "    Owning Thing: Object %d, Instance %d", 
                         feature_instance->owning_thing_obj_id, feature_instance->owning_thing_instance_id);
            } else {
                ESP_LOGI(TAG, "    Owning Thing: None");
            }
            feature_instance = feature_instance->next;
        }
    } else {
        ESP_LOGI(TAG, "  No Data Feature instances");
    }
    
    // Print Actions
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "Actions (Object %u):", objArray[9] ? objArray[9]->objID : 0);
    if (objArray[9] && objArray[9]->instanceList) {
        wot_action_instance_t *action_instance = (wot_action_instance_t *)objArray[9]->instanceList;
        while (action_instance != NULL) {
            ESP_LOGI(TAG, "  Instance %d: %s", action_instance->instanceId, action_instance->action_identifier);
            ESP_LOGI(TAG, "    Script Size: %zu bytes", action_instance->script_size);
            ESP_LOGI(TAG, "    Script Format: %s", action_instance->script_format);
            if (action_instance->has_owning_thing) {
                ESP_LOGI(TAG, "    Owning Thing: Object %d, Instance %d", 
                         action_instance->owning_thing_obj_id, action_instance->owning_thing_instance_id);
            } else {
                ESP_LOGI(TAG, "    Owning Thing: None");
            }
            action_instance = action_instance->next;
        }
    } else {
        ESP_LOGI(TAG, "  No Action instances");
    }
    
    // Print Events
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "Events (Object %u):", objArray[10] ? objArray[10]->objID : 0);
    if (objArray[10] && objArray[10]->instanceList) {
        wot_event_instance_t *event_instance = (wot_event_instance_t *)objArray[10]->instanceList;
        while (event_instance != NULL) {
            ESP_LOGI(TAG, "  Instance %d: %s", event_instance->instanceId, event_instance->event_identifier);
            ESP_LOGI(TAG, "    Script Size: %zu bytes", event_instance->script_size);
            ESP_LOGI(TAG, "    Script Format: %s", event_instance->script_format);
            if (event_instance->has_owning_thing) {
                ESP_LOGI(TAG, "    Owning Thing: Object %d, Instance %d", 
                         event_instance->owning_thing_obj_id, event_instance->owning_thing_instance_id);
            } else {
                ESP_LOGI(TAG, "    Owning Thing: None");
            }
            event_instance = event_instance->next;
        }
    } else {
        ESP_LOGI(TAG, "  No Event instances");
    }
    
    ESP_LOGI(TAG, "===============================================================");
}

/* Internal helpers */
static void save_security_info_to_rtc(const char *uri, const char *identity, size_t identity_len, const char *psk, size_t psk_len)
{
    if (uri) {
        strncpy(rtc_lwm2m_server_uri, uri, sizeof(rtc_lwm2m_server_uri) - 1);
        rtc_lwm2m_server_uri[sizeof(rtc_lwm2m_server_uri) - 1] = '\0';
    }
    if (identity) {
        memcpy(rtc_lwm2m_identity, identity, MIN(identity_len, sizeof(rtc_lwm2m_identity)));
    }
    if (psk) {
        memcpy(rtc_lwm2m_psk, psk, MIN(psk_len, sizeof(rtc_lwm2m_psk)));
    }
}



/* Read factory partition (base64 protobuf) and extract fields for LwM2M security.
 * Replaces legacy serialnumber colon-delimited parsing. We derive:
 *  - serialNumber from partition->serial (decimal)
 *  - server from partition->bootstrap_server (string bytes)
 *  - psk_key from partition->private_key (hex encoded, truncated to psk_sz-1)
 *  - pinCode left empty (not present in factory data)
 * If factory partition not found or invalid, returns error and leaves buffers unchanged.
 */
esp_err_t read_factory_and_parse(char *pinCode, size_t pin_sz, char *psk_key, size_t psk_sz, char *server, size_t server_sz)
{
    if (!pinCode || !psk_key || !server) return ESP_ERR_INVALID_ARG;
    lwm2m_FactoryPartition fp; bool valid = false;
    esp_err_t err = flash_load_lwm2m_factory_partition(&fp, &valid);
    if (err != ESP_OK || !valid) {
        ESP_LOGE(TAG, "Factory partition load failed: %s valid=%d", esp_err_to_name(err), (int)valid);
        return err != ESP_OK ? err : ESP_ERR_INVALID_STATE;
    }
    sprintf(pinCode, "%06ld", fp.pin); /* pinCode not present in factory data, leave empty */
     /* serialNumber composed of model (2 hex chars) + serial (10-digit zero-padded decimal)
         Example: model=0x1A, serial=123 -> "1A0000000123" */
    memcpy(serialNumber, fp.serial, sizeof(serialNumber) - 1);
    memcpy(public_key, fp.public_key.bytes, fp.public_key.size > sizeof(public_key) ? sizeof(public_key) : fp.public_key.size);
    memcpy(vendor_public_key, fp.signature_cert.bytes, fp.signature_cert.size > sizeof(vendor_public_key) ? sizeof(vendor_public_key) : fp.signature_cert.size);
    public_key_len = fp.public_key.size;
    memcpy(private_key, fp.private_key.bytes, fp.private_key.size > sizeof(private_key) ? sizeof(private_key) : fp.private_key.size);
    private_key_len = fp.private_key.size;
    /* bootstrap_server bytes -> server string */
    if (fp.bootstrap_server.size > 0) {
        size_t copy = fp.bootstrap_server.size < (server_sz - 1) ? fp.bootstrap_server.size : (server_sz - 1);
        memcpy(server, fp.bootstrap_server.bytes, copy);
        server[copy] = '\0';
    } else if (server_sz > 0) {
        server[0] = '\0';
    }


    /* private_key -> shift bytes to alphanumeric range for PSK (32 bytes max).
       Maps each byte to alphanumeric characters: 0-9 (48-57), A-Z (65-90), a-z (97-122)
       Total 62 characters, so we use modulo 62 to map 0-255 -> alphanumeric set */
    size_t pk_len = fp.private_key.size; /* actual protobuf field size */
    if (pk_len == 0) {
        /* Empty key */
        if (psk_sz > 0) psk_key[0] = '\0';
    } else {
        /* Use 16 bytes from private key for PSK (Wakaama/TinyDTLS limit) */
        size_t bytes_to_process = MIN(pk_len, 16); /* Wakaama PSK limit is 16 bytes */
        bytes_to_process = MIN(bytes_to_process, psk_sz); /* Respect buffer size */
        
        /* Alphanumeric character set: 0-9, A-Z, a-z (62 total characters) */
        const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        
        /* Convert each byte to alphanumeric character */
        for (size_t i = 0; i < bytes_to_process; i++) {
            uint8_t byte = fp.private_key.bytes[i];
            psk_key[i] = alphanum[byte % 62]; /* Map 0-255 to 0-61 index */
        }
        
        /* Pad with '0' if we have fewer than 16 bytes */
        for (size_t i = bytes_to_process; i < 16 && i < psk_sz; i++) {
            psk_key[i] = '0';
        }
        
        /* Null terminate only if buffer is larger than 16 bytes */
        if (psk_sz > 16) {
            psk_key[16] = '\0';
        }
    }

    ESP_LOGI(TAG, "Factory parsed serialNumber=%s pinCode=%s psk(hex)=%s server=%s", serialNumber, pinCode, psk_key, server);
    return ESP_OK;
}

static void client_task(void *pvParameters)
{
    char LWM2M_SERVER_URI[160] = {0};
    char resolved_ip[64] = {0};
    struct in_addr addr;
    if (inet_aton(server, &addr) != 0) {
        strncpy(resolved_ip, server, sizeof(resolved_ip) - 1);
    } else {
        struct addrinfo hints = {0};
        struct addrinfo *res = NULL;
        hints.ai_family = AF_INET;
        int err = getaddrinfo(server, NULL, &hints, &res);
        if (err == 0 && res) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
            strncpy(resolved_ip, inet_ntoa(ipv4->sin_addr), sizeof(resolved_ip) - 1);
            freeaddrinfo(res);
        } else {
            ESP_LOGE(TAG, "Failed to resolve server hostname: %s", server);
            strncpy(resolved_ip, server, sizeof(resolved_ip) - 1);
        }
    }
    snprintf(LWM2M_SERVER_URI, sizeof(LWM2M_SERVER_URI), "coaps://%s:5685", resolved_ip);
    ESP_LOGI(TAG, "Resolved server hostname: %s %s", resolved_ip, LWM2M_SERVER_URI);


    esp_sleep_wakeup_cause_t wakeup_reason = esp_sleep_get_wakeup_cause();
    struct timeval now; gettimeofday(&now, NULL);
    int sleep_time_ms = (now.tv_sec - sleep_enter_time.tv_sec) * 1000 + (now.tv_usec - sleep_enter_time.tv_usec) / 1000;

    switch (wakeup_reason) {
    case ESP_SLEEP_WAKEUP_TIMER:
        ESP_LOGI(TAG, "Wake up from timer. Time spent in deep sleep: %dms", sleep_time_ms);
        break;
    case ESP_SLEEP_WAKEUP_EXT1: {
        uint64_t wakeup_pin_mask = esp_sleep_get_ext1_wakeup_status();
        if (wakeup_pin_mask) {
            int pin = __builtin_ffsll(wakeup_pin_mask) - 1;
            ESP_LOGI(TAG, "Wake up from GPIO %d", pin);
        } else {
            ESP_LOGI(TAG, "Wake up from GPIO");
        }
        break; }
    default:
        ESP_LOGI(TAG, "Not a deep sleep reset");
        break;
    }

    if (wakeup_reason == ESP_SLEEP_WAKEUP_TIMER) {
        ESP_LOGI(TAG, "Restoring LwM2M config from RTC memory (URI=%s, ID=%s, PSK=%s)", rtc_lwm2m_server_uri, rtc_lwm2m_identity, rtc_lwm2m_psk);
        objArray[0] = get_security_object(1, rtc_lwm2m_server_uri, rtc_lwm2m_identity, rtc_lwm2m_psk, strlen(rtc_lwm2m_psk), false);
    } else {
        char psk_identity[96] = {0};
        snprintf(psk_identity, sizeof(psk_identity), "%s%s", serialNumber, pinCode);
        objArray[0] = get_security_object(1, LWM2M_SERVER_URI, psk_identity, psk_key, strlen(psk_key), true);
    }
    objArray[1] = get_server_object(1, "U", 300, false);
    objArray[2] = get_object_device();
    objArray[3] = get_vendor_object();
    objArray[4] = get_test_object();
    objArray[5] = get_object_gateway();  // Add gateway object
    objArray[6] = get_object_conn_m();   // Add connectivity monitoring object

    // Initialize W3C WoT objects
    objArray[7] = get_object_wot_thing();         // Object 26250
    objArray[8] = get_object_wot_data_feature();  // Object 26251
    objArray[9] = get_object_wot_action();        // Object 26252
    objArray[10] = get_object_wot_event();         // Object 26253
    
    // Apply default WoT configuration if objects were created successfully
    if (objArray[7] && objArray[8] && objArray[9] && objArray[10]) {
        // Create a temporary wot_objects structure for configuration
        wot_objects_t temp_wot_objects = {
            .wot_thing_obj = objArray[7],
            .wot_data_feature_obj = objArray[8],
            .wot_action_obj = objArray[9],
            .wot_event_obj = objArray[10]
        };
        
        wot_bootstrap_config_t* wot_config = wot_bootstrap_create_default_config();
        if (wot_config != NULL) {
            uint8_t result = wot_bootstrap_apply_config(&temp_wot_objects, wot_config);
            if (result == COAP_204_CHANGED) {
                ESP_LOGI(TAG, "WoT default configuration applied successfully");
            } else {
                ESP_LOGW(TAG, "Failed to apply WoT default configuration: %d", result);
            }
            wot_bootstrap_free_config(wot_config);
        }
        
        ESP_LOGI(TAG, "W3C WoT objects initialized with default configuration");
    } else {
        ESP_LOGW(TAG, "Failed to initialize some W3C WoT objects");
    }
    
    // Set up the callbacks for gateway object
    gateway_set_device_update_callback(objArray[5], gateway_device_update_callback);
    gateway_set_registration_update_callback(objArray[5], lwm2m_trigger_registration_update);

    device_add_instance(objArray[2], 0);
    device_update_instance_string(objArray[2], 0, 2, serialNumber); // Set Power Source to Battery

    // Initialize Object 25 instances from device ring buffer
    uint32_t device_count = device_ring_buffer_get_count();
    for (uint32_t i = 0; i < device_count; i++) {
        lwm2m_LwM2MDevice *device = device_ring_buffer_get_by_index(i);
        
        // Create Device Object instance (Object 3)
        device_add_instance(objArray[2], device->instance_id);
        char serial_str[11]; // 10 digits + null terminator
        sprintf(serial_str, "%010lu", device->serial);
        device_update_instance_string(objArray[2], device->instance_id, 2, serial_str); // Set Power Source to Battery

        // Create Object 25 instance for each device
        // Use i as instanceId, device->serial as device_id, device->instance_id as server_instance_id
        // Assume BLE connection type since devices come through BLE
        //if (device->instance_id <= 0) {
        gateway_add_instance(objArray[5], i, device->serial, CONNECTION_BLE);
        // Set the server_instance_id (resource 1) to device->instance_id
        gateway_update_instance_value(objArray[5], i, 1, device->instance_id);
        //}
        ESP_LOGI(TAG, "Added Object 25 instance %d for device serial %lu (server_instance_id=%d)", 
                 i, device->serial, device->instance_id);

        // Create Connectivity Monitoring (Object 4) instance for each device
        connectivity_moni_add_instance(objArray[6], device->instance_id, device->serial);
        ESP_LOGI(TAG, "Added Object 4 (Connectivity Monitoring) instance %d for device serial %lu", 
                 device->instance_id, device->serial);
    }
    
    ESP_LOGI(TAG, "Object 25 initialized with %ld device instances", device_count);

    client_data.sock = create_socket(LOCAL_PORT, client_data.addressFamily);
    if (client_data.sock < 0) {
        ESP_LOGE(TAG, "Failed to open socket: %d %s", errno, strerror(errno));
        vTaskDelete(NULL); return;
    }
    int flags = lwip_fcntl(client_data.sock, F_GETFL, 0);
    lwip_fcntl(client_data.sock, F_SETFL, flags | O_NONBLOCK);
    client_data.securityObjP = objArray[0];
    lwm2m_context_t *client_handle = lwm2m_init(&client_data);
    if (!client_handle) {
        ESP_LOGE(TAG, "Failed to initialize LwM2M client");
        vTaskDelete(NULL); return;
    }
    client_data.lwm2mH = client_handle;
    if (lwm2m_configure(client_handle, serialNumber, NULL, NULL, 11, objArray) != 0) {
        ESP_LOGE(TAG, "lwm2m_configure failed");
        vTaskDelete(NULL); return;
    }
    
    ESP_LOGI(TAG, "🔽 BOOTSTRAP DEBUG - WoT Objects configured:");
    ESP_LOGI(TAG, "🔽   Object 4 (Connectivity Monitoring): %s", objArray[6] ? "✅ Registered" : "❌ Failed");
    ESP_LOGI(TAG, "🔽   Object 26250 (WoT Thing): %s", objArray[7] ? "✅ Registered" : "❌ Failed");
    ESP_LOGI(TAG, "🔽   Object 26251 (WoT Data Feature): %s", objArray[8] ? "✅ Registered" : "❌ Failed");
    ESP_LOGI(TAG, "🔽   Object 26252 (WoT Action): %s", objArray[9] ? "✅ Registered" : "❌ Failed");
    ESP_LOGI(TAG, "🔽   Object 26253 (WoT Event): %s", objArray[10] ? "✅ Registered" : "❌ Failed");
    ESP_LOGI(TAG, "🔽 BOOTSTRAP DEBUG - Client ready to receive bootstrap commands...");
    
    if (wakeup_reason == ESP_SLEEP_WAKEUP_TIMER) {
        ESP_LOGI(TAG, "Restored LwM2M client state to STATE_READY");
    }
    int inactivity_counter = 0;
    const int inactivity_limit = 40; /* seconds (loop delay 10ms, counter increments each loop when READY & no data) */
    while (1) {
        time_t tv = lwm2m_gettime();
        lwm2m_step(client_handle, &tv);

        // Log state changes for bootstrap debugging
        static lwm2m_client_state_t last_state = STATE_INITIAL;
        if (client_handle->state != last_state) {
            ESP_LOGI(TAG, "🔽 BOOTSTRAP DEBUG - Client state changed: %d -> %d", last_state, client_handle->state);
            last_state = client_handle->state;
        }

        struct sockaddr_storage source_addr; socklen_t socklen = sizeof(source_addr);
        int len = recvfrom(client_data.sock, rx_buffer, sizeof(rx_buffer), 0, (struct sockaddr *)&source_addr, &socklen);
        if (len > 0) {
            connection_handle_packet(client_data.connList, rx_buffer, len);
            inactivity_counter = 0;
        } else if (client_handle->state == STATE_READY) {
            // Print WoT Things model once when client becomes ready
            if (!wot_model_printed) {
                print_wot_things_model();
                wot_model_printed = true;
            }
            
            inactivity_counter++;
            test_data_t *device_data = (test_data_t *)objArray[4]->userData;
            if (device_data->test_integer != (int)s_temperature_c) {
                ESP_LOGI(TAG, "Temperature changed, updating resource to %.2f", s_temperature_c);
                device_data->test_integer = (int)s_temperature_c;
                lwm2m_uri_t uri = {.objectId = 3442, .instanceId = 0, .resourceId = 120};
                lwm2m_resource_value_changed(client_handle, &uri);
            }
        }

        if (inactivity_counter >= inactivity_limit && client_handle->state == STATE_READY) {
            //ESP_LOGI(TAG, "Inactivity limit reached, entering deep sleep");
            // esp_wifi_stop();
            //lwm2m_object_t *securityObj = client_data.securityObjP;
            //if (securityObj) {
            //    char uri_buf[128] = {0};
            //    char *uri = security_get_uri(client_handle, securityObj, 1, uri_buf, sizeof(uri_buf));
            //    size_t identity_len = 0; char *identity = security_get_public_id(client_handle, securityObj, 1, &identity_len);
            //    size_t psk_len = 0; char *psk = security_get_secret_key(client_handle, securityObj, 1, &psk_len);
            //    save_security_info_to_rtc(uri, identity, identity_len, psk, psk_len);
            //}
            //const int wakeup_time_sec = 20;
            //ESP_ERROR_CHECK(esp_sleep_enable_timer_wakeup(wakeup_time_sec * 1000000ULL));
            //gettimeofday(&sleep_enter_time, NULL);
            //esp_deep_sleep_start();
            inactivity_counter = 0; /* after wake */
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    
    vTaskDelete(NULL);
}

void lwm2m_client_set_temperature(float temp_celsius)
{
    s_temperature_c = temp_celsius;
}

void lwm2m_client_start(void)
{
    /* Configure DTLS logging before client task starts */
    dtls_set_log_level(DTLS_LOG_DEBUG);
    xTaskCreate(client_task, "client_lwm2m", 8192, NULL, 5, NULL);
}

// Gateway statistics helper functions
void lwm2m_update_gateway_rx_stats(uint64_t bytes) {
    // Note: Object 25 no longer tracks RX/TX statistics - it tracks individual devices
    ESP_LOGD(TAG, "RX stats updated: %llu bytes", (unsigned long long)bytes);
}

void lwm2m_update_gateway_tx_stats(uint64_t bytes) {
    // Note: Object 25 no longer tracks RX/TX statistics - it tracks individual devices 
    ESP_LOGD(TAG, "TX stats updated: %llu bytes", (unsigned long long)bytes);
}

void lwm2m_set_gateway_status(const char* status) {
    // Note: Object 25 no longer has gateway status - it tracks individual devices
    ESP_LOGD(TAG, "Gateway status would be: %s", status ? status : "NULL");
}

void lwm2m_update_connected_devices_count(void) {
    // Object 25 now represents individual devices, not gateway-level counts
    // Each device gets its own instance based on protobuf device data
    if (objArray[5]) {
        uint32_t device_count = device_ring_buffer_get_count();
        ESP_LOGI(TAG, "Total devices in ring buffer: %ld", device_count);
        // TODO: Update/add/remove Object 25 instances when devices change
    }
}

void lwm2m_update_active_sessions(int32_t session_count) {
    // Object 25 no longer tracks gateway-level session counts
    // Each device instance can have its online status updated individually
    ESP_LOGI(TAG, "Active sessions: %ld (Object 25 tracks individual device status)", session_count);
}

void lwm2m_trigger_registration_update(void) {
    if (client_data.lwm2mH && client_data.lwm2mH->state == STATE_READY) {
        ESP_LOGI(TAG, "Triggering registration update due to object changes");
        int res = lwm2m_update_registration(client_data.lwm2mH, 0, true);
        if (res != COAP_NO_ERROR) {
            ESP_LOGW(TAG, "Registration update failed with error: %d", res);
        } else {
            ESP_LOGI(TAG, "Registration update triggered successfully");
        }
    } else {
        ESP_LOGW(TAG, "Cannot trigger registration update - client not ready (state: %d)", 
                 client_data.lwm2mH ? client_data.lwm2mH->state : -1);
    }
}

void lwm2m_update_device_rssi(uint16_t instance_id, int rssi) {
    if (objArray[6]) {  // Connectivity Monitoring object
        uint8_t result = connectivity_moni_update_rssi(objArray[6], instance_id, rssi);
        if (result == COAP_204_CHANGED) {
            ESP_LOGI(TAG, "Updated RSSI for device instance %d to %d dBm", instance_id, rssi);
        } else {
            ESP_LOGW(TAG, "Failed to update RSSI for device instance %d: error %d", instance_id, result);
        }
    } else {
        ESP_LOGW(TAG, "Connectivity Monitoring object not available");
    }
}

void lwm2m_update_device_link_quality(uint16_t instance_id, int link_quality) {
    if (objArray[6]) {  // Connectivity Monitoring object
        uint8_t result = connectivity_moni_update_link_quality(objArray[6], instance_id, link_quality);
        if (result == COAP_204_CHANGED) {
            ESP_LOGI(TAG, "Updated link quality for device instance %d to %d%%", instance_id, link_quality);
        } else {
            ESP_LOGW(TAG, "Failed to update link quality for device instance %d: error %d", instance_id, result);
        }
    } else {
        ESP_LOGW(TAG, "Connectivity Monitoring object not available");
    }
}

// Callback function for gateway object to update device instance_id
static void gateway_device_update_callback(uint32_t device_id, uint16_t new_instance_id)
{
    ESP_LOGI(TAG, "Gateway callback: Updating device %u with new instance_id %u", device_id, new_instance_id);
    
    // Find the corresponding device in ring buffer using device_id (serial)
    lwm2m_LwM2MDevice *device = device_ring_buffer_find_by_serial(device_id);
    if (device != NULL) {
        // Update the device's instance_id in the ring buffer
        uint16_t old_instance_id = device->instance_id;
        device->instance_id = new_instance_id;
        
        // Update connectivity monitoring instance if needed
        if (objArray[6] != NULL && old_instance_id != new_instance_id) {
            // Remove old connectivity monitoring instance if it existed
            if (old_instance_id != 0) {
                connectivity_moni_remove_instance(objArray[6], old_instance_id);
                ESP_LOGI(TAG, "Removed old connectivity monitoring instance %u", old_instance_id);
            }
            
            // Add new connectivity monitoring instance with the correct instance_id
            connectivity_moni_add_instance(objArray[6], new_instance_id, device_id);
            ESP_LOGI(TAG, "Added new connectivity monitoring instance %u for device serial %u", new_instance_id, device_id);
        }
        
        // Save the updated device ring buffer to flash
        esp_err_t save_err = device_ring_buffer_save_to_flash();
        if (save_err != ESP_OK) {
            ESP_LOGW(TAG, "Failed to save device ring buffer: %s", esp_err_to_name(save_err));
        } else {
            ESP_LOGI(TAG, "Device ring buffer updated and saved for device serial %u", device_id);
        }
    } else {
        ESP_LOGW(TAG, "Warning: Device with serial %u not found in ring buffer", device_id);
    }
}
