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
#include "flash.h"

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
size_t public_key_len = 0;
size_t private_key_len = 0;
char pinCode[32] = {0};
char psk_key[64] = {0};
char server[128] = {0};

static uint8_t rx_buffer[2048];
static RTC_DATA_ATTR struct timeval sleep_enter_time;

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

    lwm2m_object_t *objArray[5] = {0};
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
    if (lwm2m_configure(client_handle, serialNumber, NULL, NULL, 5, objArray) != 0) {
        ESP_LOGE(TAG, "lwm2m_configure failed");
        vTaskDelete(NULL); return;
    }
    if (wakeup_reason == ESP_SLEEP_WAKEUP_TIMER) {
        ESP_LOGI(TAG, "Restored LwM2M client state to STATE_READY");
    }
    int inactivity_counter = 0;
    const int inactivity_limit = 40; /* seconds (loop delay 10ms, counter increments each loop when READY & no data) */
    while (1) {
        time_t tv = lwm2m_gettime();
        lwm2m_step(client_handle, &tv);

        struct sockaddr_storage source_addr; socklen_t socklen = sizeof(source_addr);
        int len = recvfrom(client_data.sock, rx_buffer, sizeof(rx_buffer), 0, (struct sockaddr *)&source_addr, &socklen);
        if (len > 0) {
            connection_handle_packet(client_data.connList, rx_buffer, len);
            inactivity_counter = 0;
        } else if (client_handle->state == STATE_READY) {
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
 //   dtls_set_log_level(DTLS_LOG_DEBUG);
    xTaskCreate(client_task, "client_lwm2m", 8192, NULL, 5, NULL);
}
