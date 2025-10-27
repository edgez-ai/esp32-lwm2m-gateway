set(COMPONENT_SRCS 
    "main.c" 
    "crypto_test.c" 
    "lwm2m_client.c" 
    "flash.c" 
    "ble.c" 
    "device.c"
)

if(CONFIG_ENABLE_LORA)
    list(APPEND COMPONENT_SRCS "lora.cpp")
endif()

idf_component_register(SRCS ${COMPONENT_SRCS}
                    INCLUDE_DIRS "." "../components/wakaama/examples/client" )
