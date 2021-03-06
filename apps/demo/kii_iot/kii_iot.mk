#

#==============================================================================
# Global defines
#==============================================================================
GLOBAL_DEFINES += STDIO_BUFFER_SIZE=128

NAME := App_thing_if_demo

$(NAME)_DEFINES += KII_PUSH_KEEP_ALIVE_INTERVAL_SECONDS=60 \
                   KII_JSON_FIXED_TOKEN_NUM=64

$(NAME)_SOURCES := ./thing_if_demo.c \
                   ./kii_thing_if_environment_impl.c \
                   ./thing-if-ThingSDK/kii_thing_if.c \
                   ./thing-if-ThingSDK/kii/kii/kii_call.c \
                   ./thing-if-ThingSDK/kii/kii/kii_json_utils.c \
                   ./thing-if-ThingSDK/kii/kii/kii_mqtt.c \
                   ./thing-if-ThingSDK/kii/kii/kii_object.c \
                   ./thing-if-ThingSDK/kii/kii/kii_push.c \
                   ./thing-if-ThingSDK/kii/kii/kii_server_code.c \
                   ./thing-if-ThingSDK/kii/kii/kii_thing.c \
                   ./thing-if-ThingSDK/kii/kii-core/kii_core.c \
                   ./thing-if-ThingSDK/kii/kii-core/kii_libc_wrapper.c \
                   ./thing-if-ThingSDK/kii/lib/jsmn/jsmn.c \
                   ./thing-if-ThingSDK/kii/kii_json/src/kii_json.c

$(NAME)_INCLUDES := ./thing-if-ThingSDK/ \
                    ./thing-if-ThingSDK/kii/kii \
                    ./thing-if-ThingSDK/kii/kii-core \
                    ./thing-if-ThingSDK/kii/lib/jsmn \
                    ./thing-if-ThingSDK/kii/kii_json/include

$(NAME)_COMPONENTS := protocols/MQTT \
                      utilities/wiced_log \
                      utilities/command_console \
                      utilities/command_console/wps \
                      utilities/command_console/wifi \
                      utilities/command_console/thread \
                      utilities/command_console/ping \
                      utilities/command_console/platform \
                      utilities/command_console/tracex \
                      utilities/command_console/mallinfo

WIFI_CONFIG_DCT_H := wifi_config_dct.h

VALID_PLATFORMS := BCM94343W_AVN
