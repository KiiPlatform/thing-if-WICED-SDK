#include "wiced.h"
#include "kii_thing_if.h"

#include <command_console_commands.h>

/* Go to https:/developer.kii.com and create app for you! */
const char EX_APP_ID[] = "b8d819c8";
const char EX_APP_KEY[] = "bff3bfdc1e3fcf6818919144330a0770";
/* JP: "api-jp.kii.com" */
/* US: "api.kii.com" */
/* SG: "api-sg.kii.com" */
/* CN: "api-cn3.kii.com" */
const char EX_APP_SITE[] = "api-jp.kii.com";

#define EX_COMMAND_HANDLER_BUFF_SIZE 4096
#define EX_STATE_UPDATER_BUFF_SIZE 4096
#define EX_MQTT_BUFF_SIZE 2048
#define EX_STATE_UPDATE_PERIOD 60

typedef struct prv_smartlight_t {
    kii_json_boolean_t power;
    int brightness;
    int color[3];
    int color_temperature;
} prv_smartlight_t;

static prv_smartlight_t m_smartlight;
static wiced_mutex_t m_mutex;

static kii_json_parse_result_t prv_json_read_object(
        const char* json,
        size_t json_len,
        kii_json_field_t* fields,
        char error[EMESSAGE_SIZE + 1])
{
    kii_json_t kii_json;
    kii_json_resource_t* resource_pointer = NULL;

    memset(&kii_json, 0, sizeof(kii_json));
    kii_json.resource = resource_pointer;
    kii_json.error_string_buff = error;
    kii_json.error_string_length = EMESSAGE_SIZE + 1;

    return kii_json_read_object(&kii_json, json, json_len, fields);
}

static kii_bool_t prv_get_smartlight_info(prv_smartlight_t* smartlight)
{
	if (wiced_rtos_lock_mutex(&m_mutex) != WICED_SUCCESS) {
		return KII_FALSE;
    }
    smartlight->power = m_smartlight.power;
    smartlight->brightness = m_smartlight.brightness;
    smartlight->color[0] = m_smartlight.color[0];
    smartlight->color[1] = m_smartlight.color[1];
    smartlight->color[2] = m_smartlight.color[2];
    smartlight->color_temperature = m_smartlight.color_temperature;
    if (wiced_rtos_unlock_mutex(&m_mutex) != WICED_SUCCESS) {
        return KII_FALSE;
    }
    return KII_TRUE;
}

static kii_bool_t prv_set_smartlight_info(const prv_smartlight_t* smartlight)
{
	if (wiced_rtos_lock_mutex(&m_mutex) != WICED_SUCCESS) {
		return KII_FALSE;
	}
    m_smartlight.power = smartlight->power;
    m_smartlight.brightness = smartlight->brightness;
    m_smartlight.color[0] = smartlight->color[0];
    m_smartlight.color[1] = smartlight->color[1];
    m_smartlight.color[2] = smartlight->color[2];
    m_smartlight.color_temperature = smartlight->color_temperature;
    if (wiced_rtos_unlock_mutex(&m_mutex) != WICED_SUCCESS) {
        return KII_FALSE;
    }
    return KII_TRUE;
}

static kii_bool_t action_handler(
        const char* schema,
        int schema_version,
        const char* action_name,
        const char* action_params,
        char error[EMESSAGE_SIZE + 1])
{
    prv_smartlight_t smartlight;

    printf("schema=%s, schema_version=%d, action name=%s, action params=%s\n",
            schema, schema_version, action_name, action_params);

    if (strcmp(schema, "SmartLight-Demo") != 0 || schema_version != 1) {
        printf("invalid schema: %s %d\n", schema, schema_version);
        snprintf(error, EMESSAGE_SIZE + 1, "invalid schema: %s %d",
                schema, schema_version);
        return KII_FALSE;
    }

    memset(&smartlight, 0x00, sizeof(smartlight));
    if (prv_get_smartlight_info(&smartlight) == KII_FALSE) {
        printf("fail to lock.\n");
        strcpy(error, "fail to lock.");
        return KII_FALSE;
    }
    if (strcmp(action_name, "turnPower") == 0) {
        kii_json_field_t fields[2];

        memset(fields, 0x00, sizeof(fields));
        fields[0].path = "/power";
        fields[0].type = KII_JSON_FIELD_TYPE_BOOLEAN;
        fields[1].path = NULL;
        if(prv_json_read_object(action_params, strlen(action_params),
                        fields, error) !=  KII_JSON_PARSE_SUCCESS) {
            printf("invalid turnPower json\n");
            return KII_FALSE;
        }
        smartlight.power = fields[0].field_copy.boolean_value;
    } else if (strcmp(action_name, "setBrightness") == 0) {
        kii_json_field_t fields[2];

        memset(fields, 0x00, sizeof(fields));
        fields[0].path = "/brightness";
        fields[0].type = KII_JSON_FIELD_TYPE_INTEGER;
        fields[1].path = NULL;
        if(prv_json_read_object(action_params, strlen(action_params),
                        fields, error) !=  KII_JSON_PARSE_SUCCESS) {
            printf("invalid brightness json\n");
            return KII_FALSE;
        }
        smartlight.brightness = fields[0].field_copy.int_value;
    } else if (strcmp(action_name, "setColor") == 0) {
        kii_json_field_t fields[4];

        memset(fields, 0x00, sizeof(fields));
        fields[0].path = "/color/[0]";
        fields[0].type = KII_JSON_FIELD_TYPE_INTEGER;
        fields[1].path = "/color/[1]";
        fields[1].type = KII_JSON_FIELD_TYPE_INTEGER;
        fields[2].path = "/color/[2]";
        fields[2].type = KII_JSON_FIELD_TYPE_INTEGER;
        fields[3].path = NULL;
        if(prv_json_read_object(action_params, strlen(action_params),
                         fields, error) !=  KII_JSON_PARSE_SUCCESS) {
            printf("invalid color json\n");
            return KII_FALSE;
        }
        smartlight.color[0] = fields[0].field_copy.int_value;
        smartlight.color[1] = fields[1].field_copy.int_value;
        smartlight.color[2] = fields[2].field_copy.int_value;
    } else if (strcmp(action_name, "setColorTemperature") == 0) {
        kii_json_field_t fields[2];

        memset(fields, 0x00, sizeof(fields));
        fields[0].path = "/colorTemperature";
        fields[0].type = KII_JSON_FIELD_TYPE_INTEGER;
        fields[1].path = NULL;
        if(prv_json_read_object(action_params, strlen(action_params),
                        fields, error) !=  KII_JSON_PARSE_SUCCESS) {
            printf("invalid colorTemperature json\n");
            return KII_FALSE;
        }
        smartlight.color_temperature = fields[0].field_copy.int_value;
    } else {
        printf("invalid action: %s\n", action_name);
        return KII_FALSE;
    }

    if (prv_set_smartlight_info(&smartlight) == KII_FALSE) {
        printf("fail to unlock.\n");
        return KII_FALSE;
    }
    return KII_TRUE;
}

static kii_bool_t state_handler(
        kii_t* kii,
        KII_THING_IF_WRITER writer)
{
    char buf[256];
    prv_smartlight_t smartlight;
    memset(&smartlight, 0x00, sizeof(smartlight));
    if (prv_get_smartlight_info(&smartlight) == KII_FALSE) {
        printf("fail to lock.\n");
        return KII_FALSE;
    }
    if ((*writer)(kii, "{\"power\":") == KII_FALSE) {
        return KII_FALSE;
    }
    if ((*writer)(kii, smartlight.power == KII_JSON_TRUE
                    ? "true," : "false,") == KII_FALSE) {
        return KII_FALSE;
    }
    if ((*writer)(kii, "\"brightness\":") == KII_FALSE) {
        return KII_FALSE;
    }

    sprintf(buf, "%d,", smartlight.brightness);
    if ((*writer)(kii, buf) == KII_FALSE) {
        return KII_FALSE;
    }

    if ((*writer)(kii, "\"color\":") == KII_FALSE) {
        return KII_FALSE;
    }
    sprintf(buf, "[%d,%d,%d],", smartlight.color[0],
            smartlight.color[1], smartlight.color[2]);
    if ((*writer)(kii, buf) == KII_FALSE) {
        return KII_FALSE;
    }

    if ((*writer)(kii, "\"colorTemperature\":") == KII_FALSE) {
        return KII_FALSE;
    }
    sprintf(buf, "%d}", smartlight.color_temperature);
    if ((*writer)(kii, buf) == KII_FALSE) {
        return KII_FALSE;
    }
    return KII_TRUE;
}

static kii_bool_t custom_push_handler(
        kii_t *kii,
        const char* message,
        size_t message_length)
{
    kii_bool_t ret = KII_TRUE;
    printf("custom_push_handler:\n%s\n", message);
    if (strncmp(message, "{\"schema\"", 9) == 0) {
        ret = KII_FALSE;
    }
    // check no error in parsing topic.
    if (strncmp(message, "{\"Item\":\"CheckNoError\"", 22) == 0) {
        ret = KII_FALSE;
    }
    return ret;
}

static kii_thing_if_command_handler_resource_t command_handler_resource;
static kii_thing_if_state_updater_resource_t state_updater_resource;
static char command_handler_buff[EX_COMMAND_HANDLER_BUFF_SIZE];
static char state_updater_buff[EX_STATE_UPDATER_BUFF_SIZE];
static char mqtt_buff[EX_MQTT_BUFF_SIZE];
static kii_thing_if_t kii_thing_if;

static int onboard_command ( int argc, char *argv[] ) {
    kii_bool_t result;

    char *vendorThingID = NULL;
    char *thingID = NULL;
    char *password = NULL;

    for (int i = 1; i < argc; ++i) {
        if (strncmp(argv[i], "vendor-thing-id=", 16) == 0) {
            vendorThingID = argv[i] + 16;
        } else if (strncmp(argv[i], "thing-id=", 9) == 0) {
            thingID = argv[i] + 9;
        } else if (strncmp(argv[i], "password=", 9) == 0) {
            password = argv[i] + 9;
        }
    }
    if (vendorThingID == NULL && thingID == NULL) {
        printf("neither vendor-thing-id and thing-id are specified.\n");
        return ERR_CMD_OK;
    }
    if (password == NULL) {
        printf("password is not specified.\n");
        return ERR_CMD_OK;
    }
    if (vendorThingID != NULL && thingID != NULL) {
        printf("both vendor-thing-id and thing-id is specified.  either of one should be specified.\n");
        return ERR_CMD_OK;
    }
    if (vendorThingID != NULL) {
        result = onboard_with_vendor_thing_id(&kii_thing_if, vendorThingID,
                password, NULL, NULL);
    } else {
        result = onboard_with_thing_id(&kii_thing_if, thingID,
                password);
    }
    if (result == KII_FALSE) {
        printf("failed to onboard.\n");
    } else {
        printf("onboard succeed.\n");
    }
    return ERR_CMD_OK;
}

#define MAX_LINE_LENGTH  (256)
#define MAX_HISTORY_LENGTH (20)

static char line_buffer[MAX_LINE_LENGTH];
static char history_buffer_storage[MAX_LINE_LENGTH * MAX_HISTORY_LENGTH];

static const command_t commands[] =
{
    //ALL_COMMANDS
    {"onboard", onboard_command, 2, NULL, NULL, "[vendor-thing-id/thing-id]=* passwod=*", ""},
    CMD_TABLE_END
};

/******************************************************
 *               Function Definitions
 ******************************************************/
void application_start( void )
{
    wiced_result_t ret = WICED_SUCCESS;

    command_handler_resource.buffer = command_handler_buff;
    command_handler_resource.buffer_size =
        sizeof(command_handler_buff) / sizeof(command_handler_buff[0]);
    command_handler_resource.mqtt_buffer = mqtt_buff;
    command_handler_resource.mqtt_buffer_size =
        sizeof(mqtt_buff) / sizeof(mqtt_buff[0]);
    command_handler_resource.action_handler = action_handler;
    command_handler_resource.state_handler = state_handler;
    command_handler_resource.custom_push_handler = custom_push_handler;

    state_updater_resource.buffer = state_updater_buff;
    state_updater_resource.buffer_size =
        sizeof(state_updater_buff) / sizeof(state_updater_buff[0]);
    state_updater_resource.period = EX_STATE_UPDATE_PERIOD;
    state_updater_resource.state_handler = state_handler;

    wiced_rtos_init_mutex(&m_mutex);

    ret = wiced_init();
    if ( ret != WICED_SUCCESS )
    {
        WPRINT_APP_INFO( ( "wiced_init failed.\n\n" ) );
        return;
    }

    /* Disable roaming to other access points */
    wiced_wifi_set_roam_trigger( -99 ); /* -99dBm ie. extremely low signal level */

    /* Bringup the network interface */
    ret = wiced_network_up( WICED_STA_INTERFACE, WICED_USE_EXTERNAL_DHCP_SERVER, NULL );
    if ( ret != WICED_SUCCESS )
    {
        WPRINT_APP_INFO( ( "\nNot able to join the requested AP\n\n" ) );
        return;
    }

    if (init_kii_thing_if(&kii_thing_if, EX_APP_ID, EX_APP_KEY, EX_APP_SITE,
            &command_handler_resource, &state_updater_resource, NULL) == KII_FALSE) {
        WPRINT_APP_ERROR( ( "kii init failed.\n" ) );
    } else {
        WPRINT_APP_INFO( ( "kii init succeed.\n" ) );
    }

    /* Run the main application function */
    command_console_init( STDIO_UART, MAX_LINE_LENGTH, line_buffer, MAX_HISTORY_LENGTH, history_buffer_storage, " " );
    console_add_cmd_table( commands );
}
