#include "kii_thing_if_environment_impl.h"

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>

#include "kii_thing_if.h"

#include "wiced.h"
#include "wiced_log.h"

typedef struct _socket_context {
    wiced_tcp_socket_t socket;
    wiced_tls_context_t tls_context;
    wiced_packet_t *packet;
    int packet_offset;
} app_socket_context_t;

kii_socket_code_t socket_connect_cb_impl(
        kii_socket_context_t* socket_context,
        const char* host,
        unsigned int port)
{
    app_socket_context_t *context;
    wiced_ip_address_t addr;
    wiced_result_t rc;

    rc = wiced_hostname_lookup(host, &addr, 10000);
    if(rc != WICED_SUCCESS) {
        return KII_SOCKETC_FAIL;
    }

    context = malloc(sizeof(app_socket_context_t));

    rc = wiced_tcp_create_socket(&(context->socket), WICED_STA_INTERFACE);
    if (rc != WICED_SUCCESS) {
        free(context);
        return KII_SOCKETC_FAIL;
    }
    wiced_tls_init_context(&(context->tls_context), NULL, NULL);
    wiced_tcp_enable_tls(&(context->socket), &(context->tls_context));
    context->packet = NULL;
    context->packet_offset = 0;

    rc = wiced_tcp_connect(&(context->socket), &addr, port, 10000);
    if (rc != WICED_SUCCESS) {
        wiced_tcp_disconnect(&(context->socket));
        wiced_tcp_delete_socket(&(context->socket));
        free(context);
        return KII_SOCKETC_FAIL;
    }

    socket_context->app_context = context;
    return KII_SOCKETC_OK;
}

kii_socket_code_t socket_send_cb_impl(
        kii_socket_context_t* socket_context,
        const char* buffer,
        size_t length)
{
    wiced_result_t ret;
    app_socket_context_t *context = (app_socket_context_t*)socket_context->app_context;

    ret = wiced_tcp_send_buffer(&(context->socket), buffer, length);
    if (ret == WICED_SUCCESS) {
        return KII_SOCKETC_OK;
    } else {
        return KII_SOCKETC_FAIL;
    }
}

kii_socket_code_t socket_recv_cb_impl(
        kii_socket_context_t* socket_context,
        char* buffer,
        size_t length_to_read,
        size_t* out_actual_length)
{
    wiced_result_t ret = WICED_SUCCESS;
    app_socket_context_t *context = (app_socket_context_t*)socket_context->app_context;
    wiced_packet_t *packet = context->packet;
    int offset = context->packet_offset;

    if (packet == NULL) {
        ret = wiced_tcp_receive(&(context->socket), &packet, 10000);
        offset = 0;
    }

    if (ret == WICED_SUCCESS) {
        uint16_t        total;
        uint16_t        length;
        uint8_t*        data;

        wiced_packet_get_data(packet, offset, &data, &length, &total);
        *out_actual_length = MIN(length, length_to_read);
        memcpy(buffer, data, *out_actual_length);
        buffer[*out_actual_length] = 0;
        offset += *out_actual_length;
        if (*out_actual_length < total) {
            context->packet = packet;
            context->packet_offset = offset;
        } else {
            wiced_packet_delete(packet);
            context->packet = NULL;
            context->packet_offset = 0;
        }
        return KII_SOCKETC_OK;
    } else {
        return KII_SOCKETC_FAIL;
    }
}

kii_socket_code_t socket_close_cb_impl(kii_socket_context_t* socket_context)
{
    app_socket_context_t *context = (app_socket_context_t*)socket_context->app_context;

    if (context->packet != NULL) {
        wiced_packet_delete(context->packet);
    }
    wiced_tcp_disconnect(&(context->socket));
    wiced_tcp_delete_socket(&(context->socket));
    free(context);
    socket_context->app_context = NULL;
    return KII_SOCKETC_OK;
}

kii_socket_code_t mqtt_connect_cb_impl(
        kii_socket_context_t* socket_context,
        const char* host,
        unsigned int port)
{
    app_socket_context_t *context;
    wiced_ip_address_t addr;
    wiced_result_t rc;

    rc = wiced_hostname_lookup(host, &addr, 10000);
    if(rc != WICED_SUCCESS) {
        return KII_SOCKETC_FAIL;
    }

    context = malloc(sizeof(app_socket_context_t));

    rc = wiced_tcp_create_socket(&(context->socket), WICED_STA_INTERFACE);
    if (rc != WICED_SUCCESS) {
        free(context);
        return KII_SOCKETC_FAIL;
    }
    wiced_tls_init_context(&(context->tls_context), NULL, NULL);
    wiced_tcp_enable_tls(&(context->socket), &(context->tls_context));
    context->packet = NULL;
    context->packet_offset = 0;

#ifdef KII_PUSH_KEEP_ALIVE_INTERVAL_SECONDS
    wiced_tcp_enable_keepalive(&(context->socket), 0, 0, KII_PUSH_KEEP_ALIVE_INTERVAL_SECONDS * 2);
#endif

    // TODO: We need to use port_ssl(now, 8883), but port is same as port_tcp.
    rc = wiced_tcp_connect(&(context->socket), &addr, 8883, 10000);
    if (rc != WICED_SUCCESS) {
        wiced_tcp_disconnect(&(context->socket));
        wiced_tcp_delete_socket(&(context->socket));
        free(context);
        return KII_SOCKETC_FAIL;
    }

    socket_context->app_context = context;
    socket_context->socket = 1;
    return KII_SOCKETC_OK;
}

kii_socket_code_t mqtt_send_cb_impl(
        kii_socket_context_t* socket_context,
        const char* buffer,
        size_t length)
{
    wiced_result_t ret;
    app_socket_context_t *context = (app_socket_context_t*)socket_context->app_context;

    ret = wiced_tcp_send_buffer(&(context->socket), buffer, length);
    if (ret == WICED_SUCCESS) {
        return KII_SOCKETC_OK;
    } else {
        return KII_SOCKETC_FAIL;
    }
}

kii_socket_code_t mqtt_recv_cb_impl(
        kii_socket_context_t* socket_context,
        char* buffer,
        size_t length_to_read,
        size_t* out_actual_length)
{
    wiced_result_t ret = WICED_SUCCESS;
    app_socket_context_t *context = (app_socket_context_t*)socket_context->app_context;
    wiced_packet_t *packet = context->packet;
    int offset = context->packet_offset;

    if (packet == NULL) {
        ret = wiced_tcp_receive(&(context->socket), &packet, 10000);
        offset = 0;
    }

    if (ret == WICED_SUCCESS) {
        uint16_t        total;
        uint16_t        length;
        uint8_t*        data;

        wiced_packet_get_data(packet, offset, &data, &length, &total);
        *out_actual_length = MIN(length, length_to_read);
        memcpy(buffer, data, *out_actual_length);
        buffer[*out_actual_length] = 0;
        offset += *out_actual_length;
        if (*out_actual_length < total) {
            context->packet = packet;
            context->packet_offset = offset;
        } else {
            wiced_packet_delete(packet);
            context->packet = NULL;
            context->packet_offset = 0;
        }
        return KII_SOCKETC_OK;
    } else {
        return KII_SOCKETC_FAIL;
    }
}

kii_socket_code_t mqtt_close_cb_impl(kii_socket_context_t* socket_context)
{
    app_socket_context_t *context = (app_socket_context_t*)socket_context->app_context;

    if (context->packet != NULL) {
        wiced_packet_delete(context->packet);
    }
    wiced_tcp_disconnect(&(context->socket));
    wiced_tcp_delete_socket(&(context->socket));
    free(context);
    socket_context->app_context = NULL;
    socket_context->socket = 0;
    return KII_SOCKETC_OK;
}

typedef struct {
    wiced_thread_t thread;
    KII_TASK_ENTRY entry;
    void* param;
} task_thread_arg_t;

void task_thread_function( wiced_thread_arg_t arg ) {
    task_thread_arg_t* task_arg = (task_thread_arg_t*)arg;

    task_arg->entry(task_arg->param);
}

static task_thread_arg_t status_update_thread_arg;
static task_thread_arg_t recv_msg_thread_arg;
static task_thread_arg_t ping_req_thread_arg;

kii_task_code_t task_create_cb_impl(
        const char* name,
        KII_TASK_ENTRY entry,
        void* param)
{
    unsigned int stk_size = WICED_DEFAULT_APPLICATION_STACK_SIZE;
    unsigned int priority = RTOS_DEFAULT_THREAD_PRIORITY;
    task_thread_arg_t *task_arg = NULL;

    if (strcmp(name, KII_THING_IF_TASK_NAME_STATUS_UPDATE) == 0) {
        task_arg = &status_update_thread_arg;
    } else if (strcmp(name, KII_TASK_NAME_RECV_MSG) == 0) {
        task_arg = &recv_msg_thread_arg;
#ifdef KII_PUSH_KEEP_ALIVE_INTERVAL_SECONDS
    } else if (strcmp(name, KII_TASK_NAME_PING_REQ) == 0) {
        priority = RTOS_LOWER_PRIORTIY_THAN(RTOS_DEFAULT_THREAD_PRIORITY);
        task_arg = &ping_req_thread_arg;
#endif
    } else {
        wiced_log_printf("unknown task name: %s\n", name);
        return KII_TASKC_FAIL;
    }

    task_arg->entry = entry;
    task_arg->param = param;
    if (wiced_rtos_create_thread(&(task_arg->thread), priority, name, task_thread_function, stk_size, task_arg) != WICED_SUCCESS) {
        wiced_log_printf("create thread [%s] failed.\n", name);
        return KII_TASKC_FAIL;
    } else {
        return KII_TASKC_OK;
    }
}

void delay_ms_cb_impl(unsigned int msec)
{
    wiced_rtos_delay_milliseconds(msec);
}

void logger_cb_impl(const char* format, ...)
{
    va_list list;
    va_start(list, format);
    wiced_log_vprintf(format, list);
    va_end(list);
}

