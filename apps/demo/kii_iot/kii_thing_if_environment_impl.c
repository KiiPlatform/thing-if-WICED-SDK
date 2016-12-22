#include "kii_thing_if_environment_impl.h"

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>

#include "kii_thing_if.h"

#include "wiced.h"

kii_socket_code_t socket_connect_cb_impl(
        kii_socket_context_t* socket_context,
        const char* host,
        unsigned int port)
{
    wiced_tcp_socket_t sock;
    wiced_ip_address_t addr;
    wiced_result_t rc;

    rc = wiced_hostname_lookup(host, &addr, 10000);
    if(rc != WICED_SUCCESS) {
    	return KII_SOCKETC_FAIL;
    }

    rc = wiced_tcp_create_socket(&sock, WICED_STA_INTERFACE);
    if (rc != WICED_SUCCESS) {
        return KII_SOCKETC_FAIL;
    }
    rc = wiced_tcp_connect(&sock, &addr, port, 10000);
    if (rc != WICED_SUCCESS) {
        wiced_tcp_disconnect(&sock);
        wiced_tcp_delete_socket(&sock);
        return KII_SOCKETC_FAIL;
    }
    socket_context->app_context = malloc(sizeof(wiced_tcp_socket_t));
    memcpy(socket_context->app_context, &sock, sizeof(wiced_tcp_socket_t));
    return KII_SOCKETC_OK;
}

kii_socket_code_t socket_send_cb_impl(
        kii_socket_context_t* socket_context,
        const char* buffer,
        size_t length)
{
    wiced_result_t ret;
    wiced_tcp_socket_t *sock = socket_context->app_context;

    WPRINT_APP_INFO( ("%.*s\r\n", length, buffer));
    ret = wiced_tcp_send_buffer(sock, buffer, length);
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
    wiced_result_t ret;
    wiced_tcp_socket_t *sock = socket_context->app_context;
    wiced_packet_t *packet = NULL;
    uint16_t        total;
    uint16_t        length;
    uint8_t*        data;

    ret = wiced_tcp_receive(sock, packet, 0);
    if (ret == WICED_SUCCESS) {
    	wiced_packet_get_data(packet, 0, &data, &length, &total);
    	*out_actual_length = MIN(length, length_to_read);
    	memcpy(buffer, data, *out_actual_length);
    	buffer[*out_actual_length] = 0;
    	WPRINT_APP_INFO( ("%s", buffer) );
        wiced_packet_delete(packet);
        return KII_SOCKETC_OK;
    } else {
        return KII_SOCKETC_FAIL;
    }
}

kii_socket_code_t socket_close_cb_impl(kii_socket_context_t* socket_context)
{
    wiced_tcp_socket_t *sock = socket_context->app_context;

    wiced_tcp_disconnect(sock);
    wiced_tcp_delete_socket(sock);
    free(sock);
    socket_context->app_context = NULL;
    return KII_SOCKETC_OK;
}

kii_socket_code_t mqtt_connect_cb_impl(
        kii_socket_context_t* socket_context,
        const char* host,
        unsigned int port)
{
    wiced_tcp_socket_t sock;
    wiced_ip_address_t addr;
    wiced_result_t rc;

    rc = wiced_hostname_lookup(host, &addr, 10000);
    if(rc != WICED_SUCCESS) {
    	return KII_SOCKETC_FAIL;
    }

    rc = wiced_tcp_create_socket(&sock, WICED_STA_INTERFACE);
    if (rc != WICED_SUCCESS) {
        return KII_SOCKETC_FAIL;
    }

#ifdef KII_PUSH_KEEP_ALIVE_INTERVAL_SECONDS
    wiced_tcp_enable_keepalive(&sock, 0, 0, KII_PUSH_KEEP_ALIVE_INTERVAL_SECONDS * 2);
#endif

	rc = wiced_tcp_connect(&sock, &addr, port, 10000);
    if (rc != WICED_SUCCESS) {
        wiced_tcp_disconnect(&sock);
        wiced_tcp_delete_socket(&sock);
        return KII_SOCKETC_FAIL;
    }
    socket_context->app_context = malloc(sizeof(wiced_tcp_socket_t));
    memcpy(socket_context->app_context, &sock, sizeof(wiced_tcp_socket_t));
    return KII_SOCKETC_OK;
}

kii_socket_code_t mqtt_send_cb_impl(
        kii_socket_context_t* socket_context,
        const char* buffer,
        size_t length)
{
    wiced_result_t ret;
    wiced_tcp_socket_t *sock = socket_context->app_context;

    ret = wiced_tcp_send_buffer(sock, buffer, length);
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
    wiced_result_t ret;
    wiced_tcp_socket_t *sock = socket_context->app_context;
    wiced_packet_t *packet = NULL;
    uint16_t        total;
    uint16_t        length;
    uint8_t*        data;

    ret = wiced_tcp_receive(sock, packet, 0);
    if (ret == WICED_SUCCESS) {
    	wiced_packet_get_data(packet, 0, &data, &length, &total);
    	*out_actual_length = MIN(length, length_to_read);
    	memcpy(buffer, data, *out_actual_length);
    	buffer[*out_actual_length] = 0;
    	WPRINT_APP_INFO( ("%s", buffer) );
        wiced_packet_delete(packet);
        return KII_SOCKETC_OK;
    } else {
        return KII_SOCKETC_FAIL;
    }
}

kii_socket_code_t mqtt_close_cb_impl(kii_socket_context_t* socket_context)
{
    wiced_tcp_socket_t *sock = socket_context->app_context;

    wiced_tcp_disconnect(sock);
    wiced_tcp_delete_socket(sock);
    free(sock);
    socket_context->app_context = NULL;
    return KII_SOCKETC_OK;
}

kii_task_code_t task_create_cb_impl(
        const char* name,
        KII_TASK_ENTRY entry,
        void* param)
{
    unsigned int stk_size = 0;
    unsigned int priority = 0;

    if (strcmp(name, KII_THING_IF_TASK_NAME_STATUS_UPDATE) == 0) {
        stk_size = 2048;
        priority = 1;
    } else if (strcmp(name, KII_TASK_NAME_RECV_MSG) == 0) {
        stk_size = 4096;
#ifdef KII_PUSH_KEEP_ALIVE_INTERVAL_SECONDS
    } else if (strcmp(name, KII_TASK_NAME_PING_REQ) == 0) {
        stk_size = 1024;
#endif
    }

    wiced_thread_t thread;
    if (wiced_rtos_create_thread(&thread, priority, name, entry, stk_size, param) != WICED_SUCCESS) {
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
    vprintf(format, list);
    va_end(list);
}

