/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2016 Yury Luneff <yury@indigosystem.ru>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include "protocol.h"

#include <glib.h>

SR_PRIV struct sr_dev_driver angel_knock_driver_info;
SR_PRIV gboolean indigo_angel_has_data(const uint8_t *buf);

SR_PRIV gboolean indigo_angel_has_data(const uint8_t *buf)
{
//    if (buf[0] == 0x55 && buf[1] == 0x55 && buf[3] <= 32
//            && appa_55ii_checksum(buf))
    return TRUE;
}

static const uint32_t scanopts[] = {
    SR_CONF_CONN,
    SR_CONF_SERIALCOMM,
};

static const uint32_t drvopts[] = {
    SR_CONF_OSCILLOSCOPE,
};

static const uint32_t devopts[] = {
    SR_CONF_CONTINUOUS
};

#define MYLOG(...) fprintf(stderr, __VA_ARGS__)

//static GSList *scan(struct sr_dev_driver *di, GSList *options)
GSList *my_indigo_scan(struct sr_dev_driver *di, GSList *options)
{
    struct dev_context *devc;
    struct sr_serial_dev_inst *serial;
    struct sr_dev_inst *sdi;
    struct sr_config *src;
    GSList *devices, *l;
    const char *conn, *serialcomm;
    uint8_t buf[50];
    size_t len;

    printf("hello, angel knock! scan pending\n");

    struct sp_port **ports;

    sp_list_ports(&ports);

    for (int i = 0; ports[i]; i++)
        printf("Found port: '%s'.\n", sp_get_port_name(ports[i]));

    sp_free_port_list(ports);

    len = sizeof(buf);
    devices = NULL;
    conn = serialcomm = NULL;
    for (l = options; l; l = l->next) {
        src = l->data;
        switch (src->key) {
        case SR_CONF_CONN:
            conn = g_variant_get_string(src->data, NULL);
            break;
        case SR_CONF_SERIALCOMM:
            serialcomm = g_variant_get_string(src->data, NULL);
            break;
        }
    }
    printf("before!\n");
    printf("conn = %s\n", conn);
        //return NULL;
    if (!serialcomm)
        serialcomm = "115200/8n2";

    serial = sr_serial_dev_inst_new(conn, serialcomm);

    if (serial_open(serial, SERIAL_RDONLY) != SR_OK) {
        MYLOG("aborting scan\n");
        return NULL;
    }

    sr_info("Probing serial port %s.", conn);

    serial_flush(serial);

    /* Let's get a bit of data and see if we can find a packet. */
    if (serial_stream_detect(serial, buf, &len, 2,
            indigo_angel_has_data, 5000, 115200) != SR_OK)
        goto scan_cleanup;

    sr_info("Found device on port %s.", conn);

    sdi = g_malloc0(sizeof(struct sr_dev_inst));
    sdi->status = SR_ST_INACTIVE;
    sdi->vendor = g_strdup("INDIGO");
    sdi->model = g_strdup("ANGEL");
    devc = g_malloc0(sizeof(struct dev_context));
    sdi->inst_type = SR_INST_SERIAL;
    sdi->conn = serial;
    sdi->priv = devc;

    sr_channel_new(sdi, 0, SR_CHANNEL_ANALOG, TRUE, "HEART");

    devices = g_slist_append(devices, sdi);

scan_cleanup:
    serial_close(serial);

    return std_scan_complete(di, devices);
}

static int config_get(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	int ret;

	(void)sdi;
	(void)data;
	(void)cg;

    MYLOG("config_get!\n");

	ret = SR_OK;
	switch (key) {
	/* TODO */
	default:
		return SR_ERR_NA;
	}

	return ret;
}

static int config_set(uint32_t key, GVariant *data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	int ret;

	(void)data;
	(void)cg;

    MYLOG("config_set!\n");

	if (sdi->status != SR_ST_ACTIVE)
		return SR_ERR_DEV_CLOSED;

	ret = SR_OK;
	switch (key) {
	/* TODO */
	default:
		ret = SR_ERR_NA;
	    //ret = SR_OK;
	}

	return ret;
}

static int config_list(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	int ret;

	(void)sdi;
	(void)data;
	(void)cg;

    MYLOG("config_list! %d\n", key);

	ret = SR_OK;


	switch (key) {
	case SR_CONF_SCAN_OPTIONS:
	    *data = g_variant_new_fixed_array(G_VARIANT_TYPE_UINT32,
	            scanopts, ARRAY_SIZE(scanopts), sizeof(uint32_t));
	    break;
	case SR_CONF_DEVICE_OPTIONS:
	        if (!sdi)
	            *data = g_variant_new_fixed_array(G_VARIANT_TYPE_UINT32,
	                    drvopts, ARRAY_SIZE(drvopts), sizeof(uint32_t));
	        else
	            *data = g_variant_new_fixed_array(G_VARIANT_TYPE_UINT32,
	                    devopts, ARRAY_SIZE(devopts), sizeof(uint32_t));
	        break;
	default:
	    ret = SR_ERR_NA;
	}

	return ret;
}

static int dev_acquisition_start(const struct sr_dev_inst *sdi)
{
    MYLOG("dev_acquisition_start!\n");
    struct sr_serial_dev_inst *serial;
    struct dev_context *devc;

    devc = sdi->priv;
    serial = sdi->conn;

    if (sdi->status != SR_ST_ACTIVE)
        return SR_ERR_DEV_CLOSED;

    std_session_send_df_header(sdi);
    /* TODO: configure hardware, reset acquisition state, set up
     * callbacks and send header packet. */
    /* Poll every 50ms, or whenever some data comes in. */
    serial_source_add(sdi->session, serial, G_IO_IN, 50,
            angel_knock_receive_data, (void *)sdi);

    return SR_OK;
}

SR_PRIV struct sr_dev_driver angel_knock_driver_info = {
	.name = "angel-knock",
	.longname = "Angel Knock",
	.api_version = 1,
	.init = std_init,
	.cleanup = std_cleanup,
	//.scan = scan,
	.scan = my_indigo_scan,
	.dev_list = std_dev_list,
	.dev_clear = NULL,
	.config_get = config_get,
	.config_set = config_set,
	.config_list = config_list,
	.dev_open = std_serial_dev_open,
	.dev_close = std_serial_dev_close,
	.dev_acquisition_start = dev_acquisition_start,
	.dev_acquisition_stop = std_serial_dev_acquisition_stop,
	.context = NULL,
};

SR_REGISTER_DEV_DRIVER(angel_knock_driver_info);
