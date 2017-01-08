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
#include <string.h>
#include "protocol.h"

#define AK16(x)  ((((unsigned)((const uint8_t*)(x)[1] &0x3F ) <<  8) | \
                   ((unsigned)((const uint8_t*)x[0]) & 0x3F))

SR_PRIV uint8_t *angel_knock_parse_data(struct sr_dev_inst *sdi,
        const uint8_t *buf, int len) {

    struct dev_context *devc;
    struct sr_datafeed_packet packet;
    struct sr_datafeed_analog analog;
    struct sr_analog_encoding encoding;
    struct sr_analog_meaning meaning;
    struct sr_analog_spec spec;
    struct sr_channel *ch;
    float values[ANGEL_KNOCK_CHANNELS], *val_ptr;
    int i;

    values[0] = 0;

    if (len < 2)
        return 0;

    // пропускаем младший байт, если он пришел первый
    if ((buf[0] & 0xC0) == 0) {
        return buf + 1;
    }

    sr_analog_init(&analog, &encoding, &meaning, &spec, 0);
    analog.num_samples = 1; // FIXME
    analog.meaning->mq = SR_MQ_VOLTAGE;
    analog.meaning->unit = SR_UNIT_VOLT;
    analog.meaning->mqflags = 0;
    analog.data = values;

    val_ptr = values;
    for (i = 0; i < ANGEL_KNOCK_CHANNELS; i++) {
            ch = g_slist_nth_data(sdi->channels, i);
            if (!ch->enabled)
                continue;
            analog.meaning->channels = g_slist_append(analog.meaning->channels, ch);

            *val_ptr = (((((unsigned) buf[0]) & 0x3F ) << 6) | ( ( (unsigned) buf[1]) & 0x3F));
            *val_ptr -= 2048; // среднее
            *val_ptr *= 16;
            *val_ptr /= 20000;
            *val_ptr++;
            //printf("data: %f\n", values[0]);
        }

    packet.type = SR_DF_ANALOG;
    packet.payload = &analog;
    sr_session_send(sdi, &packet);
    g_slist_free(analog.meaning->channels);

    // возвращаем, что мы прочитали два байта
    return buf + 2;
}

SR_PRIV int angel_knock_receive_data(int fd, int revents, void *cb_data)
{
	const struct sr_dev_inst *sdi;
	struct dev_context *devc;
	int len;
	struct sr_serial_dev_inst *serial;
	const uint8_t *ptr, *next_ptr, *end_ptr;

	(void)fd;

	fprintf(stderr, "RECEIVE DATA\n");

	if (!(sdi = cb_data))
		return TRUE;

	if (!(devc = sdi->priv))
		return TRUE;

	if (revents != G_IO_IN) {
		return TRUE;
	}

    serial = sdi->conn;

    /* Try to get as much data as the buffer can hold. */
    len = sizeof(devc->buf) - devc->buf_len;
    printf("len %d\n", len);
    len = serial_read_nonblocking(serial, devc->buf + devc->buf_len, len);
    if (len < 1) {
        sr_err("Serial port read error: %d.", len);
        return FALSE;
    }
    devc->buf_len += len;

    /* Now look for packets in that data. */
    ptr = devc->buf;
    end_ptr = ptr + devc->buf_len;
    while ((next_ptr = angel_knock_parse_data(sdi, ptr, end_ptr - ptr)))
        ptr = next_ptr;

    /* If we have any data left, move it to the beginning of our buffer. */
    memmove(devc->buf, ptr, end_ptr - ptr);
    devc->buf_len -= ptr - devc->buf;

    /* If buffer is full and no valid packet was found, wipe buffer. */
    if (devc->buf_len >= sizeof(devc->buf)) {
        devc->buf_len = 0;
        return FALSE;
    }

	return TRUE;
}
