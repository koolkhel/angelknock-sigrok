/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2013 Bert Vermeulen <bert@biot.com>
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
#include <math.h>
#include "protocol.h"

static float parse_temperature(unsigned char *buf)
{
	float temp;
	int i;
	gboolean negative;

	negative = FALSE;
	temp = 0.0;
	for (i = 0; i < 4; i++) {
		if (buf[i] == 0x3a)
			continue;
		if (buf[i] == 0x3b) {
			if (negative) {
				sr_dbg("Double negative sign!");
				return NAN;
			} else {
				negative = TRUE;
				continue;
			}
		}
		if (buf[i] < 0x30 || buf[i] > 0x39) {
			sr_dbg("Invalid digit '%.2x'!", buf[i]);
			return NAN;
		}
		temp *= 10;
		temp += (buf[i] - 0x30);
	}
	temp /= 10;
	if (negative)
		temp = -temp;

	return temp;
}

static void process_packet(struct sr_dev_inst *sdi)
{
	struct dev_context *devc;
	struct sr_datafeed_packet packet;
	struct sr_datafeed_analog analog;
	struct sr_analog_encoding encoding;
	struct sr_analog_meaning meaning;
	struct sr_analog_spec spec;
	GString *spew;
	float temp;
	int i;
	gboolean is_valid;

	devc = sdi->priv;
	sr_dbg("Received full 19-byte packet.");
	if (sr_log_loglevel_get() >= SR_LOG_SPEW) {
		spew = g_string_sized_new(60);
		for (i = 0; i < devc->packet_len; i++)
			g_string_append_printf(spew, "%.2x ", devc->packet[i]);
		sr_spew("%s", spew->str);
		g_string_free(spew, TRUE);
	}

	is_valid = TRUE;
	if (devc->packet[1] == 0x3b && devc->packet[2] == 0x3b
			&& devc->packet[3] == 0x3b && devc->packet[4] == 0x3b)
		/* No measurement: missing channel, empty storage location, ... */
		is_valid = FALSE;

	temp = parse_temperature(devc->packet + 1);
	if (isnan(temp))
		is_valid = FALSE;

	if (is_valid) {
		sr_analog_init(&analog, &encoding, &meaning, &spec, 0);
		analog.meaning->mq = SR_MQ_TEMPERATURE;
		analog.meaning->mqflags = 0;
		switch (devc->packet[5] - 0x30) {
		case 1:
			analog.meaning->unit = SR_UNIT_CELSIUS;
			break;
		case 2:
			analog.meaning->unit = SR_UNIT_FAHRENHEIT;
			break;
		case 3:
			analog.meaning->unit = SR_UNIT_KELVIN;
			break;
		default:
			/* We can still pass on the measurement, whatever it is. */
			sr_dbg("Unknown unit 0x%.2x.", devc->packet[5]);
		}
		switch (devc->packet[13] - 0x30) {
		case 0:
			/* Channel T1. */
			analog.meaning->channels = g_slist_append(NULL, g_slist_nth_data(sdi->channels, 0));
			break;
		case 1:
			/* Channel T2. */
			analog.meaning->channels = g_slist_append(NULL, g_slist_nth_data(sdi->channels, 1));
			break;
		case 2:
		case 3:
			/* Channel T1-T2. */
			analog.meaning->channels = g_slist_append(NULL, g_slist_nth_data(sdi->channels, 2));
			analog.meaning->mqflags |= SR_MQFLAG_RELATIVE;
			break;
		default:
			sr_err("Unknown channel 0x%.2x.", devc->packet[13]);
			is_valid = FALSE;
		}
		if (is_valid) {
			analog.num_samples = 1;
			analog.data = &temp;
			packet.type = SR_DF_ANALOG;
			packet.payload = &analog;
			sr_session_send(sdi, &packet);
			g_slist_free(analog.meaning->channels);
		}
	}

	/* We count packets even if the temperature was invalid. This way
	 * a sample limit on "Memory" data source still works: unused
	 * memory slots come through as "----" measurements. */
	devc->num_samples++;
	if (devc->limit_samples && devc->num_samples >= devc->limit_samples) {
		sdi->driver->dev_acquisition_stop(sdi);
	}

}

SR_PRIV void LIBUSB_CALL uni_t_ut32x_receive_transfer(struct libusb_transfer *transfer)
{
	struct dev_context *devc;
	struct sr_dev_inst *sdi;
	int hid_payload_len, ret;

	sdi = transfer->user_data;
	devc = sdi->priv;
	if (transfer->actual_length == 8) {
		/* CH9325 encodes length in low nibble of first byte, with
		 * bytes 1-7 being the (padded) payload. */
		hid_payload_len = transfer->buffer[0] & 0x0f;
		memcpy(devc->packet + devc->packet_len, transfer->buffer + 1,
				hid_payload_len);
		devc->packet_len += hid_payload_len;
		if (devc->packet_len >= 2
				&& devc->packet[devc->packet_len - 2] == 0x0d
				&& devc->packet[devc->packet_len - 1] == 0x0a) {
			/* Got end of packet, but do we have a complete packet? */
			if (devc->packet_len == 19)
				process_packet(sdi);
			/* Either way, done with it. */
			devc->packet_len = 0;
		} else if (devc->packet_len > 19) {
			/* Guard against garbage from the device overrunning
			 * our packet buffer. */
			sr_dbg("Buffer overrun!");
			devc->packet_len = 0;
		}
	}

	/* Get the next transfer (unless we're shutting down). */
	if (sdi->status != SR_ST_STOPPING) {
		if ((ret = libusb_submit_transfer(devc->xfer)) != 0) {
			sr_dbg("Failed to resubmit transfer: %s", libusb_error_name(ret));
			sdi->status = SR_ST_STOPPING;
			libusb_free_transfer(devc->xfer);
		}
	} else
		libusb_free_transfer(devc->xfer);

}

SR_PRIV int uni_t_ut32x_handle_events(int fd, int revents, void *cb_data)
{
	struct drv_context *drvc;
	struct dev_context *devc;
	struct sr_dev_driver *di;
	struct sr_dev_inst *sdi;
	struct sr_usb_dev_inst *usb;
	struct timeval tv;
	int len, ret;
	unsigned char cmd[2];

	(void)fd;
	(void)revents;

	if (!(sdi = cb_data))
		return TRUE;

	di = sdi->driver;
	drvc = di->context;

	if (!(devc = sdi->priv))
		return TRUE;

	memset(&tv, 0, sizeof(struct timeval));
	libusb_handle_events_timeout_completed(drvc->sr_ctx->libusb_ctx, &tv,
			NULL);

	if (sdi->status == SR_ST_STOPPING) {
		usb_source_remove(sdi->session, drvc->sr_ctx);
		std_session_send_df_end(sdi);

		/* Tell the device to stop sending USB packets. */
		usb = sdi->conn;
		cmd[0] = 0x01;
		cmd[1] = CMD_STOP;
		ret = libusb_bulk_transfer(usb->devhdl, EP_OUT, cmd, 2, &len, 5);
		if (ret != 0 || len != 2) {
			/* Warning only, doesn't matter. */
			sr_dbg("Failed to send stop command: %s", libusb_error_name(ret));
		}

		sdi->status = SR_ST_ACTIVE;
		return TRUE;
	}

	return TRUE;
}
