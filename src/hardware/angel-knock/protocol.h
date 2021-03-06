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

#ifndef LIBSIGROK_HARDWARE_ANGEL_KNOCK_PROTOCOL_H
#define LIBSIGROK_HARDWARE_ANGEL_KNOCK_PROTOCOL_H

#include <stdint.h>
#include <glib.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"

#define LOG_PREFIX "angel-knock"

#define ANGEL_KNOCK_BUF_SIZE 32

#define ANGEL_KNOCK_CHANNELS 1

/** Private, per-device-instance driver context. */
struct dev_context {
    /* Temporary state across callbacks */
        uint8_t buf[ANGEL_KNOCK_BUF_SIZE];
        unsigned int buf_len;
        unsigned int num_log_records;
	/* Model-specific information */

	/* Acquisition settings */

	/* Operational state */

	/* Temporary state across callbacks */

};

SR_PRIV int angel_knock_receive_data(int fd, int revents, void *cb_data);

#endif
