/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  Nokia Corporation
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */
 
#ifndef BLESCANMODULE_H
#define BLESCANMODULE_H

#define FLAGS_AD_TYPE 0x01
#define FLAGS_LIMITED_MODE_BIT 0x01
#define FLAGS_GENERAL_MODE_BIT 0x02

#define EIR_FLAGS                   0x01  /* flags */
#define EIR_UUID16_SOME             0x02  /* 16-bit UUID, more available */
#define EIR_UUID16_ALL              0x03  /* 16-bit UUID, all listed */
#define EIR_UUID32_SOME             0x04  /* 32-bit UUID, more available */
#define EIR_UUID32_ALL              0x05  /* 32-bit UUID, all listed */
#define EIR_UUID128_SOME            0x06  /* 128-bit UUID, more available */
#define EIR_UUID128_ALL             0x07  /* 128-bit UUID, all listed */
#define EIR_NAME_SHORT              0x08  /* shortened local name */
#define EIR_NAME_COMPLETE           0x09  /* complete local name */
#define EIR_TX_POWER                0x0A  /* transmit power level */
#define EIR_DEVICE_ID               0x10  /* device ID */

typedef struct {
	char addr[18];
	int interval;
	time_t timestamp;
} wldev;	

static void sigint_handler(int sig);
static int read_flags(uint8_t *flags, const uint8_t *data, size_t size);
static int check_report_filter(uint8_t procedure, le_advertising_info *info);
static void eir_parse_name(uint8_t *eir, size_t eir_len,
						char *buf, size_t buf_len);
static int advertising_devices(int dd, uint8_t filter_type);
static void lescan(int dev_id);
static void hci_up(int ctl, int dev_id);
static void hci_down(int ctl, int dev_id);
static void hci_reset(int ctl, int dev_id);
static void hci_start(int dev_id);
static void connect_cb(GIOChannel *io, GError *err, gpointer user_data);
static void char_read_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data);
static gboolean characteristics_read(gpointer user_data);
static void mainloop_quit(gpointer user_data);
static gboolean characteristics_write(gpointer user_data);
static void char_write_req_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data);
static gboolean characteristics_write_req(gpointer user_data);
static void gatt(char *opt_dst);
static void read_whitelist(const char *filename);
static int cmp_whitelist(char *addr);
static int cmp_timestamp(wldev wl);
static void set_timestamp(char *addr);
static int udp_send(char *buf, int buflen);
static void show_help(void);							

#endif