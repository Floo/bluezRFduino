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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <glib.h>
#include <fcntl.h>
#include <unistd.h> 
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>
#include <ctype.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <btio/btio.h>

#include "blescan.h"
#include "lib/uuid.h"
#include "att.h"
#include "gattrib.h"
#include "gatt.h"
#include "gatttool.h"
#include "src/shared/util.h"
#include "src/shared/crypto.h"

#define HCI_DEVICE "hci0"
#define UDP_ADDRESS "192.168.178.255"
#define UDP_PORT 2701

static char *opt_dst_type = NULL;
static char *opt_value = NULL;
static char *opt_sec_level = NULL;
static const int opt_psm = 0;
static int opt_mtu = 0;
static int opt_handle = -1;
static GSourceFunc operation;
static GMainLoop *event_loop;
static GIOChannel *chan;
static GAttrib *attrib;
static gboolean got_error = FALSE;
static char *str_dev_id = HCI_DEVICE;
static guint udp_port = UDP_PORT;
static wldev *whitelist;
static int whitelist_len = 0;
static volatile int signal_received = 0;
static GString *send_buf;
static gushort udp_pack_count = 0;

static void sigint_handler(int sig)
{
	signal_received = sig;
}

static int read_flags(uint8_t *flags, const uint8_t *data, size_t size)
{
	size_t offset;

	if (!flags || !data)
		return -EINVAL;

	offset = 0;
	while (offset < size) {
		uint8_t len = data[offset];
		uint8_t type;

		/* Check if it is the end of the significant part */
		if (len == 0)
			break;

		if (len + offset > size)
			break;

		type = data[offset + 1];

		if (type == FLAGS_AD_TYPE) {
			*flags = data[offset + 2];
			return 0;
		}

		offset += 1 + len;
	}

	return -ENOENT;
}

static int check_report_filter(uint8_t procedure, le_advertising_info *info)
{
	uint8_t flags;

	/* If no discovery procedure is set, all reports are treat as valid */
	if (procedure == 0)
		return 1;

	/* Read flags AD type value from the advertising report if it exists */
	if (read_flags(&flags, info->data, info->length))
		return 0;

	switch (procedure) {
	case 'l': /* Limited Discovery Procedure */
		if (flags & FLAGS_LIMITED_MODE_BIT)
			return 1;
		break;
	case 'g': /* General Discovery Procedure */
		if (flags & (FLAGS_LIMITED_MODE_BIT | FLAGS_GENERAL_MODE_BIT))
			return 1;
		break;
	default:
		fprintf(stderr, "Unknown discovery procedure\n");
	}

	return 0;
}

static void eir_parse_name(uint8_t *eir, size_t eir_len,
						char *buf, size_t buf_len)
{
	size_t offset;

	offset = 0;
	while (offset < eir_len) {
		uint8_t field_len = eir[0];
		size_t name_len;

		/* Check for the end of EIR */
		if (field_len == 0)
			break;

		if (offset + field_len > eir_len)
			goto failed;

		switch (eir[1]) {
		case EIR_NAME_SHORT:
		case EIR_NAME_COMPLETE:
			name_len = field_len - 1;
			if (name_len > buf_len)
				goto failed;

			memcpy(buf, &eir[2], name_len);
			return;
		}

		offset += field_len + 1;
		eir += field_len + 1;
	}

failed:
	snprintf(buf, buf_len, "(unknown)");
}

static int advertising_devices(int dd, uint8_t filter_type)
{
	unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
	struct hci_filter nf, of;
	struct sigaction sa;
	socklen_t olen;
	int len;
	int rssi = 0;

	olen = sizeof(of);
	if (getsockopt(dd, SOL_HCI, HCI_FILTER, &of, &olen) < 0) {
		fprintf(stderr, "Could not get socket options\n");
		return -1;
	}

	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
	hci_filter_set_event(EVT_LE_META_EVENT, &nf);

	if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
		fprintf(stderr, "Could not set socket options\n");
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sigint_handler;
	sigaction(SIGINT, &sa, NULL);

	while (1) {
		evt_le_meta_event *meta;
		le_advertising_info *info;
		char addr[18];
		while ((len = read(dd, buf, sizeof(buf))) < 0) {
			if (errno == EINTR && signal_received == SIGINT) {
				len = 0;
				goto done;
			}

			if (errno == EAGAIN || errno == EINTR)
				continue;
			goto done;
		}
		ptr = buf + (1 + HCI_EVENT_HDR_SIZE);
		len -= (1 + HCI_EVENT_HDR_SIZE);
		meta = (void *) ptr;
		if (meta->subevent != 0x02)
			continue;
			//goto done;
		/* Ignoring multiple reports */
		info = (le_advertising_info *) (meta->data + 1);
		
		if (check_report_filter(filter_type, info)) { //filter_type ist ohne Bedeutung fuer RFduino
			ba2str(&info->bdaddr, addr);
			if (cmp_whitelist(addr) == 0) {
				char name[30];
				
				memset(name, 0, sizeof(name));
				eir_parse_name(info->data, info->length,
								name, sizeof(name) - 1);
				rssi = (ptr[len - 1] & 127) - (ptr[len - 1] & 128);
				
				printf("Address: %s\n", addr);
				printf("Name: %s\n", name);
				printf("RSSI: %i\n", rssi);
				g_string_printf(send_buf, "%05u BLE ADDR:%s NAME:%s RSSI:%i", udp_pack_count, addr, name, rssi);
				
				gatt(addr);
				set_timestamp(addr);
				
				g_string_append_printf(send_buf, "\n");
				udp_send(send_buf->str, send_buf->len);
			}
		}
	}

done:
	setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));

	if (len < 0)
		return -1;

	return 0;
}

static int cmp_timestamp(wldev wl)
{
	if (wl.interval == 0)
		return 0;
	if (wl.timestamp + wl.interval <= time(NULL))
		return 0;
	return -1;
}

static int cmp_whitelist(char *addr)
{
	int i;
	if (whitelist_len < 1)
		return -1;
	for (i = 0; i < whitelist_len; i++) {
		if ((g_ascii_strcasecmp(addr, whitelist[i].addr) == 0) && (cmp_timestamp(whitelist[i]) == 0))
			return 0;
	}
	return -1;
}

static void set_timestamp(char *addr)
{
	int i;
	for (i = 0; i < whitelist_len; i++) {
		if (g_ascii_strcasecmp(addr, whitelist[i].addr) == 0)
			whitelist[i].timestamp = time(NULL);
	}
}

static void lescan(int dev_id)
{
	int err, dd;
	uint8_t own_type = 0x00; //0x01; //Random
	uint8_t scan_type = 0x00; // Passive, vorher war 0x01
	uint8_t filter_type = 0; //enable general or limited discovery procedure: 0-standard, g-general, l-limited
							 //ohne Bedeutung fuer RFduino
	uint8_t filter_policy = 0x00; //0x01 fuer Whitelist, 0x00 keine Whitelist
	uint16_t interval = htobs(0x0010);
	uint16_t window = htobs(0x0010);
	uint8_t filter_dup = 0; // Filter duplicates: 0-filtering disabled, 1-filter out duplicates

//Was soll dass????
	if (dev_id < 0)
		dev_id = hci_get_route(NULL);

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("Could not open device");
		exit(1);
	}

	err = hci_le_set_scan_parameters(dd, scan_type, interval, window,
						own_type, filter_policy, 1000);
	if (err < 0) {
		perror("Set scan parameters failed");
		exit(1);
	}

	err = hci_le_set_scan_enable(dd, 0x01, filter_dup, 1000);
	if (err < 0) {
		perror("Enable scan failed");
		exit(1);
	}

	err = advertising_devices(dd, filter_type);
	if (err < 0) {
		perror("Could not receive advertising events");
		exit(1);
	}

	err = hci_le_set_scan_enable(dd, 0x00, filter_dup, 1000);
	if (err < 0) {
		perror("Disable scan failed");
		exit(1);
	}

	hci_close_dev(dd);
}

static void hci_up(int ctl, int dev_id)
{
	/* Start HCI device */
	if (ioctl(ctl, HCIDEVUP, dev_id) < 0) {
		if (errno == EALREADY)
			return;
		fprintf(stderr, "Can't init device hci%d: %s (%d)\n",
						dev_id, strerror(errno), errno);
		exit(1);
	}
}

static void hci_down(int ctl, int dev_id)
{
	/* Stop HCI device */
	if (ioctl(ctl, HCIDEVDOWN, dev_id) < 0) {
		fprintf(stderr, "Can't down device hci%d: %s (%d)\n",
						dev_id, strerror(errno), errno);
		exit(1);
	}
}

static void hci_reset(int ctl, int dev_id)
{
	/* Reset HCI device */
#if 0
	if (ioctl(ctl, HCIDEVRESET, dev_id) < 0 ){
		fprintf(stderr, "Reset failed for device hci%d: %s (%d)\n",
						dev_id, strerror(errno), errno);
		exit(1);
	}
#endif
	hci_down(ctl, dev_id);
	hci_up(ctl, dev_id);
}

static void hci_start(int dev_id)
{
	int ctl;
	struct hci_dev_info di = { .dev_id = dev_id };

	/* Open HCI socket  */
	if ((ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)) < 0) {
		perror("Can't open HCI socket.");
		exit(1);
	}
	
	if (ioctl(ctl, HCIGETDEVINFO, (void *) &di)) {
		perror("Can't get device info");
		exit(1);
	}
	if (!hci_test_bit(HCI_UP, &di.flags)) //siehe lib/hci.c:182
		hci_up(ctl, dev_id);
		
	close(ctl);
}

static void connect_cb(GIOChannel *io, GError *err, gpointer user_data)
{
	//GAttrib *attrib;
	
	if (err) {
		g_printerr("%s\n", err->message);
		got_error = TRUE;
		g_main_loop_quit(event_loop);
	}
	attrib = g_attrib_new(chan);
	operation(attrib);
}

static void char_read_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	uint8_t value[plen];
	ssize_t vlen;
	//int i;
	char *c;

	if (status != 0) {
		g_printerr("Characteristic value/descriptor read failed: %s\n",
							att_ecode2str(status));
		goto done;
	}
	vlen = dec_read_resp(pdu, plen, value, sizeof(value));
	if (vlen < 0) {
		g_printerr("Protocol error\n");
		goto done;
	}
	// g_print("Characteristic value/descriptor: ");
	// for (i = 0; i < vlen; i++)
		// g_print("%02x ", value[i]);
	// g_print("\n");
	c = g_strndup((char*)value, vlen);
	printf("Value: %s\n\n", c);
	g_string_append_printf(send_buf, " VALUE:%s", c);
	
	g_free(c);
done:
	g_main_loop_quit(event_loop);
}

static gboolean characteristics_read(gpointer user_data)
{
	if (opt_handle <= 0) {
		g_printerr("A valid handle is required\n");
		g_main_loop_quit(event_loop);
		return FALSE;
	}
	gatt_read_char(attrib, opt_handle, char_read_cb, attrib);
	return FALSE;
}

static void mainloop_quit(gpointer user_data)
{
	uint8_t *value = user_data;

	g_free(value);
	g_main_loop_quit(event_loop);
}

static gboolean characteristics_write(gpointer user_data)
{
	uint8_t *value;
	size_t len;

	if (opt_handle <= 0) {
		g_printerr("A valid handle is required\n");
		goto error;
	}

	if (opt_value == NULL || opt_value[0] == '\0') {
		g_printerr("A value is required\n");
		goto error;
	}

	len = gatt_attr_data_from_string(opt_value, &value);
	if (len == 0) {
		g_printerr("Invalid value\n");
		goto error;
	}

	gatt_write_cmd(attrib, opt_handle, value, len, mainloop_quit, value);

	return FALSE;

error:
	g_main_loop_quit(event_loop);
	return FALSE;
}

static void char_write_req_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	if (status != 0) {
		g_printerr("Characteristic Write Request failed: "
						"%s\n", att_ecode2str(status));
		goto done;
	}

	if (!dec_write_resp(pdu, plen) && !dec_exec_write_resp(pdu, plen)) {
		g_printerr("Protocol error\n");
		goto done;
	}

	g_print("Characteristic value was written successfully\n");

done:
	g_main_loop_quit(event_loop);
}

static gboolean characteristics_write_req(gpointer user_data)
{
	uint8_t *value;
	size_t len;

	if (opt_handle <= 0) {
		g_printerr("A valid handle is required\n");
		goto error;
	}

	if (opt_value == NULL || opt_value[0] == '\0') {
		g_printerr("A value is required\n");
		goto error;
	}

	len = gatt_attr_data_from_string(opt_value, &value);
	if (len == 0) {
		g_printerr("Invalid value\n");
		goto error;
	}

	gatt_write_char(attrib, opt_handle, value, len, char_write_req_cb,
									NULL);

	return FALSE;

error:
	g_main_loop_quit(event_loop);
	return FALSE;
}

static void gatt(char *opt_dst)
{
    GError *gerr = NULL;
	static char *opt_src = NULL;
	
	opt_dst_type = g_strdup("random");
	opt_sec_level = g_strdup("low");
	opt_src = g_strdup(str_dev_id);
	
	operation = characteristics_read;
	opt_handle = 0x000e;
	//operation = characteristics_write;
	//opt_handle = 0x0011;
	//opt_value = g_strdup("0x45aa");
	//operation = characteristics_write_req;
	//opt_handle = 0x0011;
	//opt_value = g_strdup("0x45aa");
	chan = gatt_connect(opt_src, opt_dst, opt_dst_type, opt_sec_level,
					opt_psm, opt_mtu, connect_cb, &gerr);
	if (chan == NULL) {
		g_printerr("%s\n", gerr->message);
		g_clear_error(&gerr);
		got_error = TRUE;
		goto done;
	}
	event_loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(event_loop);
	g_main_loop_unref(event_loop);
	
	g_attrib_unref(attrib);
	attrib = NULL;
	
	g_io_channel_shutdown(chan, FALSE, NULL);
	g_io_channel_unref(chan);
	chan = NULL;

done:
	g_free(opt_value);
	g_free(opt_dst_type);
	g_free(opt_src);
	g_free(opt_sec_level);
}

static void read_whitelist(const char *filename)
{
	GIOChannel *wl = NULL;
	GError *gerr = NULL;
	GString *buf = g_string_new(NULL);
	gchar **buf_split;
	int line_cnt = 0;
	int i;
	int c = 0;
	
	wl = g_io_channel_new_file(filename, "r", &gerr);
	if (wl == NULL) {
		g_printerr("%s\n", gerr->message);
		g_clear_error(&gerr);
		got_error = TRUE;
		return;
	}
	
	while (g_io_channel_read_line_string (wl, buf, NULL, &gerr) != G_IO_STATUS_EOF)
		line_cnt++;
	
	whitelist = (wldev *) malloc(line_cnt * sizeof(wldev));
	g_io_channel_seek_position(wl, 0, G_SEEK_SET, &gerr);
	
	for (i = 0; i < line_cnt; i++) {
		g_io_channel_read_line_string (wl, buf, NULL, &gerr);
		buf_split = g_strsplit_set(buf->str, " ,;", -1);
		if (bachk(buf_split[0]) == 0) {
			strcpy(whitelist[c].addr, buf_split[0]);
			whitelist[c].interval = atoi(buf_split[1]);
			whitelist[c++].timestamp = 0;
		}
	}
	g_string_free(buf, TRUE);
	g_strfreev(buf_split);
	whitelist_len = c;
}

static int udp_send(char *buf, int buflen)
{
	struct sockaddr_in si_udp;
	int udp_sock;
	int broadcastEnable = 1;

	if ((udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		fprintf(stderr, "Could not open UDP socket\n");
		return -1;
	}
	memset((char *) &si_udp, 0, sizeof(si_udp));
    si_udp.sin_family = AF_INET;
    si_udp.sin_port = htons(udp_port);
     
    if (inet_aton(UDP_ADDRESS, &si_udp.sin_addr) == 0)
    {
        fprintf(stderr, "inet_aton() failed\n");
        return -1;
    }
		
	if (setsockopt(udp_sock, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable)) < 0)  {
		fprintf(stderr, "Could not set socket options on UDP socket\n");
		return -1;
	}
	
	if (sendto(udp_sock, buf, buflen, 0, (struct sockaddr *) &si_udp, sizeof(si_udp)) == -1) {
		fprintf(stderr, "UDP send failed: %s (%i)\n", strerror(errno), errno);
		return -1;
	}
	
	udp_pack_count++;	
	close(udp_sock);
	return 0;
}

static void show_help(void)
{
    printf("\nusage: blescan [-i hciX] [-p port]\n"\
           "Command summary:\n\n"\
           "\t-i hciX       lokales Interface\n"\
		   "\t-p port       UDP port (2701)\n"\
           "\t-h            Show help\n\n");
}

int main(int argc, char *argv[])
{
	int index, dev_id = -1;
	
	//Kommandozeilenargumente auswerten
    while ((index = getopt (argc, argv, "hip:")) != -1) {
        switch (index)
        {
        case 'h':
            //Hilfe ausgeben
            show_help();
            exit(EXIT_FAILURE);
        case 'p':
            sscanf(optarg, "%d", &udp_port);
            if(udp_port < 1 && udp_port > 32768)
            {
                show_help();
                exit(EXIT_FAILURE);
            }
            break;
        case 'i':
			sscanf(optarg, "%s", str_dev_id);
            break;
        case '?':
            if (isprint (optopt))
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf (stderr,
                         "Unknown option character `\\x%x'.\n",
                         optopt);
            show_help();
            exit(EXIT_FAILURE);
        }
	}

	read_whitelist("blescan.conf");
	
	send_buf = g_string_new(NULL);
	
	if (got_error)
		exit(EXIT_FAILURE);
 	//dev_id = hci_devid(str_dev_id); geht nur, wenn device schon UP
	dev_id = atoi(str_dev_id + 3);
 	if (dev_id < 0) {
 		perror("Invalid device\n");
 		exit(EXIT_FAILURE);
 	}
 	hci_start(dev_id);
	
 	lescan(dev_id);
	if (got_error)
		exit(EXIT_FAILURE);
	else
		exit(EXIT_SUCCESS);
}

