BLUEZ_PATH=../bluez/bluez-5.20

BLUEZ_SRCS  = lib/bluetooth.c lib/hci.c lib/sdp.c lib/uuid.c
BLUEZ_SRCS += attrib/att.c attrib/gatt.c attrib/gattrib.c attrib/utils.c
BLUEZ_SRCS += btio/btio.c src/log.c src/shared/crypto.c

IMPORT_SRCS = $(addprefix $(BLUEZ_PATH)/, $(BLUEZ_SRCS))
LOCAL_SRCS  = blescan.c

CC = gcc
CFLAGS = -g -Wall

CPPFLAGS = -DHAVE_CONFIG_H

CPPFLAGS += -I$(BLUEZ_PATH)/attrib -I$(BLUEZ_PATH) -I$(BLUEZ_PATH)/lib -I$(BLUEZ_PATH)/src -I$(BLUEZ_PATH)/gdbus
CPPFLAGS += -I$(BLUEZ_PATH)/btio -I$(BLUEZ_PATH)/tools -I$(BLUEZ_PATH)/src/shared

CPPFLAGS += `pkg-config glib-2.0 dbus-1 --cflags`
LDLIBS += `pkg-config glib-2.0 --libs`

all: blescan 

blescan: $(LOCAL_SRCS) $(IMPORT_SRCS)
	$(CC) -L. $(CFLAGS) $(CPPFLAGS) -o $@ $(LOCAL_SRCS) $(IMPORT_SRCS) $(LDLIBS)

clean:
	rm -f *.o blescan