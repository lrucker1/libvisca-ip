//
//  libvisca_packetsender.c
//  PTZ Backup
//
//  Created by Lee Ann Rucker on 1/15/23.
//

#include <stdio.h>
#include "iniparser.h"
#include "libvisca.h"

typedef struct _VISCA_ini_ctx {
    dictionary *ini;
    char *hostname;
    char *packetID;
    int port;
    int namecount;
} VISCA_ini_ctx_t;

static char* byteArrayToHex(const unsigned char *buf, int length) {
    int j = 0;
    size_t hexlength = length * 3 + 1;
    char *result = malloc(hexlength);
    char hex[4];
    for (int i = 0; i < length; i++) {
        sprintf(hex, "%02hhx ", buf[i]);
        strncat(result, hex, 3);
        j += 3;
    }
    result[j] ='\0';
    return result;
}

/*
            Command Packet      Note
 Inquiry    8X QQ RR ... FF     QQ1) = Command/Inquiry,
                                RR2) = category code
 Reply      90                  Etc, not important here.
 1) QQ = 01 (Command), 09 (Inquiry)
 2) RR = 00 (Interface), 04 (camera 1), 06 (Pan/Tilter), 07 (camera 2)
 
 This probably will only be hit for Camera2 commands, but I believe in completeness.
 */

static char* byteArrayToName(const unsigned char *buf, int length) {
    size_t hexlength = length * 2 + 30;
    char *result = malloc(hexlength);
    int i = 0;
    int j = 0;
    int isInquiry = 0;
    if (buf[0] == VISCA_REPLY) {
        j += asprintf(&result, "Reply_");
        i = 1;
    } else {
        isInquiry = (buf[1] == VISCA_INQUIRY);
        i = 3;
        switch (buf[2]) {
            case VISCA_CATEGORY_CAMERA1:
                j+= asprintf(&result, "CAM_");
                break;
            case VISCA_CATEGORY_PAN_TILTER:
                j+= asprintf(&result, "Pan_TiltDrive_");
                break;
            case VISCA_CATEGORY_CAMERA2:
                j+= asprintf(&result, "CAM2_");
                break;
        }
    }
    char hex[3];
    for (; i < length; i++) {
        // Yes, this will pick up parameter values as well as command info, but the name just has to be unique.
        if (buf[i] != 0xFF) {
            sprintf(&result[j], "%02hhx", buf[i]);
            strncat(result, hex, 2);
            j += 2;
        }
    }
    result[j] ='\0';
    if (isInquiry) {
        strncat(result, "Inq", 3);
        j += 3;
    }
    return result;
}


/*
 Example as exported by PacketSender:
 ---
 fromIP=
 fromPort=0
 hexString=81 01 04 39 0d ff
 name=CAM_AE Bright
 port=5678
 repeat=@Variant(\0\0\0\x87\0\0\0\0)
 requestPath=
 sendResponse=0
 tcpOrUdp=TCP
 timestamp="Sun, 15 Jan 2023 11:43:44"
 toIP=192.168.100.88
 ---
 */

static void visca_ini_key_value_set(dictionary *ini, char *packetname, char *key, char * value) {
    char *iniKey;
    int len = asprintf(&iniKey, "%s:%s", packetname, key);
    if (len > 1) {
        iniparser_set(ini, iniKey, value);
    }
    free(iniKey);
}

static int visca_ini_cb_write(VISCAInterface_t *iface, const void *buf, int length, char *name)
{
#define TEMP_LEN 100
    VISCA_ini_ctx_t *ctx = iface->ctx;
    dictionary *ini = ctx->ini;
    char temp[TEMP_LEN];
    char *packetname;
    char *generatedName = NULL;
    char tcpOrUdp = (iface->protocol == VISCA_PROTOCOL_TCP);

    if (name == NULL || name[0] == '\0') {
        generatedName = byteArrayToName(buf, length);
        name = generatedName;
    }

    // PacketSender's NAMES array is 1-based.
    ctx->namecount++;
    // Prefix the packetname with the number, because order is important. PacketSender ignores the NAMES array order
    // Also because the names must be unique or PacketSender will consolidate them.
    if (ctx->packetID != NULL && strlen(ctx->packetID) > 0) {
        asprintf(&packetname, "%05d_%s_%s", ctx->namecount, ctx->packetID, name);
    } else {
        asprintf(&packetname, "%05d_%s", ctx->namecount, name);
    }
    iniparser_set(ini, packetname, NULL);
    snprintf(temp, TEMP_LEN, "NAMES:%d\\name", ctx->namecount);
    iniparser_set(ini, temp, packetname);
    snprintf(temp, TEMP_LEN, "%d", ctx->namecount);
    iniparser_set(ini, "NAMES:size", temp);
            
    char *hexValue = byteArrayToHex(buf, length);
    visca_ini_key_value_set(ini, packetname, "fromIP", "");
    visca_ini_key_value_set(ini, packetname, "fromPort", "0");
    visca_ini_key_value_set(ini, packetname, "hexString", hexValue);
    visca_ini_key_value_set(ini, packetname, "name", packetname);
    snprintf(temp, TEMP_LEN, "%d", ctx->port);
    visca_ini_key_value_set(ini, packetname, "port", temp);
    visca_ini_key_value_set(ini, packetname, "requestPath", "");
    visca_ini_key_value_set(ini, packetname, "sendResponse", "0");
    visca_ini_key_value_set(ini, packetname, "tcpOrUdp", tcpOrUdp ? "TCP" : "UDP");
    visca_ini_key_value_set(ini, packetname, "toIP", ctx->hostname);
    // timestamp is optional
    free(hexValue);
    free(packetname);
    free(generatedName);
    return length;
}

static int visca_ini_cb_read(VISCAInterface_t *iface, void *buf, int length)
{
    // Return "not executable" [90 60 41 FF]
    unsigned char reply[] = {0x90, 0x60, 0x41, 0xFF};
    length = 4;
    memcpy(buf, reply, length);
    return length;
}

static int visca_ini_cb_close(VISCAInterface_t *iface)
{
    VISCA_ini_ctx_t *ctx = iface->ctx;

    iniparser_freedict(ctx->ini);

    if (ctx->packetID) {
        free(ctx->packetID);
    }
    free(ctx->hostname);
    free(ctx);
    iface->ctx = NULL;
    return VISCA_SUCCESS;
}

static const VISCA_callback_t visca_ini_cb = {
    .write = visca_ini_cb_write,
    .read = visca_ini_cb_read,
    .close = visca_ini_cb_close,
};

VISCA_API uint32_t VISCA_ini_write_file(VISCAInterface_t *iface, const char *path) {
    VISCA_ini_ctx_t *ctx = iface->ctx;
    FILE *fd;
    if ((fd=fopen(path, "w"))==NULL) {
        fprintf(stderr, "Error: Could not open file %s\n", path);
        return VISCA_FAILURE;
    }
    iniparser_dump_ini(ctx->ini, fd);
    fclose(fd);
    return VISCA_SUCCESS;
}

/*
 Example usage for exporting data from a TCP or UDP camera:
 VISCA_open_ini(&iface, hostname, path, &iface_source->port, &iface_source->protocol)
 */
VISCA_API uint32_t VISCA_open_ini(VISCAInterface_t *iface, const char *path, const char *hostname, int port, int protocol) {
    VISCA_ini_ctx_t *ctx = calloc(1, sizeof(VISCA_ini_ctx_t));

    if (protocol == VISCA_PROTOCOL_SERIAL) {
        fprintf(stderr, "Error: PacketSender does not support serial\n");
        return VISCA_FAILURE;
    }
    // Path is optional, for adding to an existing dictionary
    if (path != NULL) {
        ctx->ini = iniparser_load(path);
    }

    if (ctx->ini == NULL) {
        ctx->ini = dictionary_new(0);
        ctx->ini->caseSensitive = 1;
        iniparser_set(ctx->ini, "NAMES", NULL);
    } else {
        ctx->ini->caseSensitive = 1;
        ctx->namecount = iniparser_getint(ctx->ini, "NAMES:size", 0);
    }

    ctx->hostname = strdup(hostname);
    ctx->port = port;

    iface->callback = &visca_ini_cb;
    iface->ctx = ctx;
    iface->address = 0;
    iface->broadcast = 0;
    iface->protocol = protocol;

    return VISCA_SUCCESS;
}

// Optional extra information to be included with the PacketSender packet name.
VISCA_API uint32_t VISCA_ini_set_packet_id(VISCAInterface_t *iface, const char *packetID) {
    VISCA_ini_ctx_t *ctx = iface->ctx;
    size_t len = strlen(packetID);
    free(ctx->packetID);
    ctx->packetID = NULL;
    if (len > 0) {
        ctx->packetID = strdup(packetID);
    }
    return VISCA_SUCCESS;
}
