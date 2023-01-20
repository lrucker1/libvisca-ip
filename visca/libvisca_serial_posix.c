#include "libvisca.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>

typedef struct _VISCA_serial_ctx {
	int port_fd;
	struct termios options;
} VISCA_serial_ctx_t;

static int visca_serial_cb_write(VISCAInterface_t *iface, const void *buf, int length, char *name)
{
	VISCA_serial_ctx_t *ctx = iface->ctx;
	return (int)write(ctx->port_fd, buf, length);
}

static int visca_serial_cb_read(VISCAInterface_t *iface, void *buf, int length)
{
	VISCA_serial_ctx_t *ctx = iface->ctx;
	return (int)read(ctx->port_fd, buf, length);
}

static void visca_serial_cb_wait_read(VISCAInterface_t *iface)
{
	// TODO: why not use select?
	VISCA_serial_ctx_t *ctx = iface->ctx;
	for (;;) {
		int bytes;
		ioctl(ctx->port_fd, FIONREAD, &bytes);
		if (bytes != 0)
			break;
		usleep(0);
	}
}

static uint32_t VISCA_unread_bytes(VISCAInterface_t *iface, unsigned char *buffer, uint32_t *buffer_size)
{
	if (!iface || !iface->ctx)
		return VISCA_FAILURE;
	VISCA_serial_ctx_t *ctx = iface->ctx;

	uint32_t bytes = 0;
	*buffer_size = 0;

	ioctl(ctx->port_fd, FIONREAD, &bytes);
	if (bytes > 0) {
		ssize_t ret;
		bytes = (bytes > *buffer_size) ? *buffer_size : bytes;
		ret = read(ctx->port_fd, &buffer, bytes);
		if (ret != bytes) {
			return bytes = (uint32_t)ret;
		}
		*buffer_size = bytes;
		return VISCA_FAILURE;
	}
	return VISCA_SUCCESS;
}

static int visca_serial_cb_close(VISCAInterface_t *iface)
{
	if (!iface || !iface->ctx)
		return VISCA_FAILURE;
	VISCA_serial_ctx_t *ctx = iface->ctx;

	// read the rest of the data: (should be empty)
	unsigned char packet[3000];
	uint32_t buffer_size = 3000;

	if (VISCA_unread_bytes(iface, packet, &buffer_size) != VISCA_SUCCESS) {
		uint32_t i;
		fprintf(stderr, "ERROR: %u bytes not processed", buffer_size);
		for (i = 0; i < buffer_size; i++)
			fprintf(stderr, "%2x ", packet[i]);
		fprintf(stderr, "\n");
	}

	if (ctx->port_fd != -1) {
		close(ctx->port_fd);
		free(ctx);
		iface->ctx = NULL;
		return VISCA_SUCCESS;
	} else
		return VISCA_FAILURE;
}
static const VISCA_callback_t visca_serial_cb = {
	.write = visca_serial_cb_write,
	.read = visca_serial_cb_read,
	.wait_read = visca_serial_cb_wait_read,
	.close = visca_serial_cb_close,
};

uint32_t VISCA_open_serial(VISCAInterface_t *iface, const char *device_name)
{
	int fd;
	VISCA_serial_ctx_t *ctx = calloc(1, sizeof(VISCA_serial_ctx_t));
	ctx->port_fd = -1;
	iface->callback = &visca_serial_cb;
	fd = open(device_name, O_RDWR | O_NDELAY | O_NOCTTY);

	if (fd == -1) {
#if DEBUG
		fprintf(stderr, "(%s): cannot open serial device %s\n", __FILE__, device_name);
#endif
		iface->ctx = NULL;
		free(ctx);
		return VISCA_FAILURE;
	} else {
		fcntl(fd, F_SETFL, 0);
		/* Setting port parameters */
		tcgetattr(fd, &ctx->options);

		/* control flags */
		cfsetispeed(&ctx->options, B9600); /* 9600 Bds   */
		ctx->options.c_cflag &= ~PARENB;   /* No parity  */
		ctx->options.c_cflag &= ~CSTOPB;   /*            */
		ctx->options.c_cflag &= ~CSIZE;    /* 8bit       */
		ctx->options.c_cflag |= CS8;       /*            */
		ctx->options.c_cflag &= ~CRTSCTS;  /* No hdw ctl */

		/* local flags */
		ctx->options.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG); /* raw input */

		/* input flags */
		/* patch: bpflegin: set to 0 in order to avoid invalid pan/tilt return values */
		ctx->options.c_iflag = 0;

		/* output flags */
		ctx->options.c_oflag &= ~OPOST; /* raw output */

		tcsetattr(fd, TCSANOW, &ctx->options);
	}
	ctx->port_fd = fd;
	iface->address = 0;
	iface->ctx = ctx;
	iface->protocol = VISCA_PROTOCOL_SERIAL;

	return VISCA_SUCCESS;
}
