/*
 * Copyright (c) 2020 Martin Wilck, SUSE Software Solutions Germany GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#define _GNU_SOURCE 1
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <sys/types.h>
#include <ioc.h>
#include <ioc-util.h>

#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <syslog.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/epoll.h>

#include <scsi/scsi.h>
#include <scsi/sg.h>
#include <unaligned.h>

#define DEFAULT_TIMEOUT_MS 30000

#define safe_snprintf(pbuf, plen, fmt, ...)				\
	({								\
		int rc = -1;						\
		if (*plen < INT_MAX) {					\
			rc = snprintf(*pbuf, *plen, fmt,		\
			      ##__VA_ARGS__);				\
			if (rc >= 0 && rc < (int)*plen) {		\
				*plen -= rc;				\
				*pbuf += rc;				\
			};						\
		};							\
		rc;							\
	})

#define overflow_error(action)						\
	do {								\
		log(LOG_ERR, "%s: buffer overflow\n", __func__);	\
		action;							\
	} while(0)

static void dump_io_hdr(const sg_io_hdr_t *io_hdr)
{
	unsigned int i, len, sz;
	char buf[128], *p;

	log(LOG_INFO, "id: %d dxfer_len: %u, resid: %d sb_len: %u/%u, info: %08x\n",
	    io_hdr->pack_id, io_hdr->dxfer_len, io_hdr->resid,
	    io_hdr->sb_len_wr, io_hdr->mx_sb_len, io_hdr->info);
	log(LOG_INFO, "status: %02x host_status: %04x driver_status: %04x\n",
	    io_hdr->masked_status,
	    io_hdr->host_status, io_hdr->driver_status);
	log(LOG_INFO, "time: %u/%u\n", io_hdr->duration, io_hdr->timeout);

	if (io_hdr->cmdp && io_hdr->cmd_len > 0) {
		len = io_hdr->cmd_len < 16 ? io_hdr->cmd_len : 16;
		sz = sizeof(buf);
		p = buf;
		for (i = 0; i < len; i++) {
			if (safe_snprintf(&p, &sz, "%02x", io_hdr->cmdp[i])
			    == -1)
				overflow_error(goto sense);
		}
		log(LOG_INFO, "command: %s\n", buf);
	}

sense:
	if (io_hdr->sbp && io_hdr->sb_len_wr > 0) {
		sz = sizeof(buf);
		p = buf;
		for (i = 0; i < io_hdr->sb_len_wr; i++) {
			if (safe_snprintf(&p, &sz, "%02x", io_hdr->sbp[i])
			    == -1)
				overflow_error(goto data);
		}
		log(LOG_INFO, "sense: %s\n", buf);
	}

data:
	if (io_hdr->dxferp && io_hdr->dxfer_len - io_hdr->resid > 0) {
		sz = sizeof(buf);
		p = buf;
		len = io_hdr->dxfer_len - io_hdr->resid;
		if (len > 32)
			len = 32;
		for (i = 0; i < len; i++) {
			if (safe_snprintf(&p, &sz, "%02x",
					  ((unsigned char*)io_hdr->dxferp)[i])
			    == -1)
				overflow_error(return);
		}
		log(LOG_INFO, "data: %s\n", buf);
	}
}

static int start_read(int fd, uint32_t lba, uint16_t nblocks, uint16_t blocksz,
		      unsigned char *buf, size_t sb_len, unsigned char *sb,
		      unsigned long timeout_ms, int *id)
{
	static unsigned int pack_id;
	unsigned char cmd[10] = { READ_10, };
	int rc;
	sg_io_hdr_t io_hdr = {
		.interface_id = 'S',
		.dxfer_direction = SG_DXFER_FROM_DEV,
		.cmd_len = 10,
		.mx_sb_len = sb_len,
		.sbp = sb,
		.dxfer_len = blocksz * nblocks,
		.dxferp = buf,
		.timeout = timeout_ms ? timeout_ms : DEFAULT_TIMEOUT_MS,
		.flags = SG_FLAG_DIRECT_IO,
		.pack_id = ++pack_id,
	};

	put_unaligned_be32(lba, &cmd[2]);
	put_unaligned_be16(nblocks, &cmd[7]);
	io_hdr.cmdp = cmd;

	dump_io_hdr(&io_hdr);
	rc = write(fd, &io_hdr, sizeof(io_hdr));

	log(LOG_INFO, "%s: rc = %d (%m)\n", __func__, rc);
	if (rc == sizeof(io_hdr)) {
		if (id)
			*id = pack_id;
		return 0;
	} else
		return rc;
}

static int finish_read(int fd, int id)
{
	int rc;
	sg_io_hdr_t io_hdr = {
		.interface_id = 'S',
		.dxfer_direction = SG_DXFER_FROM_DEV,
		.flags = SG_FLAG_DIRECT_IO,
		.pack_id = id,
	};

	rc = read(fd, &io_hdr, sizeof(io_hdr));
	log(LOG_INFO, "%s: rc = %d (%m)\n", __func__, rc);
	if (rc == sizeof(io_hdr)) {
		dump_io_hdr(&io_hdr);
		return 0;
	}
	return -1;
}

#define SG_DEV "/dev/sg0"
#define N_IO 4
#define ALIGN 4096
#define DATASZ (1024*1024)
#define BLKSZ 512
#define SENSESZ 256
#define LBA 0x345678

__attribute__((unused))
static int activate_force_id(int fd)
{
	int force_id = 1;

	if (ioctl(fd, SG_SET_FORCE_PACK_ID, &force_id) == -1) {
		log(LOG_ERR, "%s: SG_SET_FORCE_PACK_ID: %m\n", __func__);
		return -1;
	}
	return 0;
}

int main(int argc __attribute__((unused)),
	 char *const argv[] __attribute__((unused)))
{
	unsigned char *data = NULL, sense[N_IO*SENSESZ];
	int ret = 1, id = 0, running = 0;
	int fd, epfd, i;
	struct epoll_event ev, rev;

	if (libioc_init() == -1) {
		log(LOG_ERR, "%s: libioc_init\n", __func__);
		goto out;
	}

	epfd = epoll_create(1);
	if (epfd == -1) {
		log(LOG_ERR, "%s: epoll_create: %m\n", __func__);
		goto out;
	}

	if (posix_memalign((void**)&data, ALIGN, N_IO * DATASZ) == -1) {
		log(LOG_ERR, "%s: posix_memalign: %m\n", __func__);
		goto out_ep;
	}

	fd = open(SG_DEV, O_RDWR|O_NONBLOCK);
	if (fd == -1) {
		log(LOG_ERR, "%s: open %s: %m\n", __func__, SG_DEV);
		goto out_data;
	}

	ev.events = EPOLLIN;
	ev.data.fd = fd;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
		log(LOG_ERR, "%s: SG_SET_FORCE_PACK_ID: %m\n", __func__);
		goto out_epc;
	}

	for (i = 0; i < N_IO; i++) {
		ret = start_read(fd, LBA + i * DATASZ/BLKSZ,
				 DATASZ/BLKSZ, BLKSZ,
				 data + i * DATASZ,
				 sizeof(sense), sense + i * SENSESZ,
				 0, &id);
		if (ret == -1) {
			log(LOG_ERR, "%s: start %d: %m\n", __func__,
			    LBA + i * DATASZ/BLKSZ);
			goto out_epc;
		} else
			running++;
	}

	while (running > 0) {
		while ((ret = epoll_wait(epfd, &rev, 1, -1)) == -1 &&
		       errno == EINTR);
		if (ret == -1)
			log(LOG_ERR, "%s: wait %m\n", __func__);

		ret = finish_read(fd, 0);
		if (ret == -1) {
			log(LOG_ERR, "%s: finish running %d: %m\n",
			    __func__, running);
		} else
			running--;
	}

out_epc:
	if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL) == -1)
		log(LOG_ERR, "%s: EPOLL_CTL_DEL: %m\n", __func__);
//out_fd:
	close(fd);
out_data:
	free(data);
out_ep:
	close(epfd);
out:
	return ret;
}
