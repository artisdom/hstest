/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2002-2009  Marcel Holtmann <marcel@holtmann.org>
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
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <termios.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/param.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sco.h>
#include <bluetooth/rfcomm.h>

static volatile int terminate = 0;

static void sig_term(int sig) {
	terminate = 1;
}

static int rfcomm_connect(int ctl, bdaddr_t *src, bdaddr_t *dst, uint8_t channel)
{
	struct sockaddr_rc laddr, raddr;
    struct rfcomm_dev_req req;
    socklen_t alen;
    char dstbd[18], devname[MAXPATHLEN];
	int sk, fd, try = 30, dev = 0;

	sk = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0) {
		perror("Can't create RFCOMM socket");
		return -1;
	}

	memset(&laddr, 0, sizeof(laddr));
	laddr.rc_family = AF_BLUETOOTH;
	bacpy(&laddr.rc_bdaddr, src);
	laddr.rc_channel = 0;
	if (bind(sk, (struct sockaddr *) &laddr, sizeof(laddr)) < 0) {
		perror("Can't bind RFCOMM socket");
		close(sk);
		return -1;
	}

	memset(&raddr, 0, sizeof(raddr));
	raddr.rc_family = AF_BLUETOOTH;
	bacpy(&raddr.rc_bdaddr, dst);
	raddr.rc_channel = channel;

	if (connect(sk, (struct sockaddr *) &raddr, sizeof(raddr)) < 0) {
		perror("Can't connect RFCOMM socket");
		close(sk);
		return -1;
    }

	alen = sizeof(laddr);
	if (getsockname(sk, (struct sockaddr *)&laddr, &alen) < 0) {
		perror("Can't get RFCOMM socket name");
		close(sk);
		return -1;
	}

	snprintf(devname, MAXPATHLEN - 1, "/dev/rfcomm%d", dev);
	while ((fd = open(devname, O_RDONLY)) > 0) {
        printf("%s exist, try next.\n", devname);
        close(fd);
        dev++;
        snprintf(devname, MAXPATHLEN - 1, "/dev/rfcomm%d", dev);
    }

	memset(&req, 0, sizeof(req));
	req.dev_id = dev;
	req.flags = (1 << RFCOMM_REUSE_DLC) | (1 << RFCOMM_RELEASE_ONHUP);

	bacpy(&req.src, &laddr.rc_bdaddr);
	bacpy(&req.dst, &raddr.rc_bdaddr);
	req.channel = raddr.rc_channel;

	dev = ioctl(sk, RFCOMMCREATEDEV, &req);
	if (dev < 0) {
		perror("Can't create RFCOMM TTY");
		close(sk);
		return -1;
	}

	snprintf(devname, MAXPATHLEN - 1, "/dev/rfcomm%d", dev);
	while ((fd = open(devname, O_RDONLY | O_NOCTTY)) < 0) {
		if (errno == EACCES) {
			perror("Can't open RFCOMM device");
			goto release;
		}

		snprintf(devname, MAXPATHLEN - 1, "/dev/bluetooth/rfcomm/%d", dev);
		if ((fd = open(devname, O_RDONLY | O_NOCTTY)) < 0) {
			if (try--) {
				snprintf(devname, MAXPATHLEN - 1, "/dev/rfcomm%d", dev);
				usleep(100 * 1000);
				continue;
			}
			perror("Can't open RFCOMM device");
			goto release;
		}
    }

    close(sk);

	ba2str(&req.dst, dstbd);
	printf("Connected %s to %s on channel %d\n", devname, dstbd, req.channel);
	
	return fd;

release:
	memset(&req, 0, sizeof(req));
	req.dev_id = dev;
	req.flags = (1 << RFCOMM_HANGUP_NOW);
	ioctl(ctl, RFCOMMRELEASEDEV, &req);

	close(sk);
}

static int sco_connect(bdaddr_t *src, bdaddr_t *dst, uint16_t *handle, uint16_t *mtu)
{
	struct sockaddr_sco addr;
	struct sco_conninfo conn;
	struct sco_options opts;
	socklen_t size;
	int s;

	if ((s = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO)) < 0) {
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bacpy(&addr.sco_bdaddr, src);

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(s);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bacpy(&addr.sco_bdaddr, dst);

	if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0 ){
		close(s);
		return -1;
	}

	memset(&conn, 0, sizeof(conn));
	size = sizeof(conn);

	if (getsockopt(s, SOL_SCO, SCO_CONNINFO, &conn, &size) < 0) {
		close(s);
		return -1;
	}

	memset(&opts, 0, sizeof(opts));
	size = sizeof(opts);

	if (getsockopt(s, SOL_SCO, SCO_OPTIONS, &opts, &size) < 0) {
		close(s);
		return -1;
	}

	if (handle)
		*handle = conn.hci_handle;

	if (mtu)
		*mtu = opts.mtu;

	return s;
}

static void usage(void)
{
	printf("Usage:\n"
		"\thstest play   <file> <bdaddr> [channel]\n"
		"\thstest record <file> <bdaddr> [channel]\n");
}

#define PLAY	1
#define RECORD	2

int main(int argc, char *argv[])
{
	struct sigaction sa;

	fd_set rfds;
	struct timeval timeout;
	unsigned char buf[2048], wbuf[2048], *p;
	int maxfd, sel, rlen, wlen;

	bdaddr_t local;
	bdaddr_t bdaddr;
	uint8_t channel;

	char *filename;
	mode_t filemode;
	int err, mode = 0;
	int dd, rd, sd, fd, ctl;
	uint16_t sco_handle, sco_mtu, vs;

	switch (argc) {
	case 4:
		str2ba(argv[3], &bdaddr);
		//channel = 6;
		channel = 1;
		break;
	case 5:
		str2ba(argv[3], &bdaddr);
		channel = atoi(argv[4]);
		break;
	default:
		usage();
		exit(-1);
	}

	if (strncmp(argv[1], "play", 4) == 0) {
		mode = PLAY;
		filemode = O_RDONLY;
	} else if (strncmp(argv[1], "rec", 3) == 0) {
		mode = RECORD;
		filemode = O_RDWR | O_CREAT | O_TRUNC;
	} else {
		usage();
		exit(-1);
	}

	filename = argv[2];

	hci_devba(0, &local);
	dd = hci_open_dev(0);
	hci_read_voice_setting(dd, &vs, 1000);
	vs = htobs(vs);
	fprintf(stderr, "Voice setting: 0x%04x\n", vs);
	close(dd);
	if (vs != 0x0060) {
		fprintf(stderr, "The voice setting must be 0x0060\n");
		return -1;
	}

    ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_RFCOMM);
	if (ctl < 0) {
		perror("Can't open RFCOMM control socket");
		exit(1);
    }

	if (strcmp(filename, "-") == 0) {
		switch (mode) {
		case PLAY:
			fd = 0;
			break;
		case RECORD:
			fd = 1;
			break;
		default:
			return -1;
		}
	} else {
		if ((fd = open(filename, filemode)) < 0) {
			perror("Can't open input/output file");
			return -1;
		}
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGCHLD, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);

	if ((rd = rfcomm_connect(ctl, &local, &bdaddr, channel)) < 0) {
		return -1;
	}

	fprintf(stderr, "RFCOMM channel connected\n");

	if ((sd = sco_connect(&local, &bdaddr, &sco_handle, &sco_mtu)) < 0) {
		perror("Can't connect SCO audio channel");
		close(rd);
		close(ctl);
		return -1;
	}

	fprintf(stderr, "SCO audio channel connected (handle %d, mtu %d)\n", sco_handle, sco_mtu);

	if (mode == RECORD)
		err = write(rd, "RING\r\n", 6);

	maxfd = (rd > sd) ? rd : sd;

	while (!terminate) {

		FD_ZERO(&rfds);
		FD_SET(rd, &rfds);
		FD_SET(sd, &rfds);

		timeout.tv_sec = 0;
		timeout.tv_usec = 10000;

		if ((sel = select(maxfd + 1, &rfds, NULL, NULL, &timeout)) > 0) {

			if (FD_ISSET(rd, &rfds)) {
				memset(buf, 0, sizeof(buf));
				rlen = read(rd, buf, sizeof(buf));
                printf("read from rfcomm: %s\n", buf);
				if (rlen > 0) {
					fprintf(stderr, "%s\n", buf);
                    memset(buf, 0, sizeof(buf));
                    printf("> ");
                    fflush(0);
                    rlen = read(0, buf, sizeof(buf));
                    if (rlen > 1) {
                        buf[rlen-1] = '\0';
                        printf("you input is: %s\n", buf);

                        memset(wbuf, 0, sizeof(wbuf));
                        snprintf(wbuf, 2048, "\r\n%s\r\n", buf);

                        wlen = write(rd, wbuf, sizeof(wbuf));
                        printf("write to rfcomm: %s", wbuf);
                    }
                    
                    /*
					wlen = write(rd, "OK\r\n", 4);
                    printf("write to rfcomm: OK\n");
                    */

				}
			}

			if (FD_ISSET(sd, &rfds)) {
				memset(buf, 0, sizeof(buf));
				rlen = read(sd, buf, sizeof(buf));
				if (rlen > 0)
					switch (mode) {
					case PLAY:
						rlen = read(fd, buf, rlen);

						wlen = 0; 
						p = buf;
						while (rlen > sco_mtu) {
						        wlen += write(sd, p, sco_mtu);
						        rlen -= sco_mtu;
						        p += sco_mtu;
						}
						wlen += write(sd, p, rlen);
						break;
					case RECORD:
						wlen = write(fd, buf, rlen);
						break;
					default:
						break;
					}
			}

		}

	}

	close(sd);
    close(ctl);
	close(rd);
	close(fd);

	return 0;
}
