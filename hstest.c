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
#include <sys/poll.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sco.h>
#include <bluetooth/rfcomm.h>

static volatile int terminate = 0;
char pincode[5];

static void sig_term(int sig) {
	terminate = 1;
}

/*
static int info_request(char *svr)
{
    unsigned char buf[48];
    l2cap_cmd_hdr *cmd = (l2cap_cmd_hdr *) buf;
    l2cap_info_req *req = (l2cap_info_req *) (buf + L2CAP_CMD_HDR_SIZE);
    l2cap_info_rsp *rsp = (l2cap_info_rsp *) (buf + L2CAP_CMD_HDR_SIZE);
    l2cap_conn_req *req_n = (l2cap_conn_req *) (buf + L2CAP_CMD_HDR_SIZE);
    l2cap_conn_rsp *rsp_n = (l2cap_conn_rsp *) (buf + L2CAP_CMD_HDR_SIZE);
    l2cap_conf_req *req_f = (l2cap_conf_req *) (buf + L2CAP_CMD_HDR_SIZE);
    l2cap_conf_rsp *rsp_f = (l2cap_conf_rsp *) (buf + L2CAP_CMD_HDR_SIZE);
    uint16_t mtu, scid, dcid;
    uint32_t channels, mask = 0x0000;
    struct sockaddr_l2 addr;
    int sk, err;
    static bdaddr_t bdaddr;

    sk = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP);
    if (sk < 0) {
        perror("Can't create socket");
        return -1;
    }

    bacpy(&bdaddr, BDADDR_ANY);
    memset(&addr, 0, sizeof(addr));
    addr.l2_family = AF_BLUETOOTH;
    bacpy(&addr.l2_bdaddr, &bdaddr);

    if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("Can't bind socket");
        goto failed;
    }

    memset(&addr, 0, sizeof(addr));
    addr.l2_family = AF_BLUETOOTH;
    str2ba(svr, &addr.l2_bdaddr);

    if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0 ) {
        perror("Can't connect socket");
        goto failed;
    }

    memset(buf, 0, sizeof(buf));
    cmd->code  = EVT_LINK_KEY_REQ
    cmd->ident = 142;
    cmd->len   = htobs(2);
    req->type  = htobs(0x0002);

    if (send(sk, buf, L2CAP_CMD_HDR_SIZE + L2CAP_INFO_REQ_SIZE, 0) < 0) {
        perror("Can't send info request");
        goto failed;
    }

    err = recv(sk, buf, L2CAP_CMD_HDR_SIZE + L2CAP_INFO_RSP_SIZE + 4, 0);
    if (err < 0) {
        perror("Can't receive info response");
        goto failed;
    }

    memset(buf, 0, sizeof(buf));
    cmd->code  = L2CAP_INFO_REQ;
    cmd->ident = 142;
    cmd->len   = htobs(2);
    req->type  = htobs(0x0002);

    if (send(sk, buf, L2CAP_CMD_HDR_SIZE + L2CAP_INFO_REQ_SIZE, 0) < 0) {
        perror("Can't send info request");
        goto failed;
    }

    err = recv(sk, buf, L2CAP_CMD_HDR_SIZE + L2CAP_INFO_RSP_SIZE + 4, 0);
    if (err < 0) {
        perror("Can't receive info response");
        goto failed;
    }

    switch (btohs(rsp->result)) {
        case 0x0000:
            memcpy(&mask, rsp->data, sizeof(mask));
            printf("Extended feature mask is 0x%04x\n", btohl(mask));
            if (mask & 0x01)
                printf("  Flow control mode\n");
            if (mask & 0x02)
                printf("  Retransmission mode\n");
            if (mask & 0x04)
                printf("  Bi-directional QoS\n");
            if (mask & 0x08)
                printf("  Enhanced Retransmission mode\n");
            if (mask & 0x10)
                printf("  Streaming mode\n");
            if (mask & 0x20)
                printf("  FCS Option\n");
            if (mask & 0x40)
                printf("  Extended Flow Specification\n");
            if (mask & 0x80)
                printf("  Fixed Channels\n");
            if (mask & 0x0100)
                printf("  Extended Window Size\n");
            if (mask & 0x0200)
                printf("  Unicast Connectionless Data Reception\n");
            break;
        case 0x0001:
            printf("Extended feature mask is not supported\n");
            break;
    }

    memset(buf, 0, sizeof(buf));
    cmd->code  = L2CAP_CONN_REQ;
    cmd->ident = 143;
    cmd->len   = htobs(4);
    req_n->psm  = htobs(1);
    req_n->scid = htobs(0x0040);

    if (send(sk, buf, L2CAP_CMD_HDR_SIZE + L2CAP_CONN_REQ_SIZE, 0) < 0) {
        perror("Can't send conn request");
        goto failed;
    }

    err = recv(sk, buf, L2CAP_CMD_HDR_SIZE + L2CAP_CONN_RSP_SIZE + 4, 0);
    if (err < 0) {
        perror("Can't receive conn response");
        goto failed;
    }
    printf("Connect rsp: dcid 0x%04x scid 0x%04x result %d status %d\n",
            btohs(rsp_n->dcid),
            btohs(rsp_n->scid),
            btohs(rsp_n->result),
            btohs(rsp_n->status));
    switch (btohs(rsp_n->result)) {
        case 0x0000:
            printf("Connection successful\n");
            break;
        case 0x0001:
            printf("Connection pending\n");
            break;
        case 0x0002:
            printf("bad psm\n");
            break;
        case 0x0003:
            printf("sec block\n");
            break;
        case 0x0004:
            printf("no memory\n");
            break;
    }

    scid = rsp_n->dcid;
    dcid = rsp_n->scid;

    memset(buf, 0, sizeof(buf));
    cmd->code  = L2CAP_CONF_REQ;
    cmd->ident = 144;
    cmd->len   = htobs(4);
    req_f->dcid = dcid;
    req_f->flags = htobs(0x00);

    if (send(sk, buf, L2CAP_CMD_HDR_SIZE + L2CAP_CONF_REQ_SIZE, 0) < 0) {
        perror("Can't send conf request");
        goto failed;
    }

    err = recv(sk, buf, L2CAP_CMD_HDR_SIZE + L2CAP_CONF_RSP_SIZE + 4, 0);
    if (err < 0) {
        perror("Can't receive conf response");
        goto failed;
    }

    sleep(5);
    memset(buf, 0, sizeof(buf));
    cmd->code  = L2CAP_CONF_RSP;
    cmd->ident = 145;
    cmd->len   = htobs(4);
    rsp_f->scid = scid;
    rsp_f->flags = htobs(0x00);

    if (send(sk, buf, L2CAP_CMD_HDR_SIZE + L2CAP_CONF_RSP_SIZE, 0) < 0) {
        perror("Can't send conf request");
        goto failed;
    }

    close(sk);
    return 0;

failed:
    close(sk);
    return -1;
}
*/

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

static int hci_send_req_n(int dd, struct hci_request *r, int to)
{
    unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
    struct hci_filter nf, of;
    socklen_t olen;
    hci_event_hdr *hdr;
    int err, try;

    olen = sizeof(of);
    if (getsockopt(dd, SOL_HCI, HCI_FILTER, &of, &olen) < 0)
        return -1;

    hci_filter_clear(&nf);
    hci_filter_set_ptype(HCI_EVENT_PKT,  &nf);
    hci_filter_set_event(EVT_CMD_STATUS, &nf);
    hci_filter_set_event(EVT_CMD_COMPLETE, &nf);
    hci_filter_set_event(EVT_LINK_KEY_REQ, &nf);
    hci_filter_set_event(EVT_PIN_CODE_REQ, &nf);
    hci_filter_set_event(r->event, &nf);
    if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0)
        return -1;

    if (hci_send_cmd(dd, r->ogf, r->ocf, r->clen, r->cparam) < 0)
        goto failed;

    try = 10;
    while (try--) {
        evt_cmd_complete *cc;
        evt_cmd_status *cs;
        evt_remote_name_req_complete *rn;
        remote_name_req_cp *cp;
        evt_link_key_req *lkrq;
        evt_pin_code_req *pcrq;
        pin_code_reply_cp pcrp;
        int len;

        if (to) {
            struct pollfd p;
            int n;

            p.fd = dd; p.events = POLLIN;
            while ((n = poll(&p, 1, to)) < 0) {
                if (errno == EAGAIN || errno == EINTR)
                    continue;
                goto failed;
            }

            if (!n) {
                errno = ETIMEDOUT;
                goto failed;
            }

            to -= 10;
            if (to < 0) to = 0;

        }

        while ((len = read(dd, buf, sizeof(buf))) < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            goto failed;
        }

        hdr = (void *) (buf + 1);
        ptr = buf + (1 + HCI_EVENT_HDR_SIZE);
        len -= (1 + HCI_EVENT_HDR_SIZE);

        switch (hdr->evt) {
            case EVT_LINK_KEY_REQ:
                lkrq = (void *) ptr;
                hci_send_cmd(dd, OGF_LINK_CTL, OCF_LINK_KEY_NEG_REPLY, 6, &((*lkrq).bdaddr));
                break;

            case EVT_PIN_CODE_REQ:
                pcrq = (void *) ptr;
                size_t len;
                len = strlen(pincode);
                memset(&pcrp, 0, sizeof(pcrp));
                bacpy(&pcrp.bdaddr, &((*pcrq).bdaddr));
                memcpy(pcrp.pin_code, pincode, len);
                pcrp.pin_len = len;
                hci_send_cmd(dd, OGF_LINK_CTL, OCF_PIN_CODE_REPLY,
                        PIN_CODE_REPLY_CP_SIZE, &pcrp);
                break;
            case EVT_AUTH_COMPLETE:
                goto done;

            default:
                break;
        }
    }
    errno = ETIMEDOUT;

failed:
    err = errno;
    setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));
    errno = err;
    return -1;

done:
    setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));
    return 0;
}

static void usage(void)
{
	printf("Usage:\n"
		"\thstest play   <file> <pincode> <bdaddr> [channel]\n"
		"\thstest record <file> <pincode> <bdaddr> [channel]\n");
}

#define PLAY	1
#define RECORD	2

int main(int argc, char *argv[])
{
	struct sigaction sa;

	fd_set rfds;
	struct timeval timeout;
	unsigned char buf[2048], *p;
	int maxfd, sel, rlen, wlen;

	bdaddr_t local;
	bdaddr_t bdaddr;
	uint8_t channel;

	char *filename;
	mode_t filemode;
	int err, mode = 0;
	int dd, rd, sd, fd, ctl;
	uint16_t sco_handle, sco_mtu, vs;

    uint16_t handle;
    uint8_t role;
    unsigned int ptype;
    size_t len;
    evt_auth_complete rp;
    auth_requested_cp cp;
    struct hci_request rq;

    role = 0x01;
    ptype = HCI_DM1 | HCI_DM3 | HCI_DM5 | HCI_DH1 | HCI_DH3 | HCI_DH5;

    if(argc < 5) {
        usage();
        exit(1);
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

    memset(pincode, 0, sizeof(pincode));
    strncpy(pincode, argv[3], 4);
    printf("pincode: %s\n", pincode);
    str2ba(argv[4], &bdaddr);
	switch (argc) {
	case 5:
		channel = 1;
		break;
	case 6:
		channel = atoi(argv[5]);
		break;
	default:
		usage();
		exit(-1);
	}

	hci_devba(0, &local);
	dd = hci_open_dev(0);
    if (dd < 0) {
        perror("HCI device open failed");
        exit(1);
    }
	hci_read_voice_setting(dd, &vs, 1000);
	vs = htobs(vs);
	fprintf(stderr, "Voice setting: 0x%04x\n", vs);
	if (vs != 0x0060) {
		fprintf(stderr, "The voice setting must be 0x0060\n");
		return -1;
	}

    if (hci_create_connection(dd, &bdaddr, htobs(ptype),
                htobs(0x0000), role, &handle, 25000) < 0)
    {
        perror("Can't create connection");
        exit(1);
    }

    cp.handle = handle;

    rq.ogf    = OGF_LINK_CTL;
    rq.ocf    = OCF_AUTH_REQUESTED;
    rq.event  = EVT_AUTH_COMPLETE;
    rq.cparam = &cp;
    rq.clen   = AUTH_REQUESTED_CP_SIZE;
    rq.rparam = &rp;
    rq.rlen   = EVT_AUTH_COMPLETE_SIZE;
    hci_send_req_n(dd, &rq, 25000);

    hci_close_dev(dd);

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
					wlen = write(rd, "OK\r\n", 4);
                    printf("write to rfcomm: OK\n");

				}
			}

			if (FD_ISSET(sd, &rfds)) {
				memset(buf, 0, sizeof(buf));
				rlen = read(sd, buf, sizeof(buf));
				if (rlen > 0)
					switch (mode) {
					case PLAY:
						rlen = read(fd, buf, rlen);
                        if(rlen == 0)
                            goto done;

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

done:
	close(sd);
    close(ctl);
	close(rd);
	close(fd);

	return 0;
}
