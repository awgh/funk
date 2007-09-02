;;;; egg:      rawsock
;;;; file:     rawsock.scm
;;;; author:   Lenny Frank <elf@ephemeral.net>
;;;; author:   Benjamin Kurtz <bk2@alum.wpi.edu>
;;;; date:     31 aug 2007
;;;; licence:  BSD
;;;; purpose:  POSIX raw sockets
;;;; version:  2.0
;;;; changes:  v1.0 written by bk2 (available as raw-sockets)
;;;;           v2.0 refactored and cleaned by elf


#>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
<#

(define-foreign-variable errno int "errno")
(define-foreign-variable h_errno int "h_errno")
(define strerror (foreign-lambda c-string "strerror" int))

(eval-when (compile)
    (cond-expand
        ((linux)

#>
#include <asm/types.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>

struct sockaddr_ll *
make_saddr(char *iface, int fd)
{
    struct sockaddr_ll *saddr = (struct sockaddr_ll *)malloc(sizeof(struct sockaddr_ll));
    struct ifreq ireq;
    if (saddr == NULL)
        return 0;
    bzero(&ireq, sizeof(ireq));
    bzero(saddr, sizeof(struct sockaddr_ll));
    strcpy(&ireq.ifr_name, iface);
    if (ioctl(fd, SIOCGIFINDEX, &ireq) == -1) {
        free(saddr);
        return 0;
    }
    saddr->sll_ifindex = ireq.ifr_ifindex;
    saddr->sll_family = AF_PACKET;
    saddr->sll_protocol = htons(ETH_P_ALL);
    return saddr;
}

<#

(define-foreign-variable _sock_domain int "PF_PACKET")
(define-foreign-variable _sock_type int "SOCK_RAW")
(define-foreign-variable _sock_proto int "htons(ETH_P_ALL)")
(define-foreign-variable _sock_size int "sizeof(struct sockaddr_ll)")
(define-foreign-variable _mta_size int "1500")

        )
        ((macosx)

#>
#include <net/ndrv.h>

struct sockaddr *
make_saddr(char *iface, int fd)
{
    struct sockaddr *saddr = (struct sockaddr *)malloc(sizeof(struct sockaddr));
    if (saddr == NULL)
        return 0;
    saddr->sa_len = sizeof(struct sockaddr);
    saddr->sa_family = AF_NDRV;
    strcpy(saddr->sa_data, iface);
    return saddr;
}

<#

(define-foreign-variable _sock_domain int "AF_NDRV")
(define-foreign-variable _sock_type int "SOCK_RAW")
(define-foreign-variable _sock_proto int "0")
(define-foreign-variable _sock_size int "sizeof(struct sockaddr)")
(define-foreign-variable _mta_size int "1500")

        )
        (else
            (error "rawsock only works on macosx and linux targets.\n"))
    ))

(define ##raw#socket (foreign-lambda int "socket" int int int))
(define ##raw#makesaddr (foreign-lambda pointer "make_saddr" c-string int))
(define ##raw#free (foreign-lambda int "free" pointer))
(define ##raw#close (foreign-lambda int "close" int))

(define ##raw#bind
    (foreign-lambda* int ((int fd) (pointer saddr) (int size))
        "return (bind(fd, (struct sockaddr *)saddr, size));"
    ))

(define ##raw#send
    (foreign-lambda* int ((int fd) (pointer saddr) (int ssize) (u8vector pkt) (int len))
        "int nleft = len;"
        "int nwrit = 0;"
        "unsigned char *p = pkt;"
        "while (nleft > 0) {"
        "    nwrit = sendto(fd, p, nleft, 0, (struct sockaddr *)saddr, ssize);"
        "    if (nwrit <= 0) {"
        "        if (errno == EINTR)"
        "            nwrit = 0;"
        "        else"
        "            return -1;"
        "    }"
        "    nleft -= nwrit;"
        "    p += nwrit;"
        "}"
        "return 0;"
    ))


(define (raw-error pname msg . args)
    (signal
        (make-composite-condition
            (make-property-condition 'exn
                                     'message msg
                                     'location pname
                                     'arguments args)
            (make-property-condition 'raw-socket))))

(define (raw-errno pname errno msg . args)
    (apply raw-error pname (string-append msg " - " (strerror errno)) args))

;;; structure
;;; 1  2     3     4
;;; fd saddr iface open?

(define (raw-socket? d)
    (and (##core#inline "C_blockp" d)
         (##sys#structure? d 'raw-socket)))

(define (raw-socket-fd d)       (##sys#slot d 1))
(define (raw-socket-saddr d)    (##sys#slot d 2))
(define (raw-socket-iface d)    (##sys#slot d 3))
(define (raw-socket-open d)    (##sys#slot d 4))

(define (raw-socket-open? d)
    (and (raw-socket? d) (##sys#slot d 4)))

(define (open-raw-socket iface)
    (let ((pname   'open-raw-socket))
        (or (and (string? iface) (not (string-null? iface)))
            (raw-error pname "iface must be a non-null string" iface))
        (let ((fd   (##raw#socket _sock_domain _sock_type _sock_proto)))
            (and (< fd 0)
                 (raw-errno pname errno "could not create socket" iface))
            (let ((saddr   (##raw#makesaddr iface fd))
                  (e       errno))
                (and (= 0 saddr)
                     (##raw#close fd)
                     (raw-errno pname e "could not create saddr" iface))
                (let ((t   (##raw#bind fd saddr _sock_size))
                      (e   errno))
                    (and (< 0 t)
                         (##raw#close fd)
                         (##raw#free saddr)
                         (raw-errno pname e "could not bind socket" iface))
                    (##sys#make-structure 'raw-socket fd saddr iface #t))))))

(define (raw-send s pkt)
    (or (raw-socket? s)
        (raw-error 'raw-send (conc "not a raw-socket: " s) s pkt))
    (or (raw-socket-open? s)
        (raw-error 'raw-send "raw socket is closed" s pkt))
    (or (u8vector? pkt)
        (raw-error 'raw-send (conc "not a u8vector: " pkt) s pkt))
    (if (= 0 (##raw#send (raw-socket-fd s) (raw-socket-saddr s) _sock_size pkt (u8vector-length pkt)))
        #t
        (raw-errno 'raw-send errno "could not send" s pkt)))

(define (raw-recv s)
    (or (raw-socket? s)
        (raw-error 'raw-recv (conc "not a raw socket: " s) s))
    (or (raw-socket-open? s)
        (raw-error 'raw-recv "raw socket is closed" s))
    (

(define (close-raw-socket s)
    (or (raw-socket? s)
        (raw-error 'close-raw-socket (conc "not a raw socket: " s) s))
    (if (raw-socket-open? s)
        (begin
            (##raw#close (raw-socket-fd s))
            (##raw#free (raw-socket-saddr s))
            (##sys#setslot s 4 #f)
            #t)
        #t))

