;;;; egg:      rawsock
;;;; file:     rawsock.scm
;;;; author:   Lenny Frank <elf@ephemeral.net>
;;;; author:   Benjamin Kurtz <bk2@alum.wpi.edu>
;;;; date:     31 aug 2007
;;;; licence:  BSD
;;;; purpose:  POSIX raw sockets
;;;; version:  2.1
;;;; changes:  v1.0 written by bk2 (available as raw-sockets)
;;;;           v2.0 refactored and cleaned by elf
;;;;           v2.1 added non-blocking read (elf)




;; chicken library loading 

;(use library)    ; basic library functions (required for optimising compilation)
(require-extension srfi-4)     ; homogenous vectors
(require-extension srfi-13)    ; string library
(require-extension srfi-66)    ; octet vectors


;; chicken compile-time declarations

(eval-when (compile)
    (declare
        (uses library srfi-4 srfi-13)
        (always-bound
            errno
            h_errno
            _sock_domain
            _sock_type
            _sock_proto
            _sock_size
            )
        (bound-to-procedure
            strerror
            ##raw#socket
            ##raw#makesaddr
            ##raw#free
            ##raw#close
            ##raw#bind
            ##raw#send
            ##raw#recv
            raw-error
            raw-errno
            raw-socket?
            raw-socket-fd
            raw-socket-saddr
            raw-socket-iface
            raw-socket-mta
            raw-socket-open
            raw-socket-open?
            open-raw-socket
            raw-send
            raw-recv
            close-raw-socket
            )
        (export
            raw-socket?
            raw-socket-open?
            open-raw-socket
            raw-send
            raw-recv
            close-raw-socket
            )
        (emit-exports "rawsock.exports")
        ;(block)
        (import "srfi-66")
        (fixnum-arithmetic)
        (lambda-lift)
        (inline)
        (compress-literals)
        (no-bound-checks)
        (no-procedure-checks)
        (standard-bindings)
        (extended-bindings)
        (usual-integrations)
        (interrupts-enabled)
    ))


;; FFI directives

#>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/time.h>
#include <sys/select.h>

#ifdef __MACH__
#include <net/ndrv.h>
#else
#include <asm/types.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#endif

<#

(define-foreign-variable errno int "errno")
(define-foreign-variable h_errno int "h_errno")
(define strerror (foreign-lambda c-string "strerror" int))

;; only compile for allowed targets
(cond-expand
    (linux
        (define ##raw#makesaddr
            (foreign-lambda* c-pointer ((c-string iface) (int fd))
                "struct sockaddr_ll *saddr = (struct sockaddr_ll *)malloc(sizeof(struct sockaddr_ll));"
                "struct ifreq ireq;"
                "if (saddr == NULL)"
                "    return(NULL);"
                "bzero(&ireq, sizeof(ireq));"
                "bzero(saddr, sizeof(struct sockaddr_ll));"
                "strcpy(&ireq.ifr_name, iface);"
                "if (ioctl(fd, SIOCGIFINDEX, &ireq) == -1) {"
                "    free(saddr);"
                "    return(NULL);"
                "}"
                "saddr->sll_ifindex = ireq.ifr_ifindex;"
                "saddr->sll_family = AF_PACKET;"
                "saddr->sll_protocol = htons(ETH_P_ALL);"
                "return(saddr);"
            ))
        (define ##raw#makemtasize
            (foreign-lambda* int ((int fd) (c-pointer saddr) (c-string iface))
                "return(1500);"
            ))
        (define ##raw#free
            (foreign-lambda* void ((c-pointer saddr))
                "free((struct sockaddr_ll *)saddr);"
            ))
        (define-foreign-variable _sock_domain int "PF_PACKET")
        (define-foreign-variable _sock_type int "SOCK_RAW")
        (define-foreign-variable _sock_proto int "htons(ETH_P_ALL)")
        (define-foreign-variable _sock_size int "sizeof(struct sockaddr_ll)")
    )
    (macosx
        (define ##raw#makesaddr
            (foreign-lambda* c-pointer ((c-string iface) (int fd))
                "struct sockaddr *saddr = (struct sockaddr *)malloc(sizeof(struct sockaddr));"
                "if (saddr == NULL)"
                "    return(NULL);"
                "saddr->sa_len = sizeof(struct sockaddr);"
                "saddr->sa_family = AF_NDRV;"
                "strcpy(saddr->sa_data, iface);"
                "return(saddr);"
            ))
        (define ##raw#makemtasize
            (foreign-lambda* int ((int fd) (c-pointer saddr) (c-string iface))
                "return(1500);"
            ))
        (define ##raw#free
            (foreign-lambda* void ((c-pointer saddr))
                "free((struct sockaddr *)saddr);"
            ))
        (define-foreign-variable _sock_domain int "AF_NDRV")
        (define-foreign-variable _sock_type int "SOCK_RAW")
        (define-foreign-variable _sock_proto int "0")
        (define-foreign-variable _sock_size int "sizeof(struct sockaddr)")
    )
    (else
        (error "rawsock only works on macosx and linux targets.\n"))
)


;; syscall bindings

(define ##raw#socket (foreign-lambda int "socket" int int int))
;(define ##raw#makesaddr (foreign-lambda c-pointer "make_saddr" c-string int))
;(define ##raw#makemtasize (foreign-lambda int "make_mta_size" int c-pointer c-string))
;(define ##raw#free (foreign-lambda int "free" c-pointer))
(define ##raw#close (foreign-lambda int "close" int))

(define ##raw#bind
    (foreign-lambda* int ((int fd) (c-pointer saddr) (int size))
        "return (bind(fd, (struct sockaddr *)saddr, size));"
    ))

;; low-level raw send
(define ##raw#send
    (foreign-lambda* int ((int fd) (c-pointer saddr) (int ssize) (u8vector pkt) (int len))
        "int nleft = len;"
        "int nwrit = 0;"
        "unsigned char *p = pkt;"
        "while (nleft > 0) {"
        "    nwrit = sendto(fd, p, nleft, 0, (struct sockaddr *)saddr, ssize);"
        "    if (nwrit <= 0) {"
        "        if (errno == EINTR)"
        "            nwrit = 0;"
        "        else"
        "            return(-1);"
        "    }"
        "    nleft -= nwrit;"
        "    p += nwrit;"
        "}"
        "return(0);"
    ))

;; low-level raw non-blocking receive
(define ##raw#recv
    (foreign-lambda* int ((int fd) (int mtasize) (u8vector pkt))
        "int nread;"
        "struct timeval tv = { 0, 0 };"
        "fd_set rds;"
        "FD_ZERO(&rds);"
        "FD_SET(fd, &rds);"
        "do {"
        "    nread = select(fd+1, &rds, NULL, NULL, &tv);"
        "} while (errno == EINTR);"
        "if (nread <= 0)"
        "    return(nread);"
        "nread = read(fd, pkt, mtasize);"
        "return(nread);"
    ))


;; error procedures

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


;; exported interface (mostly) 

;;; structure
;;; 1  2     3     4        5
;;; fd saddr iface mta-size open?

;; predicate for identifying raw socket objects
(define (raw-socket? d)
    (and (##core#inline "C_blockp" d)
         (##sys#structure? d 'raw-socket)))

;; slot accessors (not exported)
(define (raw-socket-fd d)       (##sys#slot d 1))
(define (raw-socket-saddr d)    (##sys#slot d 2))
(define (raw-socket-iface d)    (##sys#slot d 3))
(define (raw-socket-mta d)      (##sys#slot d 4))
(define (raw-socket-open d)     (##sys#slot d 5))

;; predicate for identifying if the raw-socket is open
(define (raw-socket-open? d)
    (and (raw-socket? d) (##sys#slot d 5)))

;; opens a raw socket on the given interface
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
                (let ((m   (##raw#makemtasize fd saddr iface))
                      (t   (##raw#bind fd saddr _sock_size))
                      (e   errno))
                    (and (< 0 t)
                         (##raw#close fd)
                         (##raw#free saddr)
                         (raw-errno pname e "could not bind socket" iface))
                    (##sys#make-structure 'raw-socket fd saddr iface m #t))))))

;; sends a packet on the raw socket
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

;; receives a packet on a raw socket
;; returns (length . packet) on success
(define (raw-recv s)
    (or (raw-socket? s)
        (raw-error 'raw-recv (conc "not a raw socket: " s) s))
    (or (raw-socket-open? s)
        (raw-error 'raw-recv "raw socket is closed" s))
    (let* ((p   (make-u8vector (raw-socket-mta s)))
           (r   (##raw#recv (raw-socket-fd s) (raw-socket-mta s) p)))
        (case r
            ((-1)
                (raw-errno 'raw-recv errno "could not recv" s))
            ((0)
                (cons 0 (make-u8vector 0)))
            (else
                (let ((ret   (make-u8vector r)))
                    (u8vector-copy! p 0 ret 0 r)
                    (cons r ret))))))

;; closes a raw socket and frees the associated memory
(define (close-raw-socket s)
    (or (raw-socket? s)
        (raw-error 'close-raw-socket (conc "not a raw socket: " s) s))
    (if (raw-socket-open? s)
        (begin
            (##raw#close (raw-socket-fd s))
            (##raw#free (raw-socket-saddr s))
            (##sys#setslot s 5 #f)
            #t)
        #t))

