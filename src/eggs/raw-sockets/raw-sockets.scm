;;;; egg:      raw-sockets
;;;; file:     raw-sockets.scm
;;;; author:   Lenny Frank <elf@ephemeral.net>
;;;; author:   Benjamin L. Kurtz <bk2@alum.wpi.edu>
;;;; date:     18 Sep 2007
;;;; licence:  BSD (see LICENCE)
;;;; version:  3.0
;;;; purpose:  UNIX packet socket interface
;;;;
;;;; history:  3.0  Removed raw-recv (elf)
;;;;                Added read handlers (elf, bk2)
;;;;                Set promiscuous mode (elf)
;;;;                Proper MTU checking (elf)
;;;;           2.1  Added non-blocking read (elf)
;;;;           2.0  Refactored and cleaned everything (elf)
;;;;           1.0  Initial release (bk2)




;;; chicken library loading

(require-extension posix)      ; POSIX bindings
(require-extension srfi-1)     ; list library
(require-extension srfi-4)     ; homogenous numeric vectors
(require-extension srfi-13)    ; string library
(require-extension srfi-66)    ; octet vectors


;;; chicken compile-time options

(eval-when (compile)
    (declare
        (uses library extras posix srfi-1 srfi-4 srfi-13)
        (always-bound
            errno
            h_errno
            _sdomain   ; socket domain
            _stype     ; socket type
            _sproto    ; socket protocol
            _ssize     ; size of relevant sockaddr* struct
            _isize     ; IFNAMSIZ
            sigio-orig
            sigio-inst
            fd-count
            fd-max
            fd-table
            fd-vec
            fd-list
            fd-srvec
            fd-swvec
            fd-swind
            )
        (bound-to-procedure
            ##raw#strerror
            ##raw#makesaddr
            ##raw#free
            ##raw#getmtu
            ##raw#promisc-on
            ##raw#promisc-off
            ##raw#async
            ##raw#socket
            ##raw#close
            ##raw#bind
            ##raw#send
            ##raw#receive
            ##raw#select
            raw-error
            raw-errno
            raw-syscall
            ##raw#fd
            ##raw#saddr
            ##raw#iface
            ##raw#liface
            ##raw#mtu
            ##raw#flags
            ##raw#open?
            ##raw#recvers
            ##raw#wready?
            ##raw#wqueue
            ##raw#trecvers
            ##raw#ewqueue?
            ; ##raw#fd!
            ; ##raw#saddr!
            ; ##raw#iface!
            ; ##raw#liface!
            ; ##raw#mtu!
            ; ##raw#flags!
            ##raw#open!
            ##raw#wready!
            ##raw#urecvers!
            ##raw#drecvers!
            ##raw#awqueue!
            ##raw#pwqueue!
            ##raw#sigio-resetw
            ##raw#sigio-resetr
            ##raw#sigio-helper-write
            ##raw#sigio-helper-read
            ##raw#sigio-handler
            raw-socket?
            raw-socket-open?
            check-raw-socket
            open-raw-socket
            raw-socket-domain
            raw-socket-type
            raw-socket-protocol
            raw-socket-fd
            raw-socket-saddr
            raw-socket-iface
            raw-socket-mtu
            raw-socket-send
            raw-socket-add-recver
            raw-socket-del-recver
            raw-socket-recvers
            close-raw-socket
            )
        (constant
            ##raw#fd
            ##raw#saddr
            ##raw#iface
            ##raw#liface
            ##raw#mtu
            ##raw#flags
            ##raw#open?
            ##raw#recvers
            ##raw#wready?
            ##raw#wqueue
            ##raw#trecvers
            ##raw#ewqueue?
            raw-socket?
            raw-socket-open?
            raw-socket-domain
            raw-socket-type
            raw-socket-protocol
            raw-socket-fd
            raw-socket-saddr
            raw-socket-iface
            raw-socket-mtu
            raw-socket-recvers
            )
        (export
            open-raw-socket
            raw-socket?
            raw-socket-open?
            raw-socket-domain
            raw-socket-type
            raw-socket-protocol
            raw-socket-fd
            raw-socket-saddr
            raw-socket-iface
            raw-socket-mtu
            raw-socket-send
            raw-socket-add-recver
            raw-socket-del-recver
            raw-socket-recvers
            close-raw-socket
            )
        (emit-exports "raw-sockets.exports")
        (import "srfi-4" "srfi-66")
        (fixnum-arithmetic)
        (lambda-lift)
        (inline)
        (inline-limit 100)
        (compress-literals)
        (no-bound-checks)
        (no-procedure-checks)
        (standard-bindings)
        (extended-bindings)
        (usual-integrations)
        (interrupts-enabled)
    ))


;;; FFI directives

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
#include <fcntl.h>
#include <sys/ioctl.h>

#ifdef __MACH__
#include <net/ndrv.h>
#else
#include <asm/types.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#endif

<#


;;; C error handling

(define-foreign-variable errno int "errno")
(define-foreign-variable h_errno int "h_errno")

(define ##raw#strerror
    (foreign-lambda c-string "strerror" int))


;;; target-specific compilation

(cond-expand
    (linux
        ;; make the saddr structure (struct sockaddr_ll)
        (define ##raw#makesaddr
            (foreign-lambda* c-pointer ((int fd) (c-string iface) (int l))
                "struct sockaddr_ll *saddr = (struct sockaddr_ll *)malloc(sizeof(struct sockaddr_ll));"
                "struct ifreq ireq;"
                "if (saddr == NULL)"
                "    return(-1);"
                "bzero(&ireq, sizeof(struct ifreq));"
                "bzero(saddr, sizeof(struct sockaddr_ll));"
                "strncpy(ireq.ifr_name, iface, l);"
                "ireq.ifr_name[l] = '\\0';"
                "if (ioctl(fd, SIOCGIFINDEX, &ireq) == -1) {"
                "    free(saddr);"
                "    return(-1);"
                "}"
                "saddr->sll_ifindex = ireq.ifr_ifindex;"
                "saddr->sll_family = AF_PACKET;"
                "saddr->sll_protocol = htons(ETH_P_ALL);"
                "return(saddr);"
            ))
        ;; free the saddr structure (struct sockaddr_ll)
        (define ##raw#free
            (foreign-lambda* void ((c-pointer saddr))
                "free((struct sockaddr_ll *)saddr);"
            ))
        ;; get the MTU size
        (define ##raw#getmtu
            (foreign-lambda* int ((int fd) (c-string iface) (int l))
                "struct ifreq ireq;"
                "bzero(&ireq, sizeof(struct ifreq));"
                "strncpy(ireq.ifr_name, iface, l);"
                "ireq.ifr_name[l] = '\\0';"
                "if (ioctl(fd, SIOCGIFMTU, &ireq) == -1)"
                "    return(-1);"
                "return(ireq.ifr_mtu);"
            ))
        (define-foreign-variable _sdomain int "PF_PACKET")
        (define-foreign-variable _stype   int "SOCK_RAW")
        (define-foreign-variable _sproto  int "htons(ETH_P_ALL)")
        (define-foreign-variable _ssize   int "sizeof(struct sockaddr_ll)")
        (define-foreign-variable _isize   int "IFNAMSIZ")
    )
    (macosx
        ;; make the saddr structure (struct sockaddr)
        (define ##raw#makesaddr
            (foreign-lambda* c-pointer ((int fd) (c-string iface) (int l))
                "struct sockaddr *saddr = (struct sockaddr *)malloc(sizeof(struct sockaddr));"
                "if (saddr == NULL)"
                "    return(-1);"
                "saddr->sa_len = sizeof(struct sockaddr);"
                "saddr->sa_family = AF_NDRV;"
                "strncpy(saddr->sa_data, iface, l);"
                "saddr->sa_data[l] = '\\0';"
                "return(saddr);"
            ))
        ;; free the saddr structure (struct sockaddr)
        (define ##raw#free
            (foreign-lambda* void ((c-pointer saddr))
                "free((struct sockaddr *)saddr);"
            ))
        ;; get the MTU size
        (define ##raw#getmtu
            (foreign-lambda* int ((int fd) (c-string iface) (int l))
                "struct ifreq ireq;"
                "bzero(&ireq, sizeof(struct ifreq));"
                "strncpy(ireq.ifr_name, iface, l);"
                "ireq.ifr_name[l] = '\\0';"
                "if (ioctl(fd, SIOCGIFMTU, &ireq) == -1)"
                "    return(-1);"
                "return((ireq.ifr_mtu - 1));"
            ))
        (define-foreign-variable _sdomain int "AF_NDRV")
        (define-foreign-variable _stype   int "SOCK_RAW")
        (define-foreign-variable _sproto  int "0")
        (define-foreign-variable _ssize   int "sizeof(struct sockaddr)")
        (define-foreign-variable _isize   int "IFNAMSIZ")
    )
    (else
        (error "raw-sockets only supported for macosx and linux targets."))
)


;;; ioctl/fcntl procedures

;; turn on promiscuous mode and return the current IF_FLAGS value
(define ##raw#promisc-on
    (foreign-lambda* integer32 ((int fd) (c-string iface) (int l))
        "struct ifreq ireq;"
        "int ret;"
        "bzero(&ireq, sizeof(struct ifreq));"
        "strncpy(ireq.ifr_name, iface, l);"
        "ireq.ifr_name[l] = '\\0';"
        "if (ioctl(fd, SIOCGIFFLAGS, &ireq) == -1)"
        "    return(-1);"
        "ret = ireq.ifr_flags;"
        "ireq.ifr_flags = (ret | IFF_PROMISC);"
        "if (ioctl(fd, SIOCSIFFLAGS, &ireq) == -1)"
        "    return(-1);"
        "return(ret);"
    ))

;; restore IF_FLAGS promiscuous mode state to original value
(define ##raw#promisc-off
    (foreign-lambda* integer32 ((int fd) (c-string iface) (int l) (integer32 promisc))
        "struct ifreq ireq;"
        "bzero(&ireq, sizeof(struct ifreq));"
        "strncpy(ireq.ifr_name, iface, l);"
        "ireq.ifr_name[l] = '\\0';"
        "ireq.ifr_flags = promisc;"
        "return((ioctl(fd, SIOCSIFFLAGS, &ireq)));"
    ))

;; set asynchronous mode
(define ##raw#async
    (foreign-lambda* int ((int fd))
        "int flags;"
        "if (fcntl(fd, F_SETOWN, getpid()) == -1)"
        "    return(-1);"
        "if ((flags = fcntl(fd, F_GETFL)) == -1)"
        "    return(-1);"
        "flags |= O_ASYNC | O_NONBLOCK;"
        "return(fcntl(fd, F_SETFL, flags));"
    ))


;;; syscall bindings

;; create a socket
(define ##raw#socket
    (foreign-lambda int "socket" int int int))

;; close a socket
(define ##raw#close
    (foreign-lambda int "close" int))

;; bind a name to a socket
(define ##raw#bind
    (foreign-lambda* int ((int fd) (c-pointer saddr) (int size))
        "return(bind(fd, (struct sockaddr *)saddr, size));"
    ))

;; send a packet
(define ##raw#send
    (foreign-lambda* int ((int fd) (c-pointer saddr) (int size)
                          (u8vector pkt) (int len))
        "int nleft = len;"
        "int nwrit = 0;"
        "unsigned char *p = pkt;"
        "while (nleft > 0) {"
        "    nwrit = write(fd, p, nleft);"
;;        "    nwrit = sendto(fd, p, nleft, 0, (struct sockaddr *)saddr, size);"
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

;; receive a packet
(define ##raw#receive
    (foreign-lambda* int ((int fd) (int mtu) (u8vector pkt))
        "int nread;"
        "nread = read(fd, pkt, mtu);"
        "return(nread);"
    ))

;;; selects fds ready for read/write
(define ##raw#select
    (foreign-lambda* int ((int mfd) (u16vector rfr) (u16vector rfw))
        "fd_set fdsr, fdsw;"
        "int i, ret, r, w;"
        "struct timeval tv = { 0, 0 };"
        "FD_ZERO(&fdsr);"
        "FD_ZERO(&fdsw);"
        "for (i=0; rfr[i] != 65535; i++)"
        "    FD_SET(rfr[i], &fdsr);"
        "for (i=0; rfw[i] != 65535; i++)"
        "    FD_SET(rfw[i++], &fdsw);"
        "if ((ret = select(mfd, &fdsr, &fdsw, NULL, &tv)) == -1)"
        "    return(-1);"
        "for (i=0, r=0; rfr[i] != 65535; i++) {"
        "    if (FD_ISSET(rfr[i], &fdsr))"
        "        rfr[r++] = rfr[i];"
        "}"
        "for (i=0, w=0; rfw[i] != 65535; i++) {"
        "    if (FD_ISSET(rfw[i], &fdsw))"
        "        rfw[w++] = rfw[i];"
        "}"
        "rfr[r] = 65535;"
        "rfw[w] = 65535;"
        "return(ret);"
    ))


;;; scheme interface


;;; variables

(define sigio-orig    #f)                    ; sigio original value
(define sigio-inst    #f)                    ; sigio handler installed?
(define fd-count      0)                     ; total number of fds
(define fd-max        -1)                    ; max fd val + 1
(define fd-table      (make-hash-table =))   ; raw-socket objs
(define fd-vec        (u16vector 65535))     ; vector with all fds
(define fd-list       '())                   ; list with all fds
(define fd-srvec      (u16vector 65535))     ; vector with fds to select-read
(define fd-swvec      (u16vector 65535))     ; vector with fds to select-write
(define fd-swind      0)                     ; index for fd-swvec



;;; error procedures

;; signal an error condition
(define (raw-error pname msg . args)
    (signal
        (make-composite-condition
            (make-property-condition 'exn
                                     'message msg
                                     'location pname
                                     'arguments args)
            (make-property-condition 'raw-socket))))

;; signal an error condition from a syscall
(define (raw-errno pname errno msg . args)
    (apply raw-error pname (string-append msg " - " (##raw#strerror errno)) args))

;; handle syscall calls with error handling and cleanup
(define-inline (raw-syscall scall cleanup pname msg . margs)
    (let ((e   errno))
        (if (= -1 scall)
            (begin
                (cleanup)
                (apply raw-errno pname e msg margs))
            scall)))


;;; raw-socket structure
;;; 1  2     3     4         5   6     7     8       9       10     
;;; fd saddr iface len-iface mtu flags open? recvers wready? wqueue 

;; inline slot accessors and modifiers
(define-inline (##raw#fd d)           (##sys#slot d 1))
(define-inline (##raw#saddr d)        (##sys#slot d 2))
(define-inline (##raw#iface d)        (##sys#slot d 3))
(define-inline (##raw#liface d)       (##sys#slot d 4))
(define-inline (##raw#mtu d)          (##sys#slot d 5))
(define-inline (##raw#flags d)        (##sys#slot d 6))
(define-inline (##raw#open? d)        (##sys#slot d 7))
(define-inline (##raw#recvers d)      (##sys#slot d 8))
(define-inline (##raw#wready? d)      (##sys#slot d 9))
(define-inline (##raw#wqueue d)       (##sys#slot d 10))

(define-inline (##raw#trecvers d)     (map car (##raw#recvers d)))
(define-inline (##raw#ewqueue? d)     (queue-empty? (##raw#wqueue d)))

;(define-inline (##raw#fd! d v)        (##sys#setslot d 1 v))
;(define-inline (##raw#saddr! d v)     (##sys#setslot d 2 v))
;(define-inline (##raw#iface! d v)     (##sys#setslot d 3 v))
;(define-inline (##raw#liface! d v)    (##sys#setslot d 4 v))
;(define-inline (##raw#mtu! d v)       (##sys#setslot d 5 v))
;(define-inline (##raw#flags! d v)     (##sys#setslot d 6 v))
(define-inline (##raw#open! d v)      (##sys#setslot d 7 v))
(define-inline (##raw#wready! d v)    (##sys#setslot d 9 v))

(define-inline (##raw#urecvers! d t p)
    (##sys#setslot d 8
        (let loop ((l   (##raw#recvers d)))
            (cond ((null? l)           (list (cons t p)))
                  ((eq? t (caar l))    (cons (cons t p) (cdr l)))
                  (else                (cons (car l) (loop (cdr l))))))))

(define-inline (##raw#drecvers! d t)
    (##sys#setslot d 8
        (let loop ((l   (##raw#recvers d)))
            (cond ((null? l)           l)
                  ((eq? t (caar l))    (cdr l))
                  (else                (cons (car l) (loop (cdr l))))))))

(define-inline (##raw#awqueue! d v)
    (if (##raw#wready? d)
        (begin
            (##raw#wready! d #f)
            (##raw#send (##raw#fd d) (##raw#saddr d) _ssize
                        v (u8vector-length v))
            (u16vector-set! fd-swvec fd-swind (##raw#fd d))
            (set! fd-swind (+ 1 fd-swind))
            (u16vector-set! fd-swvec fd-swind 65535))
        (queue-add! (##raw#wqueue d) v)))

(define-inline (##raw#pwqueue! d)
    (if (##raw#ewqueue? d)
        (##raw#wready! d #t)
        (let ((t   (queue-remove! (##raw#wqueue d))))
            (##raw#wready! d #f)
            (##raw#send (##raw#fd d) (##raw#saddr d) _ssize
                        t (u8vector-length t)))))


;;; SIGIO handling

;; reset fd-swvec after select and handling
(define-inline (##raw#sigio-resetw)
    (let loop ((i    0)
               (j    1)
               (fd   (u16vector-ref fd-vec 0)))
        (cond ((= 65535 fd)
                  (set! fd-swind i)
                  (u16vector-set! fd-swvec fd-swind 65535))
              ((##raw#wready? (hash-table-ref fd-table fd))
                  (loop i (+ 1 j) (u16vector-ref fd-vec j)))
              (else
                  (u16vector-set! fd-swvec i fd)
                  (loop (+ 1 i) (+ 1 j) (u16vector-ref fd-vec j))))))

;; reset fd-srvec after select and handling
(define-inline (##raw#sigio-resetr)
    (for-each
        (lambda (fd x)
            (u16vector-set! fd-srvec x fd))
        (u16vector->list fd-vec) (iota (+ 1 fd-count))))

;; helper function for writing
(define-inline (##raw#sigio-helper-write)
    (let loop ((i     1)
               (fd    (u16vector-ref fd-swvec 0))
               (ign   #f))
        (if (= 65535 fd)
            (##raw#sigio-resetw)
            (loop (+ 1 i) (u16vector-ref fd-swvec i)
                  (##raw#pwqueue! (hash-table-ref fd-table fd))))))

;; helper function for reading
(define-inline (##raw#sigio-helper-read)
    (let loop ((i     1)
               (fd    (u16vector-ref fd-srvec 0)))
        (if (= 65535 fd)
            (##raw#sigio-resetr)
            (let* ((d   (hash-table-ref fd-table fd))
                   (p   (make-u8vector (##raw#mtu d) 0))
                   (l   (##raw#receive fd (##raw#mtu d) p)))
                (for-each
                    (lambda (r)
                        ((cdr r) p l))
                    (##raw#recvers d))
                (loop (+ 1 i) (u16vector-ref fd-srvec i))))))

;; handle SIGIO
(define (##raw#sigio-handler signum)
    (signal-mask! signal/io)
    (let ((rfd   (raw-syscall
                     (##raw#select fd-max fd-srvec fd-swvec)
                     (lambda () #t)
                     '##raw#sigio-handler
                     "error in select")))
        (if (= 0 rfd)
            (begin
                (##raw#sigio-resetr)
                (##raw#sigio-resetw)
                (and sigio-orig
                     (sigio-orig signal/io)))
            (begin
                (##raw#sigio-helper-read)
                (##raw#sigio-helper-write))))
    (signal-unmask! signal/io)
    (set-signal-handler! signal/io ##raw#sigio-handler))


;;; opening and querying raw sockets

;; predicate for identifying raw-socket objects
(define (raw-socket? obj)
    (and (##core#inline "C_blockp" obj)
         (##sys#structure? obj 'raw-socket)))

;; predicate for determining if the raw-socket is open
(define (raw-socket-open? obj)
    (and (raw-socket? obj)
         (##raw#open? obj)))

;; error if not an open raw-socket
(define-inline (check-raw-socket pname s . args)
    (or (and (##core#inline "C_blockp" s)
             (##sys#structure? s 'raw-socket))
        (apply raw-error pname (conc "not a raw-socket: " s) args))
    (or (##raw#open? s)
        (apply raw-error pname "raw-socket is not open" args)))

;; open a raw socket
(define (open-raw-socket iface)
    (or (and (string? iface) (not (string-null? iface)))
        (raw-error 'open-raw-socket "iface must be a non-null string" iface))
    (let* ((len     (string-length iface))
           (lmax    (or (< len _isize)
                        (raw-error 'open-raw-socket "len must be < IFNAMSIZ" len)))
           (fd      (raw-syscall
                        (##raw#socket _sdomain _stype _sproto)
                        (lambda () #t)
                        'open-raw-socket
                        "could not create socket" iface))
           (fdmax   (if (= 65535 fd)
                        (begin
                            (##raw#close fd)
                            (raw-error 'open-raw-socket
                                       "maximum fd number reached" fd iface))
                        fd))
           (saddr   (let ((saddr   (##raw#makesaddr fd iface len))
                          (e       errno))
                        (if (= -1 saddr)
                            (begin
                                (##raw#close fd)
                                (raw-errno 'open-raw-socket e
                                           "could not create saddr" iface))
                            saddr)))
           (mtu     (raw-syscall
                        (##raw#getmtu fd iface len)
                        (lambda () (##raw#free saddr) (##raw#close fd))
                        'open-raw-socket
                        "could not get mtu size" iface))
           (bind    (raw-syscall
                        (##raw#bind fd saddr _ssize)
                        (lambda () (##raw#free saddr) (##raw#close fd))
                        'open-raw-socket
                        "could not bind to socket" iface))
           (async   (raw-syscall
                        (##raw#async fd)
                        (lambda ()
                            (##raw#free saddr) (##raw#close fd))
                        'open-raw-socket
                        "could not set asynchronous mode" iface))
           (flags   (raw-syscall
                        (##raw#promisc-on fd iface len)
                        (lambda () (##raw#free saddr) (##raw#close fd))
                        'open-raw-socket
                        "could not set promiscuous mode" iface))
           (s       (##sys#make-structure 'raw-socket
                                          fd saddr iface len mtu flags #t '() #f
                                          (make-queue))))
        (if sigio-inst
            (signal-mask! signal/io)
            (begin
                (set! sigio-inst #t)
                (set! sigio-orig (signal-handler signal/io))
                (set-signal-handler! signal/io ##raw#sigio-handler)
                (signal-mask! signal/io)))
        (hash-table-set! fd-table fd s)
        (set! fd-max (max fd-max (+ 1 fd)))
        (set! fd-count (+ 1 fd-count))
        (set! fd-list (cons fd fd-list))
        (set! fd-vec (list->u16vector (append fd-list (list 65535))))
        (set! fd-srvec (make-u16vector (+ 1 fd-count) 65535))
        (set! fd-swvec (make-u16vector (+ 1 fd-count) 65535))
        (##raw#sigio-resetr)
        (##raw#sigio-resetw)
        (signal-unmask! signal/io)
        s))


;;; information on a packet socket

;; get the socket domain
(define (raw-socket-domain s)
    (check-raw-socket 'raw-socket-domain s s)
    _sdomain)

;; get the socket type
(define (raw-socket-type s)
    (check-raw-socket 'raw-socket-type s s)
    _stype)

;; get the socket protocol
(define (raw-socket-protocol s)
    (check-raw-socket 'raw-socket-protocol s s)
    _sproto)

;; get the fd
(define (raw-socket-fd s)
    (check-raw-socket 'raw-socket-fd s s)
    (##raw#fd s))

;; get the sockaddr structure and size
(define (raw-socket-saddr s)
    (check-raw-socket 'raw-socket-saddr s s)
    (cons (##raw#saddr s) _ssize))

;; get the interface
(define (raw-socket-iface s)
    (check-raw-socket 'raw-socket-iface s s)
    (##raw#iface s))

;; get the MTU
(define (raw-socket-mtu s)
    (check-raw-socket 'raw-socket-mtu s s)
    (##raw#mtu s))


;;; writing to a packet socket

;; write pkt to the socket, or queue if not ready
(define (raw-socket-send s pkt)
    (check-raw-socket 'raw-socket-send s s pkt)
    (or (u8vector? pkt)
        (raw-error 'raw-socket-send (conc "pkt is not a u8vector: " pkt) s pkt))
    (##raw#awqueue! s pkt))


;;; reading from a packet socket

;; add a recver procedure
(define (raw-socket-add-recver s lbl proc)
    (check-raw-socket 'raw-socket-add-recver s s lbl proc)
    (or (symbol? lbl)
        (raw-error 'raw-socket-add-recver
                   (conc "label is not a symbol: " lbl) s lbl proc))
    (or (and (procedure? proc)
             (list? (procedure-information proc))
             (= 3 (length (procedure-information proc))))
        (raw-error 'raw-socket-add-recver
                   (conc "not a handler procedure: " proc) s lbl proc))
    (##raw#urecvers! s lbl proc))

;; remove a recver procedure
(define (raw-socket-del-recver s lbl)
    (check-raw-socket 'raw-socket-del-recver s s lbl)
    (or (symbol? lbl)
        (raw-error 'raw-socket-del-recver
                   (conc "label is not a symbol: " lbl) s lbl))
    (##raw#drecvers! s lbl))

;; list recvers
(define (raw-socket-recvers s)
    (check-raw-socket 'raw-socket-recvers s s)
    (##raw#recvers s))


;;; closing the packet socket

;; close a raw-socket
(define (close-raw-socket s)
    (check-raw-socket 'close-raw-socket s s)
    (signal-mask! signal/io)
    (let ((fd      (##raw#fd s)))
        (if (= -1 (##raw#promisc-off fd (##raw#iface s) (##raw#liface s)
                                     (##raw#flags s)))
            (display "could not turn off promiscuous mode\n"))
        (##raw#free (##raw#saddr s))
        (##raw#close fd)
        (##raw#open! s #f)
        (hash-table-delete! fd-table fd)
        (set! fd-list (delete fd fd-list))
        (set! fd-vec (list->u16vector (append fd-list (list 65535))))
        (set! fd-srvec (make-u16vector fd-count 65535))
        (set! fd-swvec (make-u16vector fd-count 65535))
        (set! fd-count (- fd-count 1))
        (set! fd-max (fold (lambda (x r) (max (+ 1 x) r)) -1 fd-list))
        (##raw#sigio-resetr)
        (##raw#sigio-resetw))
    (signal-unmask! signal/io)
    (if (= 0 fd-count)
        (begin
            (set-signal-handler! signal/io sigio-orig)
            (set! sigio-inst #f)))
    #t)

