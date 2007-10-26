;;;; egg:      raw-sockets-experimental
;;;; file:     raw-sockets-experimental.scm
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
(require-extension srfi-18)    ; multithreading support


;;; chicken compile-time options

(eval-when (compile)
    (declare
        (uses library extras posix srfi-1 srfi-4 srfi-13 srfi-18)
        (always-bound
            rerrno
            _isize
            fd-count
            fd-list
            )
        (bound-to-procedure
            ##raw#strerr
            raw-mutex-error
            raw-error
            raw-errno
            ##raw#close
            ##raw#socket
            ##raw#bind
            ##raw#getmtu
            ##raw#promisc-on
            ##raw#promisc-off
            ##raw#sockopts
            ##raw#send
            ##raw#receive
            ##raw#fd
            ##raw#iface
            ##raw#mtu
            ##raw#flags
            ##raw#open?
            ##raw#recvers
            ##raw#wqueue
            ##raw#rmutex
            ##raw#rthread
            ##raw#wmutex
            ##raw#wthread
            ##raw#trecvers
            ##raw#ewqueue?
            ##raw#open!
            ##raw#urecvers!
            ##raw#drecvers!
            ##raw#awqueue!
            ##raw#thread-write
            ##raw#thread-read
            raw-socket?
            raw-socket-open?
            check-raw-socket
            open-raw-socket
            raw-socket-fd
            raw-socket-iface
            raw-socket-mtu
            raw-socket-flags
            raw-socket-wqueue
            raw-socket-rmutex
            raw-socket-rthread
            raw-socket-wmutex
            raw-socket-wthread
            raw-socket-send
            raw-socket-add-recver
            raw-socket-del-recver
            raw-socket-recvers
            close-raw-socket
            )
        (constant
            ##raw#fd
            ##raw#iface
            ##raw#mtu
            ##raw#flags
            ##raw#open?
            ##raw#recvers
            ##raw#wqueue
            ##raw#trecvers
            ##raw#ewqueue?
            raw-socket?
            raw-socket-open?
            raw-socket-fd
            raw-socket-iface
            raw-socket-mtu
            raw-socket-flags
            raw-socket-wqueue
            raw-socket-recvers
            )
        (export
            open-raw-socket
            raw-socket?
            raw-socket-open?
            raw-socket-fd
            raw-socket-iface
            raw-socket-mtu
            raw-socket-flags
            raw-socket-wqueue
            raw-socket-rmutex
            raw-socket-rthread
            raw-socket-wmutex
            raw-socket-wthread
            raw-socket-send
            raw-socket-add-recver
            raw-socket-del-recver
            raw-socket-recvers
            close-raw-socket
            raw-protect-region
            )
        (emit-exports "raw-sockets-experimental.exports")
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
        (run-time-macros)
    ))
(eval-when (load eval)
    (eval `(define-macro (raw-protect-region mx b . r)
              `(raw-protect ,mx ,b ,@r)))
    )


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
#define MAKEMTU(x)    ((x) - 1)
#else
#include <asm/types.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#define MAKEMTU(x)    (x)
#endif

<#


;;; error procedures

;; c variables
(define-foreign-variable rerrno     integer32      "errno")
(define ##raw#strerr    (foreign-lambda c-string "strerror" integer32))

;; protected regions
(define-macro (raw-protect ml . body)
    `(if (list? ,ml)
         (let ((retval   (begin
                             (for-each (lambda (x) (mutex-lock! x #f #f)) ,ml)
                             ,@body)))
             (for-each mutex-unlock! ,ml)
             retval)
         (let ((retval   (begin
                             (mutex-lock! ,ml #f #f)
                             ,@body)))
             (mutex-unlock! ,ml)
             retval)))


;; mutex error handling
(define (raw-mutex-error ml)
    (cond ((not ml)        #t)
          ((list? ml)      (for-each raw-mutex-error ml))
          ((mutex? ml)     (mutex-unlock! ml))
          ((thread? ml)    (thread-specific-set! ml #f) (thread-join! ml))
          (else            (let ((rthr   (##sys#slot ml 9))
                                 (wthr   (##sys#slot ml 11)))
                               (thread-specific-set! wthr #f)
                               (thread-specific-set! rthr #f)
                               (thread-join! wthr)
                               (or (eq? 'suspended (thread-state rthr))
                                   (thread-join! rthr))
                               (mutex-unlock! (##sys#slot ml 8))
                               (mutex-unlock! (##sys#slot ml 10))))))
            
;; signal an error condition
(define-inline (raw-error pname ml msg . args)
    (raw-mutex-error ml)
    (signal
        (make-composite-condition
            (make-property-condition 'exn
                                     'message msg
                                     'location pname
                                     'arguments args)
            (make-property-condition 'raw-socket))))

;; signal an error condition from a syscall
(define-inline (raw-errno pname ml e msg . args)
    (apply raw-error pname ml (string-append msg " - " (##raw#strerr e)) args))

;; handle syscall calls with error handling and cleanup
(define-macro (raw-syscall scall ml cleanup pname msg . margs)
    `(let* ((r   ,scall)
            (e   rerrno))
         (if (= -1 r)
             (begin
                 ,@cleanup
                 (raw-errno ',pname ,ml e ,msg ,@margs))
             r)))


;;; target-specific compilation

;; maximum interface name length
(define-foreign-variable _isize     int      "IFNAMSIZ")

;; close a socket
(define ##raw#close
    (foreign-lambda int "close" integer32))

;; only linux and macosx are supported.
;; this handles creating procedures for where they differ.
(cond-expand
    (linux
        ;; make the socket
        (define-inline (##raw#socket)
            (raw-syscall
                ((foreign-lambda* integer32 ()
                    "return((socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))));"
                    ))
                #f
                ()
                ##raw#socket
                "open-raw-socket: could not open socket"))
        ;; bind the socket
        (define-inline (##raw#bind fd iface len)
            (raw-syscall
                ((foreign-lambda* int ((integer32 fd) (c-string iface) (int l))
#<<BINDPROC
                    struct sockaddr_ll saddr;
                    struct ifreq ireq;
                    bzero(&ireq, sizeof(struct ifreq));
                    bzero(&saddr, sizeof(struct sockaddr_ll));
                    strncpy(ireq.ifr_name, iface, l);
                    ireq.ifr_name[l] = '\0';
                    if (ioctl(fd, SIOCGIFINDEX, &ireq) == -1) {
                        return(-1);
                    }
                    saddr.sll_ifindex = ireq.ifr_ifindex;
                    saddr.sll_family = AF_PACKET;
                    saddr.sll_protocol = htons(ETH_P_ALL);
                    return((bind(fd, (struct sockaddr *)(&saddr), sizeof(struct sockaddr_ll))));
BINDPROC
                    ) fd iface len)
                #f
                ((##raw#close fd))
                ##raw#bind
                "open-raw-socket: could not bind socket"
                fd iface len))
    )
    (macosx
        ;; make the socket
        (define-inline (##raw#socket)
            (raw-syscall
                ((foreign-lambda* integer32 ()
                    "return((socket(AF_NDRV, SOCK_RAW, 0)));"
                    ))
                #f
                ()
                ##raw#socket
                "open-raw-socket: could not open socket"))
        ;; bind the socket
        (define-inline (##raw#bind fd iface len)
            (raw-syscall
                ((foreign-lambda* int ((integer32 fd) (c-string iface) (int l))
#<<BINDPROC
                    struct sockaddr saddr;
                    saddr.sa_len = sizeof(struct sockaddr);
                    saddr.sa_family = AF_NDRV;
                    strncpy(saddr.sa_data, iface, l);
                    saddr.sa_data[l] = '\0';
                    return((bind(fd, (struct sockaddr *)(&saddr), sizeof(struct sockaddr))));
BINDPROC
                    ) fd iface len)
                #f
                ((##raw#close fd))
                ##raw#bind
                "open-raw-socket: could not bind socket"
                fd iface len))
    )
    (else
        (error "raw-sockets only supported for macosx and linux targets."))
)


;;; ioctl/fcntl procedures

;; get the MTU size
(define-inline (##raw#getmtu fd iface len)
    (raw-syscall
        ((foreign-lambda* integer32 ((integer32 fd) (c-string iface) (int l))
#<<MTUPROC
            struct ifreq ireq;
            int ret;
            bzero(&ireq, sizeof(struct ifreq));
            strncpy(ireq.ifr_name, iface, l);
            ireq.ifr_name[l] = '\0';
            if (ioctl(fd, SIOCGIFMTU, &ireq) == -1)
                return(-1);
            return((MAKEMTU(ireq.ifr_mtu)));
MTUPROC
                ) fd iface len)
        #f
        ((##raw#close fd))
        ##raw#getmtu
        "open-raw-socket: could not get MTU size"
        fd iface len))

;; turn on promiscuous mode and return the current IF_FLAGS value
(define-inline (##raw#promisc-on fd iface len)
    (raw-syscall
        ((foreign-lambda* integer32 ((integer32 fd) (c-string iface) (int l))
#<<PONPROC
            struct ifreq ireq;
            int ret;
            bzero(&ireq, sizeof(struct ifreq));
            strncpy(ireq.ifr_name, iface, l);
            ireq.ifr_name[l] = '\0';
            if (ioctl(fd, SIOCGIFFLAGS, &ireq) == -1)
                return(-1);
            ret = ireq.ifr_flags;
            ireq.ifr_flags |= IFF_PROMISC;
            if (ioctl(fd, SIOCSIFFLAGS, &ireq) == -1)
                return(-1);
            return(ret);
PONPROC
            ) fd iface len)
        #f
        ((##raw#close fd))
        ##raw#promisc-on
        "open-raw-socket: could not set promiscuous mode"
        fd iface len))

;; restore IF_FLAGS promiscuous mode state to original value
(define-inline (##raw#promisc-off fd iface len promisc ml)
    (raw-syscall
        ((foreign-lambda* int ((integer32 fd) (c-string iface) (int l) (integer32 promisc))
#<<POFFPROC
            struct ifreq ireq;
            bzero(&ireq, sizeof(struct ifreq));
            strncpy(ireq.ifr_name, iface, l);
            ireq.ifr_name[l] = '\0';
            ireq.ifr_flags = promisc;
            return((ioctl(fd, SIOCSIFFLAGS, &ireq)));
POFFPROC
            ) fd iface len promisc)
        ml
        ((##raw#close fd))
        ##raw#promisc-off
        "open-raw-socket: could not reset promiscuous mode"
        fd iface len promisc))

;; set socket options
(define-inline (##raw#sockopts fd)
    (raw-syscall
        ((foreign-lambda* int ((integer32 fd))
#<<SOPTSPROC1
            int flags = 0;
            if ((flags = fcntl(fd, F_GETFL)) == -1)
                return(-1);
            flags |= O_NONBLOCK;
            return((fcntl(fd, F_SETFL, flags)));
SOPTSPROC1
            ) fd)
        #f
        ((##raw#close fd))
        ##raw#sockopts
        "open-raw-socket: could not set nonblocking flag"
        fd)
    (raw-syscall
        ((foreign-lambda* int ((integer32 fd))
#<<SOPTSPROC2
            int flags = 1;
            return((setsockopt(fd, SOL_SOCKET, SO_OOBINLINE,
                               &flags, sizeof(int))));
SOPTSPROC2
            ) fd)
        #f
        ((##raw#close fd))
        ##raw#sockopts
        "open-raw-socket: could not set socket options"
        fd))


;;; syscall bindings

;; send a packet
(define-inline (##raw#send fd pkt len ml)
    (raw-protect ml
        (raw-syscall
            ((foreign-lambda* int ((integer32 fd) (u8vector pkt) (int len))
#<<SENDPROC
                int nleft = len;
                int nwrit = 0;
                unsigned char *p = pkt;
                while (nleft > 0) {
                    nwrit = write(fd, p, nleft);
                    if (nwrit <= 0) {
                        if ((errno == EAGAIN) || (errno == EINTR))
                            nwrit = 0;
                        else
                            return(-1);
                    }
                    nleft -= nwrit;
                    p += nwrit;
                }
                return(0);
SENDPROC
                ) fd pkt len)
            ml
            ()
            ##raw#send
            "raw-socket-send: could not send packet"
            fd pkt len)))

;; receive a packet
(define-inline (##raw#receive fd pkt len ml)
    (raw-protect ml
        (raw-syscall
            ((foreign-lambda* integer32 ((integer32 fd) (u8vector pkt) (int l))
#<<RECVPROC
                int ret;
                while ((ret = read(fd, pkt, l)) == -1) {
                    if (errno == EINTR)
                        continue;
                    else if (errno == EAGAIN)
                        return(0);
                    else
                        return(-1);
                }
                return(ret);
RECVPROC
                ) fd pkt len)
            ml
            ()
            ##raw#receive
            "raw-socket-recvers: could not read from socket"
            fd pkt len)))



;;; scheme interface


;;; variables

(define fd-count      0)                     ; total number of fds
(define fd-list       '())                   ; list with all fds


;;; raw-socket structure
;;; 1  2     3   4     5     6       7      8      9       10     11
;;; fd iface mtu flags open? recvers wqueue rmutex rthread wmutex wthread

;; inline slot accessors and modifiers
(define-inline (##raw#fd d)           (##sys#slot d 1))
(define-inline (##raw#iface d)        (##sys#slot d 2))
(define-inline (##raw#mtu d)          (##sys#slot d 3))
(define-inline (##raw#flags d)        (##sys#slot d 4))
(define-inline (##raw#open? d)        (##sys#slot d 5))
(define-inline (##raw#recvers d)      (##sys#slot d 6))
(define-inline (##raw#wqueue d)       (##sys#slot d 7))
(define-inline (##raw#rmutex d)       (##sys#slot d 8))
(define-inline (##raw#rthread d)      (##sys#slot d 9))
(define-inline (##raw#wmutex d)       (##sys#slot d 10))
(define-inline (##raw#wthread d)      (##sys#slot d 11))

(define-inline (##raw#trecvers d)     (map car (##raw#recvers d)))
(define-inline (##raw#ewqueue? d)     (queue-empty? (##raw#wqueue d)))

(define-inline (##raw#open! d v)      (##sys#setslot d 5 v))

(define-inline (##raw#urecvers! d t p)
    (raw-protect (##raw#rmutex d)
        (##sys#setslot d 6
            (let loop ((l   (##raw#recvers d)))
                (cond ((null? l)           (list (cons t p)))
                      ((eq? t (caar l))    (cons (cons t p) (cdr l)))
                      (else                (cons (car l) (loop (cdr l)))))))
        (thread-resume! (##raw#rthread d))))

(define-inline (##raw#drecvers! d t)
    (raw-protect (##raw#rmutex d)
        (##sys#setslot d 6
            (let loop ((l   (##raw#recvers d)))
                (cond ((null? l)           l)
                      ((eq? t (caar l))    (cdr l))
                      (else                (cons (car l) (loop (cdr l)))))))
        (and (null? (##raw#recvers d))
             (thread-suspend! (##raw#rthread d)))))

(define-inline (##raw#awqueue! d v)
    (raw-protect (list (##raw#rmutex d) (##raw#wmutex d))
        (queue-add! (##raw#wqueue d) v)))


;;; threads

(define (debug-display t . a)
    (display (apply conc "debug:  " (thread-name t) " - " a))
    (newline))

;; create a writing thread thunk
(define-inline (##raw#thread-write d)
    (let ((mx   (list (##raw#rmutex d) (##raw#wmutex d)))
          (wq   (##raw#wqueue d))
          (fd   (##raw#fd d)))
        (lambda ()
            (debug-display (current-thread) "started thread-write")
            (let loop ((c   (current-thread))
                       (y   #f))
                (debug-display c "started write loop")
                (if (##raw#ewqueue? d)
                    (if (thread-specific c)
                        (loop c (thread-yield!))
                        (debug-display c "thread-specific empty"))
                    (let* ((t   (raw-protect mx (queue-remove! wq)))
                           (n   (##raw#send fd t (u8vector-length t) mx)))
                        (if (= 0 n)
                            (if (thread-specific c)
                                (begin
                                    (raw-protect mx (queue-push-back! wq t))
                                    (loop c (thread-yield!)))
                                (begin
                                    (debug-display c "thread-specific 0 end")
                                (raw-protect mx (queue-push-back! wq t))))
                            (if (thread-specific c)
                                (loop c (debug-display c "write successful " n))
                                (debug-display c "thread-specific end")))))))))

;; create a reading thread thunk
(define-inline (##raw#thread-read d)
    (let ((fd   (##raw#fd d))
          (m    (##raw#mtu d))
          (p    (make-u8vector (##raw#mtu d) 0))
          (mx   (##raw#rmutex d)))
        (lambda ()
            (debug-display (current-thread) "started thread-read")
            (let loop ((c   (current-thread))
                       (r   (##raw#receive fd p m mx)))
                (debug-display c "started read loop")
                (if (= 0 r)
                    (if (thread-specific c)
                        (begin
                            (thread-yield!)
                            (loop c (##raw#receive fd p m mx)))
                        (debug-display c "thread-specific noin")) 
                    (let ((u   (subu8vector p 0 r)))
                        (for-each
                            (lambda (recver)
                                (raw-protect mx ((cdr recver) u r)))
                            (##raw#recvers d))
                        (debug-display c "read successful\n" u)
                        (if (thread-specific c)
                            (loop c (##raw#receive fd p m mx))
                            (debug-display c "thread-specific end"))))))))


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
        (apply raw-error pname #f (conc "not a raw-socket: " s) args))
    (or (memq (##raw#fd s) fd-list)
        (##raw#open! s #f))
    (or (##raw#open? s)
        (apply raw-error pname #f "raw-socket is not open" s args)))

;; open a raw socket
(define (open-raw-socket iface)
    (or (and (string? iface) (not (string-null? iface)))
        (raw-error 'open-raw-socket #f "iface must be a non-null string" iface))
    (or (< (string-length iface) _isize)
        (raw-error 'open-raw-socket #f "iface length >= IFNAMSIZ" _isize))
    (let* ((len     (string-length iface))
           (fd      (##raw#socket))
           (mtu     (##raw#getmtu fd iface len))
           (bind    (##raw#bind fd iface len))
           (opts    (##raw#sockopts fd))
           (flags   (##raw#promisc-on fd iface len))
           (s       (##sys#make-structure 'raw-socket
                                          fd iface mtu flags #t
                                          '() (make-queue)
                                          (make-mutex) #f
                                          (make-mutex) #f))
           (rth     (make-thread (##raw#thread-read s)
                                 (string->symbol (conc "thr-read-" fd))))
           (wth     (make-thread (##raw#thread-write s)
                                 (string->symbol (conc "thr-write-" fd)))))
        (##sys#setslot s 9 rth)
        (##sys#setslot s 11 wth)
        (thread-quantum-set! rth 1000)
        (thread-quantum-set! wth 1000)
        (set! fd-count (+ 1 fd-count))
        (set! fd-list (cons fd fd-list))
        (thread-start! rth)
        (thread-suspend! rth)
        (thread-start! wth)
        s))


;;; information on a packet socket

;; get the fd
(define (raw-socket-fd s)
    (check-raw-socket 'raw-socket-fd s)
    (##raw#fd s))

;; get the interface
(define (raw-socket-iface s)
    (check-raw-socket 'raw-socket-iface s)
    (##raw#iface s))

;; get the MTU
(define (raw-socket-mtu s)
    (check-raw-socket 'raw-socket-mtu s)
    (##raw#mtu s))

;; get the flags
(define (raw-socket-flags s)
    (check-raw-socket 'raw-socket-flags s)
    (##raw#flags s))

;; get the write queue
(define (raw-socket-wqueue s)
    (check-raw-socket 'raw-socket-wqueue s)
    (##raw#wqueue s))

;; get the read mutex
(define (raw-socket-rmutex s)
    (check-raw-socket 'raw-socket-rmutex s)
    (##raw#rmutex s))

;; get the read thread
(define (raw-socket-rthread s)
    (check-raw-socket 'raw-socket-rthread s)
    (##raw#rthread s))

;; get the write mutex
(define (raw-socket-wmutex s)
    (check-raw-socket 'raw-socket-wmutex s)
    (##raw#wmutex s))

;; get the write thread
(define (raw-socket-wthread s)
    (check-raw-socket 'raw-socket-wthread s)
    (##raw#wthread s))


;;; writing to a packet socket

;; write pkt to the socket, or queue if not ready
(define (raw-socket-send s pkt)
    (check-raw-socket 'raw-socket-send s pkt)
    (or (u8vector? pkt)
        (raw-error 'raw-socket-send #f (conc "pkt is not a u8vector: " pkt)
                   s pkt))
    (##raw#awqueue! s pkt))


;;; reading from a packet socket

;; add a recver procedure
(define (raw-socket-add-recver s lbl proc)
    (check-raw-socket 'raw-socket-add-recver s lbl proc)
    (or (symbol? lbl)
        (raw-error 'raw-socket-add-recver #f
                   (conc "label is not a symbol: " lbl) s lbl proc))
    (or (and (procedure? proc)
             (list? (procedure-information proc))
             (= 3 (length (procedure-information proc))))
        (raw-error 'raw-socket-add-recver #f
                   (conc "not a handler procedure: " proc) s lbl proc))
    (##raw#urecvers! s lbl proc))

;; remove a recver procedure
(define (raw-socket-del-recver s lbl)
    (check-raw-socket 'raw-socket-del-recver s lbl)
    (or (symbol? lbl)
        (raw-error 'raw-socket-del-recver #f
                   (conc "label is not a symbol: " lbl) s lbl))
    (##raw#drecvers! s lbl))

;; list recvers
(define (raw-socket-recvers s)
    (check-raw-socket 'raw-socket-recvers s)
    (##raw#recvers s))


;;; closing the packet socket

;; close a raw-socket
(define (close-raw-socket s)
    (check-raw-socket 'close-raw-socket s)
    (raw-mutex-error s)
    (let ((mx   (list (##raw#rmutex s) (##raw#wmutex s)))
          (fd   (##raw#fd s)))
        (raw-protect mx
            (##raw#promisc-off fd (##raw#iface s)
                               (string-length (##raw#iface s))
                               (##raw#flags s)
                               mx)
            (##raw#close fd)
            (##raw#open! s #f)
            (set! fd-list (delete fd fd-list =))
            (set! fd-count (- fd-count 1))))
    #t)

