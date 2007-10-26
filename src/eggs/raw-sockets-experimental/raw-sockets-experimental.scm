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
            thread-id
            mutex-id
            _isize
            fd-count
            fd-max
            fd-table
            fd-list
            fd-wlist
            )
        (bound-to-procedure
            ##raw#strerr
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
            ##raw#fdset-new
            ##raw#fdset-add
            ##raw#fdset-test
            ##raw#fdset-free
            ##raw#select-prim
            ##raw#select
            ##raw#fd
            ##raw#iface
            ##raw#mtu
            ##raw#flags
            ##raw#open?
            ##raw#recvers
            ##raw#wready?
            ##raw#wqueue
            ##raw#trecvers
            ##raw#ewqueue?
            ##raw#open!
            ##raw#wready!
            ##raw#urecvers!
            ##raw#drecvers!
            ##raw#awqueue!
            ##raw#pwqueue!
            ##raw#select-resetw
            ##raw#select-helper-write
            ##raw#select-helper-read
            ##raw#select-helper-excp
            ##raw#select-handler
            raw-socket?
            raw-socket-open?
            check-raw-socket
            open-raw-socket
            raw-socket-fd
            raw-socket-iface
            raw-socket-mtu
            raw-socket-flags
            raw-socket-wready?
            raw-socket-wqueue
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
            ##raw#wready?
            ##raw#wqueue
            ##raw#trecvers
            ##raw#ewqueue?
            raw-socket?
            raw-socket-open?
            raw-socket-fd
            raw-socket-iface
            raw-socket-mtu
            raw-socket-flags
            raw-socket-wready?
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
            raw-socket-wready?
            raw-socket-wqueue
            raw-socket-send
            raw-socket-add-recver
            raw-socket-del-recver
            raw-socket-recvers
            close-raw-socket
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

;; thread variables
(define thread-id     #f)                    ; thread handle
(define mutex-id      (make-mutex))          ; mutex handle

;; errno string
(define ##raw#strerr    (foreign-lambda c-string "strerror" integer32))

;; signal an error condition
(define-inline (raw-error pname m? msg . args)
    (and m?
         (mutex-unlock! mutex-id))
    (signal
        (make-composite-condition
            (make-property-condition 'exn
                                     'message msg
                                     'location pname
                                     'arguments args)
            (make-property-condition 'raw-socket))))

;; signal an error condition from a syscall
(define-inline (raw-errno pname m? e msg . args)
    (apply raw-error pname m? (string-append msg " - " (##raw#strerr e)) args))

;; handle syscall calls with error handling and cleanup
(define-macro (raw-syscall scall m? cleanup pname msg . margs)
    `(let* ((r   ,scall)
            (e   rerrno))
         (if (= -1 r)
             (begin
                 ,@cleanup
                 (raw-errno ',pname ,m? e ,msg ,@margs))
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
                #t
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
                #t
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
                #t
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
                #t
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
        #t
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
        #t
        ((##raw#close fd))
        ##raw#promisc-on
        "open-raw-socket: could not set promiscuous mode"
        fd iface len))

;; restore IF_FLAGS promiscuous mode state to original value
(define-inline (##raw#promisc-off fd iface len promisc)
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
        #t
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
        #t
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
        #t
        ((##raw#close fd))
        ##raw#sockopts
        "open-raw-socket: could not set socket options"
        fd))


;;; syscall bindings

;; send a packet
(define-inline (##raw#send fd pkt len)
    (raw-syscall
        ((foreign-lambda* integer32 ((integer32 fd) (u8vector pkt) (int len))
#<<SENDPROC
            int nleft = len;
            int nwrit = 0;
            unsigned char *p = pkt;
            while (nleft > 0) {
                nwrit = write(fd, p, nleft);
                if (nwrit <= 0) {
                    if (errno == EINTR)
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
        #t
        ()
        ##raw#send
        "raw-socket-send: could not send packet"
        fd pkt len))

;; receive a packet
(define-inline (##raw#receive fd pkt len)
    (raw-syscall
        ((foreign-lambda* integer32 ((integer32 fd) (u8vector pkt) (int l))
#<<RECVPROC
            int bready = 0;
            if (ioctl(fd, FIONREAD, &bready) == -1)
                return(-1);
            if (bready == 0)
                return(0);
            return((read(fd, pkt, l)));
RECVPROC
            ) fd pkt len)
        #t
        ()
        ##raw#receive
        "raw-socket-recvers: could not read from socket"
        fd pkt len))

;; select auxilliary procedure: create and zero a FD_SET
(define-inline (##raw#fdset-new)
    (raw-syscall
        ((foreign-lambda* c-pointer ()
#<<FDNEWPROC
            fd_set *ret = (fd_set *)malloc(sizeof(fd_set));
            return(((ret == NULL) ? -1 : ret));
FDNEWPROC
            ))
        #t
        ()
        ##raw#fdset-new
        "##raw#select: could not create fd_set"))

;; select auxilliary procedure: add a fd to a FD_SET
(define ##raw#fdset-add
    (foreign-lambda* void ((c-pointer fds) (integer32 fd))
        "FD_SET(fd, (fd_set *)fds);"
    ))

;; select auxilliary procedure: check if a fd is a member of a FD_SET
(define-inline (##raw#fdset-test fds fd)
    (= 1 ((foreign-lambda* int ((c-pointer fds) (integer32 fd))
             "return((FD_ISSET(fd, (fd_set *)fds)));"
             ) fds fd)))

;; select auxilliary procedure: free a FD_SET
(define ##raw#fdset-free
    (foreign-lambda* void ((c-pointer fds))
        "free((fd_set *)fds);"
    ))

;; select auxilliary procedure: call select
(define-inline (##raw#select-prim mfd rfds wfds efds)
    (raw-syscall
        ((foreign-lambda* integer32 ((integer32 mfd) 
                                     (c-pointer rfds)
                                     (c-pointer wfds)
                                     (c-pointer efds))
#<<SELECTPROC
            struct timeval tv = { 0L, 20000L };
            return((select(mfd, (fd_set *)rfds, (fd_set *)wfds,
                           (fd_set *)efds, &tv)));
SELECTPROC
            ) mfd rfds wfds efds)
        #t
        ((##raw#fdset-free rfds)
         (##raw#fdset-free wfds)
         (##raw#fdset-free efds))
        ##raw#select-prim
        "##raw#select: select() call failed"
        mfd rfds wfds efds))

;; selects fds ready for read/write/error
(define-inline (##raw#select afds wfds)
    (let ((prf   (##raw#fdset-new))
          (pwf   (##raw#fdset-new))
          (pef   (##raw#fdset-new)))
        (for-each
            (lambda (x)
                (##raw#fdset-add prf x)
                (##raw#fdset-add pef x))
            afds)
        (for-each
            (lambda (x)
                (##raw#fdset-add pwf x))
            wfds)
        (let ((ret   (##raw#select-prim fd-max prf pwf pef)))
            (let loop ((rtn   ret)
                       (i     0)
                       (f     prf)
                       (l     afds)
                       (cfd   '())
                       (rfd   '())
                       (wfd   '())
                       (efd   '()))
                (cond ((= 0 rtn)
                          (##raw#fdset-free prf)
                          (##raw#fdset-free pwf)
                          (##raw#fdset-free pef)
                          (vector ret
                                  (if (= 0 i) cfd rfd)
                                  (if (= 1 i) cfd wfd)
                                  (if (= 2 i) cfd efd)))
                      ((null? l)
                          (if (= 0 i)
                              (loop rtn 1 pwf wfds '() cfd wfd efd)
                              (if (= 1 i)
                                  (loop rtn 2 pef afds '() rfd cfd efd)
                                  (begin
                                      (##raw#fdset-free prf)
                                      (##raw#fdset-free pwf)
                                      (##raw#fdset-free pef)
                                      (raw-error
                                          '##raw#select
                                          #t
                                          "extra fds"
                                          rtn ret afds wfds rfd wfd cfd)))))
                      ((##raw#fdset-test f (car l))
                          (loop (- rtn 1) i f (cdr l) (cons (car l) cfd)
                                rfd wfd efd))
                      (else
                          (loop rtn i f (cdr l) cfd rfd wfd efd)))))))


;;; scheme interface


;;; variables

(define fd-count      0)                     ; total number of fds
(define fd-max        -1)                    ; highest numbered fd
(define fd-table      (make-hash-table =))   ; raw-socket objs
(define fd-list       '())                   ; list with all fds
(define fd-wlist      '())                   ; list with fds for writing


;;; raw-socket structure
;;; 1  2     3   4     5     6       7       8     
;;; fd iface mtu flags open? recvers wready? wqueue 

;; inline slot accessors and modifiers
(define-inline (##raw#fd d)           (##sys#slot d 1))
(define-inline (##raw#iface d)        (##sys#slot d 2))
(define-inline (##raw#mtu d)          (##sys#slot d 3))
(define-inline (##raw#flags d)        (##sys#slot d 4))
(define-inline (##raw#open? d)        (##sys#slot d 5))
(define-inline (##raw#recvers d)      (##sys#slot d 6))
(define-inline (##raw#wready? d)      (##sys#slot d 7))
(define-inline (##raw#wqueue d)       (##sys#slot d 8))

(define-inline (##raw#trecvers d)     (map car (##raw#recvers d)))
(define-inline (##raw#ewqueue? d)     (queue-empty? (##raw#wqueue d)))

(define-inline (##raw#open! d v)      (##sys#setslot d 5 v))
(define-inline (##raw#wready! d v)    (##sys#setslot d 7 v))

(define-inline (##raw#urecvers! d t p)
    (##sys#setslot d 6
        (let loop ((l   (##raw#recvers d)))
            (cond ((null? l)           (list (cons t p)))
                  ((eq? t (caar l))    (cons (cons t p) (cdr l)))
                  (else                (cons (car l) (loop (cdr l))))))))

(define-inline (##raw#drecvers! d t)
    (##sys#setslot d 6
        (let loop ((l   (##raw#recvers d)))
            (cond ((null? l)           l)
                  ((eq? t (caar l))    (cdr l))
                  (else                (cons (car l) (loop (cdr l))))))))

(define-inline (##raw#awqueue! d v)
    (if (##raw#wready? d)
        (begin
            (##raw#wready! d #f)
            (##raw#send (##raw#fd d) v (u8vector-length v))
            (set! fd-wlist (cons (##raw#fd d) fd-wlist)))
        (queue-add! (##raw#wqueue d) v)))

(define-inline (##raw#pwqueue! d)
    (let loop ((d   d))
        (if (##raw#ewqueue? d)
            (##raw#wready! d #t)
            (let* ((t   (queue-remove! (##raw#wqueue d)))
                   (n   (##raw#send (##raw#fd d) t (u8vector-length t))))
                (if (= n 0)
                    (begin
                        (queue-push-back! (##raw#wqueue d) t)
                        (##raw#wready! d #f))
                    (loop d))))))


;;; thread select handling

;; reset fd-wlist after select and handling
(define-inline (##raw#select-resetw)
    (let loop ((l   fd-list)
               (r   '()))
        (cond ((null? l)
                  (set! fd-wlist r))
              ((##raw#wready? (hash-table-ref fd-table (car l)))
                  (loop (cdr l) r))
              (else
                  (loop (cdr l) (cons (car l) r))))))

;; helper function for writing
(define-inline (##raw#select-helper-write fds)
    (display "debug: select write called\n")
    (for-each
        (lambda (x)
            (##raw#pwqueue! (hash-table-ref fd-table x)))
        fds)
    (##raw#select-resetw))

;; helper function for reading
(define-inline (##raw#select-helper-read fds)
    (display "debug: select read called\n")
    (for-each
        (lambda (x)
            (let* ((d   (hash-table-ref fd-table x))
                   (f   (##raw#fd d))
                   (m   (##raw#mtu d))
                   (p   (make-u8vector m 0)))
                (let loop ((r   (##raw#receive f p m))
                           (t   100))
                    (if (= 0 r)
                        #t
                        (let ((u   (subu8vector p 0 r)))
                            (for-each
                                (lambda (recver)
                                    ((cdr recver) u r))
                                (##raw#recvers d))
                            (if (= 0 t)
                                #t
                                (loop (##raw#receive f p m) (- t 1))))))))
        fds))

;; helper function for exceptions
(define-inline (##raw#select-helper-excp fds)
    (display "debug: select excp called\n")
    (if (null? fds)
        #t
        (begin
            (for-each
                (lambda (x)
                    (let* ((d   (hash-table-ref fd-table x))
                           (f   (##raw#fd d)))
                        (##raw#open! d #f)
                        (##raw#promisc-off f
                                           (##raw#iface d)
                                           (string-length (##raw#iface d))
                                           (##raw#flags d))
                        (##raw#close f)
                        (set! fd-list (delete f fd-list =))
                        (set! fd-wlist (delete f fd-wlist =))
                        (hash-table-delete! fd-table f)))
                fds)
            (set! fd-count (- fd-count (length fds)))
            (set! fd-max (+ 1 (fold (lambda (x r) (max x r)) -2 fds)))
            (if (= 0 fd-count)
                (let ((tid   thread-id))
                    (set! thread-id #f)
                    (mutex-unlock! mutex-id)
                    (thread-quantum-set! ##sys#primordial-thread 10000)
                    (thread-terminate! tid))))))

;; handle select, reading and writing
(define (##raw#select-handler)
    (let loop ((t   0))
        (display "debug: loop entered\n")
        (mutex-lock! mutex-id)
        (display "debug: select-handler locked\n")
        (let ((ret   (##raw#select fd-list fd-wlist)))
            (display (conc "debug:   ret: " ret "\n"))
            (if (= 0 (vector-ref ret 0))
                (display "debug: nothing selected\n")
                (let ((e   (vector-ref ret 3)))
                    (##raw#select-helper-excp e)
                    (##raw#select-helper-read
                        (filter (lambda (x) (not (memq x e))) (vector-ref ret 1)))
                    (##raw#select-helper-write
                        (filter (lambda (x) (not (memq x e))) (vector-ref ret 2)))))
            (mutex-unlock! mutex-id)
            (display "debug: thread yielding\n")
            (thread-yield!)
            (display "debug: thread resuming\n")
            (loop 0))))


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
    (mutex-lock! mutex-id)
    (let* ((len     (string-length iface))
           (fd      (##raw#socket))
           (mtu     (##raw#getmtu fd iface len))
           (bind    (##raw#bind fd iface len))
           (opts    (##raw#sockopts fd))
           (flags   (##raw#promisc-on fd iface len))
           (s       (##sys#make-structure 'raw-socket
                                          fd iface mtu flags #t '() #f
                                          (make-queue))))
        (hash-table-set! fd-table fd s)
        (set! fd-count (+ 1 fd-count))
        (and (<= fd-max fd)
             (set! fd-max (+ 1 fd)))
        (set! fd-list (cons fd fd-list))
        (set! fd-wlist (cons fd fd-wlist))
        (or thread-id
            (begin
                (set! thread-id (make-thread ##raw#select-handler))
                (thread-quantum-set! thread-id 1000)
                (thread-quantum-set! (current-thread) 1000)
                (thread-start! thread-id)))
        (mutex-unlock! mutex-id)
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

;; get the ready status
(define (raw-socket-wready? s)
    (check-raw-socket 'raw-socket-wready? s)
    (##raw#wready? s))

;; get the write queue
(define (raw-socket-wqueue s)
    (check-raw-socket 'raw-socket-wqueue s)
    (##raw#wqueue s))


;;; writing to a packet socket

;; write pkt to the socket, or queue if not ready
(define (raw-socket-send s pkt)
    (check-raw-socket 'raw-socket-send s pkt)
    (or (u8vector? pkt)
        (raw-error 'raw-socket-send #f (conc "pkt is not a u8vector: " pkt)
                   s pkt))
    (mutex-lock! mutex-id)
    (##raw#awqueue! s pkt)
    (mutex-unlock! mutex-id))


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
    (mutex-lock! mutex-id)
    (##raw#urecvers! s lbl proc)
    (mutex-unlock! mutex-id))

;; remove a recver procedure
(define (raw-socket-del-recver s lbl)
    (check-raw-socket 'raw-socket-del-recver s lbl)
    (or (symbol? lbl)
        (raw-error 'raw-socket-del-recver #f
                   (conc "label is not a symbol: " lbl) s lbl))
    (mutex-lock! mutex-id)
    (##raw#drecvers! s lbl)
    (mutex-unlock! mutex-id))

;; list recvers
(define (raw-socket-recvers s)
    (check-raw-socket 'raw-socket-recvers s)
    (##raw#recvers s))


;;; closing the packet socket

;; close a raw-socket
(define (close-raw-socket s)
    (check-raw-socket 'close-raw-socket s)
    (mutex-lock! mutex-id)
    (let ((fd      (##raw#fd s)))
        (##raw#promisc-off fd (##raw#iface s) (string-length (##raw#iface s))
                           (##raw#flags s))
        (##raw#close fd)
        (##raw#open! s #f)
        (set! fd-list (delete fd fd-list =))
        (set! fd-wlist (delete fd fd-wlist =))
        (hash-table-delete! fd-table fd)
        (set! fd-max (+ 1 (fold (lambda (x r) (max x r)) -2 fd-list)))
        (set! fd-count (- fd-count 1)))
    (if (= 0 fd-count)
        (begin
              (thread-terminate! thread-id)
              (thread-quantum-set! (current-thread) 10000)
              (set! thread-id #f)))
    (mutex-unlock! mutex-id)
    #t)

