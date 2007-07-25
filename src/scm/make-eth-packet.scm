(load "table.scm")
(load "default-fcns.scm")
(load "ethernet.scm")
(load "ip4.scm")
(load "tcp.scm")
    
(install-ethernet-protocol)
(install-ip4-protocol)
(install-tcp-protocol)

(define make-ethernet-layer (get-op 'make-layer '(ethernet)))
(define make-ip-layer (get-op 'make-layer '(ip4)))
(define make-tcp-layer (get-op 'make-layer '(tcp)))

(define my-data (make-u8vector 8 255))                         

(define my-tcp-packet (make-tcp-layer))

(define my-ip-packet (make-ip-layer))

(define my-eth-packet (make-ethernet-layer))

(define my-packet (list my-eth-packet my-ip-packet my-tcp-packet))

; send packet out 
(require 'raw-sockets)
(raw-open "eth0")
(define raw-packet (generate my-packet #:data my-data))
(raw-send raw-packet (u8vector-length raw-packet))
(raw-close)

;(display (validate my-packet))
;(newline)
;(display my-packet)
;(display (generate my-packet))
;(newline)

