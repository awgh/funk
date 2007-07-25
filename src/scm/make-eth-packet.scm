(load "table.scm")
(load "default-fcns.scm")
(load "ethernet.scm")
(load "ip4.scm")
    
(install-ethernet-protocol)
(install-ip4-protocol)

(define my-ip-packet (attach-tag '(ip4)
                      (list
                       "4" "5" "0" "0030"
                       "0074" "0" "1" "0"
                       "0" "80" "6"
                       "0" "192.168.1.1"
                       "192.168.1.2" ""
                       )))

(define my-eth-packet (attach-tag '(ethernet)
                      (list
                       "12:34:56:78:90:12"
                       "AA:BB:CC:DD:EE:FF"
                       "0800")))


(define my-packet (list my-eth-packet my-ip-packet ))

; send packet out 
(require 'raw-sockets)
(raw-open "eth0")
(define raw-packet (generate my-packet))
(raw-send raw-packet (u8vector-length raw-packet))
(raw-close)

;(display (validate my-packet))
;(newline)
;(display my-packet)
;(display (generate my-packet))
;(newline)

