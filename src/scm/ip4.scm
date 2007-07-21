;(load "default-fcns.scm")
(require 'crc16)

(define (install-ip4-protocol)
  
  ;; Fields ( list of lists with values: name, bitlength, validator, serializer ) 
  (define fields (list
                  (list 'version  4 (hex-validator 4) (hex-serializer 4))
                  (list 'internet-header-length 4 (hex-validator 4) (hex-serializer 4))
                  (list 'type-of-service 8 (hex-validator 8) (hex-serializer 8)) 
                  (list 'total-length 16 (hex-validator 16) (hex-serializer 16)) 
                  (list 'identification 16 (hex-validator 16) (hex-serializer 16))                   
                  (list 'CE 1 (hex-validator 1) (hex-serializer 1))                   
                  (list 'DF 1 (hex-validator 1) (hex-serializer 1))                   
                  (list 'MF 1 (hex-validator 1) (hex-serializer 1))                                     
                  (list 'fragment-offset 13 (hex-validator 13) (hex-serializer 13))                                     
                  (list 'time-to-live 8 (hex-validator 8) (hex-serializer 8))                   
                  (list 'protocol 8 (hex-validator 8) (hex-serializer 8))
                  (list 'header-checksum 16 (hex-validator 16) (hex-serializer 16))                                     
                  (list 'source-ip 32 ip-validator ip-serializer)                   
                  (list 'dest-ip 32 ip-validator ip-serializer)                   
                  (list 'options 0 (hex-validator 32) (hex-serializer 32))                                     
                  ))
  
  (define (ipv4-generator packet fields aggregator)  
    (define (ipv4-iter packet flds aggregator prevData)
      (cond ((or (null? packet) (null? flds)) prevData)
            ((eq? (car (car flds)) 'header-checksum)
             (ipv4-iter (cdr packet) (cdr fields) aggregator (aggregator prevData (crc-16 prevData))))
            (else (ipv4-iter (cdr packet) (cdr fields) aggregator (aggregator prevData ((car (cdddr (car flds))) (car packet)))))
            )
     (ipv4-iter packet fields aggregator '()))); need a bitfield aggregator     
  
  ;(define (generate packet aggregator) (default-generator packet fields aggregator))
  (define (generate packet) (default-generator packet fields))
  (define (validate packet) (default-validator packet fields))
  
  ;; Public Interface
  (put-op 'generate '(ip4) generate)
  (put-op 'validate '(ip4) validate)
  
  "ip4 done")


;; Testing Below Here----------------------------------------------------------------
(install-ip4-protocol)