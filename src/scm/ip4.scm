(require 'crc16)

(define (install-ip4-protocol)
  
  ;; Fields ( list of lists with values: name, bitlength, validator, serializer ) 
  (define fields (list
                  (make-fieldvec 'version  4 )
                  (make-fieldvec 'internet-header-length 4 )
                  (make-fieldvec 'type-of-service 8 ) 
                  (make-fieldvec 'total-length 16 ) 
                  (make-fieldvec 'identification 16 )                   
                  (make-fieldvec 'CE 1 )                   
                  (make-fieldvec 'DF 1 )                   
                  (make-fieldvec 'MF 1 )                                     
                  (make-fieldvec 'fragment-offset 13 )                                     
                  (make-fieldvec 'time-to-live 8 )                   
                  (make-fieldvec 'protocol 8 )
                  (make-fieldvec 'header-checksum 16 )                                     
                  (make-fieldvec 'source-ip 32 #:valid ip-validator #:serial ip-serializer)                   
                  (make-fieldvec 'dest-ip   32 #:valid ip-validator #:serial ip-serializer)                   
                  (make-fieldvec 'options    0 #:valid (hex-validator 32) #:serial (hex-serializer 32))                                     
                  ))   
  
  (define (ip4-generator packet fields vecs #!key data)
    (let* ([buffer   (default-generator packet fields vecs #:data data)]
           [checksum (crc-16 buffer (u8vector-length buffer))])
       (begin         
         (u8vector-copy! checksum 0 buffer 10 2)
         buffer
        )
     ))
  
  (define (generate packet vecs #!key data) (ip4-generator packet fields vecs #:data data))
  (define (validate packet vecs #!key data) (default-validator packet fields vecs #:data data))
  
  ;; Default values for fields
  (define (make-layer #!key
                      [version "4"]
                      [internet-header-length "5"]
                      [type-of-service "0"]
                      [total-length 
                       (lambda (packet fields vecs #!key data) 
                         (let* ([str (number->string 
                                      (if data (+ 20 20 (u8vector-length data)) 40) 
                                      16)]
                                [strlen (string-length str)])
                                (if (< strlen 4)
                                    (string-append (make-string (- 4 strlen) #\0) str)
                                    str)))]
                      [identification "0000"]
                      [CE "0"]
                      [DF "1"]
                      [MF "0"]
                      [fragment-offset "0"]
                      [time-to-live "80"]
                      [protocol "6"]
                      [header-checksum "0"]
                      [source-ip "192.168.1.1"]
                      [dest-ip   "192.168.1.2"]
                      [options ""]
                      )
    (attach-tag '(ip4)
                (list version internet-header-length type-of-service total-length
                      identification CE DF MF fragment-offset time-to-live protocol
                      header-checksum source-ip dest-ip options)))
                   
  ;; Public Interface
  (put-op 'generate   '(ip4) generate)
  (put-op 'validate   '(ip4) validate)
  (put-op 'make-layer '(ip4) make-layer)
  
  "ip4 done")


;; Testing Below Here----------------------------------------------------------------
;(install-ip4-protocol)