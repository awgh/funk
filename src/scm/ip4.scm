(require 'crc16)

(define (install-ip4-protocol)
  
  ;; Fields ( list of lists with values: name, bitlength, validator, serializer ) 
  (define fields (list
                  (vector 'version  4 (hex-validator 4) (hex-serializer 4))
                  (vector 'internet-header-length 4 (hex-validator 4) (hex-serializer 4))
                  (vector 'type-of-service 8 (hex-validator 8) (hex-serializer 8)) 
                  (vector 'total-length 16 (hex-validator 16) (hex-serializer 16)) 
                  (vector 'identification 16 (hex-validator 16) (hex-serializer 16))                   
                  (vector 'CE 1 (hex-validator 1) (hex-serializer 1))                   
                  (vector 'DF 1 (hex-validator 1) (hex-serializer 1))                   
                  (vector 'MF 1 (hex-validator 1) (hex-serializer 1))                                     
                  (vector 'fragment-offset 13 (hex-validator 13) (hex-serializer 13))                                     
                  (vector 'time-to-live 8 (hex-validator 8) (hex-serializer 8))                   
                  (vector 'protocol 8 (hex-validator 8) (hex-serializer 8))
                  (vector 'header-checksum 16 (hex-validator 16) (hex-serializer 16))                                     
                  (vector 'source-ip 32 ip-validator ip-serializer)                   
                  (vector 'dest-ip 32 ip-validator ip-serializer)                   
                  (vector 'options 0 (hex-validator 32) (hex-serializer 32))                                     
                  ))   
  
  (define (ip4-generator packet fields)
    (let* ([buffer   (default-generator packet fields)]
           [checksum (make-u8vector 2 0)])
       (begin
         (crc-16 buffer (u8vector-length buffer) checksum)
         (u8vector-copy! checksum 0 buffer 10 2)
         buffer
        )
     ))
  
  (define (generate packet) (ip4-generator packet fields))
  (define (validate packet) (default-validator packet fields))
  
  ;; Public Interface
  (put-op 'generate '(ip4) generate)
  (put-op 'validate '(ip4) validate)
  
  "ip4 done")


;; Testing Below Here----------------------------------------------------------------
;(install-ip4-protocol)