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
  
  (define (ip4-generator packet fields vecs)
    (let* ([buffer   (default-generator packet fields vecs)]
           [checksum (make-u8vector 2 0)])
       (begin
         (crc-16 buffer (u8vector-length buffer) checksum)
         (u8vector-copy! checksum 0 buffer 10 2)
         buffer
        )
     ))
  
  (define (generate packet vecs #!key data) (ip4-generator packet fields vecs))
  (define (validate packet) (default-validator packet fields))
  
  ;; Public Interface
  (put-op 'generate '(ip4) generate)
  (put-op 'validate '(ip4) validate)
  
  "ip4 done")


;; Testing Below Here----------------------------------------------------------------
;(install-ip4-protocol)