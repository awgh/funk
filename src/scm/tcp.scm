(require 'crc16)

(define (install-tcp-protocol)
  
  ;; Fields ( list of vectors with values: name, bitlength, validator, serializer ) 
  (define fields (list
                  (make-fieldvec 'src-port  16 )
                  (make-fieldvec 'dest-port 16 )
                  (make-fieldvec 'seq       32 )
                  (make-fieldvec 'ack       32 )
                  (make-fieldvec 'offset     4 )
                  (make-fieldvec 'reserved   4 )
                  (make-fieldvec 'CWR        1 )
                  (make-fieldvec 'ECE        1 )                                     
                  (make-fieldvec 'URG        1 )                   
                  (make-fieldvec 'ACK        1 )                                     
                  (make-fieldvec 'PSH        1 )                   
                  (make-fieldvec 'RST        1 )                                     
                  (make-fieldvec 'SYN        1 )                   
                  (make-fieldvec 'FIN        1 ) 
                  (make-fieldvec 'win-size  16 )                  
                  (make-fieldvec 'checksum  16 )
                  (make-fieldvec 'urg-data  16 )
                  (make-fieldvec 'options    0 #:valid (hex-validator 32) #:serial (hex-serializer 32))                                                       
                  ))   
  
  (define (tcp-generator packet fields vecs)
    (let* ([buffer   (default-generator packet fields)]
           [checksum (make-u8vector 2 0)])
       (begin
         (crc-16 buffer (u8vector-length buffer) checksum)
         (u8vector-copy! checksum 0 buffer 10 2)
         buffer
        )
     ))
  
  (define (generate packet vecs) (tcp-generator packet fields vecs))
  (define (validate packet) (default-validator packet fields))
  
  ;; Public Interface
  (put-op 'generate '(tcp) generate)
  (put-op 'validate '(tcp) validate)
  
  "tcp done")


;; Testing Below Here----------------------------------------------------------------
(install-tcp-protocol)