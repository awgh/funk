(require 'crc16)

(define (install-tcp-protocol)
  
  ;; Fields ( list of vectors with values: name, bitlength, validator, serializer ) 
  (define fields (list
                  (vector 'src-port  16 (hex-validator 16) (hex-serializer 16))
                  (vector 'dest-port 16 (hex-validator 16) (hex-serializer 16))
                  (vector 'seq       32 (hex-validator 32) (hex-serializer 32))
                  (vector 'ack       32 (hex-validator 32) (hex-serializer 32))
                  (vector 'offset     4 (hex-validator 4)  (hex-serializer 4))
                  (vector 'reserved   4 (hex-validator 4)  (hex-serializer 4))
                  (vector 'CWR        1 (hex-validator 1)  (hex-serializer 1))
                  (vector 'ECE        1 (hex-validator 1)  (hex-serializer 1))                                     
                  (vector 'URG        1 (hex-validator 1)  (hex-serializer 1))                   
                  (vector 'ACK        1 (hex-validator 1)  (hex-serializer 1))                                     
                  (vector 'PSH        1 (hex-validator 1)  (hex-serializer 1))                   
                  (vector 'RST        1 (hex-validator 1)  (hex-serializer 1))                                     
                  (vector 'SYN        1 (hex-validator 1)  (hex-serializer 1))                   
                  (vector 'FIN        1 (hex-validator 1)  (hex-serializer 1)) 
                  (vector 'win-size  16 (hex-validator 16) (hex-serializer 16))                  
                  (vector 'checksum  16 (hex-validator 16) (hex-serializer 16))
                  (vector 'urg-data  16 (hex-validator 16) (hex-serializer 16))
                  (vector 'options    0 (hex-validator 32) (hex-serializer 32))                                                       
                  ))   
  
  (define (tcp-generator packet fields)
    (let* ([buffer   (default-generator packet fields)]
           [checksum (make-u8vector 2 0)])
       (begin
         (crc-16 buffer (u8vector-length buffer) checksum)
         (u8vector-copy! checksum 0 buffer 10 2)
         buffer
        )
     ))
  
  (define (generate packet) (tcp-generator packet fields))
  (define (validate packet) (default-validator packet fields))
  
  ;; Public Interface
  (put-op 'generate '(tcp) generate)
  (put-op 'validate '(tcp) validate)
  
  "tcp done")


;; Testing Below Here----------------------------------------------------------------
(install-tcp-protocol)