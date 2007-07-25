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
    (let* ([genbuf   (default-generator packet fields vecs)]
           [tcpsize  (u8vector-length genbuf)]
           [ipbuf    (cdr (car vecs))]
           [checksum (make-u8vector 2 0)]
           [crcbuf   (make-u8vector (+ 96 tcpsize) 0)])
       (begin
         ; copy out ip fields for tcp pseudo-header
         (u8vector-copy! ipbuf 12 crcbuf 0 4) ; source ip
         (u8vector-copy! ipbuf 16 crcbuf 4 4) ; dest ip
         (u8vector-copy! ipbuf  9 crcbuf 9 1) ; protocol
         (u8vector-copy! genbuf 0 crcbuf 12 tcpsize) ; copy the rest
         (crc-16 crcbuf (+ 96 tcpsize) checksum)
         (u8vector-copy! checksum 0 genbuf 16 2)
         genbuf
        )
     ))
  
  (define (generate packet vecs) (tcp-generator packet fields vecs))
  (define (validate packet) (default-validator packet fields))
  
  ;; Public Interface
  (put-op 'generate '(tcp) generate)
  (put-op 'validate '(tcp) validate)
  
  "tcp done")


;; Testing Below Here----------------------------------------------------------------
;(install-tcp-protocol)