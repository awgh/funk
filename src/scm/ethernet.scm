(define (install-ethernet-protocol)
  
  ;; Fields ( list of lists with values: name, bitlength, validator, serializer ) 
  (define fields (list
                  (vector 'destmac  48 mac-validator mac-serializer)
                  (vector 'srcmac   48 mac-validator mac-serializer)
                  (vector 'pkt-type 16 (hex-validator 16) (hex-serializer 16)) 
                  ))
  
  (define (generate packet) (default-generator packet fields))
  (define (validate packet) (default-validator packet fields))
  
  ;; Public Interface
  (put-op 'generate '(ethernet) generate)
  (put-op 'validate '(ethernet) validate)
  
  "ethernet done")


;; Testing Below Here----------------------------------------------------------------
;(install-ethernet-protocol)