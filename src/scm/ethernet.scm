(define (install-ethernet-protocol)
  
  ;; Fields ( list of lists with values: name, bitlength, validator, serializer ) 
  (define fields (list
                  (make-fieldvec 'destmac  48 #:valid mac-validator  #:serial mac-serializer )
                  (make-fieldvec 'srcmac   48 #:valid mac-validator  #:serial mac-serializer )
                  (make-fieldvec 'pkt-type 16 ) 
                  ))
  
  (define (generate packet vecs #!key data) (default-generator packet fields vecs))
  (define (validate packet) (default-validator packet fields))
  
  ;; Public Interface
  (put-op 'generate '(ethernet) generate)
  (put-op 'validate '(ethernet) validate)
  
  "ethernet done")


;; Testing Below Here----------------------------------------------------------------
;(install-ethernet-protocol)