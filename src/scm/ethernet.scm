(load "default-fcns.scm")

(define (install-ethernet-protocol)
  
  ;; Fields ( list of lists with values: name, bitlength, validator, serializer ) 
  (define fields (list
                  (list 'destmac  48 mac-validator mac-serializer)
                  (list 'srcmac   48 mac-validator mac-serializer)
                  (list 'pkt-type 16 (hex-validator 16) (hex-serializer 16)) 
                  ))
  
  (define (generate packet aggregator) (default-generator packet fields aggregator))
  (define (validate packet) (default-validator packet fields))
  
  ;; Public Interface
  (put-op 'generate '(ethernet) generate)
  (put-op 'validate '(ethernet) validate)
  
  "ethernet done")


;; Testing Below Here----------------------------------------------------------------
(install-ethernet-protocol)