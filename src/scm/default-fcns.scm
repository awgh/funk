(require 'regex)
(require 'crc16)
(require 'bit-cat)
(require 'srfi-1) ; for fold
(require 'srfi-66)

(define (make-fieldvec sym len #!key [valid (hex-validator len)] [serial (hex-serializer len)])
    (vector sym len valid serial))

;; Concatenate a u8vector
;; 
(define (u8vector-cat v1 v2)
    (cond ((null? v2)
              (if (null? v1)
                  (make-u8vector 1 0)
                  v1))
          ((null? v1)
             v2)
         (else
             (let* ((n1   (u8vector-length v1))
                    (n2   (u8vector-length v2))
                    (b   (make-u8vector (+ n1 n2) 0)))
                 (u8vector-copy! v1 0 b 0  n1)
                 (u8vector-copy! v2 0 b n1 n2) 
                 b))))

;; Data Type Validators and Serializers--------------------------------------------
(define mac-validator (lambda ( mac ) 
  (not (not (string-match "^((([a-fA-F0-9]){2}:){5}([a-fA-F0-9]){2})" mac)))
  ))

(define mac-display-serializer (lambda ( mac )
  (string-substitute ":" "" mac *)))

(define (hexstring->u8 str start buffer)
    (u8vector-set! buffer (/ start 2)
      (string->number (substring str start (+ start 2)) 16)))


(define mac-serializer (lambda ( mac )
  (define (mac-iter pmac start end buffer)
    (cond ((<= start end)
      (begin
         (hexstring->u8 pmac start buffer)
         (mac-iter pmac (+ start 2) end buffer)))
      (else buffer)))
  (define cleanmac (string-substitute ":" "" mac *))
 
  (mac-iter cleanmac 0 (- (string-length cleanmac) 2) 
            (make-u8vector (/ (string-length cleanmac) 2) 0) )))

; need to also check for valid value for bitlength
(define (hex-validator bits) (lambda (x) (not (not (string-match "^([a-fA-F0-9])*" x)))))

(define (hex-serializer bits) 
  (define (hex-iter hstr start end buffer)
    (cond ((<= start end)
           (begin
             (hexstring->u8 hstr start buffer)
             (hex-iter hstr (+ start 2) end buffer)))
          (else buffer)))
  (lambda (x) 
    (cond ((odd? (string-length x))
           (hex-iter (string-append "0" x) 0 (- (+ 1 (string-length x)) 2) 
                     (make-u8vector (/ (+ (string-length x) 1) 2) 0)))
          (else 
           (hex-iter x 0 (- (string-length x) 2) 
                     (make-u8vector (/ (string-length x) 2) 0))))))



(define ip-validator (lambda (x) (not (not (string-match
                                            "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.]){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" x)))))                         

(define (ip-serializer ip)
  (define (ip-iter strlist start end buffer)
    (cond ((<= start end)
      (begin
        (u8vector-set! buffer start (string->number (car strlist))) 
         (ip-iter (cdr strlist) (+ start 1) end buffer)))
      (else buffer)))    
  (ip-iter (string-split ip ".") 0 3 (make-u8vector 4 0)))


;;--------------------------------------------------------------------------------

;; Generate/Validate Operations on Packets and Protocols-------------------------
(define (generate-layer packet vecs #!key data) ( (get-op 'generate (car packet)) 
                                                  (cdr packet) vecs #:data data ) )
(define (validate-layer packet vecs) ( (get-op 'validate (car packet)) (cdr packet)) )

(define (validate packet) 
 (cond ((null? packet) '())
       (else 
       (cons (validate-layer (car packet))
       (validate (cdr packet)) 
       ))))

; pre-elf
(define (generate-old packet) 
 (cond ((null? packet) '())
       (else
       (u8vector-cat (generate-layer (car packet))
       (generate (cdr packet))
       ))))

; post-elf (thanks elf!)
(define (generate packet #!key data)
    (let loop ((vecs   '())
               (pack   packet))
        (if (null? pack)
            (fold (lambda (a b) (u8vector-cat (cdr a) b)) '() vecs)
            
            (loop (cons (cons (caar pack) (generate-layer (car pack) vecs #:data data))
                        vecs)
                  (cdr pack)))))

;;--------------------------------------------------------------------------------

;; Protocol Field Getters
(define (field-symbol x)    (vector-ref x 0))
(define (field-bitlength x) (vector-ref x 1))
(define (field-validator x) (vector-ref x 2))
(define (field-serializer x)
  (vector-ref x 3))

(define (bytes-for-bits bits) 
    (ceiling (/ bits 8)))

;; Default Protocol-Internal Generators and Validators----------------------------
  (define (default-generator packet fields vecs) 
    (let* ([buffer (make-u8vector 1024 0)]
           [bytes  (bytes-for-bits (generate-iter packet fields buffer vecs))]
           [retval (make-u8vector bytes 0)]
           )                 
      (begin
        ;(u8vector-copy! source source-start target target-start n)
        (u8vector-copy! buffer (- (u8vector-length buffer) bytes) retval 0 bytes)
        retval
        )
      ))

  (define (generate-iter packet flds buffer vecs)
      (cond ((or (null? packet) (null? flds)) 0)
            (else
             (bit-cat
              ((field-serializer (car flds)) (car packet))
              (field-bitlength  (car flds))
              buffer
              (generate-iter (cdr packet) (cdr flds) buffer vecs)
              )
             )))
      
  (define (default-validator packet fields) (validate-iter packet fields))  
  (define (validate-iter packet flds)
    (cond ((or (null? packet) (null? flds)) '())
          (else
           (cons
            
            (cons (field-symbol (car flds)) 
                  ((field-validator (car flds)) (car packet)))
            
            (validate-iter (cdr packet) (cdr flds)))
           )))
;;--------------------------------------------------------------------------------
