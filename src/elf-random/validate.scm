;;; package: scheme-smtp
;;; file:    validate.scm
;;; purpose: validate and normalise various types of data

;; note: ben, hey, i just wrote this today, i just thought you might be 
;; interested.  its entirely uncommented and messy as hell.  the range 
;; validation stuff is why im copying it into here, cause it successfully
;; generates fairly optimised regexes for matching against ipv4 ranges.  
;; (the other stuff is pretty trivial.)  this might be fun to generalise a
;; bit ... :)  its fast as hell and precompilation is fairly cheap.   with
;; this its possible to define a hash-table with regexes as the args and 
;; the equal function a modified hash-table-ref.... O(longest-regex-time) and
;; its intentionally structured to minimise regex timings (assuming its not
;; cisco writing the regex engine)

(use srfi-13)
(use srfi-14)
(use regex)

(define (validate-nomatch fname arg)
    (signal (make-composite-condition
                (make-property-condition 'validate)
                (make-property-condition 'nomatch
                                         'type fname
                                         'args arg))))

(define (validate-range type fname . arg)
    (signal (make-composite-condition
                (make-property-condition 'exn
                                         'message (if (eq? '> type)
                                                      "invalid range (a > b)"
                                                      "invalid range (a = b)")
                                         'location fname
                                         'arguments arg)
                (make-property-condition 'validate)
                (make-property-condition 'bad-range))))

(define (v-rx s)    (regexp (string-append "^" s "$") #t #f #f))

(define vdb "[a-z0-9]([a-z0-9-]*[a-z0-9])*")
(define v-domain (conc "(" vdb "[.])+[a-z]+"))
(define v-local  (conc "(" vdb "[.])*((" vdb ")*[a-z](" vdb ")*)"))
(define v4b "(([0-9])|([1-9][0-9])|(1[0-9]{2})|(2(([0-4][0-9])|(5[0-5]))))")
(define v-ipv4 (conc "(" v4b "[.]){3}" v4b))
(define v4r "[/](([1-9])|([12][0-9])|(3[012]))")
(define v-ipv4r (conc "(" v-ipv4 "[-]" v-ipv4 ")|((" v4b "[.]){0,3}" v4b v4r ")"))

(define vrx-domain  (v-rx v-domain))
(define vrx-local   (v-rx v-local))
(define vrx-ipv4    (v-rx v-ipv4))
(define vrx-ipv4r   (v-rx v-ipv4r))

(define (validate-domain d)
   (if (string-search vrx-domain d)
       (cons 'domain d)
       (validate-nomatch 'domain d)))

(define (validate-local d)
    (if (string-search vrx-local d)
        (cons 'local d)
        (validate-nomatch 'local d)))

(define (validate-ipv4 d)
    (if (string-search vrx-ipv4 d)
        (cons 'ipv4 d)
        (validate-nomatch 'ipv4 d)))

(define (ipv4-num d s #!optional (e (string-length d)))
    (map string->number (string-tokenize (substring d s e) char-set:digit)))

(define (validate-ipv4-range d)
    (let ((t   (string-search vrx-ipv4r d)))
        (if t
            (cons 'ipv4-range
                  (v-rx (if (cadr t)
                  ;(conc (if (cadr t)
                            (let ((i   (string-index d #\-)))
                                (gen-ipv4-range d ""
                                                (ipv4-num d 0 i)
                                                (ipv4-num d (+ 1 i))))
                            (let ((t   (ipv4-num d 0)))
                                (gen-ipv4-block d
                                                (drop-right t 1)
                                                (car (take-right t 1)))))))
            (validate-nomatch 'ipv4-range d))))

(define (ipv4-rng-full? d1 d2)
    (and (= 0 (car d1)) (= 255 (car d2))))

(define (ipv4-rng-1? d1 d2)
    (= 1 (- (car d2) (car d1))))

(define (gen-ipv4-range o s d1 d2)
    (cond ((null? d1)
              (validate-range '= 'gen-ipv4-range o))
          ((> (car d1) (car d2))
              (validate-range '> 'gen-ipv4-range o))
          ((= (car d1) (car d2))
              (gen-ipv4-range o (conc s (car d1) "[.]") (cdr d1) (cdr d2)))
          ((null? (cdr d1))
              (if (ipv4-rng-full? d1 d2)
                  (conc s v4b)
                  (conc s "(" (ipv4-rng d1 d2) ")")))
          (else
              (let loop ((r1   (reverse (cdr d1)))
                         (r2   (reverse (cdr d2)))
                         (s1   "")
                         (s2   "")
                         (sf   0)
                         (lt   0))
                  (cond ((null? r1)
                            (if (= sf lt)
                                (if (ipv4-rng-full? d1 d2)
                                    (case sf
                                        ((3)    v-ipv4)
                                        ((2)    (conc s "(" v4b "[.]){2}" v4b))
                                        ((1)    (conc s v4b "[.]" v4b)))
                                    (let ((i   (conc "(" (ipv4-rng d1 d2) ")[.]")))
                                        (case sf
                                            ((3)
                                                (conc i "(" v4b "[.]){2}" v4b))
                                            ((2)
                                                (conc s i v4b "[.]" v4b))
                                            ((1)
                                                (conc s i v4b)))))
                                (if (ipv4-rng-1? d1 d2)
                                    (conc s "((" (car d1) "[.](" s1
                                            ")|(" (car d2) "[.](" s2 "))"
                                            (case sf
                                                ((2)    (conc v4b "[.]" v4b))
                                                ((1)    v4b)
                                                ((0)    "")))
                                    (conc s "((" (car d1) "[.](" s1
                                            ")|(" (car d2) "[.](" s2 ")|(("
                                            (ipv4-rng (+ 1 (car d1))
                                                      (- (car d2) 1)) 
                                            ")[.](" v4b
                                            (case (- lt sf)
                                                ((3)    (conc "[.]){2}" v4b))
                                                ((2)    (conc "[.]" v4b ")"))
                                                ((1)    ")"))
                                            (if (> sf 0) "[.]))" "))")
                                            (case sf
                                                ((2)    (conc v4b "[.]" v4b))
                                                ((1)    v4b)
                                                ((0)    ""))))))
                        ((and (ipv4-rng-full? r1 r2) (string-null? s1))
                            (loop (cdr r1) (cdr r2) s1 s2 (+ 1 sf) (+ 1 lt)))
                        ((string-null? s1)
                            (if (= 0 sf)
                                (loop (cdr r1) (cdr r2)
                                      (conc (ipv4-rng1 (car r1) 255) ")")
                                      (conc (ipv4-rng1 0 (car r2)) ")")
                                      sf (+ 1 lt))
                                (loop (cdr r1) (cdr r2)
                                      (conc (ipv4-rng1 (car r1) 255) "[.])")
                                      (conc (ipv4-rng1 0 (car r2)) "[.])")
                                      sf (+ 1 lt))))
                        (else
                            (loop (cdr r1) (cdr r2)
                                  (conc (ipv4-rng1 (car r1) 255) "[.]" s1)
                                  (conc (ipv4-rng1 0 (car r2)) "[.]" s2)
                                  sf (+ 1 lt))))))))


(define (ipv4-rng9 n)    (if (= 9 n) "9" (conc "[" n "-9]")))
(define (ipv4-rng0 n)    (if (= 0 n) "0" (conc "[0-" n "]")))
(define (ipv4-rngnz n)   (if (= 0 n) "" n))


(define (ipv4-rng% st et so eo)
    (cond ((= st et)
              (conc (ipv4-rngnz st) "[" so "-" eo "]"))
          ((= 1 (- et st))
              (conc "((" (ipv4-rngnz st) (ipv4-rng9 so)
                    ")|(" (ipv4-rngnz et) (ipv4-rng0 eo) "))"))
          (else
              (conc "((" (ipv4-rngnz st) (ipv4-rng9 so)
                    ")|([" (+ 1 st) "-" (- et 1) "][0-9]"
                    ")|(" (ipv4-rngnz et) (ipv4-rng0 eo)
                    "))"))))

(define (pl1s% n)      (fxmod n 10))
(define (pl10s% n)     (fxmod (fx/ n 10) 10))
(define (pl100s% n)    (fx/ n 100))

(define (bits-mask n)    (- (fxshl 1 n) 1))

(define (ipv4-rng s e)
    (ipv4-rng1 (if (pair? s) (car s) s)
               (if (pair? e) (car e) e)))

(define (ipv4-rng1 s e)
    (if (and (= 0 s) (= 255 e))
        v4b
        (let ((sh   (pl100s% s))
              (eh   (pl100s% e)))
            (if (= sh eh)
                (conc "(" (ipv4-rngnz sh)
                      (ipv4-rng% (pl10s% s) (pl10s% e) (pl1s% s) (pl1s% e))
                      ")")
                (let ((ps   (ipv4-rng% (pl10s% s) 9 (pl1s% s) 9))
                      (pe   (ipv4-rng% 0 (pl10s% e) 0 (pl1s% e))))
                  (if (= 1 sh)
                      (conc "((1" ps ")|(2" pe "))")
                      (if (= 1 eh)
                          (conc "((" ps ")|(1" pe "))")
                          (conc "((" ps ")|(1[0-9][0-9])|(2" pe "))"))))))))

(define (gen-ipv4-block d i m)
    (let loop ((l   (append i (make-list (- 4 (length i)) 0)))
               (m   m)
               (s   '())
               (e   '()))
        (cond ((null? l)
                  (gen-ipv4-range d "" (reverse s) (reverse e)))
              ((= m 0)
                  (loop (cdr l) m (cons 0 s) (cons 255 e)))
              ((< m 8)
                  (loop (cdr l) 0 (cons (car l) s) 
                                  (cons (fxior (car l) (bits-mask (- 8 m))) e)))
              (else
                  (loop (cdr l) (- m 8) (cons (car l) s) (cons (car l) e))))))
          


