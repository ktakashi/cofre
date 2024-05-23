;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;;   Copyright (c) 2024  Takashi Kato  <ktakashi@ymail.com>
;;;
;;;   Redistribution and use in source and binary forms, with or without
;;;   modification, are permitted provided that the following conditions
;;;   are met:
;;;
;;;   1. Redistributions of source code must retain the above copyright
;;;      notice, this list of conditions and the following disclaimer.
;;;
;;;   2. Redistributions in binary form must reproduce the above copyright
;;;      notice, this list of conditions and the following disclaimer in the
;;;      documentation and/or other materials provided with the distribution.
;;;
;;;   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;;;   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;;;   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;;;   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
;;;   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
;;;   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
;;;   TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
;;;   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
;;;   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;;;   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;;;   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;

;; Keystore command

#!nounbound
(library (cofre commands keystore)
    (export operation->command-executor
	    command-usage)
    (import (rnrs)
	    (rnrs eval)
	    (sagittarius)
	    (getopt)
	    (rfc base64)
	    (security keystore)
	    (sagittarius crypto keys)
	    (sagittarius crypto x509)
	    (sagittarius crypto random)
	    (sagittarius crypto signatures)
	    (srfi :13 strings)
	    (srfi :19 time)
	    (util duration)
	    (cofre commands api))
(define command-usage
  '(
    "keystore type operation -o $output -p $password [options]"
    "  OPTIONS"
    "    -s,--keystore: keystore $location[|$format], required"
    "      '~' for location means standard output."
    "      if it's used on input then signals an error."
    "    -p,--password: keystore password, required"
    "    -P,--key-password: individual key password, if not specified"
    "      using keystore password."
    "    -a,--alias:    alias of the entry."
    "    -S,--subject:  subject DN of the generating certificate"
    "    -A,--algorithm: key algorithm, default ec|secp256r1"
    "      Algorithm can be rsa, rsa|$bits, ec, ec|$curve, ed25519, ed448"
    "      Default RSA key size is 4096."
    "      $bits is provided, then it generates $bits size RSA key."
    "      Default EC curve is secp256r1 (aka NIST P-256)"
    "      $curve must be valid as *ec-parameter:$curve*"
    "    -T,--period:   Certificate period in days. Default 365"
    ""
    "  type: pkcs12, p12, jks or jceks"
    ""
    "  operation: create, gen"
    ""
    "  create:"
    "    Create an empty keystore"
    "  gen:"
    "    Generates self signed certificate with private key"
    ))

(define (operation->command-executor op)
  (case op
    ((pkcs12 p12) (keystore-operation 'pkcs12))
    ((jks)        (keystore-operation 'jks))
    ((jceks)      (keystore-operation 'jceks))
    (else (command-usage-error 'keystore "unknown keystore type"
			       command-usage op))))

(define ((keystore-operation type) . args)
  (define (option-error option)
    (command-usage-error 'keystore (string-append option " is required")
			 command-usage option))
  (define (check-option v option) (unless v (option-error option)))
  (with-args args
      ((keystore (#\s "keystore") #t (option-error "keystore"))
       (password (#\p "password") #t (option-error "password"))
       (key-password (#\P "key-password") #t #f)
       (alias (#\a "alias") #t #f)
       (subj (#\S "subject") #t #f)
       (algo (#\A "algorithm") #t "ec|secp256r1")
       (period (#\T "period") #t "365")
       . rest)
    (when (null? rest)
      (command-usage-error 'keystore "operation is missing" command-usage args))
    (let* ((op (string->symbol (car rest)))
	   (ks (case op
		 ((create) (make-keystore type))
		 (else (option->keystore type keystore password)))))
      (case op
	((gen)
	 (check-option subj "subject")
	 (check-option alias "alias")
	 (let-values (((priv-key cert)
		       (generate-self-signed-certificate subj algo period)))
	   (keystore-set-key! ks alias priv-key
			      (or key-password password)
			      (list cert)))))
      (write-keystore keystore ks password))))

(define (string-dn->list-components s)
  (define len (string-length s))
  (define (split-attr k&v)
    (cond ((string-index k&v #\=) =>
	   (lambda (i)
	     (list (string->symbol (substring k&v 0 i))
		   (substring k&v (+ i 1) (string-length k&v)))))
	  (else
	   (command-usage-error 'keystore "Invalid DN format"
				command-usage s))))
	     
  (let loop ((r '()) (off 0))
    (cond ((= off len) (reverse r))
	  ((string-index s #\, off) =>
	   (lambda (i)
	     (loop (cons (split-attr (substring s off i)) r) (+ i 1))))
	  (else
	   (reverse (cons (split-attr (substring s off len)) r))))))

(define random-generator (secure-random-generator *prng:chacha20*))
(define *serialnumber-upper-bound* (expt 2 64))

(define (generate-self-signed-certificate subj opt period)
  (define (generate-serial-number)
    (random-generator-random-integer random-generator
				     *serialnumber-upper-bound*))
  (define (generate-kp opt)
    (let-values (((algo other) (parse-attributed-option opt)))
      (cond ((string=? algo "rsa")
	     (values (generate-key-pair *key:rsa*
					:size (string->number (or other "4096")))
		     *signature-algorithm:rsa-ssa-pss*))
	    ((string=? algo "ec")
	     (let ((param (eval (string->symbol
				 (string-append "*ec-parameter:" other "*"))
				(environment '(sagittarius crypto keys)))))
	       (values (generate-key-pair *key:ecdsa* :ec-parameter param)
		       *signature-algorithm:ecdsa-sha256*)))
	    ((string=? algo "ed25519")
	     (values (generate-key-pair *key:ed25519*)
		     *signature-algorithm:ed25519*))
	    ((string=? algo "ed448")
	     (values (generate-key-pair *key:ed448*)
		     *signature-algorithm:ed448*))
	    (else (command-usage-error 'keystore "Unknown key algorithm"
				       command-usage opt)))))
  (define (->template dn sn period public-key)
    (define now (current-time))
    (define p (duration:of-days period))
    (x509-certificate-template-builder
     (issuer-dn dn)
     (subject-dn dn)
     (serial-number sn)
     (not-before (time-utc->date now))
     (not-after (time-utc->date (add-duration now p)))
     (public-key public-key)
     (extensions
      (list
       (make-x509-key-usage-extension
	(x509-key-usages digital-signature
			 key-encipherment
			 key-agreement
			 decipher-only)
	#t)
       (make-x509-private-key-usage-period-extension
	(make-x509-private-key-usage-period
	 :not-before (time-utc->date now))
	#t)
       
       (make-x509-basic-constraints-extension
	(make-x509-basic-constraints :ca #f))))))
  (let-values (((kp algo) (generate-kp opt)))
    (let ((priv-key (key-pair-private kp)))
      (values priv-key
	      (sign-x509-certificate-template
	       (->template (list->x509-name (string-dn->list-components subj))
			   (generate-serial-number)
			   (string->number period)
			   (key-pair-public kp))
	       algo priv-key)))))

(define (option->keystore type opt password)
  (define (open-input-port file fmt)
    (define (wrap-port in)
      (case fmt
	((base64)
	 (open-base64-decode-input-port in :owner? #t))
	(else in)))
    (unless (file-exists? file)
      (command-usage-error 'keystore "input keystore doesn't exist"
			   command-usage file))
    (wrap-port (open-file-input-port file)))

  (let-values (((loc fmt) (parse-i/o-option opt)))
    (when (string=? loc "~")
      (command-usage-error 'keystore "input keystore can't be stdin"
			   command-usage opt))
    (call-with-port (open-input-port loc fmt)
      (lambda (in) (load-keystore type in password)))))

(define (write-keystore opt ks password)
  (define (write-to-port out fmt value?)
    (define (wrap-port out)
      (case fmt
	((base64)
	 (open-base64-encode-output-port out
					 :owner? (not value?)
					 :line-width 76))
	(else out)))
    (let ((p (wrap-port out)))
      (store-keystore ks p password)
      (if value?
	  (cond ((eq? fmt 'base64)
		 (close-port p)
		 (utf8->string (get-output-bytevector out)))
		(else (get-output-bytevector out)))
	  (close-port p))))

  (let-values (((loc fmt) (parse-i/o-option opt)))
    (if (string=? loc "~")
	(let ((out (open-output-bytevector)))
	  (write-to-port out fmt #t))
	(let ((out (open-file-output-port loc (file-options no-fail))))
	  (write-to-port out fmt #f)
	  loc))))

(define (parse-i/o-option opt)
  (let-values (((a b) (parse-attributed-option opt)))
    (values a (or (and b (string->symbol b)) 'raw))))

(define (parse-attributed-option opt)
  (cond ((string-index opt #\|) =>
	 (lambda (index)
	   (let ((loc (substring opt 0 index))
		 (fmt (substring opt (+ index 1) (string-length opt))))
	     (values loc fmt))))
	(else (values opt #f))))

)
