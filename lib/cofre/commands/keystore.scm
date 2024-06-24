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
	    (sagittarius crypto signatures)
	    (sagittarius crypto x509)
	    (cofre commands api)
	    (cofre x509))
(define command-usage
  '(
    "keystore type operation -s $keystore -p $password [options]"
    "  OPTIONS"
    "    -s,--keystore: keystore $location[|$format], required"
    "    -p,--password: keystore password, required"
    "    -P,--key-password: individual key password, if not specified"
    "      using keystore password."
    "    -a,--alias:    alias of the entry."
    "    -S,--subject:  subject DN of the generating certificate"
    "    -A,--algorithm: key algorithm, default ec|secp256r1"
    "      Supporting algorithms:"
    "        - rsa, rsa|$bits: RSA with PKCS v1.5 signature"
    "        - rsa-pss, rsa-pss|$bits: RSA with RSA-SSAPSS"
    "        - ec, ec|$curve:  ECDSA with $curve"
    "        - ed25519:        Ed25519"
    "        - ed448:          Ed448"
    "      Default RSA key size is 4096."
    "      $bits is provided, then it generates $bits size RSA key."
    "      Default EC curve is secp256r1 (aka NIST P-256)"
    "      $curve must be valid as *ec-parameter:$curve*"
    "    -T,--period:   Certificate period in days. Default 365"
    "    -o,--output:   Output file $location[|$format]"
    ""
    "$location[|$format]"
    "   '~' for location means standard output."
    "   if it's used on input then signals an error."
    "   $format can be `base64`, `raw` and `pem` (only export/import)"
    ""
    "Alias option"
    "   for export and import operation, alias can be $alias[|$type]"
    "   $type can be `private-key` or `certificate` "
    ""
    "  type: pkcs12, p12, jks or jceks"
    ""
    "  operation: create, gen, list"
    ""
    "  create:"
    "    Creates an empty keystore"
    "  gen:"
    "    Generates self signed certificate with private key"
    "    This command requires -a and -S options"
    "  list:"
    "    Lists all the certificate entry with its finger print"
    "  export:"
    "    Exports specified entry"
    "    This command requires -a and -o options"
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
       (export-password (#\E "export-password") #t #f)
       (alias (#\a "alias") #t #f)
       (subj (#\S "subject") #t #f)
       (algo (#\A "algorithm") #t "ec|secp256r1")
       (period (#\T "period") #t "365")
       (output (#\o "output") #t #f)
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
	 (let ((subjct-dn (string->x509-name subj)))
	   (unless subjct-dn
	     (command-usage-error 'keystore "Invalid DN format"
				  command-usage subj))
	   (let*-values (((kp algorithm) (generate-kp algo))
			 ((priv-key cert)
			  (generate-self-signed-certificate
			   subjct-dn kp algorithm period)))
	     (unless priv-key
	       (command-usage-error
		'keystore "Failed to generate self signed certificate"
		command-usage algo))
	     (keystore-set-key! ks alias priv-key
				(or key-password password)
				(list cert))
	     (write-keystore keystore ks password))))
	((list)
	 (cond-expand
	  ((and cond-expand.version (version (>= "0.9.12")))
	   (map (lambda (alias)
		  (cons alias
			(x509-finger-print (keystore-get-certificate ks alias))))
		(keystore-aliases ks)))
	  (else '())))
	((export)
	 (check-option output "output")
	 (check-option alias "alias")
	 (let-values (((loc fmt) (parse-i/o-option output))
		      ((name entry-fmt) (parse-entry-option alias)))
	   (let ((e (case entry-fmt
		      ((private-key)
		       (retrieve-private-key ks name
			(or key-password password) export-password))
		      ((certificate)
		       (keystore-get-certificate ks name))
		      ((public-key)
		       (x509-certificate-public-key
			(keystore-get-certificate ks name)))
		      (else
		       (command-usage-error 'keystore "Invalid entry type"
					    command-usage entry-fmt)))))
	     (write-entry loc fmt e))))
	;; damn...
	(else (write-keystore keystore ks password))))))

(define (write-entry loc fmt entry)
  (define value? (string=? "~" loc))
  (define type (case fmt
		 ((pem base64) (object-type pem))
		 ((raw cer) (object-type cer))
		 (else
		  (command-usage-error 'keystore "Invalid output format"
				       command-usage fmt))))
  (let ((bv (object->bytevector entry type))
	(out (if value?
		 (open-output-bytevector)
		 (open-file-output-port loc (file-options no-fail)))))
    (put-bytevector out bv)
    (cond (value?
	   (let ((bv (get-output-bytevector out)))
	     (if (eq? type 'pem)
		 (utf8->string bv)
		 bv)))
	  (else (close-port out) loc))))


    
(define (retrieve-private-key ks name password encryption-password)
  (let ((pk (keystore-get-key ks name password)))
    (if encryption-password
	(encrypt-private-key pk encryption-password)
	(private-key->private-key-info pk))))
      
(define (generate-kp opt)
  (let-values (((algo other) (parse-attributed-option opt)))
    (cond ((string=? algo "rsa")
	   (values (generate-key-pair *key:rsa*
				      :size (string->number (or other "4096")))
		   *signature-algorithm:rsa-pkcs-v1.5-sha256*))
	  ((string=? algo "rsa-pss")
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
    (if (file-exists? loc)
	(call-with-port (open-input-port loc fmt)
	  (lambda (in) (load-keystore type in password)))
	(make-keystore type))))

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

(define (parse-entry-option opt)
  (let-values (((a b) (parse-attributed-option opt)))
    (values a (or (and b (string->symbol b)) 'certificate))))

)
