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

#!nounbound
(library (cofre x509)
    (export x509-finger-print
	    decode-pem-string
	    base64-string->certificate
	    string->x509-name
	    generate-self-signed-certificate
	    encrypt-private-key
	    private-key->private-key-info
	    object->bytevector object-type)
    (import (rnrs)
	    (rfc base64)
	    (util duration)
	    (srfi :13 strings)
	    (srfi :19 time)
	    (sagittarius crypto digests)
	    (sagittarius crypto keys)
	    (sagittarius crypto random)
	    (sagittarius crypto pem)
	    (sagittarius crypto pkcs keystore)
	    (sagittarius crypto pkcs keys)
	    (sagittarius crypto pkcs pbes)
	    (sagittarius crypto x509))

(define (x509-finger-print (cert x509-certificate?) 
			   :optional (ds *digest:sha-256*))
  (define md (make-message-digest ds))
  (digest-message md (x509-certificate->bytevector cert)))

(define (string->x509-name s)
  (cond ((string-dn->list-components s) => list->x509-name)
	(else #f)))

(define (decode-pem-string s) (pem-object->object (string->pem-object s)))
(define (base64-string->certificate s)
  (bytevector->x509-certificate (base64-decode-string s :transcoder #f)))

(define-enumeration object-type
  (pem cer)
  object-types)

(define (object->bytevector obj type)
  (if (eq? type 'pem)
      (string->utf8 (pem-object->string (->pem-object obj)))
      (cond ((x509-certificate? obj)
	     (x509-certificate->bytevector obj))
	    ((pkcs-one-asymmetric-key? obj)
	     (pkcs-one-asymmetric-key->bytevector obj))
	    ((private-key? obj)
	     (pkcs-one-asymmetric-key->bytevector
	      (private-key->pkcs-one-asymmetric-key obj)))
	    ((pkcs-encrypted-private-key-info? obj)
	     (pkcs-encrypted-private-key-info->bytevector obj))
	    (else #f))))

(define (encrypt-private-key pk password)
  (let ((salt (random-generator-read-random-bytes random-generator 20))
	(iv (random-generator-read-random-bytes random-generator 16)))
    (pkcs-one-asymmetric-key->pkcs-encrypted-private-key-info
     (private-key->pkcs-one-asymmetric-key pk)
     (make-pbes2-x509-algorithm-identifier
      (make-pbkdf2-x509-algorithm-identifier salt 10000)
      (make-aes256-encryption-x509-algorithm-identifier iv))
     password)))

(define private-key->private-key-info private-key->pkcs-one-asymmetric-key)

(define (generate-self-signed-certificate subject-dn key-pair algorithm period)
  (define (generate-serial-number)
    (random-generator-random-integer random-generator
				     *serialnumber-upper-bound*))
  
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
  (let ((priv-key (key-pair-private key-pair)))
    (or (and subject-dn
	     (values priv-key
		     (sign-x509-certificate-template
		      (->template subject-dn
				  (generate-serial-number)
				  (string->number period)
				  (key-pair-public key-pair))
		      algorithm priv-key)))
	(values #f #f))))

;; private
(define random-generator (secure-random-generator *prng:chacha20*))
(define *serialnumber-upper-bound* (expt 2 64))

(define (string-dn->list-components s)
  (define len (string-length s))
  (define (split-attr k&v)
    (cond ((string-index k&v #\=) =>
	   (lambda (i)
	     (list (string->symbol (substring k&v 0 i))
		   (substring k&v (+ i 1) (string-length k&v)))))
	  (else #f)))
	     
  (let loop ((r '()) (off 0))
    (cond ((= off len) (reverse r))
	  ((string-index s #\, off) =>
	   (lambda (i)
	     (loop (cons (split-attr (substring s off i)) r) (+ i 1))))
	  (else
	   (reverse (cons (split-attr (substring s off len)) r))))))
)
