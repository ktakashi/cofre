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

;; JWT commands

#!nounbound
(library (cofre commands jwt)
    (export operation->command-executor
	    command-usage)
    (import (rnrs)
	    (srfi :0)
	    (cofre commands api)
	    (cofre x509)
	    (clos user)
	    (getopt)
	    (sagittarius crypto pem)
	    (sagittarius crypto pkcs keys)
	    (sagittarius crypto x509)
	    (rfc jwk)
	    (rfc jwe)
	    (rfc jws)
	    (rfc jwt)
	    (rfc jose))
(define command-usage
  '(
    "jwt operation [options ...]"
    "  operations: parse, key, sign"
    ""
    "  parse [options ...] value"
    "    parse the given JWT"
    "    -h,--header: Returns JWT header as JSON"
    ""
    "  key -k $file [-t $type] [-o $output] [-p]"
    "    Convert given key file to JWK format"
    "      -k,--key: Key to be converted, must be a PEM file."
    "      -o,--output: Where to dump. Default stdout."
    "      -p,--password: Passphrase for private key."
    "     `type` can be `der` or `pem`"
    ""
    "  sign -p $payload -k $key[|type] [-a $algorithm] [-o $output]"
    "    Sing given $payload with the $key"
    "      -p,--payload: Signing payload, input format"
    "      -k,--key: Signing private key"
    "      -a,--algorithm: Signing algorithm, if it's omit, then the most"
    "        apropriate one is chosen"
    "      -o,--output: Where to dump. Default stdout"
    "     `type` can be `jwk` or `pem`"

    ))

(define (operation->command-executor op)
  (case op
    ((decode) decode-jwt)
    ((key) ->jwk)
    ((sign) sign-payload)
    (else (command-usage-error 'jwt "unknown operation" command-usage op))))

(define (decode-jwt . args)
  (with-args args
      ((header? (#\h "header") #f #f)
       . rest)
    (when (null? rest)
      (command-usage-error 'jwt "JWT value is missing" command-usage args))
    (let ((jwt (car rest)))
      (case (jose-part-count jwt)
	((3) (let ((jws (jws:parse jwt)))
	       (if header?
		   (jws-header->json-string (jws-object-header jws))
		   (jws-object-payload jws))))
	;; TODO handle JWE
	(else
	 (command-usage-error 'jwt "Invalid JWT format" command-usage jwt))))))

(define (->jwk . args)
  (with-args args
      ((key (#\k "key") #t (option-error "key"))
       (type (#\t "type") #t #f)
       (out (#\o "output") #t "~")
       (password (#\p "password") #f #f)
       . rest)
      (unless (file-exists? key)
	(command-usage-error 'jwt (string-append key " does not exist")
			     command-usage key))
      (let ((key (pkcs-key->key (decode-pem-file key))))
	(let ((v (jwk->json-string (key->jwk key))))
	  (cond ((string=? out "~") v)
		(else
		 (when (file-exists? out) (delete-file out))
		 (call-with-output-file out
		   (lambda (out) (put-string out v)))
		 out))))))


(define (sign-payload . args)
  (with-args args
      ((payload (#\p "payload") #t (option-error "payload"))
       (key (#\k "key") #t (option-error "key"))
       (algo (#\a "algorithm") #t #f)
       (out (#\o "output") #t "~")
       . rest)
    (let-values (((key kid) (parse-jwt-key key)))
      (let* ((p (read/return-conent payload :transcoder #f))
	     (header (jws-header-builder
		      (kid kid)
		      (alg (or algo (determine-jws-algorithm key)))))
	     (jws (make-jws-object header p)))
	(jws-object->string (jws:sign jws (jws-signer key)))))))
  
(define (parse-i/o-option opt)
  (let-values (((a b) (parse-attributed-option opt)))
    (values a (or (and b (string->symbol b)) 'raw))))

(define (parse-jwt-key key)
  (let-values (((a b) (parse-attributed-option key)))
    (let ((t (or (and b (string->symbol b)) 'jwk)))
      (case t
	((jwk) (let ((jwk (call-with-input-file a read-jwk)))
		 (values jwk (jwk-kid jwk))))
	((pem) (values (key->jwk (pkcs-key->key (decode-pem-file key))) #f))
	(else (command-usage-error 'jwt "Unknown key format"
				   command-usage t))))))
	

(define (option-error option)
    (command-usage-error 'jwt (string-append option " is required")
			 command-usage option))

(define-method pkcs-key->key ((k <pkcs-one-asymmetric-key>))
  (one-asymmetric-key->private-key
   (pkcs-one-asymmetric-key->one-asymmetric-key k)))

(define-method pkcs-key->key ((k <x509-certificate>))
  (x509-certificate-public-key k))

(define-method pkcs-key->key ((k <subject-public-key-info>))
  (subject-public-key-info->public-key k))

(cond-expand
 ((and cond-expand.version (version (>= "0.9.12")))
  (define-method jws-signer ((k jwk:ec?)) (make-ecdsa-jws-signer k))
  (define-method jws-signer ((k jwk:rsa?)) (make-rsa-jws-signer k))
  (define-method jws-signer ((k jwk:okp?)) (make-eddsa-jws-signer k)))
 (else
  (define (jws-signer k)
    (cond ((jwk:ec? k) (make-ecdsa-jws-signer k))
	  ((jwk:rsa? k) (make-rsa-jws-signer k))   
	  ((jwk:okp? k) (make-eddsa-jws-signer k))
	  (else (assertion-violation 'jws-signer "Not supported" k))))))

(define (determine-jws-algorithm k)
  (or (jwk-alg k)
      (%determine-jws-algorithm k)))

(cond-expand
 ((and cond-expand.version (version (>= "0.9.12")))
  (define-method %determine-jws-algorithm ((k jwk:ec?))
    (let ((crv (jwk:ec-crv k)))
      (cond ((equal? crv 'P-256) 'ES256)
	    ((equal? crv 'P-384) 'ES384)
	    ((equal? crv 'P-521) 'ES521)
	    ((equal? crv 'P-256K) 'ES256K)
	    ((equal? crv 'secp256k1) 'ES256K)
	    (else ;; couldn't determine
	     (assertion-violation 'determine-jws-algorithm
				  "Unknown JWS algorithm" crv)))))

  (define-method %determine-jws-algorithm ((k jwk:okp?)) 'EdDSA)

  (define-method %determine-jws-algorithm ((k jwk:rsa?))
    (let ((n (jwk:rsa-n k)))
      (cond ((<= 2048 n) 'RS512)
	    ((<= 1536 n) 'RS384)
	    ((<= 1024 n) 'RS256)
	    (else (assertion-violation 'determine-jws-algorithm
				       "RSA modulus is too small" n))))))
 (else
  (define (%determine-jws-algorithm k)
    (cond ((jwk:ec? k)
	   (let ((crv (jwk:ec-crv k)))
	     (cond ((equal? crv 'P-256) 'ES256)
		   ((equal? crv 'P-384) 'ES384)
		   ((equal? crv 'P-521) 'ES521)
		   ((equal? crv 'P-256K) 'ES256K)
		   ((equal? crv 'secp256k1) 'ES256K)
		   (else ;; couldn't determine
		    (assertion-violation 'determine-jws-algorithm
					 "Unknown JWS algorithm" crv)))))
	  ((jwk:okp? k) 'EdDSA)
	  ((jwk:rsa? k)
	   (let ((n (jwk:rsa-n k)))
	     (cond ((<= 2048 n) 'RS512)
		   ((<= 1536 n) 'RS384)
		   ((<= 1024 n) 'RS256)
		   (else (assertion-violation 'determine-jws-algorithm
					      "RSA modulus is too small" n)))))
	  (else (assertion-violation 'determine-jws-algorithm
				     "Not supported" k))))))
)
