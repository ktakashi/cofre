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
	    (sagittarius)
	    (getopt)
	    (rfc base64)
	    (security keystore)
	    (srfi :13 strings)
	    (cofre commands api))
(define command-usage
  '(
    "keystore type operation -o $output -p $password [options]"
    "  OPTIONS"
    "    -s,--keystore: keystore $location[|$format], required"
    "      '~' for location means standard output."
    "      if it's used on input then signals an error."
    "    -p,--password: keystore password, required"
    "    -P,--key-password: individual key password"
    "    -a,--alias:    alias"
    ""
    "  type: pkcs12, p12, jks or jceks"
    ""
    "  operation: create"
    ""
    "  create"
    "    Create an empty keystore"
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
  (with-args args
      ((keystore (#\s "keystore") #t (option-error "keystore"))
       (password (#\p "password") #t (option-error "password"))
       (key-password (#\P "key-password") #t #f)
       . rest)
    (when (null? rest)
      (command-usage-error 'keystore "operation is missing" command-usage args))
    (let* ((op (string->symbol (car rest)))
	   (ks (case op
		 ((create) (make-keystore type))
		 (else (option->keystore type keystore password)))))
      (write-keystore keystore ks password))))

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
      (when value?
	(cond ((eq? fmt 'base64)
	       (close-port p)
	       (utf8->string (get-output-bytevector out)))
	      (else (get-output-bytevector out))))))

  (let-values (((loc fmt) (parse-i/o-option opt)))
    (if (string=? loc "~")
	(let ((out (open-output-bytevector)))
	  (write-to-port out fmt #t))
	(let ((out (open-file-output-port loc (file-options no-fail))))
	  (write-to-port out fmt #f)
	  loc))))


(define (parse-i/o-option opt)
  (cond ((string-index opt #\|) =>
	 (lambda (index)
	   (let ((loc (substring opt 0 index))
		 (fmt (substring opt (+ index 1) (string-length opt))))
	     (values loc (string->symbol fmt)))))
	(else (values opt 'raw))))

)
