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
    "    -o,--output:   output, $location[|$format], required"
    "    -i,--input:    input, $location[|$format]"
    "      $format must be 'base64' or 'raw'. Default value is 'raw'"
    "      '~' for location means standard input or output."
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
      ((output (#\o "output") #t (option-error "output"))
       (input  (#\i "input")  #t #f)
       (password (#\p "password") #t (option-error "password"))
       (key-password (#\P "key-password") #t #f)
       . rest)
    (when (null? rest)
      (command-usage-error 'keystore "operation is missing" command-usage args))
    (let-values (((e out) (retrieve-output output)))
      (store-keystore
       (case (string->symbol (car rest))
	 ((create) (make-keystore type)))
       out password)
      (e))))

(define (retrieve-output opt)
  (let-values (((loc format oport out) (parse-i/o-option opt #t)))
    (define value? (string=? loc "~"))
    (values
     (if value?
	 (lambda ()
	   (when (eq? format 'base64) (close-port out))
	   (let ((v (get-output-bytevector oport)))
	     (case format
	       ((base64) (utf8->string v))
	       (else v))))
	 (lambda () (close-port out) loc))
     out)))

(define (parse-i/o-option opt out?)
  (define (wrap-port loc port fmt)
    (define value? (string=? loc "~"))
    (define format (string->symbol fmt))
    (values loc
     format
     port
     (case format
       ((base64)
	(if out?
	    (open-base64-encode-output-port port
					    :owner? (not value?)
					    :line-width 76)
	    (open-base64-decode-input-port port :owner? #t)))
       ((raw) port)
       (else
	(command-usage-error 'keystore "unknown format" command-usage fmt)))))
  (define (->port loc)
    (define (check loc)
      (when (and (not out?) (not (file-exists? loc)))
	(command-usage-error 'keystore "input keystore doesn't exist"
			     command-usage loc))
      (when (and out? (file-exists? loc))
	(command-usage-error 'keystore "output keystore exists"
			     command-usage loc)))
	
    (if (string=? loc "~")
	(if out? (open-output-bytevector) (standard-input-port))
	;; TODO are default file options okay?
	(if (and (check loc) out?)
	    (open-file-output-port loc)
	    (open-file-input-port loc))))
  (cond ((string-index opt #\|) =>
	 (lambda (index)
	   (let ((loc (substring opt 0 index))
		 (fmt (substring opt (+ index 1) (string-length opt))))
	     (wrap-port loc (->port loc) fmt))))
	(else (wrap-port opt (->port opt) "raw"))))
	   

)
