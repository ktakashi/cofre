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

;; x509 command

#!nounbound
(library (cofre commands x509)
    (export operation->command-executor
	    command-usage)
    (import (rnrs)
	    (getopt)
	    (cofre commands api)
	    (cofre x509))

(define command-usage
  '(
    "x509 operation [options] value"
    "  OPTIONS"
    "    -f,--format: input format, default PEM"
    "      supporting format PEM, Base64"
    ""
    "operation: decode"
    ))

(define (operation->command-executor op)
  (case op
    ((decode) decode-certificate)
    (else (command-usage-error 'x509 "unknown operation" command-usage op))))

(define (decode-certificate . args)
  (with-args args
      ((format (#\f "format") #t "PEM")
       . rest)
    (when (null? rest)
      (command-usage-error 'x509 "value is missing" command-usage args))
    ;; (display rest) (newline)
    (let ((value (car rest)))
      (case (string->symbol (string-downcase format))
	((pem) (decode-pem-string value))
	((base64) (base64-string->certificate value))
	(else
	 (command-usage-error 'x509 "unknown format" command-usage format))))))

)
