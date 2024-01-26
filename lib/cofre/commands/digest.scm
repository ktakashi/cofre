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

;; Digest commands

#!nounbound
(library (cofre commands digest)
    (export operation->command-executor
	    (rename (usage command-usage)))
    (import (rnrs)
	    (rnrs eval)
	    (rfc base64)
	    (getopt)
	    (util bytevector)
	    (sagittarius crypto digests)
	    (cofre commands api))

(define usage
  '(
    "digest algorithm [-f $format] [-l $length] value"
    "    -f, --format: output format, base64, hex or sexp"
    "    -l, --length: output length if needed. i.e. for shake"
    "  algorithm: specifying $name of *digest:$name*, e.g. sha-1"
    "             for the complete list, see (sagittarius crypto digests)"
    ))
  
(define (operation->command-executor op)
  (unless (symbol? op)
    (command-usage-error 'digest "operation is required" usage op))
  (command-executor op))
(define (command-executor op)
  (define name (symbol->string op))
  (define digest (string->symbol (string-append "*digest:" name "*")))
  (guard (e (else (command-usage-error
		   'digest "unknown digest algorithm" usage op)))
    (let ((md (eval `(make-message-digest ,digest)
		    (environment '(sagittarius crypto digests)))))
      (lambda args
	(with-args args
	    ((format (#\f "format") #t "base64")
	     (length (#\l "length") #t #f)
	     . rest)
	  (when (null? rest)
	    (command-usage-error 'digest "missing value" usage args))
	  (let ((str (car rest))
		(f (formatter (string->symbol format)))
		(l (and length (string->number length))))
	    (f (digest-message md (string->utf8 str) l))))))))

(define (formatter format)
  (case format
    ((base64) (lambda (bv) (utf8->string (base64-encode bv :line-width #f))))
    ((hex) bytevector->hex-string)
    ((sexp) values)
    (else (command-usage-error 'digest "unknown output format" usage format))))

)
