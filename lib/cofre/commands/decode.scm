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

;; Decode commands

#!nounbound
(library (cofre commands decode)
    (export operation->command-executor
	    (rename (usage command-usage)))
    (import (rnrs)
	    (getopt)
	    (rfc base64)
	    (rfc uri)
	    (util bytevector)
	    (cofre commands api))

(define usage
  '(
    "decode operation [-f $format] value"
    "    -f,--format: output format: string, hex or sexp"
    "  operation: base64, base64url or uri"
    ""
    "  base64 operation"
    "   The given value is decoded from Base64 text"
    "  base64url operation"
    "   The given value is decoded from Base64URL text"
    "  uri operation"
    "   The given value is decoded from percentage encoding"
    ))

(define (operation->command-executor op)
  (case op
    ((base64) (base64-decoder base64-decode-string))
    ((base64url) (base64-decoder base64url-decode-string))
    ((uri) uri-decode-string)
    (else (command-usage-error 'encode "unknown operation" usage op))))

(define ((base64-decoder decoder) . args)
  (with-args args
      ((format (#\f "format") #t "string")
       . rest)
    (when (null? rest)
      (command-usage-error 'decode "value is missing" usage args))
    (let ((str (car rest))
	  (->value (formatter (string->symbol format))))
      (->value (decoder str :transcoder #f)))))

(define (formatter format)
  (case format
    ((string) utf8->string)
    ((hex) bytevector->hex-string)
    ((sexp) values)
    (else (command-usage-error 'decode "unknown format" usage format))))

)
