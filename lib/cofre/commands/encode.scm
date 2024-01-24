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

;; Encode commands

#!nounbound
(library (cofre commands encode)
    (export operation->command-executor)
    (import (rnrs)
	    (getopt)
	    (rfc base64)
	    (rfc uri)
	    (cofre commands api))

(define usage
  '(
    "encode operation [-b $break] value"
    "    -b,--break: line length"
    "  operation: base64, base64url or uri"
    ""
    "  base64 operation"
    "   The given value is encoded to Base64 with padding"
    "  base64url operation"
    "   The given value is encoded to Base64URL"
    "  uri operation"
    "   The given value is encoded to percentage encoding"
    ))

(define (operation->command-executor op)
  (case op
    ((base64) (base64-encoder base64-encode-string))
    ((base64url) (base64-encoder base64url-encode-string))
    ((uri) uri-encode-string)
    (else (command-usage-error 'encode "unknown operation" usage op))))

(define ((base64-encoder encoder) . args)
  (with-args args
      ((length (#\b "break") #t #f)
       . rest)
    (when (null? rest)
      (command-usage-error 'encode "value is missing" usage args))
    (let ((str (car rest)))
      (encoder str :line-width (and length (string->number length))))))

)
