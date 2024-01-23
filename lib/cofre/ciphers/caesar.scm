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

;; Caesar cipher
;; see: https://en.wikipedia.org/wiki/Caesar_cipher

#!nounbound
(library (cofre ciphers caesar)
    (export cofre:caesar-shift
	    cofre:rot13)
    (import (rnrs)
	    (srfi :13)
	    (srfi :14))

(define (cofre:caesar-shift text shift)
  (define n (mod shift 26)) ;; we can shift only 26 anyway
  ;; shift only ASCII alphabets
  (define ((shift-char n) c)
    (define (char-mod base c n)
      (define b (char->integer base))
      (define t (char->integer c))
      (integer->char (+ b (mod (+ (- t b) n) 26))))
    (if (char-set-contains? char-set:ascii c)
	(cond ((char-upper-case? c) (char-mod #\A c n))
	      ((char-lower-case? c) (char-mod #\a c n))
	      (else c))
	c))
  (string-map (shift-char n) text))

(define (cofre:rot13 text) (cofre:caesar-shift text 13))

)
