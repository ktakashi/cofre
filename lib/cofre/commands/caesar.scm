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

;; Caesar shift

#!nounbound
(library (cofre commands caesar)
    (export operation->command-executor
	    (rename (usage command-usage)))
    (import (rnrs)
	    (getopt)
	    (cofre ciphers caesar)
	    (cofre commands api))

(define usage
  '(
    "caesar op -s $shift $value"
    "    op: must be enc or dec"
    "  -s,--shift: amount of shift, required"
    "`enc` and `dec` are basically the same operation, just $shift will be"
    "negated when `dec` is specified."
    ))

(define (operation->command-executor op)
  (case op
    ((enc) (caesar-shift values))
    ((dec) (caesar-shift (lambda (v) (- v))))
    (else (command-usage-error 'caesar "invalid operation" usage op))))

(define ((caesar-shift shifter) . args)
  (with-args args
      ((shift (#\s "shift") #t #f)
       . rest)
    (let ((n (and shift (string->number shift))))
      (unless n (command-usage-error 'caesar "invalid shift" usage args))
      (when (null? rest)
	(command-usage-error 'caesar "no value specified" usage args))
      (cofre:caesar-shift (car rest) (shifter n)))))

)
