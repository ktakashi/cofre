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

;; JSON commands

#!nounbound
(library (cofre commands json)
    (export operation->command-executor
	    command-usage)
    (import (rnrs)
	    (getopt)
	    (text json)
	    (text json jmespath)
	    (cofre commands api))

(define command-usage
  '(
    "json operation [options ...] value"
    "  operation: jmespath"
    ""
    "  jmespath -q $query value"
    "   -q,--query: JMESPath query"
    ))
  
(define (operation->command-executor op)
  (case op
    ((jmespath) jmespath-operation)
    (else (command-usage-error 'json "unknown operation" command-usage op))))

(define (jmespath-operation . args)
  (define (err msg arg)
    (command-usage-error 'json msg command-usage arg))
  (define (safe-query-parse query)
    (guard (e (else (err "invalid query" query)))
      (jmespath query)))
  (define (safe-json-parse json)
    (guard (e (else (err "invalid query" json)))
      (json-read (open-string-input-port json))))
  (with-args args
      ((query (#\q "query") #t #f)
       . rest)
    (unless query (err "no query" args))
    (when (null? rest) (err "no input" args))
    (let ((jp (safe-query-parse query))
	  (json (safe-json-parse (car rest))))
      (jp json))))
      
)
