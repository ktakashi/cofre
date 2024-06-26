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

#!nounbound
(library (cofre commands api)
    (export cofre:command-builder
	    cofre:command?
	    cofre:execute-command
	    cofre:command-usage

	    &command-condition
	    make-command-condition
	    command-condition?
	    command-condition-command

	    make-command-usage-condition
	    command-usage-condition?
	    command-condition-usage

	    command-usage-error
	    parse-attributed-option
	    read/return-conent
	    )
    (import (rnrs)
	    (rnrs eval)
	    (record builder)
	    (srfi :13 strings))

(define-record-type cofre:command
  (fields category
	  operation
	  arguments))

(define-syntax cofre:command-builder
  (make-record-builder cofre:command
    ((arguments '()))))

(define (cofre:execute-command (command cofre:command?))
  (define category (cofre:command-category command))
  (define lib `(cofre commands ,category))
  (define op (cofre:command-operation command))
  (define args (cofre:command-arguments command))
  (let ((command (eval `(operation->command-executor ',op)
		       (environment '(rnrs) lib))))
    (apply command args)))

(define (cofre:command-usage command)
  (guard (e (else #f))
    (eval `command-usage (environment `(cofre commands ,command)))))

(define-condition-type &command-condition &condition
  make-command-condition command-condition?
  (command command-condition-command))

(define-condition-type &command-usage-condition &command-condition
  make-command-usage-condition command-usage-condition?
  (usage command-condition-usage))

(define (command-usage-error command message usage args)
  (raise (condition
	  (make-command-usage-condition command usage)
	  (make-message-condition message)
	  (make-irritants-condition args))))

(define (parse-attributed-option opt)
  (cond ((string-index opt #\|) =>
	 (lambda (index)
	   (let ((loc (substring opt 0 index))
		 (fmt (substring opt (+ index 1) (string-length opt))))
	     (values loc fmt))))
	(else (values opt #f))))

(define (read/return-conent s :key (transcoder (native-transcoder)))
  (if (string-prefix? "@" s)
      (call-with-input-file (substring s 1 (string-length s))
	(lambda (in)
	  (let ((v (get-bytevector-all in)))
	    (if transcoder
		(bytevector->string v transcoder)
		v)))
	:transcoder #f)
      (if transcoder
	  s
	  (string->utf8 s))))

)
