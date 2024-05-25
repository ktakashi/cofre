Cofre - Chest box for tools
===========================

Cofre is a chest, not body part but box, in Spanish. This project
will be a chest box of tools what I need / use in my daily life.

Prerequisite
------------

This project requires Sagittarius version 0.9.11.

Some commands require higher version. See the command
overview section for more details.

### Try with the latest Sagittarius

You can use [`scheme-env`](https://github.com/ktakashi/scheme-env). 
to install the latest version of Sagittarius like this:

```shell
scheme-env install sagittarius@head
```

Then you can try the tool like this (in the same directory as this
file is located):

```shell
SAGITTARIUS="scheme-env run sagittarius@head --" ./cofre-cli
```


Basic usage
-----------

Executing `cofre-cli` with below format is the basic usage:

```shell
cofre-cli $command $operation $arguments ...
```

`$command` specify the executing command, such as `encode`.  
`$operation` is command specific operation, e.g. `base64` for `encode`.   
`$arguments ...` are also command specific arguments.

You can see the usage text when you type random `$operation` like this:

```shell
cofre-cli encode dummy
```

Command chain
-------------

By using `$` separator, commands can be chained. Below is a simple example.

```shell
cofre-cli encode base64 text $ decode base64
```

The result of the previous command is appended to the next command. If the
command takes argument, i.e. with hyphon, then the order of the argument
can be reordered like this:

```shell
cofre-cli json diff @file1.json @file2.json $ json patch {} -p
```

The above takes the result of the JSON diff command is appended the
next JSON patch command so the `-p` argument takes the result.


Supporting commands
-------------------

Below are the supporting commands. The detail usage can be shown
with above random operation thing.

### encode

Provides encoding operation, such as Base64

### decode

Provides decoding operation, such as Base64

### caesar

Providing Caesar cipher operation.

### digest

Providing digest operation, such as SHA-256

### json

Providing JSON operation, such as JMesPath query

### keystore

Providing keystore operations for PKCS12, JKS and JCEKS.
It's a convenient CLI for `(security keystore)`

This commend requires Sagittarius version 0.9.12 or higher

### uuid

Providing UUID generation
