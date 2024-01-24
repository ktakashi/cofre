Cofre - Chest box for tools
===========================

Cofre is a chest, not body part but box, in Spanish. This project
will be a chest box of tools what I need / use in my daily life.

Prerequisite
------------

This project requires Sagittarius version 0.9.11 (current development
version) or higher.

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
