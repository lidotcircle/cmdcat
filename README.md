## Overview
trace commands execution.


## Motivation
Because Bear[https://github.com/rizsotto/Bear] can't trace `fork` system call
and execution tree.


## Usage

```
Usage:
       cmdcat [-solih] <command>

        -s                                   suppress stdout output
        -o, --output        <file>           specify output file, default stdout
        -l, --library       <file>           path of libccat
        -i, --inet                           using AF_INET instead of AF_UNIX
            --stream                         using SOCK_STREAM instead of SOCK_DGRAM
        -p, --plugin        <plugin>         transform output by plugin. default is raw which directly dumps a json.
                                             lua plugin has higher priority than embeded c++ plugin
            --list-plugin                    list available plugin
            --lua-source    <file>           lua plugin source file, default $HOME/.cmdcat.lua
        -h                                   display help
```

