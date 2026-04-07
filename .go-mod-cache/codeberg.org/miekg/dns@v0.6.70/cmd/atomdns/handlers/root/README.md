## Name

_root_ - override the global root

# Description

This handler allows for overriding the `root` directive from the global block in the current handler block.
It works identical to the atomdns-global(1) `root`'s configuration.

# Syntax

```txt
root DIRECTORY
```

- with `root` **DIRECTORY** is the directory to use as the root directory in the handler block. Any relative path
  names will get this directory prefixed. If **DIRECTORY** itself is also relative, the current working
  directory (cwd) of the atomdns process will be prefixed.

# Examples

```conffile
example.org {
    root /my/zones
    dbfile db.example.org
}
```

The "db.example.org" zone should now be located in /my/zones.

# Notes

This handler must be set first in a handler block to effect all subsequent handlers in the block.

# Also See

atomdns-global(1).
