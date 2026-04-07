# Name

_atomdns_ - DNS nameserver that runs handlers

# Synopsis

_atomdns_ **[-C|-H|-V]** [CONFFILE]

# Description

atomdns is a DNS server that chains handlers. Each handler handles a DNS feature, like serve zone files,
transfering those to secondaries or just exporting metrics. There are many handlers, each described in their
respective manual page. If an unknown handler is encountered it is skipped, while outputting a warning.

The server atomdns can be reloaded by sending it the HUP signal, this reloads the handlers only, and does
_not_ restart any of the (web) servers, so changes to server addresses and limits (see atomdns-global(7)) will not
be applied through reloads. I.e. if you modified the health endpoint that change _will not_ be picked up.
For those kind of changes the server needs to be restarted. Modifiying origins or handlers _are_ picked up.

The _global_ handler describes the options that are also used in starting the server, see atomdns-global(7)
for more information. Normally you need a **CONFFILE** (atomdns-conffile(5)) like this, to listen on all
addresses on port 53:

```conffile
{
    dns {
        addr [::]:53
    }
}
```

When atomdns starts it emits logs telling what zones are loaded and which (background) routines are started, when
succesful you are greeted with a banner (unless `quiet` is true see atomdns-global(7)).

```
  ┏━┓  ╺┳╸  ┏━┓  ┏┳┓
  ┣━┫   ┃   ┃ ┃  ┃┃┃  DNS
  ╹ ╹   ╹   ┗━┛  ╹ ╹ v024 (0.5.15)
  High performance and flexible DNS server
  https://atomdns.miek.nl
__________________________________\o/_______
```

There is optional positional argument, the **CONFFILE** to configure atomdns. If not given atomdns will use
this builtin Conffile:

```confffile
{
  dns {
      addr [::]1053
  }
}

example.org {
  log
  whoami
}
```

The following options are available:

**-C**
: check the configuration, report any erors and exit with status 1 or if everything is OK exit with status
code 0.

**-H**
: list all handlers and quit.

**-V**
: Show version and quit.

# Handlers

The following handlers are available:

- _acl_ - enforces access control policies. See atomdns-acl(7).
- _any_ - give a minimal response to ANY queries. See atomdns-any(7).
- _as112_ - an AS112 black hole server. See atomdns-as112(7).
- _chaos_ - respond to TXT queries in the CH class. See atomdns-chaos(7).
- _cookie_ - adds an DNS cookie of this server to each reply. See atomdns-cookie(7).
- _dbfile_ - serve zone data from an RFC 1035-style file. See atomdns-dbfile(7).
- _dbhosts_ - serve data from `/etc/hosts`. See atomdns-dbhost(7).
- _dbsqilte_ - serve zone data from a SQLite database. See atomdns-dbsqlite(7).
- _drunk_ - test client behavior. See atomdns-drunk(7).
- _ecs_ - add EDNS client subnet to the context. See atomdns-ecs(7).
- _empty_ - consume setup tokens. See atomdns-empty(7).
- _geoip_ - add geographical location data. See atomdns-geoip(7).
- _global_ - hold server properties. See atomdns-global(7).
- _id_ - add unique ID to the context. See atomdns-id(7).
- _import_ - includes files or references snippets from a Conffile. See atomdns-import(7).
- _kill_ - stop atomdns after a duration. See atomdns-kill(7).
- _log_ - log queries. See atomdns-log(7).
- _metrics_ - enable [prometheus](https://prometheus.io/) metrics. See atomdns-metrics(7).
- _nsid_ - adds an identifier of this server to each reply. See atomdns-nsid(7).
- _refuse_ - refuse queries. See atomdns-refuse(7).
- _root_ - override the global root. See atomdns-root(7).
- _sign_ - add DNSSEC records to zone files. See atomdns-sign(7).
- _template_ - use Go templates to reply. See atomdns-template(7).
- _url_ - serve zone data from an URL. See atomdns-url(7).
- _whoami_ - return your resolver's local IP address, port and transport. See atomdns-whoami(7).

# Difference with CoreDNS

atomdns looks a lot like CoreDNS, the main differences are:

- Uses dnsv2 (this library) which is 2x more efficient _and_ incorperates a lot of ideas from CoreDNS.
- Allows for dynamic ordering of handlers, handlers in CoreDNS (called plugins) have a static ordering, set at
  compile time.
- Ignores unknown handlers, CoreDNS stops with an error in that case.

# Authors

atomdns authors.

# Copyright

Apache License 2.0

# See Also

See atomdns-conffile(5), and atomdns-global(7), and https://atomdns.miek.nl with more documentation.
