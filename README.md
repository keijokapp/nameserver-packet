DNS packet parsing and serialization library for (node-nameserver)[https://github.com/keijokapp/node-nameserver].

**Note:** This is still proof of concept. I might overwrite entire thing (including master branch history) at any time.

Supported RRs:

 * A
 * NS
 * CNAME
 * SOA
 * PTR
 * MX
 * AAAA
 * SRV
 * OPT (EDNS pseudorecord)
 * ANY (questions only)


**TODO:**
 * Unit tests
 * More RR types, response codes, etc...
