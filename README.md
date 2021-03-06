GoRTR
=====

A RTR (router to RPKI cache/validator protocol) library for writing RTR clients. 

Background
----------

The general architecture of RPKI is described in RFC 6480. The RFC
about the RTR protocol are RFC 6810 (for the version 0 of the
protocol) and RFC 8210 (for version 1). The library currently supports
both versions, but without negotiation, you have to indicate the
version explicitely.

Usage
-----

This library is written in [Go](http://golang.org), so you need a Go compiler 
installed. 

You can install it simply with:
go get github.com/bortzmeyer/GoRTR/rtr

To read the documentation, go in the rtr/ directory, then:
    go doc 

Or read the two samples clients, text-client (displays the prefixes
received) or database-store-client (store the prefixes in a PostgreSQL
database created with database-store-create.sql)

Reference site
--------------
[At Github](https://github.com/bortzmeyer/GoRTR)

Licence
-------
Copyright (c) 2012, Stephane Bortzmeyer
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 'AS IS'
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

Author
------

Stephane Bortzmeyer <bortzmeyer@nic.fr>


Similar programs
----------------

RTR library in C <http://rpki.realmv6.org/>