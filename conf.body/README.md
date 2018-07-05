# Configuration Conventions

File names must match domains + '.conf' 

Write here parts of nginx config that go to server {} block.

No need to specify listen 443 

Only TLS / HTTP2 is supported. 

HTTP endpoint with redirects is configured automatically.

## Non-server blocks 

If you need to define upstream or something else outside of server blocks, put it to file \_nginx-http.conf in this directory.



## TLS 1.0 and 1.1 

If you need support for older versions of TLS (for MSIE 9 or old Java) — just create empty 'tls1_0.legacy' in this directory. 