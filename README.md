# nginx-auto-acme

nginx docker container that automatically has good TLS configuration and letsencrypt client. 

The whole promise is similar to Caddy server — you are getting HTTP/2 web server with automatic HTTPS by letsencrypt; but you're getting full power of real nginx. 


## Usage 

Write **bodies of nginx server blocks** to config.body directory. File names should be domains names + '.conf'. 

'persist' directory is used to store letsencrypt key, certs (no need to change anything there)

Run container using docker-compose 

First run will take some time to generate dhparams 


## Acknowledgments 

- [acme.sh](https://github.com/Neilpang/acme.sh) letsencrypt ACME client in pure shell 
- [nginx](https://nginx.org)
