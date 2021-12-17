# nginx-auto-acme

nginx docker container that automatically has good TLS configuration and letsencrypt client. 

The whole promise is similar to Caddy server — you are getting HTTP/2 web server with automatic HTTPS by letsencrypt; but you're getting full power of real nginx. 


## Usage 

Write **bodies of nginx server blocks** to config.body directory. File names should be domains names + '.conf'. 

If you need to define upstream or something else outside of server blocks, put it to file \_nginx-http.conf in config.body directory. 

'persist' directory is used to store letsencrypt key, certs (no need to change anything there)

Run container using docker-compose: 

```yaml  
version: '2'
services:
    nginx:
        image: andrianbdn/nginx-auto-acme 
        restart: unless-stopped
        environment:
            - SLACK_CH_URL=none
        ports:
            - "443:443"
            - "80:80"
        volumes:
            - ./persist:/persist
            - ./conf.body:/etc/nginx/conf.body:ro
        logging:
            driver: json-file
            options:
                max-size: "10m"
                max-file: "3"
```

**Do not change** 443 and 80 port mappings, otherwise this letsencrypt wont be able to issue TLS certificate. 

First run will take some time to generate dhparams. 

You can optionally specify SLACK_CH_URL to Incoming Slack WebHook. If some domain could not be resolved, it will be posted in that channel. 

### Additional environment variables 

During the start, container sets worker_processes, worker_connections, keepalive_timeout nginx root config values to environment variables with the same name. 


## TLS 1.2 and 1.3 by default  

Read README.md in conf.body folder to enable older TLS.


## Acknowledgments 

- [acme.sh](https://github.com/Neilpang/acme.sh) letsencrypt ACME client in pure shell 
- [nginx](https://nginx.org)
