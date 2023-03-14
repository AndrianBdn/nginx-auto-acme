# nginx-auto-acme

nginx docker container that automatically has good TLS configuration and letsencrypt client. 

The whole promise is similar to the Caddy server — you are getting HTTP/2 web server with automatic HTTPS by letsencrypt; but you're getting full power of real nginx. 


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
        extra_hosts:
            - "host.docker.internal:host-gateway"
```

**Do not change** 443 and 80 port mappings, otherwise this letsencrypt wont be able to issue TLS certificate. 

First run will take some time to generate dhparams. 

You can optionally specify SLACK_CH_URL to Incoming Slack WebHook. If some domain could not be resolved, it will be posted in that channel. 


### Example nginx proxy config 

Usually I use nginx-auto-acme to proxy requests to other containers, that have their ports mapped to docker host. 

This is an example of a nginx config file (should be put in conf.body, name the same as hostname + conf): 

```
location / {
    proxy_pass http://host.docker.internal:8088;

    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Host      $host;
}
```


### Additional environment variables 

During the start, container sets worker_processes, worker_connections, keepalive_timeout nginx root config values to environment variables with the same name, in uppercase (WORKER_PROCESSES, WORKER_CONNECTIONS, KEEPALIVE_TIMEOUT)


## TLS 1.2 and 1.3 by default  

Read README.md in conf.body folder to enable older TLS.

## Strict-Transport-Security

nginx-auto-acme automatically adds [strict-transport-security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security) header.

```
strict-transport-security: max-age=63072000; includeSubDomains
```

Mentioning 'strict-transport-security' anywhere inside a nginx-auto-acme config will result the header not being added automatically.

Mentioning 'nginx-auto-acme-sts-preload' anywhere in nginx-auto-acme config will make the STS header contain 'preload' directrive. 

```
strict-transport-security: max-age=63072000; includeSubDomains; preload
```



## Acknowledgments 

- [acme.sh](https://github.com/Neilpang/acme.sh) letsencrypt ACME client in pure shell 
- [nginx](https://nginx.org)
