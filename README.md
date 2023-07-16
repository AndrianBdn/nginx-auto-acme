# nginx-auto-acme

nginx docker container that automatically has good* TLS configuration and Let's Encrypt client. 

* good means: rated A by [Qualys SSL Server Test](https://www.ssllabs.com/ssltest/) as of July 2023; see [their rating guide](https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide)

With nginx-auto-acme you are getting:
- HTTP/2 web server with automatic HTTPS by [Let's Encrypt](https://letsencrypt.org/)
- good defaults 
- the full power of nginx

## Usage 

You put docker-compose.yml file to some directory on the server: 

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

**Do not change** 443 and 80 port mappings, otherwise this letsencrypt won't be able to issue TLS certificate. 

You can optionally specify SLACK_CH_URL to Incoming Slack WebHook. If some domain could not be resolved, the error message will be posted to that channel.

Now you create conf.body directory and put nginx configs there. 
- You should name them as hostname.conf. For example, if you want to serve example.com, you should create example.com.conf file in conf.body directory.
- Of course, you should have DNS record for that hostname pointing to your server.
- The config does not need to contain `server {` blocks or `server_name`/`listen` directives — it all will be added automatically. Just writes parts of nginx config
that describe what you want to serve.

Now run `docker compose up -d` and you are done.

First time you run it, it will take some time to generate Diffie-Hellman parameters.

### Host config examples 

Remember, to add a hostname, just create hostname.conf file in conf.body. For example.com, that would be example.com.conf. 

#### Below are some examples:

##### Just redirect to another domain (www to non-www or vice versa):
```
return 301 https://example.org/;
```


##### This is a basic example of proxing traffic to some other port on the host (golang binary or other published port of a Docker container): 

```
location / {
    proxy_pass http://host.docker.internal:8088;

    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Host      $host;
}
```
You can use `host.docker.internal` to refer to the host machine from inside the container. Replace 8088 with the port you want to proxy to.

##### This is an example of serving static files (protected by basic auth):

```
location / {
    autoindex on;
    root /mnt/data-bin/shared;
        
    auth_basic           "Protected Area";
    auth_basic_user_file /etc/nginx/conf.body/htpasswd;
}
```

This is the `htpasswd` file, referred in the config above (also put it in conf.body directory): 

```
admin:{PLAIN}secure-password
```

Note: nginx discourage using {PLAIN}, because the password will be stored on the server in the plain text. For some cases, this is an acceptable risk.


### Additional environment variables 

During the start, container sets worker_processes, worker_connections, keepalive_timeout nginx root config values to 
environment variables with the same name, in uppercase (WORKER_PROCESSES, WORKER_CONNECTIONS, KEEPALIVE_TIMEOUT)

## TLS 1.2 and 1.3 by default  

Read README.md in conf.body folder to enable older TLS.

## Strict-Transport-Security

nginx-auto-acme automatically adds [strict-transport-security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security) header.

```
strict-transport-security: max-age=63072000; includeSubDomains
```

Mentioning 'strict-transport-security' anywhere inside a nginx-auto-acme config will result the header not being added automatically.

Mentioning 'nginx-auto-acme-sts-preload' anywhere in nginx-auto-acme config will make the STS header contain 'preload' directive. 

```
strict-transport-security: max-age=63072000; includeSubDomains; preload
```



## Acknowledgments 

- [acme.sh](https://github.com/Neilpang/acme.sh) Let's Encrypt ACME client in pure shell 
- [nginx](https://nginx.org)
