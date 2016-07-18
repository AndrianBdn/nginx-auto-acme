import re
import os
import sys
from textwrap import dedent 

# this is path to dir for user config bodies
CONF_BODY_PATH='/etc/nginx/conf.body/'

# for letsencrypt verification 
WELL_KNOWN_ACME='/etc/nginx/acme'

# acme.sh certs storage
ACME_CERTS='/persist/certs/'

# actual-factual key and crt
NGINX_KEY='/persist/nginx/all.key'
NGINX_CRT='/persist/nginx/all.crt'

# standard nginx.conf 
NGINX_CONF='/etc/nginx/conf.d/'

# special file with -d domain1 -d domain2 args for acme.sh 
ACMELINE_FILE='/root/.acmeline'


def http_config(domain):
    template = dedent(
    """
    server {{
        server_name {domain};
        listen 80; 

        location /.well-known/acme-challenge/ {{
            root {acmeroot};
            try_files $uri =404;
        }}
        location / {{
            rewrite ^.+$ https://{domain} permanent;
        }}
    }}
    """)

    return template.format(domain=domain, acmeroot=WELL_KNOWN_ACME)

def https_config(domain, body):

    if re.search('server\s+{', body) is not None:
        return None 

    template = dedent(
    """
    server {{ 
        server_name {domain};
        listen 443;
        ssl on; 
        ssl_certificate      {crt};
        ssl_certificate_key  {key};
        {body}
    }}
    """)
    return template.format(domain=domain, body=body, key=NGINX_KEY, crt=NGINX_CRT)

def tls_domain_exists(domain):
    return os.path.isdir(ACME_CERTS+domain)

def tls_cert_exists():
    return os.path.isfile(NGINX_CRT) and os.path.isfile(NGINX_KEY)

def read_file(path):
    with open(path, 'r') as f:
        return f.read()

def write_file(path, body):
    with open(path, 'w') as f:
        f.write(body)


def https_config_error():
    sys.stderr.write("Error: config for " + domain + " should not contain server block\n")
    sys.stderr.write("This is not regular nginx config\n")
    sys.exit(1)


def read_conf_dir(path):
    conf_list = os.listdir(path)
    conf_list = filter(lambda x: x.endswith('.conf'), conf_list)
    conf_list = map(lambda x: x[:-5], conf_list)
    return conf_list


def gen_config():
    need_acme = None
    conf_list = read_conf_dir(CONF_BODY_PATH)

    for domain in conf_list:
        new_config = http_config(domain)

        if tls_cert_exists():
            config_body = read_file(CONF_BODY_PATH + domain + '.conf')
            tls_config = https_config(domain, config_body)
            if https_config is None:
                https_config_error()
            new_config += tls_config
        else:
            need_acme = True # maybe there are no full certs 

        # if there is no dir for this domain, will def need to start acme 
        if tls_domain_exists(domain) is None:
            need_acme = True

        write_file(NGINX_CONF + domain + '.conf', new_config)

    if need_acme:
        write_file(ACMELINE_FILE, " ".join(map(domains, lambda x: '-d ' + x)))

    return need_acme 


def main(argv): 
    need_acme = gen_config()
    if need_acme is not None:
        return 99 

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))





