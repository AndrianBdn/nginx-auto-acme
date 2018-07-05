#!/usr/bin/python3

import time
import shutil
import re
import os
import sys
import subprocess
import zlib #for crc32
import pprint
from textwrap import dedent

# special file besides regular docker logging
RENEW_LOG_FILE = "/persist/important.txt"

# acme.sh path
ACME_SH = '/root/.acme.sh/acme.sh'

# acme.conf
ACME_ACCOUNT_PERSIST = '/persist/account.conf'
ACME_ACCOUNT_CONF = '/root/.acme.sh/account.conf'

# acme certs
ACME_CERTS_PATH = '/persist/certs/'

# this is path to dir for user config bodies
CONF_BODY_PATH = '/etc/nginx/conf.body/'

# for letsencrypt verification
WELL_KNOWN_ACME = '/etc/nginx/acme'

# actual-factual key and crt
NGINX_KEY = '/persist/nginx/all.key'
NGINX_CRT = '/persist/nginx/all.crt'

# standard nginx.conf
NGINX_CONF = '/etc/nginx/conf.d/'

# last domains
LAST_DOMAINS_FILE = '/persist/last-domains.txt'

# timestamp for cron-like stuff
LAST_TIME_FILE = '/persist/last-time.txt'

def log_fmt(string):
    return "{} {}\n".format(time.strftime("%c"), string)

def file_log(string):
    with open(RENEW_LOG_FILE, "a") as file:
        file.write(log_fmt(string))

def stderr_log(string, flush=False):
    sys.stderr.write(log_fmt(string))
    if flush: 
        sys.stderr.flush() 

def all_log(string, flush=False):
    file_log(string)
    stderr_log(string, flush)

def ssl_config():
    if not os.path.isfile('/persist/dhparams.pem'):
        all_log("don't see dhparams.pem, will generate new one: this may take long time...", True)
        shellrun('cd /persist && openssl dhparam -out dhparams.pem 2048')
        if os.path.isfile('/persist/dhparams.pem'):
            all_log("created dhparams.pem, looks good", True)
        else: 
            all_log("dhparams.pem does not exists, fail", True)


    if os.path.isfile(CONF_BODY_PATH + 'tls1_0.legacy'): 
        return dedent(
        """
        ssl_ciphers "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK";
        ssl_dhparam /persist/dhparams.pem;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:60m;
        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains";
        ssl_stapling on;
        ssl_stapling_verify on;
        resolver 8.8.8.8 8.8.4.4 valid=300s;
        resolver_timeout 5s;
        """)
    else:
        return dedent(
        """
        ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256';
        ssl_dhparam /persist/dhparams.pem;
        ssl_protocols TLSv1.2;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:60m;
        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains";
        ssl_stapling on;
        ssl_stapling_verify on;
        resolver 8.8.8.8 8.8.4.4 valid=300s;
        resolver_timeout 5s;
        """)


def http_config(domain):
    template = dedent(
    """
    server {{
        server_name {domain};
        listen 80; 
        server_tokens off;

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

    if re.search(r'server\s+{', body) is not None:
        return None 

    template = dedent(
    """
    server {{
        server_name {domain};
        listen 443 ssl http2;
        ssl_certificate      {crt};
        ssl_certificate_key  {key};
        server_tokens        off;
        {body}
    }}
    """)
    return template.format(domain=domain, body=body, key=NGINX_KEY, crt=NGINX_CRT)


def tls_cert_exists():
    return read_file(NGINX_CRT).find('BEGIN CERTIFICATE') > -1 and read_file(NGINX_KEY).find('BEGIN RSA PRIVATE KEY') > -1


def tls_cert_hash(): 
    return zlib.crc32(read_file(NGINX_CRT).encode("utf8"))


def read_file(path, fallback=''):
    if not os.path.isfile(path):
        return fallback

    with open(path, 'r') as file:
        return file.read()

def write_file(path, body):
    with open(path, 'w') as file:
        file.write(body)


def https_config_error(domain):
    sys.stderr.write("Error: config for " + domain + " should not contain server block\n")
    sys.stderr.write("This is not regular nginx config\n")
    sys.exit(1)


def read_conf_dir(path):
    conf_list = os.listdir(path)
    
    # filter out files that does not contain dots, except in .conf  
    conf_regex = re.compile('[\\-\\w\\.]+\\.[\\w\\-]+\\.conf')

    conf_list = filter(conf_regex.match, conf_list)
    conf_list = map(lambda x: x[:-5], conf_list)
    return sorted(conf_list)



def gen_config():
    # clean older configs
    shutil.rmtree(NGINX_CONF, ignore_errors=True)
    os.mkdir(NGINX_CONF)

    write_file(NGINX_CONF + '/ssl.conf', ssl_config())
    write_file(NGINX_CONF + '/_nginx-http.conf', read_file(CONF_BODY_PATH + '/_nginx-http.conf'))


    # read user configs
    domains = read_conf_dir(CONF_BODY_PATH)

    for domain in domains:
        new_config = http_config(domain)

        if tls_cert_exists():
            config_body = read_file(CONF_BODY_PATH + domain + '.conf')
            tls_config = https_config(domain, config_body)
            if https_config is None:
                https_config_error(domain)
            new_config += tls_config

        write_file(NGINX_CONF + domain + '.conf', new_config)

    return domains 

def need_reissue(domains):
    if not tls_cert_exists():
        return True
    old_domains = []
    if os.path.isfile(LAST_DOMAINS_FILE):
        old_domains = read_file(LAST_DOMAINS_FILE).strip().split(' ')
    return domains != old_domains

def set_issued(domains):
    write_file(LAST_DOMAINS_FILE, ' '.join(domains))

def acme_d_args(domains):
    args = []
    for domain in domains:
        args.append('-d')
        args.append(domain)
    return args

def shellrun(args):
    cmd = args
    if isinstance(cmd, list):
        cmd = ' '.join(cmd)
    all_log("calling {}".format(cmd))
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    all_log("{}: return code {}".format(result.args, result.returncode))
    
    if len(result.stdout) > 0:
        all_log("{}: stdout {}".format(result.args, result.stdout))

    if len(result.stderr) > 0:
        all_log("{}: stderr {}".format(result.args, result.stderr))

    return result 
    

def acme_issue(domains):
    shutil.rmtree(ACME_CERTS_PATH, ignore_errors=True)

    args = [ACME_SH, '--issue'] + acme_d_args(domains) + ['-w', WELL_KNOWN_ACME]
    if os.path.isfile(ACME_ACCOUNT_PERSIST):
        shutil.copy(ACME_ACCOUNT_PERSIST, ACME_ACCOUNT_CONF)

    result = shellrun(args)

    if os.path.isfile(ACME_ACCOUNT_CONF):
        shutil.copy(ACME_ACCOUNT_CONF, ACME_ACCOUNT_PERSIST)

    if result.returncode == 0:
        set_issued(domains)

    return result.returncode

def acme_install(domains):
    nginx_persist_dir = os.path.dirname(NGINX_CRT)
    if not os.path.isdir(nginx_persist_dir):
        os.mkdir(nginx_persist_dir)

    args = [ACME_SH, '--installcert'] + acme_d_args(domains)
    args += ['--fullchainpath', NGINX_CRT, '--keypath', NGINX_KEY]
    result = shellrun(args) 
    return result.returncode 

def nginx_start():
    pid = read_file('/var/run/nginx.pid', '-1')
    cmdline = read_file('/proc/'+pid+'/cmdline')
    if cmdline.find('nginx') == -1:
        subprocess.run('nginx', shell=True)
    else:
        nginx_restart()

def nginx_configtest():
    result = shellrun('nginx -t')
    return result.returncode

def nginx_restart():
    shellrun('nginx -s reload')


def cron_4hour():
    all_log('running 24h renewal check')

    before_renew = tls_cert_hash()
    shellrun([ACME_SH, '--cron', '--home /root/.acme.sh/'])
    after_renew = tls_cert_hash() 

    if before_renew != after_renew:
        all_log("cert hash differs, reloading nginx")
        nginx_restart()


def main(argv): 
    all_log("started")
    domains = gen_config()
    if domains is None: 
        sys.stderr.write("Cannot find any conf.body domains\n")
        sys.exit(1)
        return 0

    if len(argv) > 1 and argv[1] == 'configtest':
        sys.exit(nginx_configtest())

    nginx_start()

    if need_reissue(domains):
        acme_issue(domains)
        acme_install(domains)
        gen_config()
        nginx_restart()
    else:
        cron_4hour()

    hour_4 = 14400
    hour_24 = 86400
    while True:
        time.sleep(hour_4)
        old_time = float(read_file(LAST_TIME_FILE, '0'))
        timestamp = time.time()
        if timestamp - old_time >= hour_24:
            cron_4hour()
            write_file(LAST_TIME_FILE, str(timestamp))

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
