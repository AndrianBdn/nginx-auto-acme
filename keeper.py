#!/usr/bin/python3

import time
import datetime
import shutil
import re
import os
import sys
import subprocess
import zlib #for crc32
import textwrap
import json
import requests

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

# main nginx.conf
NGINX_ROOT_CONF = '/etc/nginx/nginx.conf'

# for letsencrypt verification
WELL_KNOWN_ACME = '/etc/nginx/acme'

# dhparam file
NGINX_DH_PARAMS = '/persist/dhparams.pem'

# actual-factual key and crt
NGINX_KEY = '/persist/nginx/all.key'
NGINX_CRT = '/persist/nginx/all.crt'

# standard nginx.conf
NGINX_CONF = '/etc/nginx/conf.d/'

# last domains
LAST_DOMAINS_FILE = '/persist/last-domains.txt'

# timestamp for cron-like stuff
LAST_TIME_FILE = '/persist/last-time.txt'

# last slack channel
LAST_SLACK_CH_URL = '/persist/last-slack-ch.txt'


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


def resolve_ip(hostname, retry=True):
    # using dns over https 
    endpoint = "https://cloudflare-dns.com/dns-query?name={}&type=A".format(hostname)

    try:
        response = requests.get(
            url=endpoint,
            headers={"accept" : "application/dns-json"}
        )
        if response.status_code == 200:
            jresp = response.json() 
            if "Answer" in jresp: 
                answer = jresp["Answer"]
                if len(answer) > 0:
                    return True 
            
        return False 
    except (json.decoder.JSONDecodeError, requests.exceptions.RequestException) as e:
        all_log('DNS-over-https request failed: {}'.format(e))
        if retry: 
            return resolve_ip(hostname, False)


def discover_my_ip():
    ip_services = ["https://ifconfig.co/ip",
                   "https://api.ipify.org/",
                   "http://whatismyip.akamai.com/"]

    for ip_service in ip_services:
        try:
            response = requests.get(url=ip_service)
            if response.status_code == 200:
                return response.content.decode("utf-8").strip() 
        except requests.exceptions.RequestException:
            print('HTTP Request failed to {}'.format(ip_service))

    return "unknown"

def slack_url():
    return os.getenv('SLACK_CH_URL', '')

def slack(text):
    all_log("!! Posting to Slack {} message {}".format(slack_url(), text))

    if slack_url().find("https://") == -1:
        all_log("no valid slack url")
        return

    full_text = "nginx-auto-acme from {} : {}".format(discover_my_ip(), text)

    try:
        response = requests.post(
            url=slack_url(),
            headers={
                "Content-Type": "application/json; charset=utf-8",
            },
            data=json.dumps({
                "text": full_text
            })
        )
        all_log('Slack response HTTP Status Code: {status_code}'.format(status_code=response.status_code))
        all_log('Slack response HTTP Response Body: {content}'.format(content=response.content))
    except requests.exceptions.RequestException:
        all_log('Slack HTTP Request Failed')


def generate_dhparams(production):
    # to speedup, we generate 8-bit dhparams when doing configtest
    bits = 2048 if production else 8

    if not os.path.isfile(NGINX_DH_PARAMS):
        all_log("don't see dhparams.pem, will generate new one: this may take long time...", True)
        shellrun('cd /persist && openssl dhparam -out dhparams.pem ' + str(bits))
        if os.path.isfile(NGINX_DH_PARAMS):
            all_log("created dhparams.pem, looks good", True)
        else:
            all_log("dhparams.pem does not exists, fail", True)
            sys.exit(1)

    # let's check that our dhparams file is not 8-bit size
    if production:
        size = os.path.getsize(NGINX_DH_PARAMS)
        proper_dhparam_size = 350
        if size < proper_dhparam_size:
            all_log("dhparams seems to be too small, let's regenerate")
            os.remove(NGINX_DH_PARAMS)
            generate_dhparams(True)


def ssl_config(production):
    generate_dhparams(production)

    if os.path.isfile(CONF_BODY_PATH + 'tls1_0.legacy'):
        return textwrap.dedent(
            """
            ssl_ciphers "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK";
            ssl_dhparam /persist/dhparams.pem;
            ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
            ssl_prefer_server_ciphers on;
            ssl_session_cache shared:SSL:60m;
            ssl_stapling on;
            ssl_stapling_verify on;
            resolver 8.8.8.8 8.8.4.4 valid=300s;
            resolver_timeout 5s;
            """)

    return textwrap.dedent(
        """
        ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
        ssl_prefer_server_ciphers off;
        ssl_dhparam /persist/dhparams.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_session_cache shared:SSL:60m;
        ssl_stapling on;
        ssl_stapling_verify on;
        resolver 8.8.8.8 8.8.4.4 valid=300s;
        resolver_timeout 5s;
        """)


def http_config(domain):
    template = textwrap.dedent(
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

    template = textwrap.dedent(
        """
        server {{
            server_name {domain};
            listen 443 ssl http2;
            add_header Strict-Transport-Security "max-age=63072000; includeSubDomains";
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

def edit_root_config():
    keys = ['worker_processes', 'worker_connections', 'keepalive_timeout']

    lines = [line.rstrip('\n') for line in open(NGINX_ROOT_CONF)]

    modified = False
    result = ''
    for line in lines:
        newline = line + "\n"
        for key in keys:
            envkey = key.upper()
            if envkey in os.environ and line.find(key) != -1:
                modified = True
                newline = key + " " + os.environ[envkey] + ";\n"    
        result = result + newline

    if modified:
        conf = open(NGINX_ROOT_CONF, 'w')
        conf.write(result)
        conf.close()


def gen_config(production=True):
    edit_root_config()

    # clean older configs
    shutil.rmtree(NGINX_CONF, ignore_errors=True)
    os.mkdir(NGINX_CONF)

    write_file(NGINX_CONF + '/ssl.conf', ssl_config(production))
    write_file(NGINX_CONF + '/_nginx-http.conf', read_file(CONF_BODY_PATH + '/_nginx-http.conf'))

    nginx_default = textwrap.dedent(
        """
        server {
            server_name _;
            listen 80 default_server;
            server_tokens off;
            return  444;
        }

        server {
            server_name _;
            listen 443 ssl http2;
            server_tokens off;
            ssl_certificate      /etc/nginx/dummy-cert.pem;
            ssl_certificate_key  /etc/nginx/dummy-key.pem;
            return 444;
        }""")

    write_file(NGINX_CONF + '/_nginx_default.conf', nginx_default)

    # read user configs
    domains = read_conf_dir(CONF_BODY_PATH)

    for domain in domains:
        if not resolve_ip(domain):
            slack("unable to resolve domain {}".format(domain))
            continue

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
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

    all_log("{}: return code {}".format(result.args, result.returncode))

    shellrun_prn = lambda n, t: all_log("{}: {} {}".format(result.args, n, textwrap.indent(t.decode('utf-8'), '  ')))

    if len(result.stdout) > 0:
        shellrun_prn('stdout', result.stdout)

    if len(result.stderr) > 0:
        shellrun_prn('stderr', result.stderr)

    return result


def acme_issue(domains):
    shutil.rmtree(ACME_CERTS_PATH, ignore_errors=True)

    args = [ACME_SH, '--issue'] + acme_d_args(domains) + ['-w', WELL_KNOWN_ACME] 
    args += ['--server', 'letsencrypt']

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
    args += ['--server', 'letsencrypt']

    result = shellrun(args)
    return result.returncode


def try_slack():
    old_slack = read_file(LAST_SLACK_CH_URL)
    if slack_url() != old_slack:
        slack("slack posting works")
    write_file(LAST_SLACK_CH_URL, slack_url())


def config_preflight(production=True):
    all_log("started")

    try_slack()

    if read_file("/etc/nginx/dummy-cert.pem") == "":
        shellrun("cd /etc/nginx && openssl req -x509 -newkey rsa:4096 -keyout dummy-key.pem -out dummy-cert.pem -days 3650 -nodes -subj '/CN=localhost'")

    domains = gen_config(production)

    if domains is None or len(domains) == 0:
        all_log("Cannot find any conf.body domains\n")
        sys.exit(1)
        return 0
    return domains


def nginx_start():
    pid = read_file('/var/run/nginx.pid', '-1')
    cmdline = read_file('/proc/'+pid+'/cmdline')
    if cmdline.find('nginx') == -1:
        subprocess.run('nginx', shell=True, check=False)
    else:
        nginx_restart()

def nginx_configtest():
    config_preflight(False)
    result = shellrun('nginx -t')
    return result.returncode

def nginx_restart():
    shellrun('nginx -s reload')


def cron_4hour(domains):
    all_log('running 4h renewal check')

    for domain in domains:
        if not resolve_ip(domain):
            slack("unable to resolve domain {}".format(domain))

    before_renew = tls_cert_hash()
    shellrun([ACME_SH, '--cron', '--home /root/.acme.sh/'])
    after_renew = tls_cert_hash()

    if before_renew != after_renew:
        all_log("cert hash differs, reloading nginx")
        nginx_restart()

    # check expiration

    shellrun("openssl x509 -noout -enddate -in {nginx_crt} > {nginx_crt}.expire".format(nginx_crt=NGINX_CRT))

    expire = read_file(NGINX_CRT + ".expire")
    if expire == "":
        slack("can't get certificate expiration")
    else:
        expire = expire.strip().replace("notAfter=", "")
        try:
            expire_date = datetime.datetime.strptime(expire, "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            slack("can't parse certificate expiration date {}".format(expire))
            return

        diff = expire_date - datetime.datetime.today()

        if diff.days < 7:
            slack("certificate is going to expire in {} days".format(diff.days))


def main(argv):

    configtest = nginx_configtest()

    if len(argv) > 1 and argv[1] == 'configtest':
        sys.exit(configtest)


    if configtest != 0:
        all_log("nginx configtest returned non-zero code")
        sys.exit(configtest)

    domains = config_preflight()

    nginx_start()

    if need_reissue(domains):
        acme_issue(domains)
        acme_install(domains)
        gen_config()
        nginx_restart()
    else:
        cron_4hour(domains)

    hour_4 = 14400
    hour_24 = 86400
    while True:
        time.sleep(hour_4)
        old_time = float(read_file(LAST_TIME_FILE, '0'))
        timestamp = time.time()
        if timestamp - old_time >= hour_24:
            cron_4hour(domains)
            write_file(LAST_TIME_FILE, str(timestamp))

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
