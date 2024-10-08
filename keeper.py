#!/usr/bin/python3

import time
import datetime
import shutil
import re
import os
import sys
import subprocess
import zlib  # for crc32
import textwrap
import json
import urllib.request
import urllib.error
import random
import shlex


# this will be replaced as to * in nginx
FS_WCARD = "_wildcard"

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


def resolve_ip(hostname, retry=3):

    endpoints = [
        "https://one.one.one.one/dns-query?name={}&type=A",
        "https://dns.google/resolve?name={}&type=A"
    ]

    endpoint = random.choice(endpoints).format(hostname)

    headers = {
        "accept": "application/dns-json"
    }

    stderr_log("querying DoH endpoint " + endpoint)

    req = urllib.request.Request(endpoint, headers=headers)

    try:
        with urllib.request.urlopen(req) as response:
            if response.status == 200:
                data = response.read()
                jresp = json.loads(data.decode('utf-8'))
                if "Answer" in jresp:
                    answer = jresp["Answer"]
                    if len(answer) > 0:
                        return True
                return False

        if retry > 0:
            return resolve_ip(hostname, retry-1)

        return False

    except (json.JSONDecodeError, urllib.error.URLError) as e:
        all_log('DNS-over-https request failed: {}'.format(e))
        if retry > 0:
            return resolve_ip(hostname, retry - 1)


cached_ip = None


def discover_my_ip():
    global cached_ip

    # Return cached IP if it exists
    if cached_ip:
        return cached_ip

    ip_services = [
        "https://ip4only.me/api/",
        "https://ifconfig.co/ip",
        "https://api.ipify.org/",
        "http://whatismyip.akamai.com/"
    ]

    # Simple regular expression to validate IPv4 addresses
    ipv4_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

    for ip_service in ip_services:
        try:
            with urllib.request.urlopen(ip_service) as response:
                if response.status == 200:
                    ip = response.read().decode("utf-8").strip()
                    if ip.startswith("IPv4,"):
                        # https://ip4only.me/ API
                        # IPv4,1.2.3.4,v1.1,,,See http://ip6.me/docs/ for api documentation
                        parts = ip.split(",")
                        if len(parts) > 1:
                            ip = parts[1]
                    # Check if the IP looks like an IPv4 address
                    if ipv4_pattern.match(ip):
                        cached_ip = ip
                        return ip
        except urllib.error.URLError:
            print('HTTP Request failed to {}'.format(ip_service))

    return "unknown"


def acme_dns():
    if 'ACME_DNS' in os.environ:
        arg = os.environ['ACME_DNS']
        # sanitized to avoid command line injection
        return re.sub('[^0-9a-zA-Z_]+', '_', arg)
    return None


def slack_url():
    return os.getenv('SLACK_CH_URL', '')


def slack(text):
    all_log("!! Posting to Slack {} message {}".format(slack_url(), text))

    if slack_url().find("https://") == -1:
        all_log("no valid slack url")
        return

    full_text = "nginx-auto-acme from {} : {}".format(discover_my_ip(), text)

    try:
        data = json.dumps({
            "text": full_text
        }).encode("utf-8")

        request = urllib.request.Request(
            slack_url(),
            data=data,
            headers={
                "Content-Type": "application/json; charset=utf-8",
            },
            method="POST"
        )
        with urllib.request.urlopen(request) as response:
            all_log('Slack response HTTP Status Code: {status_code}'.format(
                status_code=response.status))
            all_log('Slack response HTTP Response Body: {content}'.format(
                content=response.read()))

    except urllib.error.URLError:
        all_log('Slack HTTP Request Failed')


def fs_domain_replace(fs_domain):
    return fs_domain.replace(FS_WCARD+".", "*.")


def generate_dhparams():
    bits = 2048

    if not os.path.isfile(NGINX_DH_PARAMS):
        all_log(
            "don't see dhparams.pem, will generate new one: this may take long time...", True)
        shellrun('cd /persist && openssl dhparam -out dhparams.pem ' + str(bits))
        if os.path.isfile(NGINX_DH_PARAMS):
            all_log("created dhparams.pem, looks good", True)
        else:
            all_log("dhparams.pem does not exists, fail", True)
            sys.exit(1)

    # let's check that our dhparams file is not 8-bit size
    size = os.path.getsize(NGINX_DH_PARAMS)
    proper_dhparam_size = 350
    if size < proper_dhparam_size:
        all_log("dhparams seems to be too small, let's regenerate")
        os.remove(NGINX_DH_PARAMS)
        generate_dhparams()


def ssl_config():
    generate_dhparams()

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
        ssl_session_timeout 1d;
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
                return 301 https://$host$request_uri;
            }}
        }}
        """)

    return template.format(domain=fs_domain_replace(domain), acmeroot=WELL_KNOWN_ACME)


def https_config(domain, body, reuse_port):
    if re.search(r'server\s+{', body) is not None:
        all_log("server blocks are not allowed, but found in " +
                domain + " config", True)
        return None

    sts = """add_header Strict-Transport-Security "max-age=63072000; includeSubDomains";"""
    lb = body.lower()

    if lb.find("strict-transport-security") > -1:
        sts = ""

    if lb.find("nginx-auto-acme-sts-preload") > -1:
        sts = """add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";"""
    
    reuse_port_str = ""
    if reuse_port:
        reuse_port_str = " reuseport"

    quic = ""
    if lb.find("nginx-auto-acme-quic") > -1 or os.getenv('QUIC', '0') == '1':
        quic = textwrap.dedent(
            """
            listen 443 quic{reuse_port_str};
            ssl_early_data on;
            add_header alt-svc 'h3=":443"; ma=86400';
            """).format(reuse_port_str=reuse_port_str)

    template = textwrap.dedent(
        """
        server {{
            server_name {domain};
            listen 443 ssl;
            http2 on;
            {sts}
            ssl_certificate      {crt};
            ssl_certificate_key  {key};
            server_tokens        off;
            {quic}
            {body}
        }}
        """)

    return template.format(domain=fs_domain_replace(domain), body=body, quic=quic, key=NGINX_KEY, crt=NGINX_CRT, sts=sts)


def tls_cert_exists():
    return read_file(NGINX_CRT).find('--BEGIN CERTIFICATE') > -1 and read_file(NGINX_KEY).find('--BEGIN ') > -1


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
    sys.stderr.write("Error: config for " + domain +
                     " should not contain server block\n")
    sys.stderr.write("This is not regular nginx config\n")
    sys.exit(1)


def match_config(name):
    # filter out files that does not contain dots, except in .conf
    # allow _wildcard. @ start
    return re.compile('(?:_wildcard\\.)?[\\-a-z0-9\\.]+\\.[a-z0-9\\-]+\\.conf$').match(name)


def read_conf_dir(path):
    conf_list = os.listdir(path)

    conf_list = filter(match_config, conf_list)
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

    if "GEOIP_MODULE" in os.environ and result.find('ngx_http_geoip_module') == -1:
        mod_line = 'load_module "modules/ngx_http_geoip_module.so";' + "\n"
        result = result.replace("\nevents {", mod_line + "\nevents {", 1)

    if modified:
        conf = open(NGINX_ROOT_CONF, 'w')
        conf.write(result)
        conf.close()


def gen_config(production=True):
    edit_root_config()

    # clean older configs
    shutil.rmtree(NGINX_CONF, ignore_errors=True)
    os.mkdir(NGINX_CONF)

    write_file(NGINX_CONF + '/ssl.conf', ssl_config())
    write_file(NGINX_CONF + '/_nginx-http.conf',
               read_file(CONF_BODY_PATH + '/_nginx-http.conf'))

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
            ssl_certificate      /persist/dummy-cert.pem;
            ssl_certificate_key  /persist/dummy-key.pem;
            return 444;
        }""")

    write_file(NGINX_CONF + '/_nginx_default.conf', nginx_default)

    # read user configs
    domains = read_conf_dir(CONF_BODY_PATH)

    reuse_port = True 
    for domain in domains:
        dns_check = domain

        if domain.startswith("_wildcard."):
            rnd = str(random.randint(1, 99999))
            dns_check = domain.replace(FS_WCARD+".", "wildcard-check-"+rnd+".")

        if not resolve_ip(dns_check):
            slack("unable to resolve domain {}".format(dns_check))
            continue

        new_config = http_config(domain)

        if tls_cert_exists():
            config_body = read_file(CONF_BODY_PATH + domain + '.conf')
            tls_config = https_config(domain, config_body, reuse_port)
            reuse_port = False # only first domain can use reuseport
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
        # quoting wildcard symbol
        args.append(shlex.quote(fs_domain_replace(domain)))
    return args


def shellrun(args):
    cmd = args
    if isinstance(cmd, list):
        cmd = ' '.join(cmd)
    all_log("calling {}".format(cmd))
    result = subprocess.run(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

    all_log("{}: return code {}".format(result.args, result.returncode))

    def shellrun_prn(n, t): return all_log("{}: {} {}".format(
        result.args, n, textwrap.indent(t.decode('utf-8'), '  ')))

    if len(result.stdout) > 0:
        shellrun_prn('stdout', result.stdout)

    if len(result.stderr) > 0:
        shellrun_prn('stderr', result.stderr)

    return result


def acme_issue(domains):
    shutil.rmtree(ACME_CERTS_PATH, ignore_errors=True)

    args = [ACME_SH, '--issue']
    dns_arg = acme_dns()
    if dns_arg is not None:
        args += ['--dns', dns_arg]

    args += acme_d_args(domains) + ['-w', WELL_KNOWN_ACME]
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

    if read_file("/persist/dummy-cert.pem") == "":
        shellrun("cd /persist && openssl req -x509 -newkey rsa:4096 -keyout dummy-key.pem -out dummy-cert.pem -days 3650 -nodes -subj '/CN=localhost'")

    domains = gen_config(production)

    if domains is None or len(domains) == 0:
        all_log("Cannot find any conf.body domains\n")
        sys.exit(1)

    has_wildcard = any(map(lambda s: s.startswith(FS_WCARD + "."), domains))

    if has_wildcard and acme_dns() is None:
        all_log("You have a config for a wildcard domain (starts with _wildcard); it requires DNS mode (ACME_DNS)\n")
        sys.exit(1)

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

    shellrun(
        "openssl x509 -noout -enddate -in {nginx_crt} > {nginx_crt}.expire".format(nginx_crt=NGINX_CRT))

    expire = read_file(NGINX_CRT + ".expire")
    if expire == "":
        slack("can't get certificate expiration")
    else:
        expire = expire.strip().replace("notAfter=", "")
        try:
            expire_date = datetime.datetime.strptime(
                expire, "%b %d %H:%M:%S %Y %Z")
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
