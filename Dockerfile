FROM nginx:1.23.3-alpine

RUN rm -f /etc/nginx/fastcgi* /etc/nginx/koi* /etc/nginx/win* /etc/nginx/*.default /etc/nginx/*_params /etc/conf.d/*.conf; \ 
    echo "ok" && \
    apk update && apk add -u python3 py3-requests openssl curl git dumb-init && \
    mkdir /persist && \
    cd && git clone https://github.com/Neilpang/acme.sh.git acmegit && \
    cd acmegit && sh acme.sh \
	--install \
	--certhome /persist/certs \
	--accountkey /persist/account.key && \
    apk del git && \
    rm -Rf /root/acmegit && rm -Rf /var/cache/apk/*

COPY keeper.py /bin/nginx-keeper
RUN chmod 755 /bin/nginx-keeper 


ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["/bin/nginx-keeper"]
