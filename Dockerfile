FROM nginx:alpine

# remove trash
RUN rm -f /etc/nginx/fastcgi* /etc/nginx/koi* /etc/nginx/win* /etc/nginx/*.default /etc/nginx/*_params /etc/conf.d/*.conf 

# for docker / supervisor
#RUN echo "daemon off;" >> /etc/nginx/nginx.conf && \

RUN apk update && apk add -u python py-pip openssl curl mc git && \
    pip install supervisor && \
    mkdir /persist && \
    cd && git clone https://github.com/Neilpang/acme.sh.git acmegit && \
    cd acmegit && sh acme.sh \
	--install \
	--certhome /persist/certs \
	--accountkey /persist/account.key \
	--accountconf /persist/account.conf && \
    rm -Rf /root/acmegit && \
    rm -Rf /var/cache/apk/*


# ENTRYPOINT ["supervisord", "--nodaemon", "--configuration", "/etc/supervisord.conf"]
# CMD ["nginx", "-g", "daemon off;"]
