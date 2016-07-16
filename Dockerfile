FROM nginx:alpine

RUN apk update && apk add -u python py-pip openssl curl mc
RUN pip install supervisor
RUN curl https://get.acme.sh | sh
RUN rm /etc/nginx/fastcgi* /etc/nginx/koi* /etc/nginx/win* /etc/nginx/*.default /etc/nginx/*_params

# clean apk cache
RUN rm -rf /var/cache/apk/*


# ENTRYPOINT ["supervisord", "--nodaemon", "--configuration", "/etc/supervisord.conf"]
# CMD ["nginx", "-g", "daemon off;"]
