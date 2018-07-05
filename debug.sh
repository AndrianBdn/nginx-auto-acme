make img 
docker run -it --rm -v $(pwd)/conf.body:/etc/nginx/conf.body andrianbdn/nginx-auto-acme nginx-keeper configtest
