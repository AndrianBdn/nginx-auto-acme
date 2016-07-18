make img 
docker run -it --rm -p 80:80 -p 443:443 -v $(pwd)/persist:/persist -v $(pwd)/conf.body:/etc/nginx/conf.body andrianbdn/nginx-auto-tinyacme sh
