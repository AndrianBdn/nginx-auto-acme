make img 
docker run -it --rm -p 80:80 -e WORKER_PROCESSES=2 -p 443:443 -v $(pwd)/persist:/persist -v $(pwd)/conf.body:/etc/nginx/conf.body andrianbdn/nginx-auto-acme sh
