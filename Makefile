# Do not edit me with phpStorm, which converts all tabs with spaces

NAME = andrianbdn/nginx-auto-acme

.PHONY: image img hub all

imagex64:
	docker build --platform linux/amd64 -t $(NAME) --pull .

img:
	docker build -t $(NAME) .

image:
	docker build -t $(NAME) --pull .

hub: 
	docker push $(NAME)


all: image hub
