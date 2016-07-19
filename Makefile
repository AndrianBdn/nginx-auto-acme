# Do not edit me with phpStorm, which converts all tabs with spaces

NAME = andrianbdn/nginx-auto-acme

.PHONY: image img hub all

img:
	docker build -t $(NAME) .

image:
	docker build -t $(NAME) --pull .

hub: 
	docker push $(NAME)


all: image hub
