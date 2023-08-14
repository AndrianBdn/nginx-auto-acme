NAME = andrianbdn/nginx-auto-acme

.PHONY: image img hub all

imagex64:
	docker build --platform linux/amd64 -t $(NAME) --pull .

imgtest:
	docker build --platform linux/amd64 -t $(NAME):testing --pull .

hub: 
	docker push $(NAME)


hubtest: 
	docker push $(NAME):testing

all: image hub
