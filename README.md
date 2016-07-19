# nginx-auto-acme

nginx docker container that automatically has good TLS configuration and letsencrypt client 

(work in progress)


## Usage 

Write **bodies of nginx server blocks** to config.body directory. File names should be domains names + '.conf'. 

'persist' directory is used to store letsencrypt key, certs (no need to change anything there)

Run container using docker-compose 

First run will take some time to generate dhparams 
