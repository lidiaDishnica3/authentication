ECHO building image
docker build --no-cache -t atisalbania/microservices-authentication .
ECHO pushing image
docker push atisalbania/microservices-authentication
pause