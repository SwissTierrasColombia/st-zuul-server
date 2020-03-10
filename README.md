# Gateway Server

Edge and resource server.

## Running Development

```sh
$ mvn spring-boot:run
```

## Running Production

### Master Branch

Go to the master branch

```sh
$ git checkout master
```

### Generate jar

```sh
$ mvn clean package -DskipTests
```

### Create Network Docker

```sh
$ docker network create st
```

### Create image from Dockerfile

```sh
$ docker build -t st-zuul-server:lynx .
```

### Run Container

```sh
$ docker run -p 8091:8091 --name st-zuul-server --network st -d st-zuul-server:lynx
```

## License

[Agencia de Implementación - BSF Swissphoto - INCIGE](https://github.com/AgenciaImplementacion/st-zuul-server/blob/master/LICENSE)