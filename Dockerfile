FROM openjdk:12

VOLUME /tmp

EXPOSE 8091

ADD ./target/st-zuul-server-0.0.1-SNAPSHOT.jar st-zuul-server.jar

ENTRYPOINT java -jar /st-zuul-server.jar