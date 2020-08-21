FROM openjdk:12

ARG XMX=1024m
ARG PROFILE=production

ENV XMX=$XMX
ENV PROFILE=$PROFILE

VOLUME /tmp

EXPOSE 8091

ADD ./target/st-zuul-server-0.0.1-SNAPSHOT.jar st-zuul-server.jar

ENTRYPOINT java -Xmx$XMX -jar /st-zuul-server.jar --spring.profiles.active=$PROFILE