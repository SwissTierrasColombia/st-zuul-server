FROM openjdk:11

ARG XMX=1024m
ARG PROFILE=production
ARG CLOUD_CONFIG

ENV XMX=$XMX
ENV PROFILE=$PROFILE
ENV CLOUD_CONFIG=$CLOUD_CONFIG

VOLUME /tmp

EXPOSE 8091

ADD ./target/st-zuul-server-1.3.2.jar st-zuul-server.jar

ENTRYPOINT java -Xmx$XMX -jar /st-zuul-server.jar --spring.profiles.active=$PROFILE --spring.cloud.config.uri=$CLOUD_CONFIG