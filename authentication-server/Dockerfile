FROM openjdk:17-oracle
EXPOSE 8080 9251

ADD target/ss-jwt-application-server.jar ss-jwt-application-server.jar
ADD entrypoint.sh entrypoint.sh

#ENTRYPOINT ["java", "-jar","ss-jwt-application-server"]
ENTRYPOINT ["sh", "/entrypoint.sh"]
