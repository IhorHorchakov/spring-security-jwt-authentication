FROM openjdk:17-oracle
EXPOSE 8080 9251

ADD target/spring-security-jwt-authentication-server.jar spring-security-jwt-authentication-server.jar
ADD docker-image-debug-entrypoint.sh docker-image-debug-entrypoint.sh

#ENTRYPOINT ["java", "-jar","spring-security-jwt-authentication-server"]
ENTRYPOINT ["sh", "/docker-image-debug-entrypoint.sh"]
