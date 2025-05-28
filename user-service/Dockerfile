# Dockerfile para user-service
FROM maven:3.9.6-eclipse-temurin-21 AS build
WORKDIR /app
COPY . .
RUN mvn clean package -DskipTests

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /app/target/user-service-1.0-SNAPSHOT.jar app.jar

# Variáveis de ambiente para configuração do JWT (valores padrão para desenvolvimento)
ENV JWT_SECRET=default_development_secret_do_not_use_in_production
ENV JWT_EXPIRATION_MS=86400000

EXPOSE 8080
VOLUME /tmp
ENTRYPOINT ["java", "-jar", "app.jar"] 