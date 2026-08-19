FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline -B
COPY src ./src
RUN mvn clean package -DskipTests

FROM eclipse-temurin:21-jre-alpine

RUN addgroup -S auth-service && adduser -S auth-service -G auth-service

WORKDIR /app
COPY --from=build /app/target/*.jar app.jar

RUN chown -R auth-service:auth-service /app

USER auth-service

EXPOSE 8081

ENTRYPOINT ["java", "-jar", "app.jar"]