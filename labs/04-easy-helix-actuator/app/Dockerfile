# Build the Spring Boot jar (Maven deps download at build time; runtime is offline).
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml ./
RUN mvn -q -B dependency:go-offline
COPY src ./src
RUN mvn -q -B package -DskipTests

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /src/target/helix-admin-1.0.0.jar app.jar
EXPOSE 8080
CMD ["java", "-jar", "app.jar"]
