# Imagen de la aplicación (spec container-delivery CD-01..CD-03, design.md D5).

# ---- Etapa de construcción: Maven 3.9 + JDK 21 (sin Maven Wrapper) ----
FROM maven:3.9-eclipse-temurin-21 AS builder
WORKDIR /app

# Primero el POM para aprovechar la caché de capas de dependencias.
COPY pom.xml .
RUN mvn -B -q dependency:go-offline

COPY src src
RUN mvn -B -q package -DskipTests

# ---- Etapa de ejecución: solo JRE 21 sobre Alpine ----
FROM eclipse-temurin:21-jre-alpine

# Usuario sin privilegios creado con las herramientas de Alpine.
RUN addgroup -S spring && adduser -S -G spring spring

WORKDIR /app
COPY --from=builder --chown=spring:spring /app/target/*.jar app.jar

USER spring:spring
EXPOSE 8080

# wget viene con BusyBox en Alpine; no se instala curl.
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD wget -qO- http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]
