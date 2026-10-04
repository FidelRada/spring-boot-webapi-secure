# Spec Delta: container-delivery

## Purpose

Construir una imagen de contenedor reproducible y sin privilegios, escanearla con Trivy y publicarla en GHCR solo desde `main` cuando el pipeline de seguridad aprueba.

## ADDED Requirements

### Requirement: Dockerfile construible
El Dockerfile SHALL construir la aplicación con una etapa `maven:3.9-eclipse-temurin-21` (sin Maven Wrapper) y ejecutarla sobre `eclipse-temurin:21-jre-alpine`.

#### Scenario: CD-01 Build local de la imagen
- **WHEN** se ejecuta `docker build -t lab3:local .` en la raíz del repositorio
- **THEN** la construcción termina con código 0 y la imagen final no contiene `mvn` ni un JDK completo

### Requirement: Ejecución sin privilegios
El contenedor MUST ejecutarse con un usuario no root creado con `addgroup`/`adduser` de Alpine.

#### Scenario: CD-02 Usuario no root
- **WHEN** se ejecuta `docker run --rm --entrypoint id lab3:local`
- **THEN** la salida no muestra `uid=0`

### Requirement: Healthcheck funcional
La imagen SHALL declarar un `HEALTHCHECK` contra `/actuator/health` usando `wget` (incluido en Alpine), sin depender de `curl`.

#### Scenario: CD-03 Contenedor healthy
- **WHEN** se arranca el contenedor y se espera el periodo de inicio
- **THEN** `docker inspect --format '{{.State.Health.Status}}'` devuelve `healthy`

### Requirement: Escaneo de la imagen antes de publicar
El job de imagen SHALL escanear la imagen con `docker run aquasec/trivy:0.74.0 image` (sin la acción inexistente `trivy-action@0.36.0`) en dos pasadas: paquetes del SO (`--pkg-types os --ignore-unfixed`) y librerías de la aplicación (`--pkg-types library`, sin `--ignore-unfixed`). Además SHALL generar un SARIF completo sin filtros y MUST NOT publicar la imagen si alguna de las dos pasadas contiene vulnerabilidades HIGH o CRITICAL.

#### Scenario: CD-04 Imagen vulnerable no se publica
- **WHEN** el escaneo de librerías de la imagen, o el de paquetes del SO con corrección disponible, detecta una vulnerabilidad HIGH o CRITICAL
- **THEN** el paso de evaluación falla, el paso de push no se ejecuta y el SARIF se sube igualmente a Code scanning

#### Scenario: CD-08 CVE del SO sin corrección no bloquea pero queda visible
- **WHEN** la imagen base contiene una CVE HIGH/CRITICAL de un paquete del SO sin `FixedVersion`
- **THEN** no aparece en `trivy-imagen-os.json` (filtrada por `--ignore-unfixed`), no bloquea, sí figura en el SARIF completo subido a Code scanning, y la política está documentada en design.md D5

### Requirement: Publicación solo desde main tras el gate
La publicación en `ghcr.io/fidelrada/spring-boot-webapi-secure` SHALL ocurrir únicamente en push a `main`, después de que el Quality Gate del mismo run termine en `success`.

#### Scenario: CD-05 Push a main publica
- **WHEN** CI/CD se ejecuta en `main` con el gate y el escaneo de imagen en `success`
- **THEN** el paquete GHCR recibe las etiquetas `sha-<commit>`, `main` y `latest`

#### Scenario: CD-06 Develop construye pero no publica
- **WHEN** CI/CD se ejecuta en `develop`
- **THEN** la imagen se construye y escanea, y el paso de push se omite

### Requirement: Imagen en el nightly
El nightly SHALL construir y escanear la imagen con la misma política, sin publicarla.

#### Scenario: CD-07 Nightly escanea la imagen
- **WHEN** se ejecuta el nightly sobre `main`
- **THEN** el run incluye el escaneo Trivy de la imagen con su reporte como artifact y no publica en GHCR
