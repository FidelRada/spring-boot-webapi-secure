# Spec Delta: sca-scanning

## Purpose

Inventariar las dependencias (SBOM CycloneDX) y detectar componentes con vulnerabilidades conocidas mediante Trivy y OWASP Dependency-Check, sin exponer credenciales y con actualizaciones propuestas por Dependabot.

## ADDED Requirements

### Requirement: SBOM CycloneDX
El build SHALL generar `target/bom.json` en formato CycloneDX 1.6 (plugin 2.9.3) con los alcances compile, runtime y provided, excluyendo test y system.

#### Scenario: SCA-01 El SBOM refleja commons-text 1.9
- **WHEN** se ejecuta `mvn -B org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom` sobre el commit ROJO
- **THEN** `target/bom.json` existe, declara `specVersion` 1.6 y contiene el componente `pkg:maven/org.apache.commons/commons-text@1.9`

### Requirement: Análisis del SBOM con Trivy
El pipeline y el entorno local SHALL analizar el SBOM con `aquasec/trivy:0.74.0` ejecutado por Docker, en todo push y pull request, produciendo un reporte JSON completo sin `--ignore-unfixed`.

#### Scenario: SCA-02 Trivy reporta CVE-2022-42889
- **WHEN** Trivy analiza el SBOM del commit ROJO
- **THEN** el reporte JSON contiene `CVE-2022-42889` con severidad `CRITICAL` para `org.apache.commons:commons-text` 1.9

### Requirement: OWASP Dependency-Check en PR, CI/CD y nightly
El pipeline SHALL ejecutar OWASP Dependency-Check en pull requests, en CI/CD y en el nightly, generando reportes HTML, JSON y SARIF y usando el archivo `dependency-check-suppressions.xml`.

#### Scenario: SCA-03 Reportes de Dependency-Check en el pipeline
- **WHEN** termina el job Dependency-Check de un run de pull request, CI/CD o nightly
- **THEN** el artifact `reporte-dependency-check` contiene `dependency-check-report.html`, `.json` y `.sarif`, y el JSON lista `commons-text-1.9.jar` con CVE-2022-42889 en el commit ROJO

### Requirement: Clave NVD fuera del repositorio
La clave de la API de la NVD MUST provenir del secreto `NVD_API_KEY` (Actions y Dependabot) o de una variable de entorno local, y MUST NOT aparecer en ningún archivo versionado.

#### Scenario: SCA-04 Sin clave en HEAD
- **WHEN** se ejecuta `git grep -nE 'nvdApiKey>[0-9A-F-]{36}|05028C6D' HEAD`
- **THEN** no hay coincidencias y el job Dependency-Check obtiene la clave desde `secrets.NVD_API_KEY`

### Requirement: Supresiones justificadas
Toda supresión de Dependency-Check SHALL estar en `dependency-check-suppressions.xml`, ser específica (CVE + paquete), incluir una justificación en `<notes>` y una fecha de caducidad `until`.

#### Scenario: SCA-05 Archivo de supresiones válido
- **WHEN** Dependency-Check carga `dependency-check-suppressions.xml`
- **THEN** no informa error de parseo y cada `<suppress>` tiene `<notes>` no vacío y atributo `until`

### Requirement: Dependency-Check local
El entorno local SHALL poder ejecutar `mvn -B org.owasp:dependency-check-maven:check` con la clave NVD leída de una variable de entorno y guardar el reporte HTML/JSON como evidencia.

#### Scenario: SCA-06 Escaneo local "antes"
- **WHEN** se ejecuta Dependency-Check local sobre el commit ROJO con `NVD_API_KEY` exportada
- **THEN** se genera `dependency-check-report.html` en `evidencias/locales/antes/` que muestra CVE-2022-42889 para commons-text 1.9

### Requirement: Caché de la base NVD
El job Dependency-Check SHALL cachear su directorio de datos fuera de `~/.m2` para que las ejecuciones posteriores no descarguen la NVD completa.

#### Scenario: SCA-07 Segunda ejecución con caché
- **WHEN** se ejecuta Dependency-Check por segunda vez en el pipeline
- **THEN** el paso de caché informa "Cache restored" y el job dura menos que la primera ejecución

### Requirement: Umbral no relajado
El umbral de bloqueo SCA SHALL ser CVSS mayor o igual a 7.0 / severidad HIGH o CRITICAL; el umbral de fallo del plugin se expone como propiedad Maven `dc.failBuildOnCVSS` (los literales del POM prevalecen sobre `-D`) y el pipeline MUST NOT subir el umbral del gate.

#### Scenario: SCA-08 Umbral del gate fijo
- **WHEN** se revisan `pom.xml`, los workflows y `quality_gate.py`
- **THEN** el gate bloquea con CVSS ≥ 7.0 / HIGH / CRITICAL y no existe opción `--ignore-unfixed` ni umbral superior aplicado al gate

### Requirement: Dependabot
El repositorio SHALL incluir `.github/dependabot.yml` con actualizaciones semanales para `maven`, `github-actions` y `docker` en el directorio raíz.

#### Scenario: SCA-09 Configuración de Dependabot
- **WHEN** `dependabot.yml` llega a la rama predeterminada
- **THEN** la pestaña Insights → Dependency graph → Dependabot muestra los tres ecosistemas sin errores de configuración
