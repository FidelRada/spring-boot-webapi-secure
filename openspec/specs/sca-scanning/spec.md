# sca-scanning Specification

## Purpose
Inventariar las dependencias (SBOM CycloneDX) y detectar componentes con vulnerabilidades conocidas mediante Trivy y OWASP Dependency-Check, sin exponer credenciales y con actualizaciones propuestas por Dependabot.

## Requirements

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
El pipeline SHALL ejecutar OWASP Dependency-Check (`dependency-check-maven` 13.0.0) en pull requests, en CI/CD y en el nightly, generando reportes HTML, JSON y SARIF, usando el archivo `dependency-check-suppressions.xml`, con el analizador OSS Index deshabilitado (requiere credenciales de Sonatype) y la telemetría desactivada (`DO_NOT_TRACK=true`).

#### Scenario: SCA-03 Reportes de Dependency-Check en el pipeline
- **WHEN** termina el job Dependency-Check de un run de pull request, CI/CD o nightly
- **THEN** el artifact `reporte-dependency-check` contiene `dependency-check-report.html`, `.json` y `.sarif`, y el JSON lista `commons-text-1.9.jar` con CVE-2022-42889 en el commit ROJO

### Requirement: Clave NVD fuera del repositorio
La clave de la API de la NVD MUST provenir del secreto `NVD_API_KEY` (Actions y Dependabot) o de una variable de entorno local, y MUST NOT aparecer en ningún archivo versionado.

#### Scenario: SCA-04 Sin clave en HEAD
- **WHEN** se ejecuta `git grep -nE 'nvdApiKey>[0-9A-F-]{36}|0502[8]C6D' HEAD`
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
El umbral de bloqueo SCA SHALL ser CVSS mayor o igual a 7.0 / severidad HIGH o CRITICAL. El umbral de fallo del plugin se expone como la propiedad Maven `dc.failBuildOnCVSS`, que vale 7 por defecto (un literal del POM prevalece sobre `-DfailBuildOnCVSS`, pero no sobre `-Ddc.failBuildOnCVSS`). En el pipeline el plugin SHALL ejecutarse con `-Ddc.failBuildOnCVSS=11` solo para que no aborte antes de escribir los reportes, y el bloqueo con CVSS ≥ 7.0 lo SHALL aplicar el Quality Gate; el pipeline MUST NOT subir el umbral del gate.

#### Scenario: SCA-08 Umbral del gate fijo
- **WHEN** se revisan `pom.xml`, los workflows y `quality_gate.py`
- **THEN** el gate bloquea con CVSS ≥ 7.0 / HIGH / CRITICAL, el escaneo del SBOM no usa `--ignore-unfixed` y no se aplica al gate ningún umbral superior

#### Scenario: SCA-12 Dependency-Check local falla con CVSS ≥ 7
- **WHEN** se ejecuta en local `NVD_API_KEY=... mvn -B org.owasp:dependency-check-maven:check` sin override sobre el commit ROJO
- **THEN** `mvn help:effective-pom` muestra `<failBuildOnCVSS>7` y el build termina en `BUILD FAILURE` por CVE-2022-42889 (CVSS 9.8), dejando además los reportes HTML/JSON

### Requirement: Dependabot
El repositorio SHALL incluir `.github/dependabot.yml` con actualizaciones semanales para `maven`, `github-actions` y `docker` en el directorio raíz (`open-pull-requests-limit: 5`), y SHALL tener habilitados Dependency graph, Dependabot alerts y Dependabot security updates, porque esas funciones no se activan solo con el YAML (guía 02 §11).

#### Scenario: SCA-09 Configuración de Dependabot
- **WHEN** `dependabot.yml` llega a la rama predeterminada
- **THEN** la pestaña Insights → Dependency graph → Dependabot muestra los tres ecosistemas sin errores de configuración

#### Scenario: SCA-11 Alertas y actualizaciones de seguridad habilitadas
- **WHEN** se habilitan con `gh api -X PUT repos/FidelRada/spring-boot-webapi-secure/vulnerability-alerts` y `gh api -X PUT repos/FidelRada/spring-boot-webapi-secure/automated-security-fixes`, y luego se consultan con `gh api repos/FidelRada/spring-boot-webapi-secure/vulnerability-alerts` (204) y `gh api repos/FidelRada/spring-boot-webapi-secure/automated-security-fixes`
- **THEN** ambas están habilitadas (`"enabled": true` en security fixes) y Settings → Code security las muestra activas

### Requirement: Exploración del árbol de dependencias
El análisis SCA SHALL documentar el árbol de dependencias resuelto (guía 02 §5), identificando una dependencia directa y dos transitivas con quién las incorpora.

#### Scenario: SCA-10 Árbol de dependencias
- **WHEN** se ejecutan `mvn dependency:tree -DoutputFile=target/dependency-tree.txt` y `mvn dependency:tree -Dincludes=org.apache.commons:commons-text`
- **THEN** `evidencias/locales/antes/dependency-tree.txt` existe, muestra `org.apache.commons:commons-text:jar:1.9:compile` como directa y la tabla directa/transitiva de la guía queda completada en el informe
