# Spec Delta: sast-scanning

## Purpose

Analizar estáticamente el código Java con Semgrep, CodeQL y SpotBugs + FindSecBugs, tanto en local como en el pipeline, y producir reportes legibles por máquina que el Quality Gate pueda evaluar.

## ADDED Requirements

### Requirement: Semgrep sin telemetría y con reglas explícitas
El análisis Semgrep SHALL ejecutarse con `--metrics=off` y con los rulesets explícitos `p/java`, `p/owasp-top-ten`, `p/secrets` más las reglas propias de `.semgrep.yml` (no `--config auto`, que exige métricas), generando reportes SARIF y JSON.

#### Scenario: SAST-01 Semgrep detecta la SQLi del commit ROJO
- **WHEN** Semgrep analiza `src/main/java` en el commit ROJO
- **THEN** el SARIF contiene un resultado de la regla `lab-java-sql-concatenation` con nivel `error` en `ProductController.java`

#### Scenario: SAST-02 Semgrep no envía métricas
- **WHEN** se inspecciona el comando Semgrep del workflow y del script local
- **THEN** incluye `--metrics=off`, no incluye `--config auto` y el run termina sin el error "Cannot create auto config when metrics are off"

### Requirement: CodeQL para Java
El pipeline SHALL ejecutar CodeQL para `java` con la suite `security-and-quality`, compilando con Java 21, y publicar el SARIF resultante como reporte para el Quality Gate.

#### Scenario: SAST-03 CodeQL encuentra la inyección SQL
- **WHEN** CodeQL analiza el commit ROJO
- **THEN** el SARIF generado contiene un resultado `java/sql-injection` con `security-severity` mayor o igual a 7.0

### Requirement: SpotBugs con FindSecBugs
El pipeline y el entorno local SHALL ejecutar SpotBugs con el plugin FindSecBugs y generar `target/spotbugsXml.xml`; el análisis no SHALL abortar por hallazgos, solo por errores técnicos.

#### Scenario: SAST-04 FindSecBugs detecta la SQLi
- **WHEN** se ejecuta SpotBugs sobre el commit ROJO
- **THEN** `spotbugsXml.xml` contiene un `BugInstance` de categoría `SECURITY` con tipo `SQL_INJECTION_SPRING_JDBC` (o equivalente de inyección SQL) en `ProductController`

### Requirement: Publicación en Code scanning
Los SARIF de Semgrep y CodeQL SHALL subirse a GitHub Code scanning con categorías distintas y además conservarse como artifacts `reporte-*` del run.

#### Scenario: SAST-05 Alertas visibles en Security
- **WHEN** termina un run de CI sobre el commit ROJO
- **THEN** `gh api repos/FidelRada/spring-boot-webapi-secure/code-scanning/alerts` lista alertas abiertas de las herramientas `Semgrep OSS` y `CodeQL`

### Requirement: Ejecución local reproducible
El repositorio SHALL documentar y automatizar la ejecución local de Semgrep (vía imagen Docker `semgrep/semgrep` o `pipx`) y de SpotBugs con los mismos parámetros que el pipeline, guardando los reportes como evidencia.

#### Scenario: SAST-06 Escaneo local "antes"
- **WHEN** se ejecuta el script de escaneo local sobre el commit ROJO
- **THEN** se generan `semgrep.sarif`, `semgrep.json` y `spotbugsXml.xml` en `evidencias/locales/antes/` con al menos un hallazgo bloqueante cada uno

### Requirement: Los escáneres no deciden el bloqueo
Los jobs de SAST SHALL terminar en `success` cuando el análisis se completa aunque existan hallazgos, y en `failure` solo ante errores técnicos (compilación, descarga, sintaxis de reglas).

#### Scenario: SAST-07 Hallazgos sin fallo técnico
- **WHEN** Semgrep, CodeQL y SpotBugs analizan el commit ROJO sin errores técnicos
- **THEN** sus jobs terminan en `success`, suben sus reportes y es el job Quality Gate el que termina en `failure`
