# quality-gate Specification

## Purpose
Decidir si un run del pipeline aprueba o bloquea leyendo el contenido de los reportes de seguridad (no solo el estado de los jobs), con política HIGH/CRITICAL y comportamiento fail-closed.

## Requirements

### Requirement: El gate lee los reportes
El Quality Gate SHALL descargar los artifacts `reporte-*` del run, parsear cada reporte requerido (SARIF de Semgrep y CodeQL, XML de SpotBugs, JSON de Trivy y de Dependency-Check) y fallar con código 1 si existe al menos un hallazgo bloqueante.

#### Scenario: QG-01 Dependencia con CVE crítico bloquea
- **WHEN** el reporte de Trivy o de Dependency-Check contiene CVE-2022-42889 (commons-text 1.9, CRITICAL)
- **THEN** el job Quality Gate termina con código 1 y el hallazgo aparece listado en el Step Summary

#### Scenario: QG-02 Hallazgo SAST de nivel error bloquea
- **WHEN** el SARIF de Semgrep contiene un resultado cuyo nivel efectivo es `error` (en `result.level` o, si falta, en `defaultConfiguration.level` de la regla), o el de CodeQL uno cuya regla (en `tool.driver.rules` o `tool.extensions[].rules`) tiene `security-severity` ≥ 7.0
- **THEN** el gate termina con código 1 e indica herramienta, regla y ubicación

#### Scenario: QG-03 Hallazgo de severidad menor no bloquea
- **WHEN** los reportes solo contienen hallazgos `warning`/`note`, CVSS < 7.0 o severidad MEDIUM/LOW
- **THEN** el gate termina con código 0 y los informa como no bloqueantes en el Step Summary

#### Scenario: QG-04 SpotBugs de seguridad bloquea
- **WHEN** `spotbugsXml.xml` contiene un `BugInstance` de categoría `SECURITY` con prioridad 1 o 2 (p. ej. `SQL_INJECTION_SPRING_JDBC`, prioridad 2)
- **THEN** el gate termina con código 1, y los `BugInstance` `SECURITY` de prioridad 3 (p. ej. `SPRING_ENDPOINT`) se listan como no bloqueantes

#### Scenario: QG-05 Vulnerabilidad suprimida no bloquea
- **WHEN** una vulnerabilidad figura en `suppressedVulnerabilities` del JSON de Dependency-Check
- **THEN** el gate no la cuenta como bloqueante pero la lista como suprimida

### Requirement: Fail-closed
El Quality Gate MUST fallar (código 2) cuando un reporte requerido para el evento no existe, está vacío o no se puede parsear.

#### Scenario: QG-06 Falta un reporte
- **WHEN** el reporte de Trivy requerido no está entre los artifacts descargados
- **THEN** el gate termina con código 2 y el Step Summary indica "reporte faltante"

#### Scenario: QG-07 Reporte corrupto
- **WHEN** el SARIF de Semgrep contiene JSON inválido
- **THEN** el gate termina con código 2 y el Step Summary indica "reporte ilegible"

### Requirement: El gate considera el estado de los jobs
El Quality Gate SHALL ejecutarse siempre que el run no haya sido cancelado (`if: ${{ !cancelled() }}`) y MUST fallar si cualquier job del que depende terminó en `failure` o `cancelled`, o si un job requerido quedó `skipped`.

#### Scenario: QG-08 Build roto bloquea
- **WHEN** el job Build & Test termina en `failure`
- **THEN** el gate se ejecuta igualmente y termina con código 1 indicando el job fallido

#### Scenario: QG-09 Job requerido omitido
- **WHEN** el job Dependency-Check es requerido para el evento (pull request, CI/CD o nightly) pero aparece como `skipped`
- **THEN** el gate termina con un código distinto de 0

### Requirement: Reportes requeridos según el evento
El conjunto de reportes requeridos SHALL depender del caller: Dependency-Check es requerido en pull request, CI/CD y nightly, y no en push a ramas `feature/**`, donde el SCA lo cubre Trivy sobre el SBOM.

#### Scenario: QG-10 Push a feature sin Dependency-Check
- **WHEN** el caller CI se ejecuta por `push` a `feature/**`
- **THEN** el gate no exige el reporte de Dependency-Check y sí exige los de Semgrep, CodeQL, SpotBugs y Trivy

### Requirement: Resumen legible
El Quality Gate SHALL escribir en `$GITHUB_STEP_SUMMARY` una tabla Markdown con herramienta, regla/CVE, severidad, ubicación y si bloquea, junto con el veredicto final, y publicarla también como artifact.

#### Scenario: QG-11 Tabla en el Step Summary
- **WHEN** el gate evalúa los reportes del commit ROJO
- **THEN** la página del run muestra la tabla con al menos un hallazgo por herramienta y el veredicto "BLOQUEADO"

### Requirement: Gate verde con reportes limpios
El Quality Gate SHALL terminar con código 0 cuando todos los reportes requeridos existen, se parsean y no contienen hallazgos bloqueantes, y todos los jobs requeridos terminaron en `success`.

#### Scenario: QG-12 Commit remediado aprueba
- **WHEN** el gate evalúa los reportes del commit final remediado
- **THEN** termina con código 0 y el veredicto "APROBADO"

### Requirement: Gate probado y ejecutable en local
El script del gate SHALL tener pruebas unitarias con fixtures por parser y escenario (crítico, limpio, faltante, corrupto, suprimido) y SHALL poder ejecutarse en local sobre una carpeta de reportes.

#### Scenario: QG-13 Pruebas unitarias del gate
- **WHEN** se ejecuta `python3 -m unittest discover -s .github/scripts/tests -v`
- **THEN** todas las pruebas pasan y cubren los escenarios QG-01 a QG-12

#### Scenario: QG-14 Gate local antes y después
- **WHEN** se ejecuta `python3 .github/scripts/quality_gate.py --reports-dir <dir>` sobre los reportes locales "antes" y "después"
- **THEN** devuelve código 1 sobre "antes" y código 0 sobre "después"
