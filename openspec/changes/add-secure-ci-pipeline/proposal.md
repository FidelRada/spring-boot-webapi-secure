# Proposal: add-secure-ci-pipeline (momento ROJO)

## Why

El pipeline heredado del upstream no protege nada: el `quality-gate` solo mira `needs.*.result`, Dependency-Check está anulado (`if: false` / `|| true`), SpotBugs termina en `|| true`, `security-semgrep.yml` no se puede parsear (comilla rota), CI/CD usa una acción inexistente (`aquasecurity/trivy-action@0.36.0`) y un Dockerfile que no construye, los workflows piden Java 25 mientras el proyecto es Java 21, la clave de la NVD está escrita en `pom.xml` y no hay protección de ramas. Resultado: una aplicación deliberadamente vulnerable puede fusionarse en `main` con todos los checks en verde. El laboratorio exige lo contrario: que el CI **detecte y bloquee** (momento rojo) antes de remediar (change `remediate-app-vulnerabilities`, momento verde).

## What Changes

- Nuevo workflow reutilizable `.github/workflows/security-scans.yml` (`workflow_call`) con los jobs Build & Test, SAST Semgrep, SAST CodeQL, SAST SpotBugs + FindSecBugs, SCA SBOM CycloneDX + Trivy, SCA OWASP Dependency-Check (opcional por input) y Quality Gate.
- Callers reescritos: `ci-sec.yml` (push `feature/**`, `bugfix/**`, `hotfix/**` y PR a `main`/`develop`), `ci-cd-sec.yml` (push `main`/`develop`; build de imagen → Trivy imagen → push a GHCR solo en `main`) y `ci-sec-nightly.yml` (`cron: '55 20 * * *'` con `timezone: America/La_Paz` + `workflow_dispatch`, con Dependency-Check e imagen escaneada sin push). Los jobs caller conceden los permisos que el reutilizable necesita (un reutilizable solo puede reducirlos).
- **BREAKING (CI)**: se elimina `security-semgrep.yml` (absorbido en el reutilizable) y los jobs de despliegue de ejemplo deshabilitados con `if: false`.
- Nuevo `.github/scripts/quality_gate.py` (+ `tests/` con unittest y fixtures) que **lee** los reportes SARIF (Semgrep, CodeQL), XML (SpotBugs) y JSON (Dependency-Check, Trivy), falla ante hallazgos HIGH/CRITICAL y es *fail-closed* (reporte ausente o ilegible ⇒ falla).
- `pom.xml`:
  - Dependency-Check sube de 11.1.1 a 13.0.0 y se elimina `nvdApiKey`: la clave pasa al secreto `NVD_API_KEY`, leído con `nvdApiKeyEnvironmentVariable`.
  - El umbral CVSS queda parametrizado como la propiedad `dc.failBuildOnCVSS=7`.
  - Reportes DC en HTML/JSON/SARIF, OSS Index deshabilitado y archivo de supresiones.
  - SpotBugs 4.9.8.5 con FindSecBugs 1.14.0 y salida XML.
- Nuevo `dependency-check-suppressions.xml` (válido, sin supresiones injustificadas).
- `Dockerfile` reparado (builder `maven:3.9-eclipse-temurin-21`, runtime `eclipse-temurin:21-jre-alpine`, usuario no root con `adduser`, healthcheck con `wget`).
- Nuevo `.github/dependabot.yml` (maven, github-actions y docker).
- Nuevo `.github/rulesets/proteger-main-develop.json` aplicado con `gh api` (PR obligatorio, required checks, sin bypass, sin borrado ni force-push en `main` y `develop`).
- Script de escaneo local reproducible (Semgrep, Dependency-Check, SpotBugs, CycloneDX + Trivy, gate) usado para las evidencias "antes".
- **No** se toca el código vulnerable de `src/main/java` en este change: el commit debe quedar ROJO.

## Capabilities

### New Capabilities
- `ci-workflows`: disparadores, estructura reutilizable, versiones, permisos y ausencia de controles anulados en los workflows CI, CI/CD y nightly.
- `sast-scanning`: análisis estático con Semgrep, CodeQL y SpotBugs + FindSecBugs, en local y en el pipeline, con reportes legibles por máquina.
- `sca-scanning`: inventario SBOM CycloneDX, análisis Trivy y OWASP Dependency-Check, gestión de la clave NVD, supresiones y Dependabot.
- `quality-gate`: evaluación de los reportes con política HIGH/CRITICAL, fail-closed y resumen en el Step Summary.
- `branch-protection`: ruleset que impide fusionar en `main`/`develop` si el pipeline falla.
- `container-delivery`: construcción, escaneo y publicación segura de la imagen en GHCR.

### Modified Capabilities
- (ninguna; no existen specs previas en `openspec/specs/`)

## Mapeo con la consigna y la guía 02

| Punto | Fuente | Requisito(s) |
|---|---|---|
| Fork/clon del repositorio de trabajo | Consigna | Fase 1, ya hecho (`FidelRada/spring-boot-webapi-secure`, `fork: true`, público); evidencia `git remote -v` en el informe |
| Semgrep y Dependency-Check ejecutados localmente | Consigna | SAST-06, SCA-06, SCA-12, QG-14 |
| Repositorio funcional | Consigna | CIW-14, CIW-07, CIW-10 |
| CI [feature/**] | Consigna | CIW-01 |
| CI/CD [main, develop] | Consigna | CIW-03, CD-05, CD-06 |
| CI/CD nightly + SCA (Dependency-Check) | Consigna | CIW-04, CIW-05, SCA-03, CD-07 |
| CodeQL o Semgrep, Dependency-Check, SpotBugs | Consigna | SAST-01..05, SAST-07, SCA-02, SCA-03 |
| Quality gate que lea reportes con hallazgos críticos | Consigna | QG-01..QG-14 |
| Merges a main bloqueados si el pipeline falla | Consigna | BP-01..BP-07 |
| PDF con capturas (workflows, reportes locales y del pipeline) | Consigna | CIW-15 (descarga de evidencias), tasks 6.2 y 8.7, trazabilidad.md (columna Figura); el informe es la fase 8 |
| Exploración `dependency:tree` | Guía 02 §5 | SCA-10 |
| SBOM CycloneDX 2.9.3 / schema 1.6 | Guía 02 §6 | SCA-01 |
| Caso didáctico commons-text 1.9 | Guía 02 §7 | SCA-02, QG-01 |
| Trivy 0.74.0 por Docker (local y Actions) | Guía 02 §8–9 | SCA-02, CD-04 |
| Workflow SCA (SBOM → Trivy → gate) | Guía 02 §9 | Job "SCA - SBOM y vulnerabilidades" del reutilizable (CIW-01, SCA-01, SCA-02) |
| Gate HIGH/CRITICAL sin `--ignore-unfixed` | Guía 02 §9 | QG-01, SCA-08 (SBOM). Excepción documentada solo para los paquetes del SO de la imagen: CD-04, CD-08 |
| Required check en ruleset | Guía 02 §10 | BP-01, BP-06 |
| Dependabot maven + github-actions | Guía 02 §11 | SCA-09 |
| Dependency graph, alerts y security updates habilitados en Settings | Guía 02 §11 | SCA-11 |
| No bajar umbrales ni desactivar controles | Guía 02 §12 | CIW-06, SCA-08 |
| Corrección 1.9 → 1.10.0 y `comparacion.md` | Guía 02 §12–13 | change `remediate-app-vulnerabilities` (APP-20, APP-22) |

## Impact

- Archivos: `.github/workflows/*`, `.github/scripts/quality_gate.py` (+tests), `.github/dependabot.yml`, `.github/rulesets/*.json`, `pom.xml`, `Dockerfile`, `.dockerignore`, `dependency-check-suppressions.xml`, `.semgrep.yml` (sin cambios de reglas), `README.md`.
- GitHub: secreto `NVD_API_KEY` (Actions y Dependabot), rama `develop`, ruleset, Code scanning (SARIF), paquete GHCR.
- Tiempo de CI: Dependency-Check añade varios minutos en PR/CI-CD/nightly (mitigado con caché de datos NVD); en push a `feature/**` el SCA rápido es Trivy sobre el SBOM.
- Riesgo esperado y buscado: el PR del commit ROJO queda bloqueado hasta aplicar el change 2.
