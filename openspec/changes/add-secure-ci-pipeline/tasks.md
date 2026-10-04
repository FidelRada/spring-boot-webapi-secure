# Tasks: add-secure-ci-pipeline (commit ROJO)

> Regla: en este change no se modifica `src/main/**`. Ningún paso usa `|| true`, `if: false` ni `continue-on-error`.

## 1. Preparación y verificación de supuestos

- [ ] 1.1 Verificar la versión mayor vigente de cada acción (`actions/checkout`, `actions/setup-java`, `actions/cache`, `actions/upload-artifact`, `actions/download-artifact`, `github/codeql-action`, `docker/setup-buildx-action`, `docker/login-action`, `docker/metadata-action`, `docker/build-push-action`) con `gh api repos/<owner>/<repo>/releases/latest --jq .tag_name` y anotarlas en design.md (Open Questions)
- [ ] 1.2 Verificar la versión de FindSecBugs y de `spotbugs-maven-plugin` compatible con Java 21 (Maven Central) y la existencia de `nvdApiKeyEnvironmentVariable` en `dependency-check-maven` 11.1.1; anotar el resultado
- [ ] 1.3 Verificar si GitHub Actions y `actionlint` aceptan `timezone:` en `on.schedule`; decidir entre `timezone: America/La_Paz` o `cron: '55 0 * * *'` (D6)
- [ ] 1.4 Instalar herramientas locales: `docker pull semgrep/semgrep:<tag> aquasec/trivy:0.74.0 rhysd/actionlint:latest`; verificar con `docker images`

## 2. pom.xml y archivos de soporte

- [ ] 2.1 Eliminar `<nvdApiKey>` de `pom.xml` y configurar la lectura desde `NVD_API_KEY` (env); verificar con `git grep -n 05028C6D` sin resultados (SCA-04)
- [ ] 2.2 Añadir la propiedad `<dc.failBuildOnCVSS>7</dc.failBuildOnCVSS>` y usar `${dc.failBuildOnCVSS}` en el plugin, junto con `formats` HTML/JSON/SARIF, `suppressionFile` y `dataDirectory`; verificar con `mvn help:effective-pom | grep -A3 failBuildOnCVSS` (SCA-08)
- [ ] 2.3 Añadir FindSecBugs como `<plugins>` de `spotbugs-maven-plugin`, `xmlOutput=true`, `effort=Max`, `threshold=Low`, `failOnError` parametrizado; verificar que `mvn -B compile spotbugs:spotbugs` genera `target/spotbugsXml.xml` con `SQL_INJECTION_SPRING_JDBC` (SAST-04)
- [ ] 2.4 Mantener CycloneDX 2.9.3 (schema 1.6, sin test/system) y verificar `target/bom.json` con commons-text 1.9 (SCA-01)
- [ ] 2.5 Crear `dependency-check-suppressions.xml` válido (namespace `suppression-1.3.xsd`, sin supresiones o solo con `<notes>` + `until`); verificar que DC lo carga sin error (SCA-05)
- [ ] 2.6 Verificar `mvn -B clean verify` en verde sobre el commit ROJO (los tests existentes siguen pasando)

## 3. Quality Gate (`.github/scripts/quality_gate.py`)

- [ ] 3.1 Implementar `Finding`, `GateResult`, `ReportParser` y los parsers `SemgrepParser`, `CodeQLParser`, `SpotBugsParser`, `DependencyCheckParser`, `TrivyParser` con la política de design.md D3 (solo biblioteca estándar)
- [ ] 3.2 Implementar `QualityGate.evaluate()` con `--reports-dir`, `--required`, `--needs-json`, `--summary`, `--only`; códigos 0/1/2 y tabla Markdown en el Step Summary
- [ ] 3.3 Crear fixtures mínimos en `.github/scripts/tests/fixtures/` (SARIF error/warning, CodeQL 8.8/5.0, SpotBugs SECURITY p1/p3, DC con CVE-2022-42889 y suprimido, Trivy CRITICAL/limpio, JSON corrupto)
- [ ] 3.4 Escribir `.github/scripts/tests/test_quality_gate.py` con un test por escenario QG-01..QG-12; verificar con `python3 -m unittest discover -s .github/scripts/tests -v` (QG-13)

## 4. Workflows

- [ ] 4.1 Crear `.github/workflows/security-scans.yml` (`workflow_call`, inputs `run_dependency_check`, `build_image`, `push_image`, secreto `NVD_API_KEY`) con los jobs de design.md D2, Java 21, permisos mínimos por job y artifacts `reporte-*` con `if: ${{ !cancelled() }}`
- [ ] 4.2 Añadir el job Quality Gate con `needs` sobre todos los escáneres, `if: ${{ !cancelled() }}`, `NEEDS_JSON: ${{ toJSON(needs) }}`, descarga `pattern: reporte-*`, unittest y ejecución del gate (QG-08, QG-09)
- [ ] 4.3 Añadir el job de imagen (`needs: quality-gate`, `if: inputs.build_image`): buildx `load: true`, `docker run aquasec/trivy:0.74.0 image` (JSON + SARIF), `quality_gate.py --only trivy-imagen`, `upload-sarif`, push condicionado a `inputs.push_image` (CD-04..CD-07)
- [ ] 4.4 Reescribir `ci-sec.yml` como caller (push `feature/**`, `bugfix/**`, `hotfix/**`; PR a `main`/`develop`; `name: CI (${{ github.event_name }})`; DC solo en `pull_request`; concurrency con cancel) (CIW-01, CIW-02, CIW-12, CIW-13)
- [ ] 4.5 Reescribir `ci-cd-sec.yml` como caller (solo push `main`/`develop`; DC; imagen; push solo en `main`; `packages: write` solo ahí); eliminar los jobs `deploy-*` con `if: false` (CIW-03)
- [ ] 4.6 Reescribir `ci-sec-nightly.yml` como caller (schedule según 1.3 + `workflow_dispatch`; DC; imagen sin push) (CIW-04, CIW-05)
- [ ] 4.7 Eliminar `.github/workflows/security-semgrep.yml` (CIW-06)
- [ ] 4.8 Verificar `docker run --rm -v "$PWD:/repo" -w /repo rhysd/actionlint:latest -color` sin hallazgos (CIW-07) y `grep -nE '\|\| *true|if: *false|continue-on-error: *true' .github/workflows/*.yml` vacío (CIW-08)

## 5. Dependabot, Dockerfile y ruleset

- [ ] 5.1 Crear `.github/dependabot.yml` con `maven`, `github-actions` y `docker` semanales en `/` (SCA-09)
- [ ] 5.2 Reescribir `Dockerfile` (builder `maven:3.9-eclipse-temurin-21`, runtime `eclipse-temurin:21-jre-alpine`, `addgroup -S`/`adduser -S`, `HEALTHCHECK` con `wget`) y revisar `.dockerignore`; verificar `docker build -t lab3:local .`, `docker run --rm --entrypoint id lab3:local` y estado `healthy` (CD-01..CD-03)
- [ ] 5.3 Crear `.github/rulesets/proteger-main-develop.json` (main + develop, `pull_request` con 0 aprobaciones, `required_status_checks` con nombres provisionales, `deletion`, `non_fast_forward`, sin bypass); validar JSON con `python3 -m json.tool`. Se aplica en la fase E2E tras confirmar los nombres reales (BP-01)
- [ ] 5.4 Actualizar `README.md` (sección CI seguro: workflows, gate, comandos locales, secreto `NVD_API_KEY`); verificar que los comandos documentados coinciden con los del workflow

## 6. Escaneo local "antes" (fuera del repo, carpeta del lab)

- [ ] 6.1 Crear `herramientas/escaneo_local.sh <antes|despues>` que ejecuta Semgrep (Docker, `--metrics=off`), Dependency-Check (Maven + `NVD_API_KEY`), SpotBugs, CycloneDX + Trivy (Docker) y el gate, guardando todo en `evidencias/locales/<fase>/`
- [ ] 6.2 Ejecutar `escaneo_local.sh antes` sobre el commit ROJO y verificar: SQLi en Semgrep (SAST-01, SAST-06), CVE-2022-42889 en Trivy y DC (SCA-02, SCA-06), FindSecBugs SQLi (SAST-04) y gate local con código 1 (QG-14 parte "antes")

## 7. Commit ROJO e integración

- [ ] 7.1 Commit en `feature/lab3-ci-seguro`: `ci: pipeline seguro con SAST, SCA y quality gate (commit ROJO)`; verificar `git diff --stat main -- src/main` vacío
- [ ] 7.2 Push y comprobar el run de CI `push`: escáneres en `success`, Quality Gate en `failure` con tabla en el Step Summary (SAST-07, QG-11)
- [ ] 7.3 Crear `develop` en el fork, registrar `NVD_API_KEY` (Actions y Dependabot), abrir PR #1 → `develop`, leer nombres reales con `gh api .../check-runs`, ajustar y aplicar el ruleset (BP-01), y comprobar `mergeStateStatus=BLOCKED` y `gh pr merge` rechazado (BP-02, BP-03)
- [ ] 7.4 Verificar alertas en Code scanning (SAST-05), artifacts de DC (SCA-03) y caché DC en la segunda ejecución (SCA-07)
- [ ] 7.5 Ejecutar `openspec validate add-secure-ci-pipeline --strict` y marcar las tareas completadas
