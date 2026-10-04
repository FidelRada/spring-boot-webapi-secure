# Tasks: add-secure-ci-pipeline (commit ROJO)

> Reglas: en este change no se modifica `src/` (ni `src/main/**` ni `src/test/**`). Ningún paso usa `|| true`, `if: false` ni `continue-on-error`. Las secciones 1 a 7 son **locales** (fase 3, ejecutor; sin push). La sección 8 es **[E2E]** (fase 6): requiere push, secretos, ruleset y PRs en GitHub, y no se ejecuta antes.

## 1. Preparación y verificación de supuestos (cerrada en la auditoría de la fase 2)

- [x] 1.1 Verificar la versión mayor vigente de cada acción con `gh api repos/<owner>/<repo>/releases/latest --jq .tag_name` → checkout v7, setup-java v6, upload-artifact v7, download-artifact v8, cache v6, codeql-action v4, setup-buildx v4, login v4, metadata v6, build-push v7 (design.md D8)
- [x] 1.2 Verificar FindSecBugs (1.14.0), `spotbugs-maven-plugin` (4.9.8.5: 4.10.x exige Maven ≥ 3.8.9) y los parámetros de `dependency-check-maven` 13.0.0 con `mvn help:describe -Ddetail`: `nvdApiKeyEnvironmentVariable`, `dataDirectory`, `formats`, `suppressionFiles`, `ossIndexAnalyzerEnabled` y `failBuildOnCVSS` existen (design.md D2, D8)
- [x] 1.3 Verificar `timezone:` en `on.schedule`: lo admiten la documentación oficial y actionlint 1.7.12, que además valida el nombre IANA → `cron: '55 20 * * *'` + `timezone: America/La_Paz` (D6)
- [x] 1.4 Descargar las imágenes de herramientas locales `semgrep/semgrep:1.179.0`, `aquasec/trivy:0.74.0` y `rhysd/actionlint:1.7.12`; verificar con `docker images`

## 2. pom.xml y archivos de soporte

- [x] 2.1 Eliminar `<nvdApiKey>` de `pom.xml` y añadir `<nvdApiKeyEnvironmentVariable>NVD_API_KEY</nvdApiKeyEnvironmentVariable>`; verificar con `git grep -n 0502[8]C6D` sin resultados (SCA-04)
- [x] 2.2 Subir `dependency-check-maven` a 13.0.0. Añadir la propiedad `<dc.failBuildOnCVSS>7</dc.failBuildOnCVSS>` y usar `${dc.failBuildOnCVSS}` en el plugin, junto con `<formats>` HTML/JSON/SARIF, `<suppressionFiles>`, `<dataDirectory>${user.home}/.cache/dependency-check-data</dataDirectory>` y `<ossIndexAnalyzerEnabled>false</ossIndexAnalyzerEnabled>`. Verificar con `mvn -B -q help:effective-pom -Doutput=/dev/stdout | grep failBuildOnCVSS`: `7` sin override y `11` con `-Ddc.failBuildOnCVSS=11` (SCA-08)
- [x] 2.3 Fijar `spotbugs-maven-plugin` 4.9.8.5 con FindSecBugs 1.14.0 en `<plugins>`, `xmlOutput=true`, `effort=Max`, `threshold=Low`; verificar que `mvn -B compile spotbugs:spotbugs` genera `target/spotbugsXml.xml` con `SQL_INJECTION_SPRING_JDBC` (prioridad 2) y `SPRING_CSRF_PROTECTION_DISABLED` (prioridad 1) (SAST-04)
- [x] 2.4 Mantener CycloneDX 2.9.3 (schema 1.6, sin test/system) y verificar que `target/bom.json` contiene commons-text 1.9 (SCA-01)
- [x] 2.5 Crear `dependency-check-suppressions.xml` válido (namespace `suppression-1.3.xsd`, sin supresiones, o solo con `<notes>` + `until`); verificar que DC lo carga sin error (SCA-05)
- [x] 2.6 Verificar `mvn -B clean verify` en verde, sin variables de entorno, con los 2 tests originales pasando y `git diff --stat main -- src/` vacío (CIW-14)

## 3. Quality Gate (`.github/scripts/quality_gate.py`)

- [x] 3.1 Implementar `Finding`, `GateResult`, `ReportParser` y los parsers `SemgrepParser`, `CodeQLParser`, `SpotBugsParser`, `DependencyCheckParser` y `TrivyParser` con la política de design.md D3, usando solo la biblioteca estándar:
  - Semgrep: el nivel efectivo sale de `result.level` y, si falta, de `defaultConfiguration.level` de la regla.
  - CodeQL: `security-severity` se busca en `tool.driver.rules` y en `tool.extensions[].rules`.
  - SpotBugs: bloquea `SECURITY` con prioridad ≤ 2.
- [x] 3.2 Implementar `QualityGate.evaluate()` con `--reports-dir`, `--required`, `--needs-json`, `--summary` y `--only`; códigos de salida 0/1/2 y tabla Markdown en el Step Summary
- [x] 3.3 Crear fixtures mínimos en `.github/scripts/tests/fixtures/`:
  - SARIF real de Semgrep sin `level` en el resultado, para los casos error y warning (copiar la estructura de `../evidencias/auditoria/semgrep_rojo_auditoria.sarif`, en la carpeta del lab; lo mismo para `spotbugsXml_rojo_auditoria.xml` y `sca-report_rojo_auditoria.json`).
  - CodeQL con reglas en `extensions`, una de 8.8 y otra de 5.0.
  - SpotBugs `SECURITY` con prioridades 1, 2 y 3.
  - DC con CVE-2022-42889 y con un caso suprimido.
  - Trivy SBOM con un CRITICAL y uno limpio; Trivy imagen os/library.
  - Un JSON corrupto.
- [x] 3.4 Escribir `.github/scripts/tests/test_quality_gate.py` con un test por escenario QG-01..QG-12 y CD-08; verificar con `python3 -m unittest discover -s .github/scripts/tests -v` (QG-13)

## 4. Workflows

- [x] 4.1 Crear `.github/workflows/security-scans.yml` con los jobs de design.md D2:
  - Disparador `workflow_call` con los inputs `run_dependency_check`, `build_image` y `push_image`, y el secreto `NVD_API_KEY`.
  - Java 21.
  - `semgrep/semgrep:1.179.0`.
  - CodeQL `@v4` con `build-mode: none`.
  - `DO_NOT_TRACK: 'true'` en el job de DC, caché DC con `actions/cache@v6` y `timeout-minutes: 60`.
  - Permisos mínimos por job.
  - Artifacts `reporte-*` con `if: ${{ !cancelled() }}`, `if-no-files-found: error` y `retention-days: 7`.
- [x] 4.2 Añadir el job Quality Gate (QG-08, QG-09):
  - `needs` sobre todos los escáneres e `if: ${{ !cancelled() }}`.
  - `NEEDS_JSON: ${{ toJSON(needs) }}`.
  - Descarga con `actions/download-artifact@v8` y `pattern: reporte-*`.
  - Ejecución de los unittest y después del gate.
- [x] 4.3 Añadir el job de imagen (D5; CD-04..CD-08):
  - `needs: quality-gate` e `if: inputs.build_image`.
  - Buildx con `load: true`.
  - Dos pasadas de `docker run aquasec/trivy:0.74.0 image`: `--pkg-types os --ignore-unfixed` y `--pkg-types library`, más un SARIF completo.
  - `quality_gate.py --only trivy-imagen` y `upload-sarif`.
  - Push condicionado a `inputs.push_image`.
- [x] 4.4 Reescribir `ci-sec.yml` como caller (CIW-01, CIW-02, CIW-11, CIW-12, CIW-13):
  - Push a `feature/**`, `bugfix/**` y `hotfix/**`; PR a `main`/`develop`.
  - Job `name: CI (${{ github.event_name }})` con permisos `contents: read`, `actions: read` y `security-events: write`.
  - DC solo en `pull_request`.
  - `concurrency` con cancelación.
- [x] 4.5 Reescribir `ci-cd-sec.yml` como caller (CIW-03, CIW-11):
  - Solo push a `main`/`develop`, con DC e imagen.
  - Push de la imagen solo en `main`.
  - El job caller además concede `packages: write`.
  - Eliminar los jobs `deploy-*` con `if: false`.
- [x] 4.6 Reescribir `ci-sec-nightly.yml` como caller con `schedule` (`cron: '55 20 * * *'`, `timezone: America/La_Paz`) + `workflow_dispatch`, DC e imagen sin push (CIW-04, CIW-05)
- [x] 4.7 Eliminar `.github/workflows/security-semgrep.yml` (CIW-06)
- [x] 4.8 Verificar (CIW-07, CIW-08):
  - `docker run --rm -v "$PWD:/repo" -w /repo rhysd/actionlint:1.7.12` termina con 0 y sin hallazgos.
  - `grep -nE '\|\| *true|if: *false|continue-on-error: *true' .github/workflows/*.yml` no devuelve nada.

## 5. Dependabot, Dockerfile y ruleset

- [x] 5.1 Crear `.github/dependabot.yml` con `maven`, `github-actions` y `docker`, semanales, en `/` y con `open-pull-requests-limit: 5` (SCA-09)
- [x] 5.2 Reescribir el `Dockerfile` y revisar `.dockerignore` (CD-01..CD-03):
  - Builder `maven:3.9-eclipse-temurin-21` y runtime `eclipse-temurin:21-jre-alpine`.
  - Usuario con `addgroup -S`/`adduser -S`.
  - `HEALTHCHECK` con `wget`.
  - Verificar `docker build -t lab3:local .`, `docker run --rm --entrypoint id lab3:local` y que el contenedor llega a `healthy`.
- [x] 5.3 Crear `.github/rulesets/proteger-main-develop.json` y validar el JSON con `python3 -m json.tool` (BP-01). Contenido:
  - `main` + `develop`.
  - `pull_request` con 0 aprobaciones.
  - `required_status_checks` con los nombres provisionales `CI (pull_request) / Quality Gate` y `CI (pull_request) / Build & Test` (`integration_id` 15368).
  - `deletion` y `non_fast_forward`, sin bypass.

  Se **aplica** en la sección 8.
- [x] 5.4 Actualizar `README.md` con una sección de CI seguro: workflows, gate, comandos locales, secreto `NVD_API_KEY` y `DO_NOT_TRACK`. Verificar que los comandos documentados coinciden con los del workflow

## 6. Escaneo local "antes" (fuera del repo, carpeta del lab)

- [ ] 6.1 Crear `herramientas/escaneo_local.sh <antes|despues>`. Debe ejecutar:
  - `mvn dependency:tree -DoutputFile` (SCA-10).
  - Semgrep (Docker 1.179.0, `--metrics=off`).
  - Dependency-Check (Maven + `NVD_API_KEY` + `DO_NOT_TRACK=true`, **sin** override del umbral).
  - SpotBugs.
  - CycloneDX + Trivy 0.74.0 (Docker).
  - El gate.

  Todo se guarda en `evidencias/locales/<fase>/`.
- [ ] 6.2 Ejecutar `escaneo_local.sh antes` sobre el commit ROJO y verificar:
  - SQLi en Semgrep (SAST-01, SAST-06).
  - CVE-2022-42889 en Trivy y en DC (SCA-02, SCA-06).
  - DC local en `BUILD FAILURE` con `failBuildOnCVSS=7` (SCA-12).
  - SQLi de FindSecBugs (SAST-04).
  - Árbol de dependencias (SCA-10).
  - Gate local con código 1 (QG-14, parte "antes").

## 7. Commit ROJO (local, sin push)

- [ ] 7.1 Hacer el commit en `feature/lab3-ci-seguro` con el mensaje `ci: pipeline seguro con SAST, SCA y quality gate (commit ROJO)`. Verificar:
  - `git diff --stat main -- src/` vacío.
  - `mvn -B clean verify` en verde (CIW-14).
  - `git grep -n 0502[8]C6D HEAD` sin resultados (SCA-04).
  - Autor del commit: `git config user.name` = `FideRada` (nombre global existente; no se cambia).
- [ ] 7.2 Ejecutar `openspec validate add-secure-ci-pipeline --strict` y marcar las tareas completadas

## 8. [E2E] GitHub (fase 6; requiere push y configuración remota)

- [ ] 8.1 [E2E] Registrar los secretos y preparar el repositorio:
  - `gh secret set NVD_API_KEY` y `gh secret set NVD_API_KEY --app dependabot`.
  - Crear `develop` en el fork y habilitar Actions.
  - Habilitar Dependabot alerts y security updates con `gh api -X PUT .../vulnerability-alerts` y `.../automated-security-fixes`.
  - Verificar con `gh secret list` y con los `gh api` de SCA-11.
- [ ] 8.2 [E2E] Hacer push de `feature/lab3-ci-seguro` y comprobar el run de CI `push` (SAST-07, QG-11, CIW-01): escáneres en `success` y Quality Gate en `failure` con la tabla en el Step Summary
- [ ] 8.3 [E2E] Abrir el PR #1 → `develop` (CIW-02). Leer los nombres reales con `gh api repos/FidelRada/spring-boot-webapi-secure/commits/<sha>/check-runs --jq '.check_runs[].name'` (CIW-12) y ajustar el JSON del ruleset si difieren
- [ ] 8.4 [E2E] Aplicar el ruleset con `gh api -X POST repos/FidelRada/spring-boot-webapi-secure/rulesets --input .github/rulesets/proteger-main-develop.json` (BP-01). Comprobar `mergeStateStatus=BLOCKED` y que `gh pr merge 1 --merge` se rechaza (BP-02, BP-03). Probar el push directo, el force-push y el borrado (BP-06, BP-07)
- [ ] 8.5 [E2E] Verificar las alertas de Code scanning (SAST-05), el artifact de DC (SCA-03) y la caché de DC en la segunda ejecución (SCA-07)
- [ ] 8.6 [E2E] Después de los merges del change 2: CI/CD de `develop` y `main` (CIW-03, CD-05, CD-06), nightly con `gh workflow enable` + `gh workflow run ci-sec-nightly.yml --ref main` (CIW-04, CD-07), Dependabot en la rama predeterminada (SCA-09) y PR #3 de regresión (BP-05)
- [ ] 8.7 [E2E] Ejecutar `gh run download` de cada run citado a `evidencias/pipeline/<runId>_<workflow>/` antes de que expire (7 días) y registrarlo en `evidencias/indice_evidencias.md` y `referencia_pipeline.md` (CIW-15)
