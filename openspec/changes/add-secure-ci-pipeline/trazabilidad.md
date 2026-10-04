# Trazabilidad: add-secure-ci-pipeline

Matriz escenario → prueba → evidencia → figura del informe. La columna *Figura* se completa en la fase 8 (informe SOE); la columna *Estado* en la fase 7 (auditoría de pruebas).

Tipos de prueba: **unittest** (gate en Python), **local** (escaneo local con `herramientas/escaneo_local.sh`), **run** (ejecución de GitHub Actions), **api** (`gh api`/`gh pr`), **docker** (comandos Docker locales), **lint** (actionlint/grep), **revisión** (inspección de archivos).

| ID | Capability | Prueba | Tipo | Evidencia esperada | Figura | Estado |
|---|---|---|---|---|---|---|
| CIW-01 | ci-workflows | Push a `feature/lab3-ci-seguro` | run | `evidencias/pipeline/<runId>_ci-push/` + captura de la lista de jobs | pendiente | pendiente |
| CIW-02 | ci-workflows | Abrir PR #1 → `develop` | run | Run `pull_request` con job Dependency-Check | pendiente | pendiente |
| CIW-03 | ci-workflows | Merge PR #1 y PR #2 | run | Runs CI/CD en `develop` y `main` | pendiente | pendiente |
| CIW-04 | ci-workflows | `gh workflow run ci-sec-nightly.yml --ref main` | run | Run `workflow_dispatch` en success | pendiente | pendiente |
| CIW-05 | ci-workflows | Inspección de `on.schedule` + actionlint | lint | Fragmento YAML + salida actionlint | pendiente | pendiente |
| CIW-06 | ci-workflows | `ls .github/workflows` + grep `uses: ./.github/workflows/security-scans.yml` | revisión | Listado de archivos | pendiente | pendiente |
| CIW-07 | ci-workflows | `actionlint` en Docker | lint | `evidencias/locales/actionlint.txt` vacío, exit 0 | pendiente | pendiente |
| CIW-08 | ci-workflows | grep de anulaciones | lint | Salida vacía | pendiente | pendiente |
| CIW-09 | ci-workflows | grep `java-version` + log de setup-java | run | Log con "Java 21" | pendiente | pendiente |
| CIW-10 | ci-workflows | Runs sin "Unable to resolve action" | run | Runs completos | pendiente | pendiente |
| CIW-11 | ci-workflows | Revisión de bloques `permissions` | revisión | Tabla de permisos en el informe | pendiente | pendiente |
| CIW-12 | ci-workflows | `gh api .../commits/<sha>/check-runs` | api | `evidencias/pipeline/check-runs_<sha>.json` | pendiente | pendiente |
| CIW-13 | ci-workflows | Dos push seguidos a la rama feature | run | Primer run `cancelled` | pendiente | pendiente |
| SAST-01 | sast-scanning | Semgrep sobre commit ROJO | local + run | `semgrep.sarif` con `lab-java-sql-concatenation` | pendiente | pendiente |
| SAST-02 | sast-scanning | Inspección del comando Semgrep | revisión | Fragmento YAML/script con `--metrics=off` | pendiente | pendiente |
| SAST-03 | sast-scanning | CodeQL en run de CI | run | `reporte-codeql/*.sarif` con `java/sql-injection` | pendiente | pendiente |
| SAST-04 | sast-scanning | SpotBugs + FindSecBugs | local + run | `spotbugsXml.xml` con `SQL_INJECTION_SPRING_JDBC` | pendiente | pendiente |
| SAST-05 | sast-scanning | `gh api .../code-scanning/alerts` | api | JSON de alertas + captura Security → Code scanning (manual) | pendiente | pendiente |
| SAST-06 | sast-scanning | `escaneo_local.sh antes` | local | `evidencias/locales/antes/semgrep.*`, `spotbugsXml.xml` | pendiente | pendiente |
| SAST-07 | sast-scanning | Run de CI ROJO | run | Escáneres success, gate failure | pendiente | pendiente |
| SCA-01 | sca-scanning | CycloneDX local | local | `evidencias/locales/antes/bom.json` con commons-text 1.9 | pendiente | pendiente |
| SCA-02 | sca-scanning | Trivy SBOM local y en run | local + run | `sca-report.json` con CVE-2022-42889 CRITICAL | pendiente | pendiente |
| SCA-03 | sca-scanning | Job Dependency-Check en PR/CI-CD/nightly | run | Artifact `reporte-dependency-check` (HTML/JSON/SARIF) | pendiente | pendiente |
| SCA-04 | sca-scanning | `git grep` de la clave + log del job | revisión | Salida vacía; secreto enmascarado `***` | pendiente | pendiente |
| SCA-05 | sca-scanning | Carga del archivo de supresiones | local + run | Log DC sin error de parseo | pendiente | pendiente |
| SCA-06 | sca-scanning | DC local "antes" | local | `evidencias/locales/antes/dependency-check-report.html` | pendiente | pendiente |
| SCA-07 | sca-scanning | Segunda ejecución DC | run | Log "Cache restored" + duración menor | pendiente | pendiente |
| SCA-08 | sca-scanning | Revisión de umbrales | revisión | Fragmentos de pom/workflow/gate | pendiente | pendiente |
| SCA-09 | sca-scanning | Dependabot en la rama predeterminada | api | Captura Insights → Dependabot / PR de Dependabot | pendiente | pendiente |
| QG-01 | quality-gate | `test_trivy_critical_bloquea`, `test_dc_critical_bloquea` + run ROJO | unittest + run | Exit 1; Step Summary con CVE-2022-42889 | pendiente | pendiente |
| QG-02 | quality-gate | `test_semgrep_error_bloquea`, `test_codeql_alta_bloquea` | unittest | Exit 1 | pendiente | pendiente |
| QG-03 | quality-gate | `test_hallazgos_menores_no_bloquean` | unittest | Exit 0 | pendiente | pendiente |
| QG-04 | quality-gate | `test_spotbugs_security_bloquea` | unittest | Exit 1 | pendiente | pendiente |
| QG-05 | quality-gate | `test_dc_suprimido_no_bloquea` | unittest | Exit 0 + listado "suprimido" | pendiente | pendiente |
| QG-06 | quality-gate | `test_reporte_faltante_fail_closed` | unittest | Exit 2 | pendiente | pendiente |
| QG-07 | quality-gate | `test_reporte_corrupto_fail_closed` | unittest | Exit 2 | pendiente | pendiente |
| QG-08 | quality-gate | `test_job_fallido_bloquea` | unittest | Exit 1 | pendiente | pendiente |
| QG-09 | quality-gate | `test_job_requerido_skipped_bloquea` | unittest | Exit ≠ 0 | pendiente | pendiente |
| QG-10 | quality-gate | `test_push_feature_no_exige_dc` + run push | unittest + run | Exit según hallazgos, sin "reporte faltante" de DC | pendiente | pendiente |
| QG-11 | quality-gate | Run ROJO | run | Captura del Step Summary con veredicto BLOQUEADO | pendiente | pendiente |
| QG-12 | quality-gate | `test_reportes_limpios_aprueban` + run final | unittest + run | Exit 0; veredicto APROBADO | pendiente | pendiente |
| QG-13 | quality-gate | `python3 -m unittest discover -s .github/scripts/tests -v` | unittest | `evidencias/locales/unittest_gate.txt` | pendiente | pendiente |
| QG-14 | quality-gate | Gate local antes/después | local | `evidencias/locales/{antes,despues}/quality_gate.md` con exit 1/0 | pendiente | pendiente |
| BP-01 | branch-protection | `gh api .../rulesets/<id>` | api | `evidencias/pipeline/ruleset.json` + captura Settings → Rules (manual) | pendiente | pendiente |
| BP-02 | branch-protection | `gh pr view 1 --json mergeStateStatus` | api | `BLOCKED` + captura "Merging is blocked" (manual) | pendiente | pendiente |
| BP-03 | branch-protection | `gh pr merge 1 --merge` | api | Mensaje de rechazo | pendiente | pendiente |
| BP-04 | branch-protection | Merge del PR #1 tras remediar | api | `mergeStateStatus=CLEAN`, PR MERGED | pendiente | pendiente |
| BP-05 | branch-protection | PR #3 de regresión | run + api | Gate failure, `BLOCKED`, PR cerrado | pendiente | pendiente |
| BP-06 | branch-protection | `git push origin HEAD:main` | api | Mensaje "repository rule violations" | pendiente | pendiente |
| BP-07 | branch-protection | Force-push y borrado de `develop` | api | Mensajes de rechazo | pendiente | pendiente |
| CD-01 | container-delivery | `docker build -t lab3:local .` | docker | Log del build exit 0 | pendiente | pendiente |
| CD-02 | container-delivery | `docker run --rm --entrypoint id lab3:local` | docker | `uid` distinto de 0 | pendiente | pendiente |
| CD-03 | container-delivery | `docker inspect` health | docker | `healthy` | pendiente | pendiente |
| CD-04 | container-delivery | Escaneo de imagen en CI/CD | run | `reporte-trivy-imagen`; push omitido si HIGH/CRITICAL | pendiente | pendiente |
| CD-05 | container-delivery | CI/CD en `main` | run + api | Paquete GHCR con etiquetas `sha-*`, `main`, `latest` | pendiente | pendiente |
| CD-06 | container-delivery | CI/CD en `develop` | run | Paso push `skipped` | pendiente | pendiente |
| CD-07 | container-delivery | Nightly | run | Reporte de imagen sin push | pendiente | pendiente |
