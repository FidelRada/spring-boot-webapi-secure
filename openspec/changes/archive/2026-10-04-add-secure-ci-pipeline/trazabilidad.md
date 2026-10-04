# Trazabilidad: add-secure-ci-pipeline

Matriz escenario → prueba → evidencia → figura del informe. Columnas *Estado* y *Figura* completadas en la fase 7 (auditoría de pruebas, 2026-10-04). *Figura* usa los identificadores F-xx de `evidencias/indice_evidencias.md` (carpeta del laboratorio); el informe SOE puede renumerarlos. Estados: **OK** (verificado en local), **OK (E2E GitHub)** (verificado en los runs del fork) y **OK por configuración** (BP-03, BP-06, BP-07: ruleset efectivo sin bypass + PR bloqueados; la prueba activa no se ejecutó por política de seguridad del asistente). Numeración real de PR: #1 Dependabot, **#2** PR del laboratorio, #3 verificación temporal E-01, #4 develop → main, **#5** regresión.

Tipos de prueba: **unittest** (gate en Python), **local** (escaneo local con `herramientas/escaneo_local.sh`), **run** (ejecución de GitHub Actions), **api** (`gh api`/`gh pr`), **docker** (comandos Docker locales), **lint** (actionlint/grep), **revisión** (inspección de archivos).

| ID | Capability | Prueba | Tipo | Evidencia esperada | Figura | Estado |
|---|---|---|---|---|---|---|
| CIW-01 | ci-workflows | Push a `feature/lab3-ci-seguro` | run | `evidencias/pipeline/<runId>_ci-push/` + captura de la lista de jobs | F-34, F-44 | OK (E2E GitHub) |
| CIW-02 | ci-workflows | Abrir el PR del laboratorio (#2) → `develop` | run | Run `pull_request` con job Dependency-Check | F-35 | OK (E2E GitHub) |
| CIW-03 | ci-workflows | Merge del PR #2 (→ `develop`) y del PR #4 (`develop` → `main`) | run | Runs CI/CD en `develop` y `main` | F-51, F-51b, F-51c | OK (E2E GitHub) |
| CIW-04 | ci-workflows | `gh workflow run ci-sec-nightly.yml --ref main` | run | Run `workflow_dispatch` en success | F-43, F-52 | OK (E2E GitHub) |
| CIW-05 | ci-workflows | Inspección de `on.schedule` (`'55 20 * * *'` + `timezone: America/La_Paz`) + actionlint 1.7.12 | lint | Fragmento YAML + salida actionlint (prueba positiva/negativa de la auditoría en `evidencias/auditoria/`) | F-29, F-52 | OK |
| CIW-06 | ci-workflows | `ls .github/workflows` + grep `uses: ./.github/workflows/security-scans.yml` | revisión | Listado de archivos | F-30, F-45 | OK |
| CIW-07 | ci-workflows | `actionlint` en Docker | lint | `evidencias/locales/pruebas/actionlint.txt` vacío, exit 0 | F-29 | OK |
| CIW-08 | ci-workflows | grep de anulaciones | lint | Salida vacía | F-30 | OK |
| CIW-09 | ci-workflows | grep `java-version` + log de setup-java | run | Log con "Java 21" | F-30, F-34 | OK (E2E GitHub) |
| CIW-10 | ci-workflows | Runs sin "Unable to resolve action" | run | Runs completos | F-34, F-41 | OK (E2E GitHub) |
| CIW-11 | ci-workflows | Revisión de bloques `permissions` | revisión | Tabla de permisos en el informe | F-30, F-51b | OK (E2E GitHub) |
| CIW-12 | ci-workflows | `gh api .../commits/<sha>/check-runs` | api | `evidencias/pipeline/check-runs_<sha>.json` | F-38, F-39 | OK (E2E GitHub) |
| CIW-13 | ci-workflows | Dos push seguidos a la rama feature | run | Primer run `cancelled` | F-53 | OK (E2E GitHub) |
| CIW-14 | ci-workflows | `mvn -B clean verify` local sobre ROJO + job Build & Test | local + run | `evidencias/locales/antes/maven/mvn_verify.log` y `pruebas/mvn_verify_rojo.txt` (BUILD SUCCESS, 2 tests) + job success | F-02, F-19, F-34 | OK (E2E GitHub) |
| CIW-15 | ci-workflows | `gh run download` de cada run citado | api | `evidencias/pipeline/<runId>_<wf>/` + `indice_evidencias.md` | F-47 | OK (E2E GitHub) |
| SAST-01 | sast-scanning | Semgrep sobre commit ROJO | local + run | `semgrep.sarif` con `lab-java-sql-concatenation` | F-04, F-05, F-35 | OK (E2E GitHub) |
| SAST-02 | sast-scanning | Inspección del comando Semgrep | revisión | Fragmento YAML/script con `--metrics=off` | F-30 | OK |
| SAST-03 | sast-scanning | CodeQL en run de CI | run | `reporte-codeql/*.sarif` con `java/sql-injection` | F-27, F-46 | OK (E2E GitHub) |
| SAST-08 | sast-scanning | CodeQL en run `pull_request` sobre el ROJO, sin diff-informed | run | `reporte-codeql/codeql.sarif` del PR con los mismos bloqueantes que el push; `quality_gate.md` | F-46b, F-46c | OK (E2E GitHub) |
| SAST-04 | sast-scanning | SpotBugs 4.9.8.5 + FindSecBugs 1.14.0 | local + run | `spotbugsXml.xml` con `SQL_INJECTION_SPRING_JDBC` (p2) y `SPRING_CSRF_PROTECTION_DISABLED` (p1); ya observado en la auditoría | F-06, F-07 | OK (E2E GitHub) |
| SAST-05 | sast-scanning | `gh api .../code-scanning/alerts` | api | JSON de alertas + captura Security → Code scanning (manual) | F-46 | OK (E2E GitHub) |
| SAST-06 | sast-scanning | `escaneo_local.sh antes` | local | `evidencias/locales/antes/semgrep.*`, `spotbugsXml.xml` | F-04, F-06 | OK |
| SAST-07 | sast-scanning | Run de CI ROJO | run | Escáneres success, gate failure | F-13, F-34, F-40 | OK (E2E GitHub) |
| SCA-01 | sca-scanning | CycloneDX local | local | `evidencias/locales/antes/bom.json` con commons-text 1.9 | F-11 | OK |
| SCA-02 | sca-scanning | Trivy SBOM local y en run | local + run | `sca-report.json` con CVE-2022-42889 CRITICAL | F-11, F-36 | OK (E2E GitHub) |
| SCA-03 | sca-scanning | Job Dependency-Check en PR/CI-CD/nightly | run | Artifact `reporte-dependency-check` (HTML/JSON/SARIF) | F-35, F-47 | OK (E2E GitHub) |
| SCA-04 | sca-scanning | `git grep` de la clave + log del job | revisión | Salida vacía; secreto enmascarado `***` | F-30, F-49, F-50 | OK (E2E GitHub) |
| SCA-05 | sca-scanning | Carga del archivo de supresiones | local + run | Log DC sin error de parseo | F-10, F-41 | OK (E2E GitHub) |
| SCA-06 | sca-scanning | DC local "antes" | local | `evidencias/locales/antes/dependency-check-report.html` | F-08 | OK |
| SCA-07 | sca-scanning | Segunda ejecución DC | run | Log "Cache restored" + duración menor | F-48, F-52 | OK (E2E GitHub) |
| SCA-08 | sca-scanning | Revisión de umbrales | revisión | Fragmentos de pom/workflow/gate | F-30 | OK |
| SCA-09 | sca-scanning | Dependabot en la rama predeterminada | api | Captura Insights → Dependabot / PR de Dependabot | F-50 | OK (E2E GitHub) |
| SCA-10 | sca-scanning | `mvn dependency:tree` (completo y `-Dincludes`) | local | `evidencias/locales/antes/dependency-tree.txt` + tabla directa/transitiva | F-03 | OK |
| SCA-11 | sca-scanning | `gh api .../vulnerability-alerts` y `.../automated-security-fixes` | api | 204 / `enabled: true` + captura Settings → Code security (manual) | F-50 | OK (E2E GitHub) |
| SCA-12 | sca-scanning | DC local sin override sobre ROJO | local | `BUILD FAILURE` con `failBuildOnCVSS=7` + `dependency-check-report.html` | F-09 | OK |
| QG-01 | quality-gate | `test_trivy_critical_bloquea`, `test_dc_critical_bloquea` + run ROJO | unittest + run | Exit 1; Step Summary con CVE-2022-42889 | F-12, F-23, F-36 | OK (E2E GitHub) |
| QG-02 | quality-gate | `test_semgrep_error_bloquea`, `test_codeql_alta_bloquea` | unittest | Exit 1 | F-22 | OK |
| QG-03 | quality-gate | `test_hallazgos_menores_no_bloquean` | unittest | Exit 0 | F-22 | OK |
| QG-04 | quality-gate | `test_spotbugs_security_bloquea` (p1 y p2 bloquean, p3 no) | unittest | Exit 1 | F-07, F-23 | OK |
| QG-05 | quality-gate | `test_dc_suprimido_no_bloquea` | unittest | Exit 0 + listado "suprimido" | F-24 | OK |
| QG-06 | quality-gate | `test_reporte_faltante_fail_closed` | unittest | Exit 2 | F-25 | OK |
| QG-07 | quality-gate | `test_reporte_corrupto_fail_closed` | unittest | Exit 2 | F-25 | OK |
| QG-08 | quality-gate | `test_job_fallido_bloquea` | unittest | Exit 1 | F-26 | OK |
| QG-09 | quality-gate | `test_job_requerido_skipped_bloquea` | unittest | Exit ≠ 0 | F-26 | OK |
| QG-10 | quality-gate | `test_push_feature_no_exige_dc` + run push | unittest + run | Exit según hallazgos, sin "reporte faltante" de DC | F-28, F-34, F-41 | OK (E2E GitHub) |
| QG-11 | quality-gate | Run ROJO | run | Captura del Step Summary con veredicto BLOQUEADO | F-36, F-54 | OK (E2E GitHub) |
| QG-12 | quality-gate | `test_reportes_limpios_aprueban` + run final | unittest + run | Exit 0; veredicto APROBADO | F-24, F-41 | OK (E2E GitHub) |
| QG-13 | quality-gate | `python3 -m unittest discover -s .github/scripts/tests -v` | unittest | `evidencias/locales/pruebas/unittest_gate.txt` | F-22 | OK |
| QG-14 | quality-gate | Gate local antes/después | local | `evidencias/locales/{antes,despues}/quality_gate.md` con exit 1/0 | F-12, F-23, F-24 | OK |
| BP-01 | branch-protection | `gh api .../rulesets/<id>` | api | `evidencias/pipeline/ruleset.json` + captura Settings → Rules (manual) | F-38 | OK (E2E GitHub) |
| BP-02 | branch-protection | `gh pr view 2 --json mergeStateStatus` (también #1 Dependabot y #5) | api | `BLOCKED` + captura "Merging is blocked" (manual) | F-37 | OK (E2E GitHub) |
| BP-03 | branch-protection | `gh pr merge 2 --merge` (no ejecutado: OK por configuración) | api | Mensaje de rechazo | F-37, F-54b | OK por configuración |
| BP-04 | branch-protection | Merge del PR #2 tras remediar (y del PR #4) | api | `mergeStateStatus=CLEAN`, PR MERGED | F-42, F-46c, F-55 | OK (E2E GitHub) |
| BP-05 | branch-protection | PR #5 de regresión | run + api | Gate failure, `BLOCKED`, PR cerrado | F-54 | OK (E2E GitHub) |
| BP-06 | branch-protection | `git push origin HEAD:main` | api | Mensaje "repository rule violations" (no ejecutado: OK por configuración; reglas efectivas) | F-54b | OK por configuración |
| BP-07 | branch-protection | Force-push y borrado de `develop` | api | Mensajes de rechazo | F-54b | OK por configuración |
| CD-01 | container-delivery | `docker build -t lab3:local .` | docker | Log del build exit 0 | F-14 | OK |
| CD-02 | container-delivery | `docker run --rm --entrypoint id lab3:local` | docker | `uid` distinto de 0 | F-15, F-56 | OK |
| CD-03 | container-delivery | `docker inspect` health | docker | `healthy` | F-15, F-56 | OK |
| CD-04 | container-delivery | Escaneo de imagen en CI/CD | run | `reporte-trivy-imagen`; push omitido si HIGH/CRITICAL | F-16, F-17, F-51b | OK |
| CD-05 | container-delivery | CI/CD en `main` | run + api | Paquete GHCR con etiquetas `sha-*`, `main`, `latest` | F-51b, F-56 | OK (E2E GitHub) |
| CD-06 | container-delivery | CI/CD en `develop` | run | Paso push `skipped` | F-51 | OK (E2E GitHub) |
| CD-07 | container-delivery | Nightly | run | Reporte de imagen sin push | F-43, F-52 | OK (E2E GitHub) |
| CD-08 | container-delivery | `test_trivy_imagen_os_sin_fix_no_bloquea` + SARIF completo en Code scanning | unittest + run | Exit 0 con CVE de SO sin fix; visible en SARIF | F-16, F-22, F-43, F-46 | OK (E2E GitHub) |
