# Comparación del análisis SCA

Plantilla de la guía 02 §13, completada para el Laboratorio 3 (change
`remediate-app-vulnerabilities`, escenario APP-22). Los datos de los runs de GitHub Actions
se completaron en la fase 6 (E2E en GitHub, 2026-10-04).

## Identificación

- Autor: Andrés Fidel Rada Rojas (trabajo individual)
- Repositorio: https://github.com/FidelRada/spring-boot-webapi-secure (fork de `pablovillazon/spring-boot-webapi-secure`)
- Commit anterior: `8acb79d` (ROJO_FINAL publicado: pipeline `1a9980a` + fix de auditoría `442fd98`/`8acb79d`, mismo `src/` y `pom.xml` que `1a9980a`)
- Commit posterior: `cc5f4cc` (HEAD de `feature/lab3-ci-seguro`; la corrección SCA es `c0fe5cf` — `fix(deps): commons-text 1.10.0 y CVE transitivos`)
- Ejecución anterior: run `pull_request` [37226787496](https://github.com/FidelRada/spring-boot-webapi-secure/actions/runs/37226787496) (gate en failure) y run `push` [37226599366](https://github.com/FidelRada/spring-boot-webapi-secure/actions/runs/37226599366)
- Ejecución posterior: run `pull_request` [37227469858](https://github.com/FidelRada/spring-boot-webapi-secure/actions/runs/37227469858) (gate en success), run `push` [37227467114](https://github.com/FidelRada/spring-boot-webapi-secure/actions/runs/37227467114) y nightly [37227684557](https://github.com/FidelRada/spring-boot-webapi-secure/actions/runs/37227684557)
- Pull request: [PR #2](https://github.com/FidelRada/spring-boot-webapi-secure/pull/2) `feature/lab3-ci-seguro` → `develop` (el #1 lo abrió Dependabot: `commons-text` 1.9 → 1.10.0 hacia `main`)
- Versión de Trivy: 0.74.0 (`aquasec/trivy:0.74.0`, por Docker); OWASP Dependency-Check 13.0.0 (NVD); CycloneDX Maven Plugin 2.9.3 (schema 1.6)
- Fecha y hora de los análisis locales: 2026-10-04, 13:23 (antes, regenerado desde un `git worktree` del commit `1a9980a`, mismo código que `8acb79d`) y 13:18 (después, commit `89e8155` = `d8eed4c`, mismo código que `cc5f4cc`). Runs de GitHub: 2026-10-04, entre 15:01 y 15:21, America/La_Paz

## Hallazgo seleccionado

| Campo | Antes | Después |
|---|---|---|
| Componente | `org.apache.commons:commons-text` | `org.apache.commons:commons-text` |
| Versión resuelta | 1.9 | 1.10.0 |
| CVE seleccionado | CVE-2022-42889 (Text4Shell, interpolación de variables → RCE) | CVE-2022-42889 |
| Severidad reportada | CRITICAL (Trivy/GHSA); CVSS v3.1 9.8 (Dependency-Check/NVD) | — |
| Presencia del hallazgo | Sí: Trivy SBOM y Dependency-Check (`BUILD FAILURE` con `failBuildOnCVSS=7`) | No: ausente en Trivy y en Dependency-Check |
| Estado del quality gate | Rojo: `quality_gate.py` local exit 1 (80 bloqueantes, 23 de Trivy y 47 de DC); run del PR 37226787496: **failure**, 81 bloqueantes (Trivy 23, DC 47) | Verde en SCA: Trivy 0 HIGH/CRITICAL, DC `BUILD SUCCESS` sin override; gate local completo en `evidencias/locales/despues/`; run del PR 37227469858: **success**, 0 bloqueantes (DC 8 no bloqueantes y 15 suprimidos; Trivy 1 MEDIUM) |

Resumen de Trivy sobre el SBOM (local):

| Severidad | Antes (commit ROJO) | Después |
|---|---|---|
| CRITICAL | 7 | 0 |
| HIGH | 16 | 0 |
| MEDIUM | 23 | 1 |
| LOW | 5 | 0 |

## Análisis

1. **¿La dependencia era directa o transitiva?**
   Directa: `mvn dependency:tree` muestra `org.apache.commons:commons-text:jar:1.9:compile` declarada en el `pom.xml` (caso didáctico de la guía 02 §7). Los demás HIGH/CRITICAL eran transitivos, heredados de Spring Boot 3.5.14: `tomcat-embed-core` 10.1.54, `jackson-core`/`jackson-databind` 2.21.2, `micrometer-core` 1.15.11, `spring-webmvc`/`spring-expression` 6.2.18 y `log4j-api` 2.24.3.

2. **¿Qué cambio se realizó y por qué?**
   - `commons-text` 1.9 → 1.10.0, la primera versión corregida (aviso de Apache Commons Text).
   - Parent `spring-boot-starter-parent` 3.5.14 → 3.5.16 (spring 6.2.19, micrometer 1.15.12) y las propiedades gestionadas `tomcat.version=10.1.60`, `jackson-bom.version=2.21.7` y `log4j2.version=2.25.5`, porque el parent 3.5.16 todavía trae tomcat 10.1.55, jackson 2.21.4 y log4j 2.24.3, que siguen siendo vulnerables.
   - Ningún umbral cambió: Trivy sigue sin `--ignore-unfixed`, DC sigue con `failBuildOnCVSS=7` y el gate con CVSS ≥ 7.0 / HIGH / CRITICAL.

3. **¿Qué pruebas se ejecutaron para verificar compatibilidad?**
   `mvn -B clean verify` con 24 pruebas en verde: las 2 originales (una ajustada a 401), 17 de `SecurityRemediationTests`, 2 de `ErroresSinStacktraceTests` y 3 de `config/RegistroUsuariosTests` (añadidas en la auditoría de ejecución, commit `bd0019e`, antes `8c7d9f7`). Además, arranque local de la aplicación y los comandos curl del README (CSRF, HTTP Basic, actuator, H2).

4. **¿Qué evidencia muestra que desapareció el hallazgo seleccionado?**
   - `evidencias/locales/antes/sbom-trivy/sca-report.json` contiene CVE-2022-42889 y `evidencias/locales/despues/sbom-trivy/sca-report.json` no lo contiene (carpeta del laboratorio).
   - `bom.json` posterior declara `pkg:maven/org.apache.commons/commons-text@1.10.0`.
   - Dependency-Check local pasa de `BUILD FAILURE` (CVE-2022-42889, 9.8) a `BUILD SUCCESS`.
   - Los artifacts `reporte-trivy-sbom` y `reporte-dependency-check` de ambos runs están descargados en `evidencias/pipeline/37226787496_ci_pull_request_rojo/` y `evidencias/pipeline/37227469858_ci_pull_request_verde/` (carpeta del laboratorio). Además, Dependabot abrió una alerta crítica (CVE-2022-42889) sobre `main` y el PR #1 con la misma corrección.

5. **¿Qué otros hallazgos o limitaciones quedan pendientes?**
   - **Spring sin versión OSS corregida.** Dependency-Check, por CPE, reporta 12 CVE de Spring Framework 6.2.0–6.2.19 y 3 de Spring Security 6.5.0–6.5.11. Las versiones corregidas (6.2.20 y 6.5.12) no están publicadas en Maven Central: la línea Spring Boot 3.5 ya no tiene soporte OSS. Ninguno aplica a esta aplicación: afectan a WebFlux, RSocket, Jetty, XsltView, SSE, SpEL con entrada del usuario, data binding de rutas de propiedades, LDAP embebido, DPoP o WebAuthn, que la app no usa ni tiene en el classpath. Trivy (GHSA) no los reporta. Se suprimieron uno a uno en `dependency-check-suppressions.xml`, con justificación en `<notes>` y `until="2026-12-31Z"`. Al vencer vuelven a bloquear. La solución definitiva es migrar a Spring Boot 4.x (Framework 7 / Security 7), fuera del alcance del laboratorio.
   - `commons-lang3` 3.17.0, CVE-2025-48924: MEDIUM, no bloquea según la política; se corrige en 3.18.0.
   - Los resultados dependen de la fecha: la base de vulnerabilidades cambia aunque el código no cambie.

## Seguimiento tras el merge (fases 6b y 7, 2026-10-04)

- **Promoción:** PR #2 → `develop` (`75fa4eb`) y PR #4 `develop` → `main` (`8e01f3d`), fusionados por el autor.
- **CI/CD `develop`:** run [37231215444](https://github.com/FidelRada/spring-boot-webapi-secure/actions/runs/37231215444), success; imagen construida y escaneada con Trivy, publicación en GHCR `skipped` (solo `main` publica).
- **CI/CD `main`:** run [37232239081](https://github.com/FidelRada/spring-boot-webapi-secure/actions/runs/37232239081), success; gate de la imagen APROBADO (Trivy en 2 pasadas: SO con `--ignore-unfixed`, librerías sin él) y publicación de `ghcr.io/fidelrada/spring-boot-webapi-secure` con las etiquetas `main`, `latest` y `sha-8e01f3d`, digest `sha256:1a38c5702a2315825b23f3d38b9ee4d8ca01f1e03761b1a954ce33c30c66fe8d`.
- **Nightly en `main`:** run [37232685268](https://github.com/FidelRada/spring-boot-webapi-secure/actions/runs/37232685268), success, con las cachés de Dependency-Check y Trivy restauradas.
- **Dependabot:** la alerta #1 (CVE-2022-42889, crítica) pasó a `fixed` el 2026-10-04T20:28:41Z, al llegar `commons-text` 1.10.0 a `main`; Dependabot cerró su PR #1 («up-to-date now»).
- **Code scanning en `main`:** 11 alertas abiertas (Semgrep 1 warning, Trivy 2 medium/note, dependency-check 8 medium/low); ninguna alcanza el umbral del gate.
- **Re-ejecución (fase 7):** la imagen publicada `sha-8e01f3d` arranca `healthy` como `uid=100(spring)` y supera los 19 controles E2E con curl.

### Equivalencias de SHA

Los análisis locales se hicieron antes del reorden de la historia (fase 6). Los commits citados equivalen a los publicados así: `1a9980a` = mismo `src/`, `pom.xml` y `.semgrep.yml` que ROJO_FINAL `8acb79d`; `89e8155` → `d8eed4c` (mismo código que `cc5f4cc`); `8c7d9f7` → `bd0019e`; `ac51ff1` → `442fd98`; `e437c2d` → `8acb79d`.
