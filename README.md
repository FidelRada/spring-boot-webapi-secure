# Spring Boot DevSecOps Lab

Aplicacion deliberadamente vulnerable para prácticas controladas de SAST, SCA,
secret scanning, análisis de contenedores y DAST.

> **Advertencia:** ejecutar únicamente en `localhost` o en una red de laboratorio
> aislada. No desplegar en Internet ni reutilizar credenciales reales.

## Requisitos

- JDK 21
- Maven 3.9+
- Docker, opcional
- Semgrep, para el análisis local

## Iniciar la aplicación

```bash
mvn clean verify
mvn spring-boot:run
```

La aplicación estará disponible en `http://localhost:8080`.

## Endpoints del laboratorio

```text
GET  /api/products/search?name=Laptop
POST /api/comments/preview
GET  /api/admin/users/1
POST /api/auth/login
```

Ejemplo para la vista previa:

```bash
curl -X POST http://localhost:8080/api/comments/preview \
  -H "Content-Type: application/json" \
  -d '{"comment":"Comentario de prueba"}'
```

Ejemplo de autenticación:

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"usuario","password":"prueba"}'
```

## CI seguro (SAST, SCA y Quality Gate)

La batería de seguridad está en un único workflow reutilizable,
`.github/workflows/security-scans.yml`, que invocan tres callers:

| Workflow | Disparadores | Dependency-Check | Imagen |
|---|---|---|---|
| `ci-sec.yml` | push a `feature/**`, `bugfix/**`, `hotfix/**`; PR a `main`/`develop` | solo en PR | no |
| `ci-cd-sec.yml` | push a `main`/`develop` | sí | build + Trivy; push a GHCR solo en `main` |
| `ci-sec-nightly.yml` | diario 20:55 `America/La_Paz` y `workflow_dispatch` | sí | build + Trivy, sin push |

Jobs: Build & Test, SAST - Semgrep, SAST - CodeQL, SAST - SpotBugs + FindSecBugs,
SCA - SBOM y vulnerabilidades (CycloneDX + Trivy), SCA - OWASP Dependency-Check y
**Quality Gate**. Los escáneres solo fallan por errores técnicos; el gate
(`.github/scripts/quality_gate.py`, con pruebas en `.github/scripts/tests/`) **lee los
reportes** y bloquea si encuentra:

- Semgrep: resultado con nivel `error`.
- CodeQL: regla con `security-severity` ≥ 7.0.
- SpotBugs + FindSecBugs: categoría `SECURITY` con prioridad ≤ 2.
- Dependency-Check: CVSS ≥ 7.0 o severidad HIGH/CRITICAL (no cuenta las suprimidas).
- Trivy (SBOM e imagen): HIGH o CRITICAL.

Es *fail-closed*: un reporte requerido que falta o no se puede leer hace fallar el gate
(código 2). Los merges a `main` y `develop` exigen el check `Quality Gate` mediante el
ruleset `.github/rulesets/proteger-main-develop.json`.

### Secreto de la NVD

Dependency-Check lee la clave de la API de la NVD de la variable de entorno
`NVD_API_KEY` (`<nvdApiKeyEnvironmentVariable>` en `pom.xml`). En GitHub es el secreto
`NVD_API_KEY` (también para Dependabot); nunca se escribe en archivos versionados.
La telemetría se desactiva con `DO_NOT_TRACK=true` (Dependency-Check) y
`--metrics=off` (Semgrep).

### Comandos locales (los mismos que el pipeline)

```bash
mvn -B clean verify

# Semgrep (sin --config auto, que exige métricas)
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD:/src" -w /src \
  semgrep/semgrep:1.179.0 semgrep scan --metrics=off \
  --config p/java --config p/owasp-top-ten --config p/secrets --config .semgrep.yml \
  --sarif-output=semgrep.sarif --json-output=semgrep.json src/main/java

# OWASP Dependency-Check: en local falla con CVSS >= 7 (dc.failBuildOnCVSS=7)
export NVD_API_KEY=...          # solo en el entorno, nunca en archivos
DO_NOT_TRACK=true mvn -B org.owasp:dependency-check-maven:check

# SpotBugs + FindSecBugs
mvn -B compile com.github.spotbugs:spotbugs-maven-plugin:spotbugs

# SBOM CycloneDX + Trivy
mvn -B org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom
docker run --rm -v "$PWD/target:/work" -v devsecops-trivy-cache:/root/.cache/trivy \
  aquasec/trivy:0.74.0 sbom --scanners vuln --exit-code 0 \
  --format json --output /work/sca-report.json /work/bom.json

# Quality Gate sobre una carpeta con los reportes
python3 -m unittest discover -s .github/scripts/tests -v
python3 .github/scripts/quality_gate.py --reports-dir <carpeta> \
  --required semgrep,spotbugs,trivy,dependency-check

# Validar los workflows
docker run --rm -v "$PWD:/repo" -w /repo rhysd/actionlint:1.7.12
```

En el pipeline, Dependency-Check se ejecuta con `-Ddc.failBuildOnCVSS=11` solo para que el
plugin escriba siempre los reportes completos; el umbral CVSS ≥ 7.0 lo aplica el Quality Gate.

El docente dispone de `docs/GUIA-DOCENTE.md`, que contiene el catálogo de
hallazgos y las pruebas sugeridas. Se recomienda entregar inicialmente a los
estudiantes el resto del repositorio sin dicho documento.
