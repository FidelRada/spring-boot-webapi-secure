# Spring Boot DevSecOps Lab

Aplicación del laboratorio de DevSecOps, inicialmente vulnerable (SQLi, XSS, control de
acceso roto, CSRF, secretos, configuración y dependencias) y remediada con el pipeline de
seguridad de este repositorio (SAST, SCA, quality gate y protección de ramas).

> **Advertencia:** ejecutar únicamente en `localhost` o en una red de laboratorio
> aislada. No desplegar en Internet ni reutilizar credenciales reales.

## Requisitos

- JDK 21
- Maven 3.9+
- Docker, opcional
- Semgrep, para el análisis local

## Iniciar la aplicación

Las credenciales no están en el código: los usuarios `admin` (rol ADMIN) y `ana`
(rol USER) se registran solo si se exporta el hash bcrypt de su contraseña.

```bash
# Generar un hash bcrypt (htpasswd viene en apache2-utils)
export LAB_ADMIN_PASSWORD_HASH="$(htpasswd -bnBC 10 "" 'MiClaveAdmin' | tr -d ':\n')"
export LAB_USER_PASSWORD_HASH="$(htpasswd -bnBC 10 "" 'MiClaveAna' | tr -d ':\n')"
export LAB_EXTERNAL_API_KEY=...   # opcional

mvn clean verify       # las pruebas usan el perfil "test" y no necesitan variables
mvn spring-boot:run
```

Sin esas variables la aplicación arranca igual (el healthcheck no necesita usuarios),
pero `/api/admin/**` y el login no tendrán usuarios válidos.

La aplicación estará disponible en `http://localhost:8080`.

## Endpoints del laboratorio

```text
GET  /api/products/search?name=Laptop   público
POST /api/comments/preview              público, requiere token CSRF
GET  /api/csrf                          público, devuelve el token CSRF y crea la sesión
GET  /api/admin/users/1                 HTTP Basic, rol ADMIN
POST /api/auth/login                    público, requiere token CSRF
GET  /actuator/health                   público
```

Las peticiones `POST` exigen el token CSRF de la sesión:

```bash
TOKEN=$(curl -s -c cookies.txt http://localhost:8080/api/csrf | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')

curl -X POST http://localhost:8080/api/comments/preview \
  -b cookies.txt -H "X-CSRF-TOKEN: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"comment":"Comentario de prueba"}'

curl -X POST http://localhost:8080/api/auth/login \
  -b cookies.txt -H "X-CSRF-TOKEN: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"MiClaveAdmin"}'
```

Administración con HTTP Basic:

```bash
curl -u admin:MiClaveAdmin http://localhost:8080/api/admin/users/2
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
