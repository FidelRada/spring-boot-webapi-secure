# Spec Delta: ci-workflows

## Purpose

Define cuándo y cómo se ejecutan los workflows de seguridad (CI, CI/CD y nightly) en GitHub Actions, garantizando que ningún control quede anulado y que todos compartan la misma batería de análisis.

## ADDED Requirements

### Requirement: CI en ramas de trabajo
El workflow CI SHALL ejecutarse en cada push a `feature/**`, `bugfix/**` y `hotfix/**`, y en cada pull request dirigido a `main` o `develop`, invocando la batería completa de análisis y el Quality Gate.

#### Scenario: CIW-01 Push a una rama feature dispara CI
- **WHEN** se hace push de un commit a `feature/lab3-ci-seguro`
- **THEN** GitHub Actions crea un run del workflow CI con evento `push` que incluye los jobs Build & Test, Semgrep, CodeQL, SpotBugs, SBOM + Trivy y Quality Gate

#### Scenario: CIW-02 Pull request a develop o main dispara CI con Dependency-Check
- **WHEN** se abre o sincroniza un pull request desde `feature/lab3-ci-seguro` hacia `develop`
- **THEN** se crea un run del workflow CI con evento `pull_request` que además incluye el job OWASP Dependency-Check

### Requirement: CI/CD en ramas de integración
El workflow CI/CD SHALL ejecutarse en cada push a `main` y `develop` (y solo en ellas), aplicar la misma batería de análisis con Dependency-Check y, si el Quality Gate aprueba, construir y escanear la imagen de contenedor.

#### Scenario: CIW-03 Push a develop o main dispara CI/CD
- **WHEN** se fusiona un pull request en `develop` o en `main`
- **THEN** se crea un run del workflow CI/CD con evento `push` sobre esa rama, con Dependency-Check y el job de imagen que depende del Quality Gate

### Requirement: Nightly con SCA
El workflow nightly SHALL ejecutarse todos los días a las 20:55 hora de Bolivia (America/La_Paz, UTC-4, equivalente a `55 0 * * *` UTC) y bajo demanda (`workflow_dispatch`), incluyendo OWASP Dependency-Check y el escaneo de la imagen sin publicarla.

#### Scenario: CIW-04 Ejecución manual del nightly
- **WHEN** se ejecuta `gh workflow run ci-sec-nightly.yml --ref main`
- **THEN** se crea un run con evento `workflow_dispatch` que incluye Dependency-Check, SBOM + Trivy, los SAST y el Quality Gate, y termina en `success` sobre el código remediado

#### Scenario: CIW-05 Programación del nightly
- **WHEN** se inspecciona el bloque `on.schedule` del workflow nightly
- **THEN** la expresión cron equivale a las 20:55 de America/La_Paz y `actionlint` no reporta errores sobre ella

### Requirement: Batería centralizada en un workflow reutilizable
Los análisis SHALL definirse una sola vez en un workflow reutilizable (`workflow_call`) invocado por CI, CI/CD y nightly; no SHALL existir workflows de seguridad duplicados ni sintácticamente inválidos.

#### Scenario: CIW-06 Un único origen de los jobs de seguridad
- **WHEN** se listan los archivos de `.github/workflows/`
- **THEN** existen `security-scans.yml`, `ci-sec.yml`, `ci-cd-sec.yml` y `ci-sec-nightly.yml`, no existe `security-semgrep.yml` y los tres callers usan `uses: ./.github/workflows/security-scans.yml`

#### Scenario: CIW-07 Workflows válidos
- **WHEN** se ejecuta `actionlint` sobre `.github/workflows/`
- **THEN** el comando termina con código 0 y sin hallazgos

### Requirement: Ningún control anulado
Los workflows MUST NOT contener `|| true`, `if: false`, `continue-on-error: true` ni umbrales relajados en pasos de análisis o del gate; un escáner solo puede terminar en error por fallos técnicos y la decisión por hallazgos corresponde exclusivamente al Quality Gate.

#### Scenario: CIW-08 Búsqueda de anulaciones
- **WHEN** se ejecuta `grep -nE '\|\| *true|if: *false|continue-on-error: *true' .github/workflows/*.yml`
- **THEN** el comando no devuelve coincidencias

### Requirement: Entorno coherente con el proyecto
Todos los jobs que compilan SHALL usar Java 21 (Temurin) igual que `pom.xml` y el Dockerfile, y las acciones de terceros SHALL fijarse en su versión mayor vigente verificada.

#### Scenario: CIW-09 Java 21 en todos los workflows
- **WHEN** se buscan las definiciones de versión de Java en `.github/workflows/`
- **THEN** todas valen `21` y el log del paso de configuración de Java muestra una JDK 21

#### Scenario: CIW-10 Acciones existentes
- **WHEN** se ejecuta cualquiera de los workflows
- **THEN** ningún paso falla con "Unable to resolve action" ni por una versión inexistente

### Requirement: Permisos mínimos
Cada workflow SHALL declarar `permissions: contents: read` por defecto y conceder permisos adicionales (`security-events: write`, `actions: read`, `packages: write`) solo en los jobs que los necesitan.

#### Scenario: CIW-11 Revisión de permisos
- **WHEN** se inspeccionan los bloques `permissions` de los cuatro workflows
- **THEN** el nivel de workflow es `contents: read` y `packages: write` aparece únicamente en el job que publica la imagen

### Requirement: Checks identificables por evento
Los nombres de los checks SHALL incluir el evento o el workflow de origen, de modo que los runs de `push` y `pull_request` no colisionen y el ruleset pueda exigir un check concreto.

#### Scenario: CIW-12 Nombres de check distintos
- **WHEN** se consultan los check-runs de un commit con `gh api repos/FidelRada/spring-boot-webapi-secure/commits/<sha>/check-runs`
- **THEN** el Quality Gate del pull request y el del push aparecen con nombres distintos (p. ej. `CI (pull_request) / Quality Gate` y `CI (push) / Quality Gate`)

### Requirement: Cancelación de ejecuciones obsoletas
Los callers CI y CI/CD SHALL agrupar las ejecuciones por workflow y referencia y cancelar las que queden obsoletas, salvo el nightly.

#### Scenario: CIW-13 Push consecutivos
- **WHEN** se hacen dos push seguidos a la misma rama `feature/**`
- **THEN** el run del primer push queda `cancelled` y solo el segundo llega al Quality Gate
