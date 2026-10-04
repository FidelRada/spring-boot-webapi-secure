# branch-protection Specification

## Purpose
Impedir que código que no supera el pipeline de seguridad llegue a `main` o `develop`, exigiendo pull request y checks obligatorios mediante un ruleset versionado.

## Requirements

### Requirement: Ruleset versionado y aplicado
El repositorio SHALL versionar `.github/rulesets/proteger-main-develop.json` y aplicarlo con `gh api` como ruleset activo (`enforcement: active`, disponible en repositorios públicos con GitHub Free) sobre `refs/heads/main` y `refs/heads/develop`, sin actores de bypass.

#### Scenario: BP-01 Ruleset activo sin bypass
- **WHEN** se ejecuta `gh api repos/FidelRada/spring-boot-webapi-secure/rulesets/<id>`
- **THEN** la respuesta muestra `enforcement: active`, ambas ramas en `conditions.ref_name.include` y `bypass_actors` vacío

### Requirement: Merge bloqueado si el pipeline falla
El ruleset SHALL exigir pull request (0 aprobaciones) y los status checks del Quality Gate con sus nombres reales; un pull request cuyo Quality Gate no esté en `success` MUST NOT poder fusionarse.

#### Scenario: BP-02 PR ROJO bloqueado
- **WHEN** el PR #1 (`feature/lab3-ci-seguro` → `develop`) tiene el check del Quality Gate en `failure`
- **THEN** `gh pr view 1 --json mergeStateStatus` devuelve `BLOCKED` y la interfaz muestra "Merging is blocked"

#### Scenario: BP-03 Intento de merge rechazado
- **WHEN** se ejecuta `gh pr merge 1 --merge` con el gate en `failure`
- **THEN** GitHub rechaza la operación por required status checks no satisfechos

#### Scenario: BP-04 PR verde fusionable
- **WHEN** tras la remediación todos los checks requeridos del PR están en `success`
- **THEN** `mergeStateStatus` es `CLEAN` y el merge se completa

#### Scenario: BP-05 Regresión bloqueada en main
- **WHEN** el PR #3 (`feature/demo-regresion` → `main`) reintroduce la inyección SQL
- **THEN** su Quality Gate termina en `failure`, el PR queda `BLOCKED` y se cierra sin merge

### Requirement: Historial protegido
El ruleset SHALL impedir el push directo, el borrado y el force-push sobre `main` y `develop`.

#### Scenario: BP-06 Push directo rechazado
- **WHEN** se intenta `git push origin HEAD:main` con un commit que no pasó por pull request
- **THEN** el remoto rechaza el push indicando una violación de la regla del repositorio

#### Scenario: BP-07 Force-push y borrado rechazados
- **WHEN** se intenta `git push --force origin develop` o `git push origin :develop`
- **THEN** el remoto rechaza ambas operaciones
