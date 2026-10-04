# Trazabilidad: remediate-app-vulnerabilities

Matriz escenario → prueba → evidencia → figura del informe. *Estado* y *Figura* completados en la fase 7 (identificadores F-xx de `evidencias/indice_evidencias.md`, carpeta del laboratorio). El PR del laboratorio es el **#2** (el #1 lo abrió Dependabot).

Tipos: **MockMvc** (`SecurityRemediationTests`), **curl** (`herramientas/e2e_curl.sh` contra la app en `:8080`, antes = commit ROJO, después = HEAD), **local** (escaneo local), **run** (GitHub Actions), **revisión**.

| ID | Requisito | Prueba | Tipo | Evidencia esperada (antes → después) | Figura | Estado |
|---|---|---|---|---|---|---|
| APP-01 | SQLi | `busquedaConPayloadSqlNoDevuelveCatalogo` + `curl '...search?name=%27%20OR%20%271%27%3D%271'` | MockMvc + curl | 3 productos → `[]` | F-18, F-31, F-32 | OK |
| APP-02 | SQLi | `busquedaLegitimaDevuelveLaptop` | MockMvc | 1 producto en ambos | F-18 | OK |
| APP-03 | SQLi | `comillaAisladaNoProvocaError` | MockMvc + curl | 500 → 200 `[]` | F-18, F-31, F-32 | OK |
| APP-04 | XSS | `previewEscapaScript` + curl con `<script>` | MockMvc + curl | `<script>` literal → `&lt;script&gt;` | F-18, F-31, F-32 | OK |
| APP-05 | XSS | `previewIncluyeCabecerasDeDefensa` | MockMvc + curl `-I` | sin CSP → CSP + nosniff | F-18, F-32 | OK |
| APP-06 | Authz | `adminAnonimoRecibe401` + curl sin credenciales | MockMvc + curl | 200 con datos → 401 | F-18, F-31, F-32, F-56 | OK |
| APP-07 | Authz | `adminConRolUserRecibe403` | MockMvc + curl `-u ana:...` | 200 → 403 | F-18, F-32, F-56 | OK |
| APP-08 | Authz | `adminConRolAdminRecibe200` | MockMvc + curl `-u admin:...` | 200 → 200 (autenticado) | F-18, F-32, F-56 | OK |
| APP-09 | Authz | `adminIdInexistenteRecibe404` | MockMvc | 500 con trace → 404 | F-18, F-31, F-32 | OK |
| APP-10 | Denegación por defecto | `rutaNoDeclaradaExigeAutenticacion` | MockMvc | 404 público → 401 | F-18 | OK |
| APP-11 | CSRF | `postSinTokenCsrfRecibe403` + curl sin token | MockMvc + curl | 200 → 403 | F-18, F-31, F-32 | OK |
| APP-12 | CSRF | `postConTokenCsrfRecibe200` + curl con `/api/csrf` | MockMvc + curl | n/a → 200 | F-18, F-32 | OK |
| APP-13 | Login | `loginValidoNoDevuelveSecreto` | MockMvc + curl | `token: devsecops-lab-secret…` → sin `token` | F-18, F-31, F-32 | OK |
| APP-14 | Login | `passwordHardcodeadaYaNoFunciona` (con token CSRF) | MockMvc + curl | 200 → 401 | F-18, F-31, F-32 | OK |
| APP-15 | Logs | `logNoContienePasswordNiSaltos` (OutputCapture) | MockMvc | password en log → ausente | F-18 | OK |
| APP-16 | Secretos | `git grep` + Semgrep `p/secrets`/`lab-hardcoded-secret` | local | hallazgos → 0 | F-04, F-30 | OK |
| APP-17 | Configuración | `actuatorSoloExponeHealth` + curl `/actuator/env` | MockMvc + curl | env visible → 401/404; health UP | F-18, F-31, F-32 | OK |
| APP-18 | Configuración | `consolaH2Deshabilitada` + curl `/h2-console` | MockMvc + curl | consola → 401/404 | F-18, F-31, F-32 | OK |
| APP-19 | Configuración | `erroresSinStacktrace` (`RANDOM_PORT` + `TestRestTemplate`) + curl | SpringBootTest + curl | `trace` presente → ausente; código 404/400 (no 401) | F-18, F-31, F-32 | OK |
| APP-20 | Dependencias | Trivy SBOM + DC local y en run | local + run | CVE-2022-42889 CRITICAL → ausente | F-08, F-10, F-11, F-16 | OK (E2E GitHub) |
| APP-21 | Dependencias | `quality_gate.py` sobre reportes SCA + revisión de supresiones | local + run | bloqueantes → 0; umbral 7.0 intacto | F-12, F-41 | OK (E2E GitHub) |
| APP-22 | Dependencias | Revisión de `evidencias/sca/comparacion.md` | revisión | Documento completo | — (`evidencias/sca/comparacion.md`), F-50 | OK (E2E GitHub) |
| APP-23 | Regresión | `mvn -B clean verify` + run CI del PR #2 | MockMvc + run | ≥ 8 pruebas OK; Quality Gate failure → success | F-18, F-19, F-20, F-21, F-42 | OK (E2E GitHub) |
