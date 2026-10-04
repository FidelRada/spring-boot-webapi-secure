# Trazabilidad: remediate-app-vulnerabilities

Matriz escenario → prueba → evidencia → figura del informe. *Figura* se completa en la fase 8; *Estado* en la fase 7.

Tipos: **MockMvc** (`SecurityRemediationTests`), **curl** (`herramientas/e2e_curl.sh` contra la app en `:8080`, antes = commit ROJO, después = HEAD), **local** (escaneo local), **run** (GitHub Actions), **revisión**.

| ID | Requisito | Prueba | Tipo | Evidencia esperada (antes → después) | Figura | Estado |
|---|---|---|---|---|---|---|
| APP-01 | SQLi | `busquedaConPayloadSqlNoDevuelveCatalogo` + `curl '...search?name=%27%20OR%20%271%27%3D%271'` | MockMvc + curl | 3 productos → `[]` | pendiente | pendiente |
| APP-02 | SQLi | `busquedaLegitimaDevuelveLaptop` | MockMvc | 1 producto en ambos | pendiente | pendiente |
| APP-03 | SQLi | `comillaAisladaNoProvocaError` | MockMvc + curl | 500 → 200 `[]` | pendiente | pendiente |
| APP-04 | XSS | `previewEscapaScript` + curl con `<script>` | MockMvc + curl | `<script>` literal → `&lt;script&gt;` | pendiente | pendiente |
| APP-05 | XSS | `previewIncluyeCabecerasDeDefensa` | MockMvc + curl `-I` | sin CSP → CSP + nosniff | pendiente | pendiente |
| APP-06 | Authz | `adminAnonimoRecibe401` + curl sin credenciales | MockMvc + curl | 200 con datos → 401 | pendiente | pendiente |
| APP-07 | Authz | `adminConRolUserRecibe403` | MockMvc + curl `-u ana:...` | 200 → 403 | pendiente | pendiente |
| APP-08 | Authz | `adminConRolAdminRecibe200` | MockMvc + curl `-u admin:...` | 200 → 200 (autenticado) | pendiente | pendiente |
| APP-09 | Authz | `adminIdInexistenteRecibe404` | MockMvc | 500 con trace → 404 | pendiente | pendiente |
| APP-10 | Denegación por defecto | `rutaNoDeclaradaExigeAutenticacion` | MockMvc | 404 público → 401 | pendiente | pendiente |
| APP-11 | CSRF | `postSinTokenCsrfRecibe403` + curl sin token | MockMvc + curl | 200 → 403 | pendiente | pendiente |
| APP-12 | CSRF | `postConTokenCsrfRecibe200` + curl con `/api/csrf` | MockMvc + curl | n/a → 200 | pendiente | pendiente |
| APP-13 | Login | `loginValidoNoDevuelveSecreto` | MockMvc + curl | `token: devsecops-lab-secret…` → sin `token` | pendiente | pendiente |
| APP-14 | Login | `passwordHardcodeadaYaNoFunciona` | MockMvc + curl | 200 → 401 | pendiente | pendiente |
| APP-15 | Logs | `logNoContienePasswordNiSaltos` (OutputCapture) | MockMvc | password en log → ausente | pendiente | pendiente |
| APP-16 | Secretos | `git grep` + Semgrep `p/secrets`/`lab-hardcoded-secret` | local | hallazgos → 0 | pendiente | pendiente |
| APP-17 | Configuración | `actuatorSoloExponeHealth` + curl `/actuator/env` | MockMvc + curl | env visible → 401/404; health UP | pendiente | pendiente |
| APP-18 | Configuración | `consolaH2Deshabilitada` + curl `/h2-console` | MockMvc + curl | consola → 401/404 | pendiente | pendiente |
| APP-19 | Configuración | `erroresSinStacktrace` | MockMvc + curl | `trace` presente → ausente | pendiente | pendiente |
| APP-20 | Dependencias | Trivy SBOM + DC local y en run | local + run | CVE-2022-42889 CRITICAL → ausente | pendiente | pendiente |
| APP-21 | Dependencias | `quality_gate.py` sobre reportes SCA + revisión de supresiones | local + run | bloqueantes → 0; umbral 7.0 intacto | pendiente | pendiente |
| APP-22 | Dependencias | Revisión de `evidencias/sca/comparacion.md` | revisión | Documento completo | pendiente | pendiente |
| APP-23 | Regresión | `mvn -B clean verify` + run CI del PR #1 | MockMvc + run | ≥ 8 pruebas OK; Quality Gate failure → success | pendiente | pendiente |
