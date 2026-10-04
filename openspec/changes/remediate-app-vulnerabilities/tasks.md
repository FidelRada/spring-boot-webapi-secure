# Tasks: remediate-app-vulnerabilities (commits VERDE)

> Requisito previo: change `add-secure-ci-pipeline` aplicado y PR #1 bloqueado (BP-02). Ningún umbral ni control del pipeline se modifica en este change.

## 1. Base de pruebas

- [x] 1.1 Crear `src/test/resources/application-test.properties` con hashes bcrypt de contraseñas de prueba para `admin` y `ana` (documentados como solo de prueba) y `@ActiveProfiles("test")` en las clases de test (no `application.properties`, que ocultaría la configuración principal). Verificar con `env -u LAB_ADMIN_PASSWORD_HASH -u LAB_USER_PASSWORD_HASH mvn -B test` que el contexto arranca sin variables de entorno
- [x] 1.2 Redactar `src/test/java/bo/edu/devsecops/SecurityRemediationTests.java` (`@SpringBootTest`, `@AutoConfigureMockMvc`, `@ActiveProfiles("test")`, `@ExtendWith(OutputCaptureExtension.class)`) con una prueba por escenario APP-01..APP-18. APP-19 va en una clase `RANDOM_PORT` con `TestRestTemplate`. Ejecutarlas sobre el commit ROJO **sin commitearlas** y guardar la salida en `evidencias/locales/antes/tests_seguridad_rojo.txt` (demuestra que detectan la vulnerabilidad). Después, cada commit de la sección 2 a la 6 incorpora solo las pruebas de su familia, para que cada commit compile y pase (D8)

## 2. Inyección SQL

- [x] 2.1 Parametrizar `ProductController.search` con `LIKE ? ESCAPE '\'` y escape de comodines (D1); verificar APP-01, APP-02, APP-03 en verde y que Semgrep ya no reporta `lab-java-sql-concatenation` ni FindSecBugs `SQL_INJECTION_SPRING_JDBC`
- [x] 2.2 Commit `fix(sqli): consulta parametrizada en búsqueda de productos`

## 3. XSS

- [x] 3.1 Añadir `org.owasp.encoder:encoder:1.5.0` y escapar `comment` con `Encode.forHtml` (importado) en una variable antes de `ResponseEntity.ok(html)` en `CommentController.preview` (D2). Verificar APP-04 y que Semgrep ya no reporta `lab-html-without-output-encoding` ni `tainted-html-string`; CodeQL `java/xss` se verifica en el primer run de CI posterior
- [x] 3.2 Commit `fix(xss): codificación de salida en vista previa`

## 4. Autenticación, autorización y CSRF

- [x] 4.1 Crear `LabSecurityProperties` (`lab.security.admin-password-hash`, `lab.security.user-password-hash`) y registrar `@EnableConfigurationProperties`; verificar arranque con y sin variables de entorno
- [x] 4.2 Reescribir `SecurityConfig` (D3, D4): rutas públicas, `dispatcherTypeMatchers(ERROR).permitAll()`, `/api/admin/**` y `/actuator/**` ADMIN, `anyRequest().authenticated()`, `httpBasic`, CSRF activo, CSP, `PasswordEncoder` delegante, `InMemoryUserDetailsManager` y `AuthenticationManager`. Verificar APP-05, APP-06, APP-07, APP-08, APP-10, APP-11 y que FindSecBugs ya no reporta `SPRING_CSRF_PROTECTION_DISABLED`
- [x] 4.3 Crear `CsrfController` (`GET /api/csrf`); verificar APP-12
- [x] 4.4 Manejar id inexistente en `AdminController` con 404; verificar APP-09
- [x] 4.5 Ajustar `DevSecOpsLabApplicationTests.adminEndpointIsCurrentlyExposedForTheLab` para esperar 401 (renombrar a `adminEndpointRequiresAuthentication`); verificar `mvn -B test`
- [x] 4.6 Commit `fix(authz-csrf): autorización por rutas, HTTP Basic y CSRF activo`

## 5. Secretos, logs y configuración

- [x] 5.1 Reescribir `AuthController.login` con `AuthenticationManager`, sin `ADMIN_PASSWORD`/`JWT_SECRET`, sin password en logs y con el usuario neutralizado con `replace("\r","_").replace("\n","_")` (D5). Verificar APP-13, APP-14 y APP-15, y que FindSecBugs ya no reporta `CRLF_INJECTION_LOGS`
- [x] 5.2 Endurecer `application.properties` (D6) y mover `lab.external.api-key` a `${LAB_EXTERNAL_API_KEY:}`; verificar APP-17, APP-18, APP-19
- [x] 5.3 Verificar APP-16 con `git grep -nE 'Admin123!|devsecops-lab-secret|LAB-DEMO-KEY' -- src/main` vacío y Semgrep `p/secrets` + `lab-hardcoded-secret` sin hallazgos
- [x] 5.4 Actualizar `README.md` (flujo curl con CSRF y Basic, generación del hash bcrypt, variables de entorno); verificar que los comandos del README funcionan contra la app local
- [x] 5.5 Commit `fix(secretos-config): credenciales por entorno y configuración endurecida`

## 6. Dependencias

- [x] 6.1 Subir `commons-text` a 1.10.0; verificar `mvn dependency:tree -Dincludes=org.apache.commons:commons-text` y Trivy sobre el nuevo `bom.json` sin CVE-2022-42889 (APP-20)
- [x] 6.2 Subir el parent a 3.5.16 y fijar `<tomcat.version>10.1.60</tomcat.version>` y `<jackson-bom.version>2.21.7</jackson-bom.version>` (D7, ya prototipado: 0 HIGH/CRITICAL en Trivy). Ejecutar Trivy SBOM y Dependency-Check locales y, para cada CVE HIGH/CRITICAL restante (p. ej. falsos positivos de CPE en DC), subir la propiedad gestionada o crear una supresión con `<notes>` y `until`. Verificar `mvn -B clean verify` y reportes sin bloqueantes (APP-21)
- [x] 6.3 Crear `evidencias/sca/comparacion.md` con la plantilla de la guía 02 §13 completada (commits, runs, Trivy 0.74.0, tabla antes/después) (APP-22)
- [x] 6.4 Commit `fix(deps): commons-text 1.10.0 y CVE transitivos`

## 7. Verificación integrada

- [x] 7.1 `mvn -B clean verify` en HEAD: `SecurityRemediationTests` con ≥ 8 pruebas y 0 fallos (APP-23)
- [x] 7.2 `herramientas/escaneo_local.sh despues`: gate local con código 0 (QG-14 parte "después")
- [ ] 7.3 E2E con la app en marcha (`herramientas/e2e_curl.sh`) contra el commit ROJO y contra HEAD: explotaciones de APP-01, APP-04, APP-06, APP-11, APP-14, APP-17 funcionan antes y quedan bloqueadas después; guardar salidas en `evidencias/e2e/{antes,despues}/`
- [ ] 7.4 [E2E] Push: CI del PR #1 con Quality Gate `success` y `mergeStateStatus=CLEAN` (APP-23, BP-04); confirmar en el SARIF de CodeQL que no queda `java/xss` (D2) ni otra regla con `security-severity` ≥ 7
- [x] 7.5 Ejecutar `openspec validate remediate-app-vulnerabilities --strict` y marcar las tareas completadas

## Notas de aplicación (fase 3, 2026-10-04)

- Commits:

  | Commit | Mensaje | Familia |
  |---|---|---|
  | `079e330` | `fix(sqli)` | inyección SQL |
  | `0fad219` | `fix(xss)` | XSS |
  | `cd2b7b2` | `fix(authz-csrf)` | autorización, CSRF e IDOR |
  | `e1e5bcb` | `fix(secretos-logs)` | secretos y logs |
  | `1042b3b` | `fix(config)` | configuración |
  | `93ae916` | `fix(deps)` | dependencias |

  La tarea 5.5, que preveía un único commit `fix(secretos-config)`, se dividió en dos (`fix(secretos-logs)` y `fix(config)`) por instrucción del orquestador.
- Pruebas: 17 en `SecurityRemediationTests` y 2 en `ErroresSinStacktraceTests`.
  - Contra el ROJO, 17 de 19 fallan; las 2 restantes, APP-02 y APP-08, prueban funcionalidad legítima. Evidencia en `evidencias/locales/antes/tests_seguridad_rojo.txt`.
  - `application-test.properties` usa además una BD H2 única por contexto (`jdbc:h2:mem:devsecopsdb-${random.uuid}`): si no, `schema.sql` falla al cargar el segundo contexto de Spring.
- Tarea 6.2:
  - Spring Framework 6.2.20 y Spring Security 6.5.12 no están publicados en Maven Central.
  - Los 15 CVE de DC sobre 6.2.19 y 6.5.11 no son aplicables (WebFlux, RSocket, Jetty, XsltView, SSE, SpEL, LDAP, DPoP, WebAuthn) y se suprimieron uno a uno con `<notes>` y `until=2026-12-31Z`.
  - log4j se subió a 2.25.5.
- Semgrep `lab-sensitive-data-in-log` (WARNING, no bloquea) sigue apareciendo. Es un falso positivo de la regla upstream: su `metavariable-regex` está fuera de `patterns`, así que marca cualquier `LOGGER.info` con argumentos. No se modificó `.semgrep.yml`.
- Tarea 7.3 (E2E curl antes/después): pospuesta a la fase 6 por instrucción del orquestador. `herramientas/e2e_curl.sh` ya existe y se probó en modo "antes" contra la imagen ROJO: 9 de 9 explotaciones confirmadas.
- Escaneo "después" (`evidencias/locales/despues/`):
  - gate exit 0: 0 bloqueantes, 17 no bloqueantes y 15 suprimidos.
  - DC local sin override en `BUILD SUCCESS`.
  - Trivy SBOM: 0 HIGH/CRITICAL.
  - Imagen remediada: gate `--only trivy-imagen` en APROBADO.

## Notas de la auditoría de ejecución (fase 4, 2026-10-04)

- `SecurityConfig.registrar` solo acepta hashes bcrypt bien formados (con o sin `{bcrypt}`). Un valor vacío, en claro o con otro esquema (`{noop}`, `{MD5}`…) deja el usuario sin registrar: no hay contraseña por defecto ni hash conocido. Pruebas en `config/RegistroUsuariosTests` (3). Total de la suite: 24 pruebas.
