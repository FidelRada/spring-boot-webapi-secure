# Tasks: remediate-app-vulnerabilities (commits VERDE)

> Requisito previo: change `add-secure-ci-pipeline` aplicado y PR #1 bloqueado (BP-02). Ningún umbral ni control del pipeline se modifica en este change.

## 1. Base de pruebas

- [ ] 1.1 Crear `src/test/resources/application.properties` con hashes bcrypt de contraseñas de prueba para `admin` y `ana` (documentados como solo-prueba); verificar que el contexto arranca con `mvn -B test -Dtest=DevSecOpsLabApplicationTests`
- [ ] 1.2 Crear `src/test/java/bo/edu/devsecops/SecurityRemediationTests.java` (`@SpringBootTest`, `@AutoConfigureMockMvc`, `@ExtendWith(OutputCaptureExtension.class)`) con una prueba por escenario APP-01..APP-19; verificar que fallan sobre el commit ROJO (demuestra que detectan la vulnerabilidad)

## 2. Inyección SQL

- [ ] 2.1 Parametrizar `ProductController.search` con `LIKE ? ESCAPE '\'` y escape de comodines (D1); verificar APP-01, APP-02, APP-03 en verde y que Semgrep ya no reporta `lab-java-sql-concatenation` ni FindSecBugs `SQL_INJECTION_SPRING_JDBC`
- [ ] 2.2 Commit `fix(sqli): consulta parametrizada en búsqueda de productos`

## 3. XSS

- [ ] 3.1 Escapar `comment` con `HtmlUtils.htmlEscape` en `CommentController.preview` (D2); verificar APP-04 y que Semgrep ya no reporta `lab-html-without-output-encoding`
- [ ] 3.2 Commit `fix(xss): codificación de salida en vista previa`

## 4. Autenticación, autorización y CSRF

- [ ] 4.1 Crear `LabSecurityProperties` (`lab.security.admin-password-hash`, `lab.security.user-password-hash`) y registrar `@EnableConfigurationProperties`; verificar arranque con y sin variables de entorno
- [ ] 4.2 Reescribir `SecurityConfig` (rutas públicas, `/api/admin/**` y `/actuator/**` ADMIN, `anyRequest().authenticated()`, `httpBasic`, CSRF activo, CSP, `PasswordEncoder` delegante, `InMemoryUserDetailsManager`, `AuthenticationManager`) (D3, D4); verificar APP-05, APP-06, APP-07, APP-08, APP-10, APP-11
- [ ] 4.3 Crear `CsrfController` (`GET /api/csrf`); verificar APP-12
- [ ] 4.4 Manejar id inexistente en `AdminController` con 404; verificar APP-09
- [ ] 4.5 Ajustar `DevSecOpsLabApplicationTests.adminEndpointIsCurrentlyExposedForTheLab` para esperar 401 (renombrar a `adminEndpointRequiresAuthentication`); verificar `mvn -B test`
- [ ] 4.6 Commit `fix(authz-csrf): autorización por rutas, HTTP Basic y CSRF activo`

## 5. Secretos, logs y configuración

- [ ] 5.1 Reescribir `AuthController.login` con `AuthenticationManager`, sin `ADMIN_PASSWORD`/`JWT_SECRET`, sin password en logs y con usuario neutralizado (D5); verificar APP-13, APP-14, APP-15
- [ ] 5.2 Endurecer `application.properties` (D6) y mover `lab.external.api-key` a `${LAB_EXTERNAL_API_KEY:}`; verificar APP-17, APP-18, APP-19
- [ ] 5.3 Verificar APP-16 con `git grep -nE 'Admin123!|devsecops-lab-secret|LAB-DEMO-KEY' -- src/main` vacío y Semgrep `p/secrets` + `lab-hardcoded-secret` sin hallazgos
- [ ] 5.4 Actualizar `README.md` (flujo curl con CSRF y Basic, generación del hash bcrypt, variables de entorno); verificar que los comandos del README funcionan contra la app local
- [ ] 5.5 Commit `fix(secretos-config): credenciales por entorno y configuración endurecida`

## 6. Dependencias

- [ ] 6.1 Subir `commons-text` a 1.10.0; verificar `mvn dependency:tree -Dincludes=org.apache.commons:commons-text` y Trivy sobre el nuevo `bom.json` sin CVE-2022-42889 (APP-20)
- [ ] 6.2 Ejecutar Trivy SBOM y Dependency-Check locales; para cada CVE HIGH/CRITICAL restante, subir la propiedad de versión gestionada o crear supresión con `<notes>` y `until` (D7); verificar `mvn -B clean verify` y reportes sin bloqueantes (APP-21)
- [ ] 6.3 Crear `evidencias/sca/comparacion.md` con la plantilla de la guía 02 §13 completada (commits, runs, Trivy 0.74.0, tabla antes/después) (APP-22)
- [ ] 6.4 Commit `fix(deps): commons-text 1.10.0 y CVE transitivos`

## 7. Verificación integrada

- [ ] 7.1 `mvn -B clean verify` en HEAD: `SecurityRemediationTests` con ≥ 8 pruebas y 0 fallos (APP-23)
- [ ] 7.2 `herramientas/escaneo_local.sh despues`: gate local con código 0 (QG-14 parte "después")
- [ ] 7.3 E2E con la app en marcha (`herramientas/e2e_curl.sh`) contra el commit ROJO y contra HEAD: explotaciones de APP-01, APP-04, APP-06, APP-11, APP-14, APP-17 funcionan antes y quedan bloqueadas después; guardar salidas en `evidencias/e2e/{antes,despues}/`
- [ ] 7.4 Push: CI del PR #1 con Quality Gate `success` y `mergeStateStatus=CLEAN` (APP-23, BP-04)
- [ ] 7.5 Ejecutar `openspec validate remediate-app-vulnerabilities --strict` y marcar las tareas completadas
