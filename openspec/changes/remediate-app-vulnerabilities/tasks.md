# Tasks: remediate-app-vulnerabilities (commits VERDE)

> Requisito previo: change `add-secure-ci-pipeline` aplicado y PR #1 bloqueado (BP-02). Ningún umbral ni control del pipeline se modifica en este change.

## 1. Base de pruebas

- [ ] 1.1 Crear `src/test/resources/application-test.properties` con hashes bcrypt de contraseñas de prueba para `admin` y `ana` (documentados como solo de prueba) y `@ActiveProfiles("test")` en las clases de test (no `application.properties`, que ocultaría la configuración principal). Verificar con `env -u LAB_ADMIN_PASSWORD_HASH -u LAB_USER_PASSWORD_HASH mvn -B test` que el contexto arranca sin variables de entorno
- [ ] 1.2 Redactar `src/test/java/bo/edu/devsecops/SecurityRemediationTests.java` (`@SpringBootTest`, `@AutoConfigureMockMvc`, `@ActiveProfiles("test")`, `@ExtendWith(OutputCaptureExtension.class)`) con una prueba por escenario APP-01..APP-18. APP-19 va en una clase `RANDOM_PORT` con `TestRestTemplate`. Ejecutarlas sobre el commit ROJO **sin commitearlas** y guardar la salida en `evidencias/locales/antes/tests_seguridad_rojo.txt` (demuestra que detectan la vulnerabilidad). Después, cada commit de la sección 2 a la 6 incorpora solo las pruebas de su familia, para que cada commit compile y pase (D8)

## 2. Inyección SQL

- [ ] 2.1 Parametrizar `ProductController.search` con `LIKE ? ESCAPE '\'` y escape de comodines (D1); verificar APP-01, APP-02, APP-03 en verde y que Semgrep ya no reporta `lab-java-sql-concatenation` ni FindSecBugs `SQL_INJECTION_SPRING_JDBC`
- [ ] 2.2 Commit `fix(sqli): consulta parametrizada en búsqueda de productos`

## 3. XSS

- [ ] 3.1 Añadir `org.owasp.encoder:encoder:1.5.0` y escapar `comment` con `Encode.forHtml` (importado) en una variable antes de `ResponseEntity.ok(html)` en `CommentController.preview` (D2). Verificar APP-04 y que Semgrep ya no reporta `lab-html-without-output-encoding` ni `tainted-html-string`; CodeQL `java/xss` se verifica en el primer run de CI posterior
- [ ] 3.2 Commit `fix(xss): codificación de salida en vista previa`

## 4. Autenticación, autorización y CSRF

- [ ] 4.1 Crear `LabSecurityProperties` (`lab.security.admin-password-hash`, `lab.security.user-password-hash`) y registrar `@EnableConfigurationProperties`; verificar arranque con y sin variables de entorno
- [ ] 4.2 Reescribir `SecurityConfig` (D3, D4): rutas públicas, `dispatcherTypeMatchers(ERROR).permitAll()`, `/api/admin/**` y `/actuator/**` ADMIN, `anyRequest().authenticated()`, `httpBasic`, CSRF activo, CSP, `PasswordEncoder` delegante, `InMemoryUserDetailsManager` y `AuthenticationManager`. Verificar APP-05, APP-06, APP-07, APP-08, APP-10, APP-11 y que FindSecBugs ya no reporta `SPRING_CSRF_PROTECTION_DISABLED`
- [ ] 4.3 Crear `CsrfController` (`GET /api/csrf`); verificar APP-12
- [ ] 4.4 Manejar id inexistente en `AdminController` con 404; verificar APP-09
- [ ] 4.5 Ajustar `DevSecOpsLabApplicationTests.adminEndpointIsCurrentlyExposedForTheLab` para esperar 401 (renombrar a `adminEndpointRequiresAuthentication`); verificar `mvn -B test`
- [ ] 4.6 Commit `fix(authz-csrf): autorización por rutas, HTTP Basic y CSRF activo`

## 5. Secretos, logs y configuración

- [ ] 5.1 Reescribir `AuthController.login` con `AuthenticationManager`, sin `ADMIN_PASSWORD`/`JWT_SECRET`, sin password en logs y con el usuario neutralizado con `replace("\r","_").replace("\n","_")` (D5). Verificar APP-13, APP-14 y APP-15, y que FindSecBugs ya no reporta `CRLF_INJECTION_LOGS`
- [ ] 5.2 Endurecer `application.properties` (D6) y mover `lab.external.api-key` a `${LAB_EXTERNAL_API_KEY:}`; verificar APP-17, APP-18, APP-19
- [ ] 5.3 Verificar APP-16 con `git grep -nE 'Admin123!|devsecops-lab-secret|LAB-DEMO-KEY' -- src/main` vacío y Semgrep `p/secrets` + `lab-hardcoded-secret` sin hallazgos
- [ ] 5.4 Actualizar `README.md` (flujo curl con CSRF y Basic, generación del hash bcrypt, variables de entorno); verificar que los comandos del README funcionan contra la app local
- [ ] 5.5 Commit `fix(secretos-config): credenciales por entorno y configuración endurecida`

## 6. Dependencias

- [ ] 6.1 Subir `commons-text` a 1.10.0; verificar `mvn dependency:tree -Dincludes=org.apache.commons:commons-text` y Trivy sobre el nuevo `bom.json` sin CVE-2022-42889 (APP-20)
- [ ] 6.2 Subir el parent a 3.5.16 y fijar `<tomcat.version>10.1.60</tomcat.version>` y `<jackson-bom.version>2.21.7</jackson-bom.version>` (D7, ya prototipado: 0 HIGH/CRITICAL en Trivy). Ejecutar Trivy SBOM y Dependency-Check locales y, para cada CVE HIGH/CRITICAL restante (p. ej. falsos positivos de CPE en DC), subir la propiedad gestionada o crear una supresión con `<notes>` y `until`. Verificar `mvn -B clean verify` y reportes sin bloqueantes (APP-21)
- [ ] 6.3 Crear `evidencias/sca/comparacion.md` con la plantilla de la guía 02 §13 completada (commits, runs, Trivy 0.74.0, tabla antes/después) (APP-22)
- [ ] 6.4 Commit `fix(deps): commons-text 1.10.0 y CVE transitivos`

## 7. Verificación integrada

- [ ] 7.1 `mvn -B clean verify` en HEAD: `SecurityRemediationTests` con ≥ 8 pruebas y 0 fallos (APP-23)
- [ ] 7.2 `herramientas/escaneo_local.sh despues`: gate local con código 0 (QG-14 parte "después")
- [ ] 7.3 E2E con la app en marcha (`herramientas/e2e_curl.sh`) contra el commit ROJO y contra HEAD: explotaciones de APP-01, APP-04, APP-06, APP-11, APP-14, APP-17 funcionan antes y quedan bloqueadas después; guardar salidas en `evidencias/e2e/{antes,despues}/`
- [ ] 7.4 [E2E] Push: CI del PR #1 con Quality Gate `success` y `mergeStateStatus=CLEAN` (APP-23, BP-04); confirmar en el SARIF de CodeQL que no queda `java/xss` (D2) ni otra regla con `security-severity` ≥ 7
- [ ] 7.5 Ejecutar `openspec validate remediate-app-vulnerabilities --strict` y marcar las tareas completadas
