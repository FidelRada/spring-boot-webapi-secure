# Proposal: remediate-app-vulnerabilities (momento VERDE)

## Why

Con el change `add-secure-ci-pipeline` aplicado, el PR #1 queda bloqueado porque el Quality Gate encuentra hallazgos reales en la aplicación. La consigna exige que el pipeline sea funcional y que los merges solo ocurran con el pipeline en verde, y la guía 02 prohíbe bajar umbrales o desactivar controles para conseguirlo. La única salida legítima es **corregir el código, la configuración y las dependencias** hasta que los reportes queden limpios, demostrando además con pruebas que cada explotación deja de funcionar.

## What Changes

Hallazgos observados en el código actual (`src/main/**`) y su corrección:

| Hallazgo (archivo) | Corrección |
|---|---|
| SQLi por concatenación en `GET /api/products/search` (`ProductController`) | Consulta parametrizada `LIKE ?` con el comodín añadido al parámetro |
| XSS reflejado en `POST /api/comments/preview` (`CommentController`) | Codificación de salida con `HtmlUtils.htmlEscape` + cabeceras CSP y `nosniff` |
| `permitAll` global y `/api/admin/users/{id}` accesible sin autenticación (IDOR/BOLA) (`SecurityConfig`, `AdminController`) | Autorización por rutas: `/api/admin/**` solo `ROLE_ADMIN`, denegación por defecto, HTTP Basic; id inexistente ⇒ 404 |
| CSRF deshabilitado (`SecurityConfig`) | CSRF activo con token de sesión expuesto por `GET /api/csrf` |
| `ADMIN_PASSWORD` y `JWT_SECRET` hardcodeados; el "token" devuelto es el propio secreto (`AuthController`) | Autenticación con `AuthenticationManager` y usuarios cuyo hash bcrypt llega por variable de entorno; la respuesta no contiene secretos |
| Password escrita en el log e inyección en logs (`AuthController`) | Sin password en logs; usuario neutralizado (CR/LF) |
| `lab.external.api-key` en claro (`application.properties`) | `${LAB_EXTERNAL_API_KEY:}` |
| Actuator `*` con `env` visible, consola H2 abierta a otros hosts, `include-stacktrace=always` (`application.properties`) | Exposición solo `health,info`, `show-values=never`, H2 console deshabilitada, errores sin mensaje ni stacktrace |
| commons-text 1.9 (CVE-2022-42889, CRITICAL) (`pom.xml`) | commons-text 1.10.0 (mínimo histórico de la guía 02) |
| CVE transitivos HIGH/CRITICAL que reporten Trivy o Dependency-Check | Subir la versión gestionada (propiedad del parent) o supresión justificada con `until`; **nunca** bajar umbrales |

- Nueva clase de pruebas `SecurityRemediationTests` (MockMvc) con al menos 8 pruebas de seguridad; se ajusta `adminEndpointIsCurrentlyExposedForTheLab`, que hoy espera el comportamiento inseguro.
- `evidencias/sca/comparacion.md` en el repositorio (plantilla de la guía 02 §13).
- **BREAKING (API)**: `/api/admin/**` exige credenciales ADMIN; los `POST` exigen token CSRF; `/api/auth/login` deja de devolver `token`.

## Capabilities

### New Capabilities
- `app-security`: comportamiento seguro observable de la API (entrada, salida, autenticación, autorización, CSRF, manejo de secretos, configuración expuesta y dependencias sin CVE altos).

### Modified Capabilities
- (ninguna; las capabilities del change `add-secure-ci-pipeline` no cambian de requisitos)

## Mapeo con la consigna y la guía 02

| Punto | Requisito(s) |
|---|---|
| Quality gate en verde sin relajar controles | APP-21, APP-23 |
| Merges a main permitidos solo con pipeline verde | APP-23 (junto con BP-04 del change 1) |
| Guía 02 §12: commons-text 1.9 → 1.10.0 | APP-20 |
| Guía 02 §13: comparación antes/después | APP-22 |
| Guía 02: no desactivar controles para la captura verde | APP-21 |

## Impact

- Código: `SecurityConfig`, `ProductController`, `CommentController`, `AdminController`, `AuthController`, nuevo `CsrfController`, nuevas propiedades `lab.security.*`.
- Configuración: `application.properties`, `src/test/resources/application.properties` (hashes de prueba).
- Dependencias: `pom.xml` (commons-text y, si hace falta, propiedades de versión gestionadas).
- Tests: `DevSecOpsLabApplicationTests` ajustado, `SecurityRemediationTests` nuevo.
- Operación: para usar `/api/admin/**` o el login hay que exportar `LAB_ADMIN_PASSWORD_HASH` (y opcionalmente `LAB_USER_PASSWORD_HASH`) con un hash bcrypt; el healthcheck del contenedor sigue funcionando sin credenciales.
