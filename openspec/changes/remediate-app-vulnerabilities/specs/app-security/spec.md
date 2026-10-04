# Spec Delta: app-security

## Purpose

Garantiza que la API del laboratorio resista las vulnerabilidades que el pipeline detecta (inyección, XSS, control de acceso roto, CSRF, exposición de secretos y de configuración, dependencias vulnerables) y que esto se demuestre con pruebas automatizadas y E2E.

## ADDED Requirements

### Requirement: Búsqueda de productos sin inyección SQL
El endpoint `GET /api/products/search` SHALL tratar el parámetro `name` exclusivamente como dato de una consulta parametrizada, de modo que ningún valor altere la estructura de la sentencia SQL.

#### Scenario: APP-01 Payload de inyección no devuelve el catálogo
- **WHEN** se solicita `GET /api/products/search?name=' OR '1'='1`
- **THEN** la respuesta es 200 con una lista vacía (no los 3 productos)

#### Scenario: APP-02 Búsqueda legítima funciona
- **WHEN** se solicita `GET /api/products/search?name=Lap`
- **THEN** la respuesta es 200 y contiene exactamente el producto `Laptop`

#### Scenario: APP-03 Comilla aislada no provoca error SQL
- **WHEN** se solicita `GET /api/products/search?name='`
- **THEN** la respuesta es 200 con lista vacía y no 500

### Requirement: Vista previa de comentarios sin XSS
El endpoint `POST /api/comments/preview` SHALL codificar para HTML todo el contenido proporcionado por el usuario antes de incluirlo en la respuesta, y la respuesta SHALL llevar `X-Content-Type-Options: nosniff` y una `Content-Security-Policy` restrictiva.

#### Scenario: APP-04 Script reflejado se neutraliza
- **WHEN** se envía `{"comment":"<script>alert(1)</script>"}` con un token CSRF válido
- **THEN** la respuesta 200 contiene `&lt;script&gt;alert(1)&lt;/script&gt;` y no contiene `<script>`

#### Scenario: APP-05 Cabeceras de defensa
- **WHEN** se obtiene cualquier respuesta de `/api/comments/preview`
- **THEN** incluye `X-Content-Type-Options: nosniff` y `Content-Security-Policy` con `default-src 'none'` o más restrictiva

### Requirement: Administración restringida a ADMIN
Las rutas `/api/admin/**` SHALL exigir un usuario autenticado con rol ADMIN; las peticiones anónimas MUST recibir 401 y las de usuarios sin ese rol 403.

#### Scenario: APP-06 Acceso anónimo rechazado
- **WHEN** se solicita `GET /api/admin/users/1` sin credenciales
- **THEN** la respuesta es 401 y no contiene datos de usuarios

#### Scenario: APP-07 Usuario sin rol ADMIN rechazado
- **WHEN** el usuario `ana` (rol USER) solicita `GET /api/admin/users/1` con HTTP Basic
- **THEN** la respuesta es 403

#### Scenario: APP-08 Administrador autorizado
- **WHEN** el usuario `admin` (rol ADMIN) solicita `GET /api/admin/users/2` con HTTP Basic
- **THEN** la respuesta es 200 con el usuario `ana`

#### Scenario: APP-09 Identificador inexistente
- **WHEN** el administrador solicita `GET /api/admin/users/999`
- **THEN** la respuesta es 404 sin stacktrace ni texto de excepción

### Requirement: Denegación por defecto
Toda ruta no declarada explícitamente como pública (`/api/products/search`, `/api/comments/preview`, `/api/auth/login`, `/api/csrf`, `/actuator/health`) SHALL requerir autenticación.

#### Scenario: APP-10 Ruta no declarada exige autenticación
- **WHEN** se solicita `GET /api/otra-ruta` sin credenciales
- **THEN** la respuesta es 401

### Requirement: Protección CSRF activa
Las peticiones que cambian estado o envían datos (`POST`, `PUT`, `PATCH`, `DELETE`) SHALL exigir un token CSRF válido, obtenible mediante `GET /api/csrf` junto con la cookie de sesión.

#### Scenario: APP-11 POST sin token rechazado
- **WHEN** se envía `POST /api/comments/preview` sin token CSRF
- **THEN** la respuesta es 403

#### Scenario: APP-12 POST con token aceptado
- **WHEN** se obtiene el token con `GET /api/csrf` y se reenvía en la cabecera indicada junto con la cookie de sesión
- **THEN** `POST /api/comments/preview` responde 200

### Requirement: Login sin secretos expuestos
`POST /api/auth/login` SHALL validar las credenciales contra el almacén de usuarios con contraseñas bcrypt y MUST NOT devolver secretos de firma ni credenciales en la respuesta; los fallos SHALL responder 401 con un mensaje genérico.

#### Scenario: APP-13 Credenciales válidas
- **WHEN** se envía el usuario `admin` con la contraseña cuyo hash está configurado y un token CSRF válido
- **THEN** la respuesta es 200, contiene el usuario y sus roles, y no contiene el campo `token` ni la cadena `devsecops-lab-secret`

#### Scenario: APP-14 Credenciales inválidas
- **WHEN** se envía `{"username":"admin","password":"Admin123!"}` (la contraseña hardcodeada anterior)
- **THEN** la respuesta es 401 con `Credenciales incorrectas`

### Requirement: Logs sin datos sensibles
La aplicación MUST NOT escribir contraseñas en los logs y SHALL neutralizar los caracteres de control (CR/LF) de cualquier valor del usuario que registre.

#### Scenario: APP-15 Password ausente del log
- **WHEN** se intenta un login con la contraseña `ClaveDePrueba-XYZ` y se captura la salida de log
- **THEN** la salida no contiene `ClaveDePrueba-XYZ`, y un usuario con `\r\n` aparece sin saltos de línea

### Requirement: Sin secretos en el código
El código y la configuración versionados MUST NOT contener contraseñas, claves de firma ni API keys; las credenciales SHALL leerse de variables de entorno (`LAB_ADMIN_PASSWORD_HASH`, `LAB_USER_PASSWORD_HASH`, `LAB_EXTERNAL_API_KEY`).

#### Scenario: APP-16 Búsqueda de secretos conocidos
- **WHEN** se ejecuta `git grep -nE 'Admin123!|devsecops-lab-secret|LAB-DEMO-KEY' -- src/main` y Semgrep `p/secrets` + `lab-hardcoded-secret`
- **THEN** no hay coincidencias ni hallazgos

### Requirement: Configuración expuesta mínima
La aplicación SHALL exponer de Actuator solo `health` (público) e `info`, ocultar valores de entorno, deshabilitar la consola H2 y no incluir mensaje ni stacktrace en las respuestas de error.

#### Scenario: APP-17 Actuator restringido
- **WHEN** se solicitan `/actuator/health` y `/actuator/env` sin credenciales
- **THEN** `/actuator/health` responde 200 con `"status":"UP"` y `/actuator/env` no devuelve variables (401 o 404)

#### Scenario: APP-18 Consola H2 deshabilitada
- **WHEN** se solicita `GET /h2-console`
- **THEN** la respuesta no es la consola H2 (401 o 404)

#### Scenario: APP-19 Errores sin stacktrace
- **WHEN** una petición provoca un error del servidor o de validación
- **THEN** el cuerpo JSON no contiene `trace` ni el mensaje interno de la excepción

### Requirement: Dependencias sin vulnerabilidades altas
Las dependencias resueltas SHALL quedar sin vulnerabilidades HIGH/CRITICAL según Trivy y Dependency-Check; commons-text SHALL estar en 1.10.0 o superior, y cualquier excepción MUST ser una supresión justificada con fecha `until`, sin bajar umbrales.

#### Scenario: APP-20 CVE-2022-42889 desaparece
- **WHEN** se regenera el SBOM y se analiza con Trivy y Dependency-Check tras la remediación
- **THEN** `commons-text` aparece en 1.10.0 (o superior) y ningún reporte contiene CVE-2022-42889

#### Scenario: APP-21 Reportes SCA limpios sin relajar controles
- **WHEN** se ejecuta el gate sobre los reportes SCA del commit remediado
- **THEN** no hay hallazgos HIGH/CRITICAL no suprimidos, el umbral sigue en CVSS 7.0 / HIGH y cada supresión tiene `<notes>` y `until`

#### Scenario: APP-22 Comparación antes/después documentada
- **WHEN** se abre `evidencias/sca/comparacion.md`
- **THEN** contiene commits, runs, versión de Trivy y la tabla antes/después de commons-text con el estado del gate (rojo → verde)

### Requirement: Pruebas de regresión de seguridad
El proyecto SHALL incluir pruebas MockMvc que verifiquen los escenarios APP-01 a APP-19 y el pipeline completo SHALL aprobar el Quality Gate sobre el commit remediado.

#### Scenario: APP-23 Suite de seguridad y gate en verde
- **WHEN** se ejecuta `mvn -B clean verify` y el workflow CI sobre el commit remediado
- **THEN** `SecurityRemediationTests` ejecuta al menos 8 pruebas sin fallos y el check Quality Gate del PR termina en `success`
