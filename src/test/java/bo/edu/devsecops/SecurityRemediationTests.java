package bo.edu.devsecops;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Pruebas de regresión de seguridad de la API. Los errores del servlet /error se prueban en
 * {@link ErroresSinStacktraceTests} porque necesitan un servidor real para observar el cuerpo de /error.
 *
 * Las contraseñas de abajo son SOLO de prueba: sus hashes bcrypt están en
 * src/test/resources/application-test.properties (perfil "test").
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@ExtendWith(OutputCaptureExtension.class)
class SecurityRemediationTests {

    static final String ADMIN = "admin";
    static final String CLAVE_ADMIN_PRUEBA = "AdminPrueba-2026!";
    static final String ANA = "ana";
    static final String CLAVE_ANA_PRUEBA = "AnaPrueba-2026!";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ApplicationContext contexto;

    private final ObjectMapper json = new ObjectMapper();

    // ------------------------------------------------------------------ SQLi

    @Test
    @DisplayName("El payload de inyección SQL no devuelve el catálogo")
    void busquedaConPayloadSqlNoDevuelveCatalogo() throws Exception {
        mockMvc.perform(get("/api/products/search").param("name", "' OR '1'='1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(0)));
    }

    @Test
    @DisplayName("La búsqueda legítima sigue funcionando")
    void busquedaLegitimaDevuelveLaptop() throws Exception {
        mockMvc.perform(get("/api/products/search").param("name", "Lap"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(content().string(containsString("Laptop")));
    }

    @Test
    @DisplayName("Una comilla aislada no provoca error SQL")
    void comillaAisladaNoProvocaError() throws Exception {
        mockMvc.perform(get("/api/products/search").param("name", "'"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(0)));
    }

    // ------------------------------------------------------------------- XSS

    @Test
    @DisplayName("El script reflejado se codifica para HTML")
    void previewEscapaScript() throws Exception {
        mockMvc.perform(post("/api/comments/preview").with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"comment\":\"<script>alert(1)</script>\"}"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("&lt;script&gt;alert(1)&lt;/script&gt;")))
                .andExpect(content().string(not(containsString("<script>"))));
    }

    @Test
    @DisplayName("La vista previa lleva nosniff y una CSP restrictiva")
    void previewIncluyeCabecerasDeDefensa() throws Exception {
        mockMvc.perform(post("/api/comments/preview").with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"comment\":\"hola\"}"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Content-Security-Policy", containsString("default-src 'none'")));
    }

    // ------------------------------------------------------- Autorización

    @Test
    @DisplayName("Administración sin credenciales: 401 y sin datos")
    void adminAnonimoRecibe401() throws Exception {
        mockMvc.perform(get("/api/admin/users/1"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(not(containsString("admin@lab.local"))));
    }

    @Test
    @DisplayName("Usuario con rol USER: 403")
    void adminConRolUserRecibe403() throws Exception {
        mockMvc.perform(get("/api/admin/users/1").with(httpBasic(ANA, CLAVE_ANA_PRUEBA)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Administrador autorizado: 200 con el usuario ana")
    void adminConRolAdminRecibe200() throws Exception {
        mockMvc.perform(get("/api/admin/users/2").with(httpBasic(ADMIN, CLAVE_ADMIN_PRUEBA)))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("ana@lab.local")));
    }

    @Test
    @DisplayName("Identificador inexistente: 404 sin detalle de la excepción")
    void adminIdInexistenteRecibe404() throws Exception {
        mockMvc.perform(get("/api/admin/users/999").with(httpBasic(ADMIN, CLAVE_ADMIN_PRUEBA)))
                .andExpect(status().isNotFound())
                .andExpect(content().string(not(containsString("EmptyResultDataAccessException"))));
    }

    @Test
    @DisplayName("Una ruta no declarada exige autenticación")
    void rutaNoDeclaradaExigeAutenticacion() throws Exception {
        mockMvc.perform(get("/api/otra-ruta"))
                .andExpect(status().isUnauthorized());
    }

    // ------------------------------------------------------------------ CSRF

    @Test
    @DisplayName("POST sin token CSRF: 403")
    void postSinTokenCsrfRecibe403() throws Exception {
        mockMvc.perform(post("/api/comments/preview")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"comment\":\"hola\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("POST con el token de GET /api/csrf y la sesión: 200")
    void postConTokenCsrfRecibe200() throws Exception {
        MvcResult respuesta = mockMvc.perform(get("/api/csrf"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.headerName").value("X-CSRF-TOKEN"))
                .andReturn();
        JsonNode cuerpo = json.readTree(respuesta.getResponse().getContentAsString());
        MockHttpSession sesion = (MockHttpSession) respuesta.getRequest().getSession(false);
        assertThat(sesion).as("GET /api/csrf debe crear la sesión").isNotNull();

        mockMvc.perform(post("/api/comments/preview").session(sesion)
                        .header(cuerpo.get("headerName").asText(), cuerpo.get("token").asText())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"comment\":\"hola\"}"))
                .andExpect(status().isOk());
    }

    // ---------------------------------------------------------------- Login

    @Test
    @DisplayName("Login válido: usuario y roles, sin token ni secreto")
    void loginValidoNoDevuelveSecreto() throws Exception {
        mockMvc.perform(post("/api/auth/login").with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(credenciales(ADMIN, CLAVE_ADMIN_PRUEBA)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.usuario").value(ADMIN))
                .andExpect(jsonPath("$.roles", hasItem("ROLE_ADMIN")))
                .andExpect(jsonPath("$.token").doesNotExist())
                .andExpect(content().string(not(containsString("devsecops-lab-secret"))));
    }

    @Test
    @DisplayName("La contraseña hardcodeada anterior ya no funciona (401; sin CSRF 403)")
    void passwordHardcodeadaYaNoFunciona() throws Exception {
        String anterior = credenciales(ADMIN, "Admin123!");
        mockMvc.perform(post("/api/auth/login").with(csrf())
                        .contentType(MediaType.APPLICATION_JSON).content(anterior))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Credenciales incorrectas"))
                .andExpect(content().string(not(containsString("devsecops-lab-secret"))));
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON).content(anterior))
                .andExpect(status().isForbidden());
    }

    // ------------------------------------------------------------------ Logs

    @Test
    @DisplayName("El log no contiene la contraseña ni saltos de línea del usuario")
    void logNoContienePasswordNiSaltos(CapturedOutput salida) throws Exception {
        mockMvc.perform(post("/api/auth/login").with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(credenciales("intruso\r\nFALSO admin", "ClaveDePrueba-XYZ")))
                .andExpect(status().isUnauthorized());
        assertThat(salida.getAll()).doesNotContain("ClaveDePrueba-XYZ");
        assertThat(salida.getAll()).doesNotContain("\nFALSO admin");
        assertThat(salida.getAll()).contains("intruso__FALSO admin");
    }

    // ---------------------------------------------------------- Configuración

    @Test
    @DisplayName("Actuator: health público, env no expuesto")
    void actuatorSoloExponeHealth() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
        mockMvc.perform(get("/actuator/env"))
                .andExpect(status().is(anyOf(is(401), is(404))))
                .andExpect(content().string(not(containsString("LAB-DEMO-KEY"))));
        // Ni siquiera un administrador puede leer el entorno: el endpoint no está expuesto.
        mockMvc.perform(get("/actuator/env").with(httpBasic(ADMIN, CLAVE_ADMIN_PRUEBA)))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("Consola H2 deshabilitada")
    void consolaH2Deshabilitada() throws Exception {
        assertThat(contexto.containsBean("h2Console"))
                .as("la consola H2 no debe registrarse como servlet").isFalse();
        mockMvc.perform(get("/h2-console"))
                .andExpect(status().is(anyOf(is(401), is(404))));
    }

    private String credenciales(String usuario, String clave) throws Exception {
        return json.writeValueAsString(java.util.Map.of("username", usuario, "password", clave));
    }
}
