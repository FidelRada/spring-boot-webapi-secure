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
 * Pruebas de regresión de seguridad (change remediate-app-vulnerabilities, escenarios
 * APP-01..APP-18). APP-19 está en {@link ErroresSinStacktraceTests} porque necesita un
 * servidor real para observar el cuerpo de /error.
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
    @DisplayName("APP-01 El payload de inyección SQL no devuelve el catálogo")
    void busquedaConPayloadSqlNoDevuelveCatalogo() throws Exception {
        mockMvc.perform(get("/api/products/search").param("name", "' OR '1'='1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(0)));
    }

    @Test
    @DisplayName("APP-02 La búsqueda legítima sigue funcionando")
    void busquedaLegitimaDevuelveLaptop() throws Exception {
        mockMvc.perform(get("/api/products/search").param("name", "Lap"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(content().string(containsString("Laptop")));
    }

    @Test
    @DisplayName("APP-03 Una comilla aislada no provoca error SQL")
    void comillaAisladaNoProvocaError() throws Exception {
        mockMvc.perform(get("/api/products/search").param("name", "'"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(0)));
    }

    // ------------------------------------------------------------------- XSS



    // ------------------------------------------------------- Autorización






    // ------------------------------------------------------------------ CSRF



    // ---------------------------------------------------------------- Login



    // ------------------------------------------------------------------ Logs


    // ---------------------------------------------------------- Configuración



    private String credenciales(String usuario, String clave) throws Exception {
        return json.writeValueAsString(java.util.Map.of("username", usuario, "password", clave));
    }
}
