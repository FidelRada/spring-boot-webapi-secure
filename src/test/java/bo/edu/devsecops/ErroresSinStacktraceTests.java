package bo.edu.devsecops;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * APP-19: los errores reales del servidor (servlet /error) no exponen stacktrace ni el
 * mensaje interno de la excepción, y conservan su código (404/400), no 401.
 * MockMvc no reenvía a /error, por eso se usa un servidor en puerto aleatorio.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class ErroresSinStacktraceTests {

    @Autowired
    private TestRestTemplate rest;

    @Test
    @DisplayName("APP-19 Id inexistente como admin: 404 sin trace ni mensaje interno")
    void idInexistenteSinStacktrace() {
        ResponseEntity<String> respuesta = rest
                .withBasicAuth(SecurityRemediationTests.ADMIN, SecurityRemediationTests.CLAVE_ADMIN_PRUEBA)
                .getForEntity("/api/admin/users/999", String.class);

        assertThat(respuesta.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(respuesta.getBody())
                .doesNotContain("\"trace\"")
                .doesNotContain("Incorrect result size")
                .doesNotContain("EmptyResultDataAccessException");
    }

    @Test
    @DisplayName("APP-19 JSON mal formado con token CSRF: 400 sin trace ni mensaje del parser")
    @SuppressWarnings("rawtypes")
    void jsonMalFormadoSinStacktrace() {
        ResponseEntity<Map> csrf = rest.getForEntity("/api/csrf", Map.class);
        assertThat(csrf.getStatusCode()).isEqualTo(HttpStatus.OK);
        List<String> cookies = csrf.getHeaders().get(HttpHeaders.SET_COOKIE);
        assertThat(cookies).as("GET /api/csrf debe crear la sesión").isNotEmpty();

        HttpHeaders cabeceras = new HttpHeaders();
        cabeceras.setContentType(MediaType.APPLICATION_JSON);
        cabeceras.add(HttpHeaders.COOKIE, cookies.get(0).split(";", 2)[0]);
        cabeceras.add(String.valueOf(csrf.getBody().get("headerName")), String.valueOf(csrf.getBody().get("token")));

        ResponseEntity<String> respuesta = rest.exchange("/api/auth/login", HttpMethod.POST,
                new HttpEntity<>("{malformado", cabeceras), String.class);

        assertThat(respuesta.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(respuesta.getBody())
                .doesNotContain("\"trace\"")
                .doesNotContain("JSON parse error");
    }
}
