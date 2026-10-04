package bo.edu.devsecops.controller;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Expone el token CSRF de la sesión para los clientes de la API (design.md D4):
 * GET /api/csrf → {"headerName":"X-CSRF-TOKEN","token":"..."} + cookie JSESSIONID.
 */
@RestController
public class CsrfController {

    @GetMapping("/api/csrf")
    public Map<String, String> csrf(CsrfToken csrfToken) {
        return Map.of("headerName", csrfToken.getHeaderName(), "token", csrfToken.getToken());
    }
}
