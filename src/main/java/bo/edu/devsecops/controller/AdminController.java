package bo.edu.devsecops.controller;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

/** Solo accesible con rol ADMIN (regla /api/admin/** de SecurityConfig). */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final JdbcTemplate jdbcTemplate;

    public AdminController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/users/{id}")
    public Map<String, Object> findUser(@PathVariable Long id) {
        try {
            return jdbcTemplate.queryForMap(
                    "SELECT id, username, email, role FROM users WHERE id = ?", id);
        } catch (EmptyResultDataAccessException e) {
            // 404 sin detalles internos.
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuario no encontrado");
        }
    }
}
