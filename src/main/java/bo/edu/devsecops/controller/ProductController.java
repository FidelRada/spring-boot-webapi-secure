package bo.edu.devsecops.controller;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    /** Consulta fija: el texto del usuario solo viaja como parámetro enlazado. */
    private static final String CONSULTA_BUSQUEDA =
            "SELECT id, name, price FROM products WHERE name LIKE ? ESCAPE '\\'";

    private final JdbcTemplate jdbcTemplate;

    public ProductController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/search")
    public List<Map<String, Object>> search(@RequestParam(defaultValue = "") String name) {
        String literal = escaparComodines(name);
        return jdbcTemplate.queryForList(CONSULTA_BUSQUEDA, "%" + literal + "%");
    }

    /** Los comodines de LIKE escritos por el usuario se tratan como caracteres literales. */
    private static String escaparComodines(String texto) {
        return texto.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
    }
}
