package bo.edu.devsecops.config;

import jakarta.servlet.DispatcherType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.regex.Pattern;

/**
 * Seguridad de la API (change remediate-app-vulnerabilities, design.md D3 y D4):
 * denegación por defecto, /api/admin/** y /actuator/** solo para ADMIN, HTTP Basic,
 * CSRF activo con token de sesión y cabeceras de defensa (CSP, nosniff).
 */
@Configuration
@EnableConfigurationProperties(LabSecurityProperties.class)
public class SecurityConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityConfig.class);

    private static final String PREFIJO_BCRYPT = "{bcrypt}";
    private static final Pattern HASH_BCRYPT = Pattern.compile("^\\$2[aby]?\\$\\d{2}\\$[./A-Za-z0-9]{53}$");

    private static final String CSP =
            "default-src 'none'; style-src 'self'; frame-ancestors 'none'";

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth
                        // Los reenvíos a /error conservan su código (404/400) en vez de 401.
                        .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/products/search", "/api/csrf", "/actuator/health")
                        .permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/comments/preview", "/api/auth/login")
                        .permitAll()
                        .requestMatchers("/api/admin/**", "/actuator/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults())
                // CSRF activo (por defecto) con HttpSessionCsrfTokenRepository; el token se
                // obtiene con GET /api/csrf y se envía en la cabecera X-CSRF-TOKEN.
                .csrf(Customizer.withDefaults())
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp.policyDirectives(CSP)))
                .build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        DelegatingPasswordEncoder encoder =
                (DelegatingPasswordEncoder) PasswordEncoderFactories.createDelegatingPasswordEncoder();
        // Acepta también hashes bcrypt sin el prefijo {bcrypt} (p. ej. generados con htpasswd).
        encoder.setDefaultPasswordEncoderForMatches(new BCryptPasswordEncoder());
        return encoder;
    }

    @Bean
    UserDetailsService userDetailsService(LabSecurityProperties propiedades) {
        InMemoryUserDetailsManager usuarios = new InMemoryUserDetailsManager();
        // Si falta un hash (o no es bcrypt), ese usuario no se registra y la aplicación arranca igual
        // (el healthcheck del contenedor no requiere usuarios).
        if (!registrar(usuarios, "admin", propiedades.adminPasswordHash(), "ADMIN")) {
            LOGGER.warn("Usuario 'admin' no registrado: falta LAB_ADMIN_PASSWORD_HASH");
        }
        if (!registrar(usuarios, "ana", propiedades.userPasswordHash(), "USER")) {
            LOGGER.warn("Usuario 'ana' no registrado: falta LAB_USER_PASSWORD_HASH");
        }
        return usuarios;
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration configuracion) throws Exception {
        return configuracion.getAuthenticationManager();
    }

    /**
     * Registra el usuario solo si recibe un hash bcrypt bien formado (con o sin el prefijo
     * {bcrypt}). Un valor vacío, en claro o con otro esquema ({noop}, {MD5}...) se rechaza:
     * el usuario queda deshabilitado en lugar de aceptar una contraseña débil o conocida.
     */
    static boolean registrar(InMemoryUserDetailsManager usuarios, String nombre, String hash, String rol) {
        if (hash == null || hash.isBlank()) {
            return false;
        }
        String bcrypt = hash.startsWith(PREFIJO_BCRYPT) ? hash.substring(PREFIJO_BCRYPT.length()) : hash;
        if (!HASH_BCRYPT.matcher(bcrypt).matches()) {
            LOGGER.warn("Usuario '{}' no registrado: el hash recibido no es bcrypt", nombre);
            return false;
        }
        usuarios.createUser(User.withUsername(nombre).password(PREFIJO_BCRYPT + bcrypt).roles(rol).build());
        return true;
    }
}
