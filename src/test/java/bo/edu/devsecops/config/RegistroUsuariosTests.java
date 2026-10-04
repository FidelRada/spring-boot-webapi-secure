package bo.edu.devsecops.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Credenciales externas: sin variable de entorno o con un valor que no
 * es bcrypt, el usuario no existe; nunca se usa una contraseña por defecto ni un hash conocido.
 */
class RegistroUsuariosTests {

    private static final String HASH_ADMIN_PRUEBA =
            "$2a$10$QaqRNRsMuukuwDEYAofGaOKENzGwd3Rrmz.2U473DlatNPioB21dS";

    private final SecurityConfig config = new SecurityConfig();

    @Test
    @DisplayName("Sin LAB_*_PASSWORD_HASH no se registra ningún usuario")
    void sinHashesNoHayUsuarios() {
        UserDetailsService usuarios = config.userDetailsService(new LabSecurityProperties("", null));
        assertThatThrownBy(() -> usuarios.loadUserByUsername("admin")).isInstanceOf(UsernameNotFoundException.class);
        assertThatThrownBy(() -> usuarios.loadUserByUsername("ana")).isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    @DisplayName("Un valor en claro o con {noop} se rechaza")
    void hashNoBcryptSeRechaza() {
        UserDetailsService usuarios = config.userDetailsService(
                new LabSecurityProperties("{noop}Admin123!", "Admin123!"));
        assertThatThrownBy(() -> usuarios.loadUserByUsername("admin")).isInstanceOf(UsernameNotFoundException.class);
        assertThatThrownBy(() -> usuarios.loadUserByUsername("ana")).isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    @DisplayName("Un hash bcrypt, con o sin prefijo, registra el usuario con {bcrypt}")
    void hashBcryptSeAcepta() {
        UserDetailsService usuarios = config.userDetailsService(
                new LabSecurityProperties(HASH_ADMIN_PRUEBA, "{bcrypt}" + HASH_ADMIN_PRUEBA));
        assertThat(usuarios.loadUserByUsername("admin").getPassword()).isEqualTo("{bcrypt}" + HASH_ADMIN_PRUEBA);
        assertThat(usuarios.loadUserByUsername("ana").getPassword()).isEqualTo("{bcrypt}" + HASH_ADMIN_PRUEBA);
    }
}
