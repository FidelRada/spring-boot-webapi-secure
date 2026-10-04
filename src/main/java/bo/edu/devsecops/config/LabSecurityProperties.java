package bo.edu.devsecops.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Hashes bcrypt de las contraseñas de los usuarios del laboratorio. Llegan por variables de
 * entorno (LAB_ADMIN_PASSWORD_HASH, LAB_USER_PASSWORD_HASH); nunca se versionan en claro.
 */
@ConfigurationProperties(prefix = "lab.security")
public record LabSecurityProperties(String adminPasswordHash, String userPasswordHash) {
}
