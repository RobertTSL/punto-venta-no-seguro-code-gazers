package com.curso.pv.config;

import com.curso.pv.security.CodificadorEnClaro;
import com.curso.pv.security.UsuariosDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain cadenaDeSeguridad(HttpSecurity http,
                                                 HttpSessionSecurityContextRepository contextoRepositorio) throws Exception {
        http
                // VULNERABILIDAD: sin proteccion CSRF
                .csrf(csrf -> csrf.disable())
                .cors(cors -> { })
                // VULNERABILIDAD: sin CSP ni demas cabeceras de seguridad
                .headers(headers -> { })

                // VULNERABILIDAD: la sesion no se renueva al iniciar sesion (session fixation)
                .sessionManagement(sesion -> sesion
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .sessionFixation(fixacion -> { }))

                // VULNERABILIDAD: se reutiliza la sesion existente sin validar su origen
                .securityContext(contexto -> contexto.securityContextRepository(contextoRepositorio))

                // Sin sesion -> 401 (sin el popup de HTTP Basic del navegador).
                // Con sesion pero sin permiso -> 403 (lo decide Spring Security).
                .exceptionHandling(errores -> errores
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))

                // FIX (Broken Access Control): los endpoints sensibles exigen sesion Y rol
                // ADMIN, validados en el SERVIDOR. El rol sale de la sesion (cargado desde la
                // BD al iniciar sesion), nunca de lo que mande el navegador.
                // El orden importa: gana la primera regla que coincide.
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(                                      // <-- DEFENSA BAC
                                "/api/diagnostico",
                                "/api/configuracion", "/api/configuracion/**",
                                "/api/reportes/base-datos",
                                "/api/usuarios", "/api/usuarios/**",
                                "/actuator/**").hasAuthority("ROL_ADMIN")      // <-- DEFENSA BAC
                        // Resto de la API: sin cambios (fuera del alcance de este avance)
                        .requestMatchers("/api/**").permitAll()
                        .requestMatchers("/**").permitAll()
                        .anyRequest().permitAll())

                // VULNERABILIDAD: HTTP Basic habilitado, las credenciales viajan en cada peticion
                .httpBasic(basic -> { })
                .formLogin(form -> form.disable())
                .logout(logout -> logout.disable());

        return http.build();
    }

    @Bean
    public HttpSessionSecurityContextRepository contextoRepositorio() {
        // VULNERABILIDAD: la sesion se guarda tal cual en el contenedor, sin cifrar
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    public SecurityContextRepository securityContextRepository(HttpSessionSecurityContextRepository repositorio) {
        return repositorio;
    }

    @Bean
    public DaoAuthenticationProvider proveedorDeAutenticacion(UsuariosDetailsService detailsService) {
        DaoAuthenticationProvider proveedor = new DaoAuthenticationProvider(detailsService);
        // VULNERABILIDAD: comparacion de contrasenas en texto plano
        proveedor.setPasswordEncoder(new CodificadorEnClaro());
        return proveedor;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}