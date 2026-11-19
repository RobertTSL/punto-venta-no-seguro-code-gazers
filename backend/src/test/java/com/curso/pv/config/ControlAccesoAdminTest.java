package com.curso.pv.config;

import com.curso.pv.reporte.ReporteControlador;
import com.curso.pv.reporte.ReporteServicio;
import com.curso.pv.recurso.SaludController;
import com.curso.pv.security.UsuariosDetailsService;
import com.curso.pv.usuario.UsuarioControlador;
import com.curso.pv.usuario.UsuarioServicio;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.junit.jupiter.web.SpringJUnitWebConfig;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Broken Access Control: los endpoints sensibles deben exigir sesion Y rol ADMIN en el SERVIDOR.
 *
 * Usa la cadena de seguridad REAL (SecurityConfig) con controladores reales y servicios simulados,
 * asi que NO necesita MySQL ni Docker.
 *
 * PARA VERLO EN ROJO: en SecurityConfig cambia  .hasAuthority("ROL_ADMIN")  por  .permitAll()
 * y corre  ./mvnw test -Dtest=ControlAccesoAdminTest
 */
@SpringJUnitWebConfig(ControlAccesoAdminTest.Contexto.class)
class ControlAccesoAdminTest {

    @Configuration
    @EnableWebMvc
    @EnableWebSecurity
    @Import(SecurityConfig.class)
    static class Contexto {
        @Bean UsuariosDetailsService usuariosDetailsService() { return Mockito.mock(UsuariosDetailsService.class); }
        @Bean ConfiguracionRepositorio configuracionRepositorio() { return Mockito.mock(ConfiguracionRepositorio.class); }
        @Bean ConfiguracionConsultasInseguras configuracionConsultas() { return Mockito.mock(ConfiguracionConsultasInseguras.class); }
        @Bean ConfiguracionControlador configuracionControlador(ConfiguracionRepositorio r, ConfiguracionConsultasInseguras c) {
            return new ConfiguracionControlador(r, c);
        }
        @Bean ReporteServicio reporteServicio() { return Mockito.mock(ReporteServicio.class); }
        @Bean ReporteControlador reporteControlador(ReporteServicio s) { return new ReporteControlador(s); }
        @Bean UsuarioServicio usuarioServicio() { return Mockito.mock(UsuarioServicio.class); }
        @Bean UsuarioControlador usuarioControlador(UsuarioServicio s) { return new UsuarioControlador(s); }
        @Bean SaludController saludController() { return new SaludController(); }
    }

    @Autowired
    WebApplicationContext contexto;

    MockMvc mvc;

    @BeforeEach
    void preparar() {
        mvc = MockMvcBuilders.webAppContextSetup(contexto).apply(springSecurity()).build();
    }

    private static RequestPostProcessor conRol(String rol) {
        return user("alguien").authorities(new SimpleGrantedAuthority(rol));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/api/diagnostico", "/api/configuracion", "/api/configuracion/categoria/PASARELA",
            "/api/reportes/base-datos", "/api/usuarios", "/actuator/env"})
    void sin_sesion_responde_401(String ruta) throws Exception {
        mvc.perform(get(ruta)).andExpect(status().isUnauthorized());
    }

    @ParameterizedTest
    @ValueSource(strings = {"/api/diagnostico", "/api/configuracion", "/api/configuracion/categoria/PASARELA",
            "/api/reportes/base-datos", "/api/usuarios", "/actuator/env"})
    void con_rol_vendedor_responde_403(String ruta) throws Exception {
        mvc.perform(get(ruta).with(conRol("ROL_VENDEDOR"))).andExpect(status().isForbidden());
    }

    // El camino feliz: el ADMIN sigue pudiendo usar sus pantallas
    @ParameterizedTest
    @ValueSource(strings = {"/api/diagnostico", "/api/configuracion", "/api/reportes/base-datos", "/api/usuarios"})
    void con_rol_admin_responde_200(String ruta) throws Exception {
        mvc.perform(get(ruta).with(conRol("ROL_ADMIN"))).andExpect(status().isOk());
    }

    // Lo que NO es sensible sigue publico (no rompimos el resto del POS)
    @Test
    void salud_sigue_publica() throws Exception {
        mvc.perform(get("/api/salud")).andExpect(status().isOk());
    }
}
