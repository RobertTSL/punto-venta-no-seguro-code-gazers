package com.curso.pv.auth;

import com.curso.pv.log.ServicioAuditoria;
import com.curso.pv.usuario.Usuario;
import com.curso.pv.usuario.UsuarioConsultasInseguras;
import com.curso.pv.usuario.UsuarioRepositorio;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Broken Access Control (escalada de privilegios): el auto-registro no puede crear ADMIN.
 * Sin esto, cualquiera se registra como ADMIN y la regla de SecurityConfig no sirve de nada.
 *
 * PARA VERLO EN ROJO: en AuthServicio.registrar cambia
 *     String rol = "VENDEDOR";
 * por
 *     String rol = datos.getOrDefault("rol", "VENDEDOR");
 */
class RegistroNoConfiaEnElRolDelClienteTest {

    @Test
    void registro_con_rol_ADMIN_en_el_cuerpo_crea_un_VENDEDOR() {
        UsuarioRepositorio repositorio = mock(UsuarioRepositorio.class);
        when(repositorio.save(any(Usuario.class))).thenAnswer(inv -> inv.getArgument(0));
        UsuarioConsultasInseguras consultas = mock(UsuarioConsultasInseguras.class);
        when(consultas.porUsername("intruso")).thenReturn(null);
        AuthServicio servicio = new AuthServicio(repositorio, consultas, mock(ServicioAuditoria.class));

        servicio.registrar(Map.of("username", "intruso", "password", "x", "rol", "ADMIN"),
                new MockHttpServletRequest());

        ArgumentCaptor<Usuario> guardado = ArgumentCaptor.forClass(Usuario.class);
        verify(repositorio).save(guardado.capture());
        assertEquals("VENDEDOR", guardado.getValue().getRol());
    }
}
