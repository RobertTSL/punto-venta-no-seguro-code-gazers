package com.curso.pv.integracion;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestTemplate;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * SSRF: el backend NO debe poder ser usado para leer recursos internos.
 * Levanta un "servicio interno" real en 127.0.0.1 (como lo seria el propio backend, MySQL o Adminer)
 * y comprueba que /api/integraciones no lo alcanza. No necesita Docker ni internet.
 *
 * PARA VERLO EN ROJO: en IntegracionServicio.consultarUrl cambia
 *     destino = validador.validar(url);
 * por
 *     destino = URI.create(url);
 */
class IntegracionServicioSsrfTest {

    static final String SECRETO = "SECRETO-INTERNO-NO-DEBE-SALIR";

    HttpServer interno;    // responde el secreto
    HttpServer redirector; // responde 302 hacia el servicio interno

    @BeforeEach
    void levantarServidores() throws Exception {
        interno = servidor(200, SECRETO, null);
        redirector = servidor(302, "", "http://127.0.0.1:" + interno.getAddress().getPort() + "/");
    }

    @AfterEach
    void apagar() {
        interno.stop(0);
        redirector.stop(0);
    }

    private static HttpServer servidor(int codigo, String cuerpo, String location) throws Exception {
        HttpServer s = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        s.createContext("/", exchange -> {
            byte[] bytes = cuerpo.getBytes(StandardCharsets.UTF_8);
            if (location != null) exchange.getResponseHeaders().add("Location", location);
            exchange.sendResponseHeaders(codigo, bytes.length == 0 ? -1 : bytes.length);
            if (bytes.length > 0) exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        s.start();
        return s;
    }

    private IntegracionServicio servicio() {
        return new IntegracionServicio(new ValidadorUrlDestino("example.com"));
    }

    @Test
    void no_alcanza_un_servicio_interno_por_127_0_0_1() {
        Map<String, Object> r = servicio().consultarUrl("http://127.0.0.1:" + interno.getAddress().getPort() + "/");

        assertEquals("BLOQUEADO", r.get("estado"));
        assertFalse(r.toString().contains(SECRETO), "el secreto interno salio por SSRF");
    }

    @Test
    void no_alcanza_un_servicio_interno_por_localhost() {
        Map<String, Object> r = servicio().consultarUrl("http://localhost:" + interno.getAddress().getPort() + "/");

        assertEquals("BLOQUEADO", r.get("estado"));
        assertFalse(r.toString().contains(SECRETO), "el secreto interno salio por SSRF");
    }

    @Test
    void verificar_host_ya_no_sirve_para_escanear_puertos_internos() {
        Map<String, Object> r = servicio().verificarHost("127.0.0.1", interno.getAddress().getPort());

        assertEquals("BLOQUEADO", r.get("estado"));
    }

    // El cliente HTTP no debe seguir redirecciones (si no, un host permitido podria redirigir a uno interno)
    @Test
    void el_cliente_http_no_sigue_redirecciones() {
        RestTemplate cliente = IntegracionServicio.crearClienteSeguro();
        String cuerpo = null;
        try {
            cuerpo = cliente.getForObject(URI.create("http://127.0.0.1:" + redirector.getAddress().getPort() + "/"), String.class);
        } catch (Exception ignorada) {
            // una 3xx sin cuerpo puede terminar en excepcion: tambien es "no seguir la redireccion"
        }
        assertFalse(String.valueOf(cuerpo).contains(SECRETO), "el cliente siguio la redireccion hacia el servicio interno");
    }
}
