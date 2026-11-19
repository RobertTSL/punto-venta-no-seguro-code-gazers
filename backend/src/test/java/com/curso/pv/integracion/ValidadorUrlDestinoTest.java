package com.curso.pv.integracion;

import com.curso.pv.integracion.ValidadorUrlDestino.DestinoNoPermitidoException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetAddress;
import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Reglas del validador SSRF. DNS simulado: no necesita internet. */
class ValidadorUrlDestinoTest {

    // example.com -> IP publica; interno.example.com -> 10.0.0.5 (dominio permitido que apunta adentro)
    private final ValidadorUrlDestino validador = new ValidadorUrlDestino(
            "example.com, interno.example.com",
            host -> switch (host) {
                case "example.com" -> new InetAddress[]{InetAddress.getByAddress(new byte[]{93, (byte) 184, (byte) 216, 34})};
                case "interno.example.com" -> new InetAddress[]{InetAddress.getByName("10.0.0.5")};
                default -> InetAddress.getAllByName(host);
            });

    @Test
    void permite_un_host_de_la_allowlist_por_https() {
        URI uri = validador.validar("https://example.com/ruta?x=1");
        assertEquals("example.com", uri.getHost());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {
            // loopback y variantes de escritura
            "http://localhost:8080/api/diagnostico", "http://127.0.0.1/", "http://127.1/", "http://0.0.0.0/",
            "http://2130706433/", "http://0x7f000001/", "http://0177.0.0.1/", "http://[::1]/",
            "http://[::ffff:127.0.0.1]/", "https://127.0.0.1/",
            // metadatos de la nube y redes privadas
            "http://169.254.169.254/latest/meta-data/", "https://169.254.169.254/",
            "http://10.0.0.5/", "http://172.16.0.1/", "http://192.168.1.1/", "https://10.0.0.5/",
            // esquemas peligrosos
            "file:///etc/passwd", "ftp://example.com/", "gopher://example.com/", "http://example.com/",
            // trucos de parseo
            "https://example.com@127.0.0.1/", "https://127.0.0.1#@example.com/",
            "https://example.com.evil.com/", "https://evil.com/example.com",
            "https://example.com\\@127.0.0.1/",
            // puertos
            "https://example.com:8443/", "https://example.com:80/",
            // dominio permitido que resuelve a una IP interna
            "https://interno.example.com/"})
    void bloquea_destinos_peligrosos(String url) {
        assertThrows(DestinoNoPermitidoException.class, () -> validador.validar(url));
    }

    @Test
    void clasifica_bien_las_ip_internas_y_publicas() throws Exception {
        for (String ip : new String[]{"127.0.0.1", "10.1.2.3", "172.31.0.1", "192.168.0.9", "169.254.169.254",
                "0.0.0.0", "100.100.0.1", "198.18.0.1", "224.0.0.1", "255.255.255.255", "::1", "fe80::1", "fd12::1"}) {
            assertTrue(ValidadorUrlDestino.esDireccionInterna(InetAddress.getByName(ip)), ip + " debia ser interna");
        }
        for (String ip : new String[]{"8.8.8.8", "93.184.216.34", "172.32.0.1", "100.63.0.1", "2606:4700:4700::1111"}) {
            assertFalse(ValidadorUrlDestino.esDireccionInterna(InetAddress.getByName(ip)), ip + " debia ser publica");
        }
    }
}
