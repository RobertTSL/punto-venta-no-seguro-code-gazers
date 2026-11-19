package com.curso.pv.integracion;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * FIX (SSRF): decide si el servidor tiene permitido hacer una peticion a una URL.
 *
 * Reglas (si falla CUALQUIERA, se bloquea):
 *   1. Solo esquema https (adios file://, ftp://, gopher://, http://localhost...).
 *   2. Sin usuario/contrasena embebidos en la URL (https://permitido@malo/).
 *   3. Solo el puerto 443.
 *   4. El host debe estar en la ALLOWLIST (app.integraciones.hosts-permitidos).
 *   5. Todas las IP a las que resuelve el host deben ser publicas: se bloquean
 *      loopback, redes privadas, link-local (169.254.x.x = metadatos de la nube),
 *      CGNAT, multicast, etc. Es una segunda barrera por si un dominio permitido
 *      apunta (o es redirigido por DNS) a una IP interna.
 */
@Component
public class ValidadorUrlDestino {

    /**
     * Se lanza cuando el destino no esta permitido. IntegracionServicio SIEMPRE la captura
     * y la convierte en una respuesta "BLOQUEADO" (si saliera al controlador, el manejador
     * global de errores la devolveria con stack trace).
     */
    public static class DestinoNoPermitidoException extends RuntimeException {
        public DestinoNoPermitidoException(String motivo) {
            super(motivo);
        }
    }

    /** Resolucion DNS inyectable para poder probar sin red. */
    @FunctionalInterface
    interface Resolutor {
        InetAddress[] resolver(String host) throws UnknownHostException;
    }

    private final Set<String> hostsPermitidos;
    private final Resolutor resolutor;

    @Autowired
    public ValidadorUrlDestino(
            @Value("${app.integraciones.hosts-permitidos:example.com}") String hostsPermitidos) {
        this(hostsPermitidos, InetAddress::getAllByName);
    }

    ValidadorUrlDestino(String hostsPermitidos, Resolutor resolutor) {
        this.hostsPermitidos = Arrays.stream(hostsPermitidos.split(","))
                .map(h -> h.trim().toLowerCase(Locale.ROOT))
                .filter(h -> !h.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
        this.resolutor = resolutor;
    }

    /** Devuelve la URI ya validada (usar ESTA para hacer la peticion) o lanza DestinoNoPermitidoException. */
    public URI validar(String url) {
        if (url == null || url.isBlank()) {
            throw new DestinoNoPermitidoException("url vacia");
        }

        URI uri;
        try {
            uri = new URI(url.trim());
        } catch (Exception e) {
            throw new DestinoNoPermitidoException("url mal formada");
        }

        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            throw new DestinoNoPermitidoException("esquema no permitido");
        }
        if (uri.getUserInfo() != null) {
            throw new DestinoNoPermitidoException("credenciales en la url");
        }
        if (uri.getPort() != -1 && uri.getPort() != 443) {
            throw new DestinoNoPermitidoException("puerto no permitido");
        }

        String host = uri.getHost();
        if (host == null) {
            throw new DestinoNoPermitidoException("sin host");
        }
        host = host.toLowerCase(Locale.ROOT);
        if (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }
        if (!hostsPermitidos.contains(host)) {
            throw new DestinoNoPermitidoException("host fuera de la allowlist");
        }

        InetAddress[] direcciones;
        try {
            direcciones = resolutor.resolver(host);
        } catch (UnknownHostException e) {
            throw new DestinoNoPermitidoException("host no resuelve");
        }
        for (InetAddress direccion : direcciones) {
            if (esDireccionInterna(direccion)) {
                throw new DestinoNoPermitidoException("resuelve a una direccion interna");
            }
        }
        return uri;
    }

    /** true si la IP NO es de internet publica (loopback, privada, link-local, etc.). */
    static boolean esDireccionInterna(InetAddress a) {
        if (a.isAnyLocalAddress() || a.isLoopbackAddress() || a.isLinkLocalAddress()
                || a.isSiteLocalAddress() || a.isMulticastAddress()) {
            return true;                                   // 0.0.0.0, 127/8, ::1, 169.254/16, 10/8, 172.16/12, 192.168/16...
        }
        byte[] b = a.getAddress();
        if (b.length == 4) {
            int p0 = b[0] & 0xFF;
            int p1 = b[1] & 0xFF;
            return p0 == 0                                  // 0.0.0.0/8
                    || (p0 == 100 && p1 >= 64 && p1 <= 127) // 100.64.0.0/10 (CGNAT)
                    || (p0 == 198 && (p1 == 18 || p1 == 19))// 198.18.0.0/15 (pruebas de red)
                    || p0 >= 240;                           // 240.0.0.0/4 y broadcast
        }
        // IPv6: fc00::/7 (direcciones locales unicas, el "10.x" de IPv6)
        return (b[0] & 0xFE) == 0xFC;
    }
}
