package com.curso.pv.integracion;

import com.curso.pv.integracion.ValidadorUrlDestino.DestinoNoPermitidoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

@Service
public class IntegracionServicio {

    private static final Logger log = LoggerFactory.getLogger(IntegracionServicio.class);

    static final String BLOQUEADO = "BLOQUEADO";

    private final ValidadorUrlDestino validador;
    private final RestTemplate cliente = crearClienteSeguro();

    public IntegracionServicio(ValidadorUrlDestino validador) {
        this.validador = validador;
    }

    /**
     * FIX (SSRF): cliente HTTP que NO sigue redirecciones. Si no, un servidor permitido
     * podria responder "302 -> http://169.254.169.254/..." y saltarse la validacion.
     * Ademas pone timeouts para que no se pueda usar para colgar el servidor.
     */
    static RestTemplate crearClienteSeguro() {
        HttpClient http = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(3))
                .build();
        JdkClientHttpRequestFactory fabrica = new JdkClientHttpRequestFactory(http);
        fabrica.setReadTimeout(Duration.ofSeconds(5));
        return new RestTemplate(fabrica);
    }

    /**
     * FIX (SSRF): antes de salir a la red, la URL pasa por el validador (allowlist + bloqueo
     * de rangos internos). Se hace la peticion a la URI ya validada, no al texto original.
     */
    public Map<String, Object> consultarUrl(String url) {
        log.info("Consultando URL externa solicitada por el cliente: {}", url);

        URI destino;
        try {
            destino = validador.validar(url);                         // <-- DEFENSA SSRF
        } catch (DestinoNoPermitidoException bloqueo) {
            return bloqueado(url, bloqueo);
        }

        Map<String, Object> respuesta = new HashMap<>();
        try {
            String cuerpo = cliente.getForObject(destino, String.class);
            respuesta.put("url", url);
            respuesta.put("estado", "OK");
            respuesta.put("contenido", cuerpo);
            respuesta.put("longitud", cuerpo != null ? cuerpo.length() : 0);
        } catch (Exception error) {
            respuesta.put("url", url);
            respuesta.put("estado", "ERROR");
            // Mensaje generico: el detalle del error revelaria la topologia interna
            respuesta.put("error", "No se pudo consultar el destino");
        }
        return respuesta;
    }

    /** Mismo control para el envio por POST. */
    public Map<String, Object> enviarPost(String url, Map<String, Object> cuerpo) {
        log.info("POST a URL externa solicitada por el cliente: {}", url);

        URI destino;
        try {
            destino = validador.validar(url);                         // <-- DEFENSA SSRF
        } catch (DestinoNoPermitidoException bloqueo) {
            return bloqueado(url, bloqueo);
        }

        Map<String, Object> respuesta = new HashMap<>();
        try {
            String resultado = cliente.postForObject(destino, cuerpo, String.class);
            respuesta.put("url", url);
            respuesta.put("estado", "OK");
            respuesta.put("contenido", resultado);
        } catch (Exception error) {
            respuesta.put("url", url);
            respuesta.put("estado", "ERROR");
            respuesta.put("error", "No se pudo consultar el destino");
        }
        return respuesta;
    }

    /**
     * Antes servia para escanear puertos internos. Ahora el host/puerto pasan por el mismo
     * validador: solo hosts de la allowlist y solo el puerto 443.
     */
    public Map<String, Object> verificarHost(String host, Integer puerto) {
        String url = "https://" + host + ":" + puerto + "/";

        URI destino;
        try {
            destino = validador.validar(url);                         // <-- DEFENSA SSRF
        } catch (DestinoNoPermitidoException bloqueo) {
            return bloqueado(url, bloqueo);
        }

        Map<String, Object> respuesta = new HashMap<>();
        respuesta.put("host", host);
        respuesta.put("puerto", puerto);
        try {
            cliente.getForObject(destino, String.class);
            respuesta.put("abierto", true);
        } catch (Exception error) {
            respuesta.put("abierto", false);
        }
        return respuesta;
    }

    /** Respuesta uniforme y generica: no revela POR QUE se bloqueo (eso va solo al log). */
    private Map<String, Object> bloqueado(String url, DestinoNoPermitidoException bloqueo) {
        String urlLimpia = url == null ? "null" : url.replaceAll("[\\r\\n]", "_");
        log.warn("SSRF bloqueado ({}): {}", bloqueo.getMessage(), urlLimpia);

        Map<String, Object> respuesta = new HashMap<>();
        respuesta.put("estado", BLOQUEADO);
        respuesta.put("error", "Destino no permitido");
        return respuesta;
    }
}
