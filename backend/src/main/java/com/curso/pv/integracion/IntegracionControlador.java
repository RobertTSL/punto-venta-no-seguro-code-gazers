package com.curso.pv.integracion;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/integraciones")
public class IntegracionControlador {

    private final IntegracionServicio servicio;

    public IntegracionControlador(IntegracionServicio servicio) {
        this.servicio = servicio;
    }

    // La URL ya no se usa a ciegas: el servicio la valida (allowlist + rangos internos).
    // Si se bloquea, se responde 403 en vez de 200.
    @PostMapping("/consultar-url")
    public ResponseEntity<Map<String, Object>> consultar(@RequestParam String url) {
        return responder(servicio.consultarUrl(url));
    }

    @PostMapping("/enviar")
    public ResponseEntity<Map<String, Object>> enviar(@RequestParam String url, @RequestBody Map<String, Object> cuerpo) {
        return responder(servicio.enviarPost(url, cuerpo));
    }

    @GetMapping("/verificar-host")
    public ResponseEntity<Map<String, Object>> verificar(@RequestParam String host, @RequestParam(defaultValue = "443") Integer puerto) {
        return responder(servicio.verificarHost(host, puerto));
    }

    private static ResponseEntity<Map<String, Object>> responder(Map<String, Object> resultado) {
        HttpStatus estado = IntegracionServicio.BLOQUEADO.equals(resultado.get("estado"))
                ? HttpStatus.FORBIDDEN
                : HttpStatus.OK;
        return ResponseEntity.status(estado).body(resultado);
    }
}
