# ADR-002 · Prevención de SSRF con allowlist y bloqueo de rangos internos

**Estado:** Aceptado · **Familia:** SSRF

## Contexto
`/api/integraciones/*` hacía peticiones HTTP a la URL que mandaba el usuario, sin validar. Permite leer servicios internos (`localhost`, red de Docker, metadatos de la nube) y escanear puertos.

## Decisión
`ValidadorUrlDestino` valida la URL **antes** de salir a la red. Se bloquea si falla cualquiera de estas reglas:
1. Esquema distinto de `https`.
2. Usuario/contraseña dentro de la URL.
3. Puerto distinto de 443.
4. Host fuera de la **allowlist** (`app.integraciones.hosts-permitidos`, por defecto `example.com`).
5. El DNS del host resuelve a una IP no pública (loopback, privada, link-local `169.254.x.x`, CGNAT, multicast, etc.).

Además: el cliente HTTP **no sigue redirecciones** y tiene timeouts; la petición se hace a la `URI` ya validada; los errores devuelven un mensaje genérico (el motivo real solo va al log). El mismo validador protege `consultar-url`, `enviar` y `verificar-host`. Una URL bloqueada responde **403**.

## Alternativas consideradas
- **Blocklist** (bloquear `localhost`, `127.0.0.1`...): descartada. Se evade con `2130706433`, `0x7f000001`, `127.1`, `[::1]`, un dominio que resuelve a 127.0.0.1, etc. La allowlist es "denegar por defecto".
- **Solo bloquear rangos IP:** insuficiente sin allowlist, porque deja salir a cualquier sitio de internet.
- **Eliminar la función de integraciones:** no, el negocio la usa (verificar proveedores).

## Consecuencias
- (+) Un atacante no puede alcanzar la red interna ni usar al POS de proxy o escáner.
- (+) Para habilitar un proveedor basta agregar su dominio en configuración, sin recompilar.
- (−) Riesgo residual: *DNS rebinding* (se resuelve el DNS dos veces). Mitigación futura: conectar a la IP ya validada.
- (−) Solo HTTPS en 443: proveedores en otros puertos requieren decisión explícita.
