# Checklist U2 (parcial: Broken Access Control y SSRF)

| Control | Familia | OWASP 2021 | STRIDE | Estado en el POS |
|---|---|---|---|---|
| Autenticación exigida en endpoints sensibles | BAC | A01 | I, E | ✅ Corregido (`SecurityConfig`) |
| Autorización por rol validada en el servidor | BAC | A01 | E | ✅ Corregido (`hasAuthority("ROL_ADMIN")`) |
| No confiar en el rol que manda el cliente (registro) | BAC | A01 | E | ✅ Corregido (`AuthServicio`) |
| Guard de rol en cliente solo como UX | BAC | A01 | E | ✅ Aceptado (ADR-001) |
| Deny by default en toda la API | BAC | A01 | E | ❌ Pendiente (Unidad 3) |
| Actuator restringido | BAC / Config | A01, A05 | I | ✅ Restringido a ADMIN |
| Allowlist de destinos salientes | SSRF | A10 | I, E | ✅ Corregido (`ValidadorUrlDestino`) |
| Bloqueo de IP privadas / loopback / link-local | SSRF | A10 | I, E | ✅ Corregido |
| Solo `https` y puerto 443 | SSRF | A10 | T | ✅ Corregido |
| Sin seguir redirecciones, con timeouts | SSRF | A10 | I | ✅ Corregido |
| Errores genéricos hacia el cliente | SSRF | A10 | I | ✅ Corregido |
| Protección contra DNS rebinding (conectar a la IP validada) | SSRF | A10 | I | ❌ Riesgo residual |
