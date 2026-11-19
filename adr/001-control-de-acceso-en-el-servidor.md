# ADR-001 · El control de acceso se decide en el servidor

**Estado:** Aceptado · **Familia:** Broken Access Control

## Contexto
La API era totalmente pública (`SecurityConfig`: `/api/**` → `permitAll`). La única "protección" era un guard en React que lee el rol de `localStorage`, que el usuario puede editar. Además el auto-registro aceptaba `"rol":"ADMIN"` del cliente.

## Decisión
1. En `SecurityConfig` las rutas sensibles (`/api/diagnostico`, `/api/configuracion/**`, `/api/reportes/base-datos`, `/api/usuarios/**`, `/actuator/**`) exigen `hasAuthority("ROL_ADMIN")`. Sin sesión → **401**; con sesión sin permiso → **403**.
2. El rol sale de la sesión del servidor (cargado de la BD al iniciar sesión). El cliente nunca decide su rol: `AuthServicio.registrar` siempre crea `VENDEDOR`.
3. El guard de React se conserva solo como mejora de interfaz, no como control de seguridad.

Se usa `hasAuthority("ROL_ADMIN")` y no `hasRole("ADMIN")` porque `hasRole` antepone `ROLE_` y este proyecto usa el prefijo `ROL_` (`CodificadorEnClaro.autoridadesDe`).

## Alternativas consideradas
- **Solo esconder las vistas en React:** descartada, el atacante llama a la API directo con `curl`.
- **`@PreAuthorize` en cada controlador:** válida, pero el `ManejadorGlobalDeErrores` atrapa toda `Exception` y devolvería el `AccessDeniedException` como 200 con stack trace. La regla en el filtro de seguridad corta antes de llegar al controlador.
- **Deny by default (`anyRequest().authenticated()`):** es la meta ideal, pero toca todo el POS y queda fuera de este avance. Queda como recomendación.

## Consecuencias
- (+) El control no se puede saltar manipulando el navegador; es fácil de auditar (una sola lista).
- (+) Autenticación (¿quién eres?) y autorización (¿qué puedes hacer?) quedan separadas: 401 vs 403.
- (−) Cada ruta nueva sensible debe agregarse a la lista, mientras no exista deny by default.
- (−) Un VENDEDOR que abra *Diagnóstico* ya no verá datos de configuración (devuelve 403).
