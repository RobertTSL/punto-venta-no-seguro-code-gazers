# Reporte de auditoría · Avance U2 (Broken Access Control y SSRF)

**Sistema:** punto-venta-no-seguro (Spring Boot 4.1 + Java 21 · React 19 · MySQL 8.4)
**Alcance de este reporte:** 2 de las 6 familias de la Unidad 2: *Broken Access Control* y *SSRF*.
**Rama:** `endurecimiento-u2` · **Herramientas de IA usadas:** _(declara aquí la herramienta, p. ej. Claude, y conserva tus prompts)_

> Las líneas citadas son del código **original** (antes del fix), rama `main`.

## Resumen

| ID | Familia | Hallazgo | Severidad | STRIDE | OWASP Top 10 (2021) | Estado |
|---|---|---|---|---|---|---|
| BAC-01 | Broken Access Control | Endpoints sensibles sin autenticación ni rol | **Crítica** | I, E | A01 | Corregido (PR 1) |
| BAC-02 | Broken Access Control | Auto-registro permite elegir el rol ADMIN | **Crítica** | E | A01 | Corregido (PR 1) |
| BAC-03 | Broken Access Control | El rol "se valida" solo en el navegador | Alta | E | A01 | Mitigado por BAC-01 (el servidor decide) |
| SSRF-01 | SSRF | `/api/integraciones/consultar-url` consulta cualquier URL | **Alta** | I, E | A10 | Corregido (PR 2) |
| SSRF-02 | SSRF | `/api/integraciones/enviar` hace POST a cualquier URL | Alta | T, E | A10 | Corregido (PR 2) |
| SSRF-03 | SSRF | `/api/integraciones/verificar-host` permite escanear puertos | Media | I | A10 | Corregido (PR 2) |



---

## BAC-01 · Endpoints sensibles sin autenticación ni rol

- **Dónde:** `SecurityConfig.java:39-43` (`/api/**` → `permitAll`), `ConfiguracionControlador.java:28` (`/api/configuracion`), `:41-67` (`/api/diagnostico`), `ReporteControlador.java:50` (`/api/reportes/base-datos`), `UsuarioControlador.java:16-19` (`/api/usuarios`), `application.yml:60-64` (Actuator expuesto).
- **Pasos para reproducir (sin sesión):**
  ```bash
  curl -s http://localhost:8080/api/diagnostico            # variables de entorno + usuario/clave de MySQL (root/root123)
  curl -s http://localhost:8080/api/configuracion          # secreto JWT, claves de la pasarela, clave del correo
  curl -s http://localhost:8080/api/reportes/base-datos    # estructura de la BD
  curl -s http://localhost:8080/api/usuarios               # todos los usuarios, con su contraseña
  ```
  
- **Impacto en el negocio:** cualquiera en internet obtiene las credenciales de la base de datos, las claves de cobro con tarjeta y la lista de usuarios con sus contraseñas. Con eso puede robar o alterar ventas, cobrar a nombre de la tienda y entrar como administrador.
- **Severidad (Crítica):** no requiere cuenta, se explota con un solo `curl` (facilidad máxima) y expone secretos que dan control total del sistema (impacto máximo).
- **STRIDE:** **I**nformation disclosure (se filtran secretos) y **E**levation of privilege (los secretos permiten actuar como admin).

## BAC-02 · Escalada de privilegios en el auto-registro

- **Dónde:** `AuthServicio.java:36` (`datos.getOrDefault("rol", ...)`) y `:57` (`usuario.setRol(rol)`); `Registro.jsx:12-14` y `:60` (el formulario manda `rol`).
- **Pasos para reproducir:**
  ```bash
  curl -s -X POST http://localhost:8080/api/auth/registro \
    -H 'Content-Type: application/json' \
    -d '{"username":"intruso","password":"x","rol":"ADMIN"}'
  # la respuesta trae "rol":"ADMIN"; ahora inicia sesión como intruso/x y tendrás vistas de administrador
  ```
- **Impacto:** cualquier persona se convierte en administrador. Sin corregir esto, el control de BAC-01 se salta creando una cuenta ADMIN.
- **Severidad (Crítica):** anónimo, un request, privilegio máximo.
- **STRIDE:** **E**levation of privilege.

## BAC-03 · El rol se confía al cliente

- **Dónde:** `App.jsx:21-32` (`RutaProtegida`), `ContextoAuth.jsx:8-17` y `:56` (el rol sale de `localStorage`), `Layout.jsx:21-23`.
- **Pasos para reproducir:** inicia sesión como `vendedor/vendedor` → DevTools → *Application → Local Storage → `pv_usuario`* → cambia `authorities` a `[{"authority":"ROL_ADMIN"}]` → recarga: aparece el menú **Usuarios** y la ruta `/usuarios` abre.
- **Impacto:** la barrera es solo visual. Antes del fix la API tampoco comprobaba nada, así que además los datos se leían.
- **Severidad (Alta):** requiere sesión (cualquier vendedor), un cambio en DevTools.
- **STRIDE:** **E**levation of privilege.
- **Remediación:** el control real pasa al servidor (BAC-01). El guard de React se queda solo como comodidad de interfaz.

---

## SSRF-01 · Consulta de URL arbitraria

- **Dónde:** `IntegracionControlador.java:22-26`, `IntegracionServicio.java:26-48` (`cliente.getForObject(url, ...)` con la URL tal cual), `Reportes.jsx:9` y `:35-44` (pantalla *Reportes → Verificar URL de proveedor*).
- **Pasos para reproducir:**
  ```bash
  # El backend consulta a sí mismo (localhost dentro del contenedor) y devuelve el contenido:
  curl -s -X POST "http://localhost:8080/api/integraciones/consultar-url?url=http://localhost:8080/api/salud"
  # Servicios internos de la red de Docker que no se publican hacia afuera:
  curl -s -X POST "http://localhost:8080/api/integraciones/consultar-url?url=http://adminer:8080/"
  ```
  También desde la pantalla *Reportes*, campo "Verificar URL de proveedor".
  _Evidencia: [captura]_
- **Impacto:** el atacante usa al POS como "proxy" hacia la red interna: lee servicios que no deberían ser alcanzables, y en un servidor en la nube podría pedir `169.254.169.254` (metadatos con credenciales de la nube).
- **Severidad (Alta):** no necesita autenticación y alcanza la red interna. Sería Crítica en la nube por los metadatos.
- **STRIDE:** **I**nformation disclosure; **E**levation (pivote hacia servicios internos).

## SSRF-02 · POST a URL arbitraria
- **Dónde:** `IntegracionControlador.java:28`, `IntegracionServicio.java:54-71`. Misma causa que SSRF-01 pero además envía un cuerpo a un servicio interno (**T**ampering).
- **Reproducir:** `curl -s -X POST "http://localhost:8080/api/integraciones/enviar?url=http://localhost:8080/api/salud" -H 'Content-Type: application/json' -d '{}'`

## SSRF-03 · Escáner de puertos
- **Dónde:** `IntegracionControlador.java:34`, `IntegracionServicio.java:77-94`. La respuesta (`abierto`, `error`) permite mapear qué puertos/servicios existen.
- **Reproducir:** `curl -s "http://localhost:8080/api/integraciones/verificar-host?host=mysql&puerto=3306"`

---

## Correcciones

| PR | Qué corrige | Archivos | Pruebas (rojo → verde) |
|---|---|---|---|
| 1 · `fix/bac-control-acceso-servidor` | BAC-01, BAC-02 (y BAC-03 al validar en servidor) | `SecurityConfig.java`, `AuthServicio.java` | `ControlAccesoAdminTest`, `RegistroNoConfiaEnElRolDelClienteTest` |
| 2 · `fix/ssrf-allowlist` | SSRF-01, 02, 03 | `ValidadorUrlDestino.java` (nuevo), `IntegracionServicio.java`, `IntegracionControlador.java`, `application.yml` | `ValidadorUrlDestinoTest`, `IntegracionServicioSsrfTest` |

ADRs: `adr/001-control-de-acceso-en-el-servidor.md`, `adr/002-prevencion-ssrf-allowlist.md`.

## Riesgo residual y pendientes (para la Unidad 3 / recomendación a la dirección)

- **El resto de la API sigue pública** (productos, ventas, pagos, clientes, `reportes/resumen`…). Solo se protegió lo sensible. Recomendación: política *deny by default* (`anyRequest().authenticated()`) con una lista corta de rutas públicas (`/api/auth/login`, `/api/auth/registro`, `/api/salud`).
- **HTTP Basic sigue habilitado, CSRF desactivado y CORS abierto**: fuera del alcance de este avance; afectan a la autenticación.
- **SSRF, DNS rebinding:** el validador resuelve el DNS y la petición lo resuelve de nuevo. Un atacante que controle el DNS de un dominio *permitido* podría cambiar la respuesta entre ambos pasos. Mitigación futura: conectar directamente a la IP ya validada.
- Los hosts de la allowlist son confiables por definición: si el proveedor es comprometido, el POS le seguirá hablando.
- Los secretos que devuelve `/api/configuracion` siguen guardados en claro y el frontend los cachea (familia *Datos sensibles*, no evaluada aquí). El fix solo restringe quién puede leerlos.
