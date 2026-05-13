# WPSentry

> Herramienta de auditoria de seguridad pasiva para WordPress. Analiza cualquier sitio en segundos, desde el navegador, sin instalar nada.

**[Abrir WPSentry](https://ccyl13.github.io/wordpress-security-guard/)**

---

## Vista previa

### Hero

![WPSentry — pantalla principal](https://i.imgur.com/placeholder.png)

> _Captura real: hero con tipografia grande, stats en tiempo real y formulario de auditoria_

---

## Que analiza

| Check | Detalle |
|---|---|
| **Cabeceras HTTP** | CSP, HSTS, X-Frame-Options, X-Content-Type, Referrer-Policy, Permissions-Policy |
| **Endpoints criticos** | /xmlrpc.php, /wp-login.php, /wp-admin/, /wp-json/, /readme.html, /debug.log, /.env |
| **Enumeracion de usuarios** | REST API /wp/v2/users, author archive bypass |
| **Informacion del sitio** | Version WordPress, tema activo, cabecera Generator, WAF detectado, SSL/TLS |
| **Score CVSS 3.1** | Puntuacion de riesgo agregada con vector estandar |
| **Recomendaciones** | Pasos concretos con codigo de correccion para cada hallazgo |

---

## Como funciona

1. Introduces la URL del sitio WordPress a auditar
2. WPSentry lanza peticiones a traves de proxies CORS publicos
3. Analiza las respuestas HTTP sin ejecutar codigo en el servidor
4. Genera un informe con score, referencias OWASP/CWE y recomendaciones accionables

El analisis es **100% pasivo**: no explota vulnerabilidades, no realiza fuerza bruta ni deja rastro en el servidor objetivo.

---

## Privacidad y datos

- Sin registro ni autenticacion
- Sin base de datos propia ni almacenamiento en servidor
- El historial de auditorias se guarda **unicamente en el localStorage del navegador** del usuario — nunca sale de su dispositivo
- No se transmite ninguna informacion a servidores propios
- Codigo completamente abierto y auditable

---

## Stack tecnico

```
React 18 + TypeScript
Tailwind CSS
Vite
Shadcn/ui + Lucide icons
Space Grotesk + JetBrains Mono
GitHub Actions + GitHub Pages
```

---

## Uso etico

Usar unicamente en sitios propios o con permiso expreso del propietario.
Esta herramienta no debe emplearse para recopilar informacion de terceros sin autorizacion.

---

**Thomas Oneil Alvarez**  
[github.com/ccyl13](https://github.com/ccyl13) · [linkedin.com/in/thomasoneilalvarez](https://www.linkedin.com/in/thomasoneil%C3%A1lvarez/)
