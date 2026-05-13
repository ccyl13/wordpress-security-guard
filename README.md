# WPSentry

> Audita la seguridad de cualquier WordPress en segundos. Sin registro, sin instalacion, directo desde el navegador.

**[Abrir WPSentry](https://ccyl13.github.io/wordpress-security-guard/)**

---

## Que hace

Introduce la URL de cualquier sitio WordPress y WPSentry analiza:

- **Cabeceras HTTP de seguridad** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options y mas
- **Endpoints criticos expuestos** — xmlrpc.php, wp-login, wp-admin, wp-json, readme.html, debug.log...
- **Enumeracion de usuarios** — detecta si la REST API o los autores exponen nombres de usuario validos
- **Informacion de la instalacion** — version de WordPress, tema activo, cabecera Generator, WAF
- **Puntuacion CVSS 3.1** — score de riesgo estandar basado en los hallazgos
- **Recomendaciones con codigo** — pasos concretos para corregir cada problema encontrado

Todo desde el navegador, sin instalar nada. Analisis 100% pasivo: no explota vulnerabilidades ni modifica ningun dato.

## Stack

React 18 · TypeScript · Tailwind CSS · Vite · GitHub Pages

## Uso etico

Usar unicamente en sitios propios o con permiso expreso del propietario.

---

**Thomas Oneil Alvarez** — [GitHub](https://github.com/ccyl13) · [LinkedIn](https://www.linkedin.com/in/thomasoneil%C3%A1lvarez/)
