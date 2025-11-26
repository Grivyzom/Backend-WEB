# Documentación del Backend de Grivyzom

## 1. Introducción

Este documento detalla la arquitectura y el funcionamiento del backend del proyecto Grivyzom. El backend está construido con Django, un framework de alto nivel para desarrollo web en Python, y utiliza Django REST Framework para la creación de APIs RESTful.

### 1.1. Tecnologías Principales

-   **Django:** Framework principal para el desarrollo web.
-   **Django REST Framework:** Para la construcción de la API REST.
-   **djangorestframework-simplejwt:** Para la autenticación basada en JSON Web Tokens (JWT).
-   **django-cors-headers:** Para manejar las políticas de Cross-Origin Resource Sharing (CORS).
-   **MySQL/PostgreSQL:** Como sistema de gestión de bases de datos.
-   **Pillow:** Para el procesamiento de imágenes (avatares de usuario, imágenes de la web, etc.).

## 2. Estructura del Proyecto

El proyecto sigue una estructura estándar de Django:

-   `backendGrivyzom/`: El directorio raíz del proyecto Django.
    -   `backendGrivyzom/`: Contiene la configuración principal del proyecto (`settings.py`, `urls.py`).
    -   `core/`: Una aplicación de Django que contiene la lógica principal del negocio, incluyendo modelos, vistas y URLs.
    -   `media/`: Directorio donde se almacenan los archivos subidos por los usuarios (avatares, etc.).
    -   `static/`: Directorio para archivos estáticos (CSS, JS, imágenes).
    -   `templates/`: Para las plantillas de Django.
    -   `manage.py`: La utilidad de línea de comandos de Django.
    -   `requirements.txt`: Lista de las dependencias de Python del proyecto.

## 3. Modelos de la Base de Datos

Los modelos de datos se definen en `core/models.py` y son los siguientes:

### 3.1. `User`

Modelo de usuario personalizado que extiende el `AbstractUser` de Django.

-   **Campos Principales:**
    -   `username`: Nombre de usuario único.
    -   `email`: Email único.
    -   `password`: Contraseña hasheada.
    -   `role`: Rol del usuario en el sistema (enum `Role`).
    -   `discord_username`: Nombre de usuario de Discord (opcional).
    -   `minecraft_username`: Nombre de usuario de Minecraft (único).
    -   `avatar`: Imagen de avatar del usuario (opcional).
    -   `bio`: Biografía del usuario (opcional).
    -   `is_banned`, `ban_reason`: Para el manejo de baneos.
-   **Propiedades:**
    -   `is_player_role`, `is_staff_role`: Para verificar si el usuario es un jugador o parte del staff.
    -   `is_developer`, `can_moderate`, `can_build`: Para comprobaciones de permisos específicos.

### 3.2. `HeroSection`

Modelo para la sección "héroe" de la página principal.

-   **Campos:** `title`, `description`, `image`.

### 3.3. `GameHeader`

Modelo para el encabezado principal de la página.

-   **Campos:** `title`, `subtitle`, `button_text`, `image`.

### 3.4. `Contact`

Modelo para almacenar los mensajes del formulario de contacto.

-   **Campos:** `client_name`, `email`, `discord`, `message`.

## 4. Endpoints de la API

La API está versionada bajo el prefijo `/api/`.

### 4.1. Endpoints Públicos

Estos endpoints no requieren autenticación.

-   `GET /api/hero-section/`: Devuelve el contenido de la sección "héroe".
-   `GET /api/game-header/`: Devuelve el contenido del encabezado principal.
-   `POST /api/contact/`: Envía un mensaje a través del formulario de contacto.
    -   **Body:** `{ "client_name": "...", "email": "...", "discord": "...", "message": "..." }`

### 4.2. Autenticación

-   `POST /api/auth/register/`: Registra un nuevo usuario.
    -   **Body:** `{ "username": "...", "email": "...", "password": "...", "minecraft_username": "...", "discord_username": "..." }`
-   `POST /api/auth/login/`: Inicia sesión.
    -   **Body:** `{ "username": "...", "password": "..." }` (el campo `username` puede ser el nombre de usuario, email o nombre de Minecraft).
-   `POST /api/auth/logout/`: Cierra la sesión del usuario.

### 4.3. Perfil de Usuario

Estos endpoints requieren que el usuario esté autenticado.

-   `GET /api/auth/profile/`: Obtiene la información del perfil del usuario actual.
-   `PUT /api/auth/update-profile/`: Actualiza la información del perfil.
    -   **Body:** `{ "username": "...", "minecraft_username": "...", "email": "...", "discord_username": "...", "bio": "..." }`
-   `POST /api/auth/change-password/`: Cambia la contraseña del usuario.
    -   **Body:** `{ "current_password": "...", "new_password": "...", "confirm_password": "..." }`
-   `POST /api/auth/upload-avatar/`: Sube un nuevo avatar para el usuario.
    -   **Body (form-data):** `avatar`: (fichero de imagen)
-   `DELETE /api/auth/upload-avatar/`: Elimina el avatar del usuario.

## 5. Autenticación

El sistema de autenticación se basa en sesiones de Django. Después de un login exitoso, el servidor crea una sesión para el usuario, y las peticiones subsecuentes se autentican a través de esta sesión.

## 6. Seguridad

Se han implementado varias medidas de seguridad:

-   **Contraseñas seguras:** Se valida la fortaleza de las contraseñas en el registro.
-   **Sanitización de entradas:** Se limpian las entradas del usuario para prevenir ataques de inyección (XSS, etc.).
-   **CSRF Protection:** Django tiene protección CSRF incorporada, aunque se ha deshabilitado en algunas vistas de la API que son consumidas por un frontend desacoplado.
-   **Manejo de CORS:** Se utiliza `django-cors-headers` para controlar qué dominios pueden acceder a la API.

## 7. Dependencias

Las dependencias principales del proyecto se encuentran en el archivo `requirements.txt`. Algunas de las más importantes son:

-   `Django`
-   `djangorestframework`
-   `djangorestframework-simplejwt`
-   `django-cors-headers`
-   `mysqlclient` / `psycopg2-binary`
-   `Pillow`
