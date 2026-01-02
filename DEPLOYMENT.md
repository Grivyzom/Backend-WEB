# GUÍA DE DEPLOYMENT - GRIVYZOM BACKEND

## INSTALACIÓN INICIAL

### 1. Clonar el repositorio y configurar entorno

```bash
cd Backend-WEB

# Crear entorno virtual
python3 -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate

# Instalar dependencias
pip install -r requirements.txt
```

### 2. Configurar variables de entorno

```bash
# Copiar el archivo de ejemplo
cp .env.example .env

# Editar el archivo .env con tus valores
nano .env
```

**Variables CRÍTICAS que debes cambiar**:

```bash
# 1. Generar SECRET_KEY
python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'

# Copiar el resultado y pegarlo en .env como:
SECRET_KEY=tu-secret-key-generada-aqui

# 2. Configurar DEBUG (False para producción)
DEBUG=False

# 3. Configurar bases de datos
DB_NAME=grivyzom_db
DB_USER=tu_usuario_db
DB_PASSWORD=tu_password_segura
DB_HOST=localhost
DB_PORT=3306

MINECRAFT_DB_NAME=nLogin
MINECRAFT_DB_USER=tu_usuario_minecraft
MINECRAFT_DB_PASSWORD=tu_password_minecraft
MINECRAFT_DB_HOST=tu_host_minecraft
MINECRAFT_DB_PORT=3306

# 4. Generar API Key para Minecraft Plugin
openssl rand -hex 32
# Copiar el resultado:
MC_PLUGIN_API_KEY=tu-api-key-generada-aqui

# 5. Configurar Email (ejemplo con Gmail)
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=tu-email@gmail.com
EMAIL_HOST_PASSWORD=tu-app-password
DEFAULT_FROM_EMAIL=noreply@grivyzom.com

# 6. Configurar URLs
FRONTEND_URL=https://grivyzom.com
ALLOWED_HOSTS=api.grivyzom.com,grivyzom.com,www.grivyzom.com
```

### 3. Configurar base de datos

```bash
# Crear las tablas
python manage.py migrate

# Crear superusuario
python manage.py createsuperuser
```

### 4. Recolectar archivos estáticos

```bash
python manage.py collectstatic --noinput
```

### 5. Probar localmente

```bash
# En modo desarrollo
DEBUG=True python manage.py runserver

# Visitar http://localhost:8000/api/
```

## DEPLOYMENT EN PRODUCCIÓN

### Opción 1: Servidor con Nginx + Gunicorn

#### 1. Instalar Gunicorn (ya en requirements.txt)

```bash
pip install gunicorn
```

#### 2. Configurar Gunicorn

Crear archivo `gunicorn_config.py`:

```python
bind = "127.0.0.1:8000"
workers = 3  # (2 x $num_cores) + 1
worker_class = "sync"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50
timeout = 30
keepalive = 2

# Logging
accesslog = "/var/log/grivyzom/gunicorn-access.log"
errorlog = "/var/log/grivyzom/gunicorn-error.log"
loglevel = "info"
```

#### 3. Crear servicio systemd

Crear `/etc/systemd/system/grivyzom.service`:

```ini
[Unit]
Description=Grivyzom Django Backend
After=network.target

[Service]
Type=notify
User=www-data
Group=www-data
WorkingDirectory=/path/to/Backend-WEB
Environment="PATH=/path/to/Backend-WEB/venv/bin"
ExecStart=/path/to/Backend-WEB/venv/bin/gunicorn \
    --config gunicorn_config.py \
    backendGrivyzom.wsgi:application

[Install]
WantedBy=multi-user.target
```

Activar y arrancar:

```bash
sudo systemctl daemon-reload
sudo systemctl enable grivyzom
sudo systemctl start grivyzom
sudo systemctl status grivyzom
```

#### 4. Configurar Nginx

Crear `/etc/nginx/sites-available/grivyzom`:

```nginx
upstream grivyzom_backend {
    server 127.0.0.1:8000;
}

server {
    listen 80;
    server_name api.grivyzom.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.grivyzom.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/api.grivyzom.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.grivyzom.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Logs
    access_log /var/log/nginx/grivyzom-access.log;
    error_log /var/log/nginx/grivyzom-error.log;

    # Static files
    location /static/ {
        alias /path/to/Backend-WEB/staticfiles/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # Media files
    location /media/ {
        alias /path/to/Backend-WEB/media/;
        expires 30d;
    }

    # Proxy to Django
    location / {
        proxy_pass http://grivyzom_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # CORS headers (Django ya las maneja, pero por si acaso)
        add_header 'Access-Control-Allow-Credentials' 'true' always;
    }

    # Limitar tamaño de uploads
    client_max_body_size 10M;
}
```

Activar configuración:

```bash
sudo ln -s /etc/nginx/sites-available/grivyzom /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

#### 5. Configurar SSL con Let's Encrypt

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d api.grivyzom.com
sudo certbot renew --dry-run  # Probar renovación automática
```

### Opción 2: Docker (Recomendado para facilidad)

#### 1. Crear Dockerfile

```dockerfile
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y \
    gcc \
    default-libmysqlclient-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copiar requirements e instalar
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código
COPY . .

# Recolectar archivos estáticos
RUN python manage.py collectstatic --noinput

# Exponer puerto
EXPOSE 8000

# Comando de inicio
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "backendGrivyzom.wsgi:application"]
```

#### 2. Crear docker-compose.yml

```yaml
version: '3.8'

services:
  web:
    build: .
    command: gunicorn --bind 0.0.0.0:8000 backendGrivyzom.wsgi:application
    volumes:
      - ./media:/app/media
      - ./staticfiles:/app/staticfiles
    ports:
      - "8000:8000"
    env_file:
      - .env
    depends_on:
      - db

  db:
    image: mysql:8.0
    environment:
      MYSQL_DATABASE: ${DB_NAME}
      MYSQL_USER: ${DB_USER}
      MYSQL_PASSWORD: ${DB_PASSWORD}
      MYSQL_ROOT_PASSWORD: ${DB_PASSWORD}
    volumes:
      - mysql_data:/var/lib/mysql
    ports:
      - "3306:3306"

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./staticfiles:/app/staticfiles:ro
      - ./media:/app/media:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro
    depends_on:
      - web

volumes:
  mysql_data:
```

#### 3. Desplegar con Docker

```bash
# Construir y arrancar
docker-compose up -d

# Ver logs
docker-compose logs -f

# Ejecutar migraciones
docker-compose exec web python manage.py migrate

# Crear superusuario
docker-compose exec web python manage.py createsuperuser
```

## MANTENIMIENTO

### Actualizar código

```bash
# Detener servicio
sudo systemctl stop grivyzom

# Actualizar código
git pull origin main

# Activar entorno virtual
source venv/bin/activate

# Instalar nuevas dependencias
pip install -r requirements.txt

# Ejecutar migraciones
python manage.py migrate

# Recolectar estáticos
python manage.py collectstatic --noinput

# Reiniciar servicio
sudo systemctl start grivyzom
```

### Backup de base de datos

```bash
# Backup
mysqldump -u user -p grivyzom_db > backup_$(date +%Y%m%d).sql

# Restore
mysql -u user -p grivyzom_db < backup_20250101.sql
```

### Monitorear logs

```bash
# Logs de Gunicorn
tail -f /var/log/grivyzom/gunicorn-error.log

# Logs de Nginx
tail -f /var/log/nginx/grivyzom-error.log

# Logs de Django
tail -f /path/to/Backend-WEB/logs/django.log
```

## TROUBLESHOOTING

### Error: "SECRET_KEY not found"

```bash
# Verificar que .env existe y tiene SECRET_KEY
cat .env | grep SECRET_KEY

# Si no existe, generar una:
python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'
```

### Error: "Access denied for user"

```bash
# Verificar credenciales en .env
cat .env | grep DB_

# Verificar conexión a MySQL
mysql -u $DB_USER -p$DB_PASSWORD -h $DB_HOST
```

### Error 502 Bad Gateway (Nginx)

```bash
# Verificar que Gunicorn está corriendo
sudo systemctl status grivyzom

# Ver logs
sudo journalctl -u grivyzom -f
```

### CORS Errors

- Verificar que el frontend esté en `CORS_ALLOWED_ORIGINS` en `settings.py`
- Verificar que `withCredentials: true` esté en las peticiones HTTP del frontend

## CHECKLIST POST-DEPLOYMENT

- [ ] API responde correctamente: `curl https://api.grivyzom.com/api/`
- [ ] Panel admin accesible: `https://api.grivyzom.com/admin/`
- [ ] Archivos estáticos se sirven correctamente
- [ ] Subida de imágenes funciona
- [ ] Reset de contraseñas envía emails
- [ ] Rate limiting está activo (probar con múltiples requests)
- [ ] HTTPS funciona sin errores
- [ ] Logs se están escribiendo correctamente
- [ ] Backup automático configurado

## SOPORTE

Para problemas de deployment, revisar:
- [Django Deployment Checklist](https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/)
- [Gunicorn Documentation](https://docs.gunicorn.org/)
- [Nginx Documentation](https://nginx.org/en/docs/)
