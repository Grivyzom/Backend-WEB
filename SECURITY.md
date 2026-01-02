# NOTAS DE SEGURIDAD - GRIVYZOM BACKEND

## CONFIGURACIÓN REQUERIDA ANTES DE DEPLOYMENT

### 1. Variables de Entorno Críticas

**IMPORTANTE**: Antes de desplegar en producción, debes configurar el archivo `.env` con valores seguros.

```bash
# Genera una SECRET_KEY segura
python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'

# Genera una API Key segura para Minecraft
openssl rand -hex 32
```

Copia `.env.example` a `.env` y completa TODOS los valores:

```bash
cp .env.example .env
nano .env  # o tu editor preferido
```

### 2. Variables que DEBES cambiar

- `SECRET_KEY`: **CRÍTICO** - Genera una nueva y mantenla secreta
- `DEBUG`: **DEBE** ser `False` en producción
- `DB_PASSWORD`: Contraseña segura de tu base de datos
- `MINECRAFT_DB_PASSWORD`: Contraseña de la base de datos de Minecraft
- `MC_PLUGIN_API_KEY`: Clave API segura (64+ caracteres)
- `EMAIL_HOST_USER` y `EMAIL_HOST_PASSWORD`: Credenciales de email

### 3. Configuración de Email

Para que funcione el reset de contraseñas, configura un servicio de email:

**Gmail (desarrollo/testing)**:
```env
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=tu-email@gmail.com
EMAIL_HOST_PASSWORD=tu-app-password  # NO tu contraseña de Gmail, usa App Password
DEFAULT_FROM_EMAIL=noreply@grivyzom.com
```

**Producción (recomendado: SendGrid, Mailgun, AWS SES)**:
```env
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.sendgrid.net
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=apikey
EMAIL_HOST_PASSWORD=tu-api-key-de-sendgrid
DEFAULT_FROM_EMAIL=noreply@grivyzom.com
```

## MEJORAS DE SEGURIDAD IMPLEMENTADAS

### ✅ Completadas

1. **Credenciales movidas a variables de entorno**
   - SECRET_KEY ahora se carga desde `.env`
   - Credenciales de base de datos en variables de entorno
   - DEBUG configurable por entorno

2. **Rate Limiting implementado**
   - Login: 10 intentos/minuto por IP
   - Registro: 5 intentos/hora por IP
   - Forgot Password: 3 intentos/hora por IP

3. **Validación mejorada de imágenes**
   - Verificación real del contenido con Pillow
   - Validación de dimensiones máximas (4096x4096)
   - Validación de formato de imagen

4. **Logging mejorado**
   - Uso de logger en lugar de print()
   - No se expone información sensible en logs

5. **Configuración de cookies segura**
   - SESSION_COOKIE_SECURE basado en DEBUG
   - CSRF_COOKIE_SECURE basado en DEBUG

## TAREAS PENDIENTES (ALTA PRIORIDAD)

### 🔴 CRÍTICO - Implementar antes de producción

#### 1. Interceptor CSRF en Angular

El frontend Angular necesita un interceptor HTTP para enviar tokens CSRF automáticamente.

**Crear**: `GrivyzomWEB/src/app/core/interceptors/csrf.interceptor.ts`

```typescript
import { HttpInterceptorFn } from '@angular/common/http';

export const csrfInterceptor: HttpInterceptorFn = (req, next) => {
  // Obtener CSRF token de la cookie
  const csrfToken = getCookie('csrftoken');

  if (csrfToken && (req.method === 'POST' || req.method === 'PUT' || req.method === 'DELETE' || req.method === 'PATCH')) {
    req = req.clone({
      setHeaders: {
        'X-CSRFToken': csrfToken
      }
    });
  }

  return next(req);
};

function getCookie(name: string): string | null {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) {
    return parts.pop()?.split(';').shift() || null;
  }
  return null;
}
```

**Registrar en**: `GrivyzomWEB/src/app/app.config.ts`

```typescript
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { csrfInterceptor } from './core/interceptors/csrf.interceptor';

export const appConfig: ApplicationConfig = {
  providers: [
    provideHttpClient(withInterceptors([csrfInterceptor])),
    // ... otros providers
  ]
};
```

**Después de implementar el interceptor**, remover `@csrf_exempt` de las vistas en `views.py`.

#### 2. Reemplazar todos los print() con logger

Hay ~30 print() statements restantes en `views.py` que deben convertirse a:

```python
# En lugar de:
print(f"Error en Vista: {e}")

# Usar:
logger.error(f"Error in Vista: {str(e)}")
```

Esto evita exponer información sensible en producción.

#### 3. Configurar HTTPS en producción

Asegúrate de que tu servidor use HTTPS. Con nginx:

```nginx
server {
    listen 443 ssl http2;
    server_name api.grivyzom.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## MEJORAS RECOMENDADAS (MEDIA PRIORIDAD)

### 1. Implementar Paginación

Agregar paginación a todos los endpoints de lista para evitar sobrecarga:

```python
from django.core.paginator import Paginator

def gallery_images_api_view(request):
    images = GalleryImage.objects.all()

    page_number = request.GET.get('page', 1)
    page_size = request.GET.get('page_size', 20)

    paginator = Paginator(images, page_size)
    page_obj = paginator.get_page(page_number)

    # Serializar y retornar
```

### 2. Configurar Redis para Cache y Rate Limiting

```bash
pip install django-redis redis
```

```python
# settings.py
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}

# Usar Redis para rate limiting
RATELIMIT_USE_CACHE = 'default'
```

### 3. Implementar Monitoreo (Sentry)

```bash
pip install sentry-sdk
```

```python
# settings.py
import sentry_sdk

if not DEBUG:
    sentry_sdk.init(
        dsn="tu-sentry-dsn",
        traces_sample_rate=1.0,
    )
```

### 4. Sanitización de HTML en Posts y Comentarios

```bash
pip install bleach
```

```python
import bleach

# En CommunityPostCreateView
content = bleach.clean(
    data.get('content'),
    tags=['p', 'br', 'strong', 'em', 'u', 'a', 'ul', 'ol', 'li', 'code', 'pre'],
    attributes={'a': ['href', 'title']},
    strip=True
)
```

## CHECKLIST DE DEPLOYMENT

Antes de desplegar a producción:

- [ ] `.env` configurado con valores de producción
- [ ] `DEBUG=False` en `.env`
- [ ] `SECRET_KEY` generada y única
- [ ] Todas las credenciales de DB actualizadas
- [ ] Email configurado y probado
- [ ] HTTPS configurado en el servidor
- [ ] `pip install -r requirements.txt` ejecutado
- [ ] Migraciones aplicadas: `python manage.py migrate`
- [ ] Archivos estáticos recolectados: `python manage.py collectstatic`
- [ ] Interceptor CSRF implementado en Angular
- [ ] `@csrf_exempt` removidos de views.py
- [ ] Print statements reemplazados con logger
- [ ] Configurar firewall para permitir solo puertos necesarios
- [ ] Backup de base de datos configurado
- [ ] Monitoreo y logs configurados

## RECURSOS ADICIONALES

- [Django Security Checklist](https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Django Ratelimit Docs](https://django-ratelimit.readthedocs.io/)
- [Pillow Security](https://pillow.readthedocs.io/en/stable/reference/Image.html#PIL.Image.Image.verify)

## CONTACTO

Si tienes preguntas sobre seguridad, revisa la documentación de Django o contacta al equipo de desarrollo.
