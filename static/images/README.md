# Directorio de Imágenes Estáticas

## Imagen Placeholder

### Ubicación
Coloca tu imagen placeholder en esta carpeta con el nombre:
```
placeholder.jpg
```

### Ruta completa
```
I:\Desarrollo Grivyzom\Backend\backendGrivyzom\static\images\placeholder.jpg
```

### Características recomendadas
- **Formato**: JPG o PNG
- **Dimensiones**: 1920x1080px (Full HD) o superior
- **Peso**: < 500KB para mejor rendimiento
- **Aspecto**: Neutro, genérico, con colores corporativos si es posible

### Placeholders adicionales
Puedes crear múltiples placeholders para diferentes contextos:

- `placeholder.jpg` - General (por defecto)
- `placeholder-hero.jpg` - Para hero sections
- `placeholder-header.jpg` - Para game headers
- `placeholder-avatar.jpg` - Para avatares de usuario
- `placeholder-post.jpg` - Para posts/artículos

## Uso en el código

### Backend (Django)

#### Opción 1: Usar la función utils
```python
from core.utils import get_image_url

# En tus vistas
image_url = get_image_url(request, model_instance.image)

# Con placeholder personalizado
image_url = get_image_url(request, model_instance.image, 'placeholder-hero.jpg')
```

#### Opción 2: Usar el método del modelo
```python
# En tus vistas
hero = HeroSection.objects.latest('created_at')
image_url = hero.get_image_url(request)
```

### Frontend (Angular)

El frontend recibirá automáticamente la URL correcta (imagen o placeholder) desde la API.

## Ventajas del sistema

✅ **Universal**: Funciona para todos los modelos con ImageField
✅ **Automático**: No requiere cambios en el frontend
✅ **Flexible**: Permite diferentes placeholders por contexto
✅ **Seguro**: Maneja errores de imágenes faltantes o corruptas
✅ **Centralizado**: Un solo lugar para gestionar placeholders
