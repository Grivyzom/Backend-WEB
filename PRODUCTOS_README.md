# Sistema de Administración de Productos - Grivyzom

## Descripción General

Sistema completo y seguro para gestionar productos de la tienda Minecraft desde el panel de administración. Soporta 5 tipos de productos: Rangos, Cosméticos, Cajas, Funciones e Items.

## Arquitectura y Seguridad

### 8 Capas de Seguridad Implementadas

1. **Validación Frontend**: Feedback inmediato al usuario
2. **Transporte HTTP**: Session cookies con `withCredentials: true`
3. **Autenticación**: Verificación de `request.user.is_authenticated`
4. **Autorización**: Solo staff (`is_staff_role`) puede gestionar productos
5. **Validación Backend**: 15+ validaciones por request
6. **Sanitización**: Django ORM previene SQL injection
7. **File Upload Security**: Validación de tamaño (5MB) y tipos (JPEG/PNG/WebP)
8. **Auditoría**: Campos `created_by`, `last_modified_by`, timestamps

### Permisos por Rol

- **HELPER+**: Puede crear, editar, y activar/desactivar productos
- **ADMIN/DEVELOPER**: Además puede eliminar productos permanentemente

---

## Configuración Inicial

### 1. Verificar Migraciones

```bash
cd /archivos/Backend-WEB
source venv/bin/activate
python manage.py migrate
```

### 2. Crear Directorio de Media

```bash
mkdir -p media/products
chmod 755 media/products
```

### 3. Acceder al Admin de Django

Navega a: `http://localhost:8000/admin/`

---

## Gestión de Productos (Django Admin)

### Paso 1: Crear Categorías

Antes de crear productos, debes crear categorías:

1. Ve a **Django Admin** → **Product categories**
2. Click en **"Add Product Category"**
3. Completa los campos:
   - **Name**: Nombre de la categoría (ej: "Rangos VIP")
   - **Slug**: Se genera automáticamente
   - **Description**: Descripción detallada
   - **Product type**: Selecciona el tipo (rank, cosmetic, crate, feature, item)
   - **Icon**: Nombre del icono Lucide (ej: crown, sparkles, box, zap, coins)
   - **Color**: Código hex (ej: #f59e0b)
   - **Order**: Orden de visualización (número)
   - **Is active**: Marcar para activar

#### Categorías Recomendadas

```
Rangos VIP
  - Type: rank
  - Icon: crown
  - Color: #f59e0b

Cosméticos Premium
  - Type: cosmetic
  - Icon: sparkles
  - Color: #ec4899

Cajas de Tesoro
  - Type: crate
  - Icon: box
  - Color: #8b5cf6

Funciones Especiales
  - Type: feature
  - Icon: zap
  - Color: #3b82f6

Items y Recursos
  - Type: item
  - Icon: coins
  - Color: #10b981
```

### Paso 2: Crear Productos

1. Ve a **Django Admin** → **Products**
2. Click en **"Add Product"**
3. Completa los campos según el tipo de producto:

#### Campos Comunes (Todos los Tipos)

- **Name**: Nombre del producto
- **Slug**: Se genera automáticamente
- **Product type**: Selecciona el tipo
- **Category**: Selecciona la categoría
- **Rarity**: COMMON, RARE, EPIC, LEGENDARY, MYTHIC
- **Short description**: Descripción breve (150 caracteres)
- **Description**: Descripción completa (markdown soportado)
- **Image**: Imagen del producto (JPEG/PNG/WebP, máx 5MB)
- **Price**: Precio en moneda del servidor
- **Discount price**: Precio con descuento (opcional)
- **Stock**: Cantidad disponible (NULL = ilimitado)
- **Is available**: Marcar para mostrar en tienda
- **Is featured**: Marcar para destacar
- **Is new**: Marcar como "nuevo"
- **Order**: Orden de visualización

#### Campos Específicos por Tipo (type_specific_data)

##### RANK (Rangos)
```json
{
  "benefits": ["Acceso a zona VIP", "Kit mensual", "Prefijo personalizado"],
  "duration": "permanent",
  "prefix": "[VIP]"
}
```

**Duraciones permitidas**: permanent, 30_days, 60_days, 90_days

##### COSMETIC (Cosméticos)
```json
{
  "subcategory": "particle",
  "preview_url": "https://example.com/preview.gif"
}
```

**Subcategorías**: particle, pet, trail, hat, emote, music

##### CRATE (Cajas)
```json
{
  "possible_items": [
    {"item": "Diamantes x64", "rarity": "EPIC", "chance": 10},
    {"item": "Esmeraldas x32", "rarity": "RARE", "chance": 25},
    {"item": "Oro x16", "rarity": "COMMON", "chance": 65}
  ]
}
```

**Nota**: La suma de chances debe ser 100

##### FEATURE (Funciones)
```json
{
  "command": "/fly",
  "duration": "permanent"
}
```

**Duraciones permitidas**: permanent, 30_days, 60_days, 90_days

##### ITEM (Items)
```json
{
  "quantity": 64
}
```

### Paso 3: Acciones Rápidas en Django Admin

Selecciona múltiples productos y usa las acciones en lote:

- **✅ Marcar como disponible**: Activa productos
- **❌ Marcar como no disponible**: Desactiva productos
- **⭐ Destacar productos**: Marca como featured
- **⚪ Quitar de destacados**: Remueve featured

---

## API Endpoints

### Endpoints Públicos (Frontend Tienda)

#### 1. Listar Productos
```http
GET /api/store/products/
```

**Query Params**:
- `type`: Filtrar por tipo (rank, cosmetic, crate, feature, item)
- `category`: Filtrar por ID de categoría
- `featured`: true/false

**Respuesta**:
```json
{
  "products": [
    {
      "id": 1,
      "name": "Rango VIP",
      "slug": "rango-vip",
      "type": "rank",
      "price": "15.99",
      "discount_price": null,
      "final_price": "15.99",
      "rarity": "EPIC",
      "image": "/media/products/2025/01/vip.png",
      "is_featured": true,
      "type_specific_data": {
        "benefits": ["Acceso VIP", "Kit mensual"],
        "duration": "permanent",
        "prefix": "[VIP]"
      }
    }
  ],
  "total": 1
}
```

#### 2. Detalle de Producto
```http
GET /api/store/products/<slug>/
```

**Respuesta**: Objeto producto completo

#### 3. Listar Categorías
```http
GET /api/store/categories/
```

**Respuesta**:
```json
{
  "categories": [
    {
      "id": 1,
      "name": "Rangos VIP",
      "slug": "rangos-vip",
      "product_type": "rank",
      "icon": "crown",
      "color": "#f59e0b"
    }
  ]
}
```

### Endpoints Admin (Requieren Staff)

Todos los endpoints admin requieren:
- Autenticación de sesión
- Usuario con `is_staff_role = True`
- CSRF token (excepto GET)

#### 1. Estadísticas de Productos
```http
GET /api/admin/products/stats/
```

**Respuesta**:
```json
{
  "total_products": 25,
  "available_products": 20,
  "featured_products": 5,
  "products_by_type": {
    "rank": 5,
    "cosmetic": 10,
    "crate": 3,
    "feature": 4,
    "item": 3
  },
  "total_revenue_potential": "1250.00",
  "low_stock_products": 2,
  "out_of_stock_products": 1
}
```

#### 2. Listar Productos (Admin)
```http
GET /api/admin/products/?page=1&search=&type=&category=&availability=all&featured=all
```

#### 3. Crear Producto
```http
POST /api/admin/products/create/
Content-Type: multipart/form-data
```

**FormData**:
```
name: Rango VIP
product_type: rank
category: 1
rarity: EPIC
short_description: Acceso VIP permanente
description: Descripción completa...
image: [File]
price: 15.99
is_available: true
is_featured: false
type_specific_data: {"benefits": [...], "duration": "permanent", "prefix": "[VIP]"}
```

#### 4. Actualizar Producto
```http
PUT /api/admin/products/<id>/update/
Content-Type: multipart/form-data
```

#### 5. Eliminar Producto (Solo ADMIN/DEVELOPER)
```http
DELETE /api/admin/products/<id>/delete/
```

#### 6. Toggle Disponibilidad
```http
POST /api/admin/products/<id>/toggle-availability/
```

#### 7. Toggle Destacado
```http
POST /api/admin/products/<id>/toggle-featured/
```

---

## Validaciones Backend

### Validaciones de Campos

1. **Name**: Requerido, 3-200 caracteres
2. **Product Type**: Debe ser uno de los 5 tipos válidos
3. **Price**: Decimal positivo, máx 10 dígitos
4. **Discount Price**: Opcional, debe ser menor que precio normal
5. **Stock**: Entero positivo o NULL (ilimitado)
6. **Image**:
   - Tamaño máximo: 5MB
   - Tipos permitidos: JPEG, PNG, WebP
   - Obligatoria en creación, opcional en edición

### Validaciones Específicas por Tipo

#### RANK
- `benefits`: Array requerido, mínimo 1 elemento
- `duration`: Debe ser uno de: permanent, 30_days, 60_days, 90_days
- `prefix`: String requerido

#### COSMETIC
- `subcategory`: Debe ser: particle, pet, trail, hat, emote, music
- `preview_url`: URL opcional

#### CRATE
- `possible_items`: Array requerido, mínimo 1 elemento
- Cada item debe tener: `item`, `rarity`, `chance`
- La suma de chances debe ser 100

#### FEATURE
- `command`: String requerido
- `duration`: permanent, 30_days, 60_days, 90_days

#### ITEM
- `quantity`: Entero positivo requerido

---

## Frontend Angular (Admin Panel)

### Acceso al Panel de Productos

1. Inicia sesión como usuario staff
2. Navega a `/admin/products`
3. O usa el sidebar: **Productos** (icono de paquete)

### Funcionalidades del Panel

- **Lista de productos** con paginación
- **Filtros avanzados**:
  - Búsqueda por nombre/descripción
  - Tipo de producto
  - Categoría
  - Disponibilidad
  - Destacados
- **Acciones rápidas**:
  - Toggle disponibilidad
  - Toggle destacado
- **CRUD completo**:
  - Crear producto con formulario dinámico
  - Editar producto existente
  - Eliminar producto (solo ADMIN/DEVELOPER)
  - Ver detalles completos

### Formulario Dinámico

El formulario cambia según el tipo de producto seleccionado:

- **Rank**: Muestra campos para benefits (array), duration (dropdown), prefix
- **Cosmetic**: Muestra subcategory (dropdown), preview URL opcional
- **Crate**: Muestra tabla para agregar items con rareza y probabilidad
- **Feature**: Muestra command input, duration dropdown
- **Item**: Muestra quantity input

---

## Integración con la Tienda Frontend

El servicio `StoreService` ya está actualizado para usar la API real:

```typescript
// En /archivos/GrivyzomWEB/src/app/core/services/store.service.ts

// Carga automática de productos
loadProducts(): Observable<Product[]>

// Carga automática de categorías
loadCategories(): Observable<Category[]>
```

La página de tienda (`/tienda`) ahora muestra productos reales de la base de datos.

---

## Solución de Problemas

### Error: "No se pueden crear productos"

**Solución**: Verifica que existan categorías activas del mismo tipo que el producto.

### Error: "Imagen muy grande"

**Solución**: Comprime la imagen a menos de 5MB. Tamaño recomendado: 800x800px.

### Error: "Formato de imagen no válido"

**Solución**: Usa solo JPEG, PNG o WebP. Convierte otros formatos.

### Error: "Type specific data inválido"

**Solución**: Verifica que el JSON tenga todos los campos requeridos según el tipo:
- **Rank**: benefits (array), duration, prefix
- **Cosmetic**: subcategory
- **Crate**: possible_items (array con suma de chances = 100)
- **Feature**: command, duration
- **Item**: quantity

### Error: "Permisos insuficientes"

**Solución**: Verifica que tu usuario tenga rol HELPER o superior:
```python
# En Django shell
python manage.py shell
>>> from core.models import User
>>> user = User.objects.get(username='tu_usuario')
>>> user.role
'DEFAULT'  # ❌ No tiene permisos
>>> user.role = User.Role.HELPER
>>> user.save()
# ✅ Ahora tiene permisos
```

---

## Mejores Prácticas

### Imágenes

- **Tamaño recomendado**: 800x800px o 1000x1000px
- **Formato preferido**: WebP (mejor compresión) o PNG (transparencias)
- **Optimización**: Comprime imágenes antes de subir
- **Nombres**: Usa nombres descriptivos (ej: `rango-vip-gold.webp`)

### Precios

- Usa precios coherentes (5.99, 9.99, 14.99, etc.)
- Los descuentos deben ser significativos (mínimo 10%)
- Precio con descuento debe ser menor que el precio normal

### Descripciones

- **Short description**: 1-2 líneas, impactante
- **Description**: Detallada, usa markdown para formato
- Incluye beneficios claros
- Especifica duración si aplica

### Stock

- **NULL**: Usar para productos digitales ilimitados (rangos, cosméticos)
- **Número específico**: Usar para productos limitados o promociones
- **0**: El sistema alertará "Sin stock"
- **< 10**: El sistema alertará "Stock bajo"

### Organización

- Crea categorías antes de productos
- Usa `order` para controlar la visualización
- Marca como `featured` solo productos importantes (máx 5-8)
- Usa `is_new` temporalmente para lanzamientos (30 días)

---

## Próximos Pasos Sugeridos

### 1. Sistema de Pagos
- Integrar PayPal o Stripe
- Crear modelo `Order` para tracking de compras
- Webhook para confirmación de pagos

### 2. Integración con Minecraft
- Plugin que consulte `/api/store/products/`
- Endpoint para registrar compras
- Sincronización de inventarios

### 3. Analytics
- Dashboard con métricas de ventas
- Productos más vendidos
- Ingresos por categoría/tipo
- Conversión de visitantes

### 4. Optimizaciones
- Implementar caché Redis para productos
- CDN para imágenes
- Lazy loading en frontend
- Rate limiting en API

### 5. Features Adicionales
- Sistema de reviews/valoraciones
- Múltiples imágenes por producto
- Variantes de productos (colores, tamaños)
- Cupones de descuento
- Bundles/paquetes

---

## Soporte

Para reportar problemas o solicitar features:
- Revisa los logs de Django: `/archivos/Backend-WEB/logs/`
- Verifica la consola del navegador (F12)
- Comprueba permisos de usuario
- Valida el formato JSON de `type_specific_data`

---

## Changelog

### v1.0.0 - 2025-01-27
- ✅ Implementación inicial
- ✅ 2 modelos: ProductCategory, Product
- ✅ 11 vistas: 3 públicas + 8 admin
- ✅ 12 endpoints: 3 públicos + 9 admin
- ✅ Sistema de validación completo
- ✅ Upload de imágenes seguro
- ✅ Integración con Angular frontend
- ✅ Django Admin configurado
- ✅ 8 capas de seguridad
- ✅ Auditoría con created_by/last_modified_by
