# Instrucciones para Implementar el Modelo de Usuario Personalizado

## ⚠️ IMPORTANTE
Este proceso requiere resetear la base de datos de desarrollo. Asegúrate de respaldar datos importantes antes de continuar.

## 📋 Pasos para Implementar

### 1. Preparación

El modelo de usuario completo está guardado en: `USER_MODEL_TEMP.py`

### 2. Resetear la Base de Datos (Solo en Desarrollo)

```powershell
# Desde el directorio Backend/backendGrivyzom
cd "I:\Desarrollo Grivyzom\Backend\backendGrivyzom"

# Opción A: Conectarse a MySQL y eliminar/recrear la base de datos
mysql -u root -P 3307
DROP DATABASE grivyzom_db;
CREATE DATABASE grivyzom_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
EXIT;
```

### 3. Eliminar Migraciones Existentes

```powershell
# Eliminar archivos de migración excepto __init__.py
Remove-Item "core\migrations\000*.py" -Force
```

### 4. Restaurar el Modelo de Usuario

Copiar el contenido de `USER_MODEL_TEMP.py` y pegarlo al inicio de `core/models.py` (después de los imports).

### 5. Descomentar AUTH_USER_MODEL en settings.py

```python
# En backendGrivyzom/settings.py
AUTH_USER_MODEL = 'core.User'  # Descomentar esta línea
```

### 6. Crear y Aplicar Migraciones

```powershell
# Crear migraciones iniciales
python manage.py makemigrations

# Aplicar migraciones
python manage.py migrate

# Crear superusuario
python manage.py createsuperuser
# Username: admin
# Minecraft username: AdminMC
# Email: admin@grivyzom.com
# Password: (tu contraseña segura)
```

### 7. Verificar el Admin

```powershell
# Iniciar el servidor
python manage.py runserver

# Acceder a: http://localhost:8000/admin
```

## 🎮 Sistema de Roles Implementado

### Roles de Jugadores:
- **DEFAULT**: Rol por defecto para nuevos usuarios
- **USUARIO**: Usuario básico
- **APRENDIZ**: Aprendiz del servidor
- **MIEMBRO**: Miembro establecido
- **VETERANO**: Jugador veterano
- **VIP**: Jugador VIP
- **VIP+**: Jugador VIP Plus
- **STREAMER**: Creadores de contenido

### Roles de Staff:
- **HELPER**: Ayudante
- **BUILDER**: Constructor
- **MODERADOR**: Moderador
- **ADMIN**: Administrador
- **DEVELOPER**: Desarrollador (Admin Total)

## 🔌 APIs Disponibles

Una vez completada la migración, estarán disponibles:

- `POST /api/auth/register/` - Registro de usuarios
- `POST /api/auth/login/` - Inicio de sesión
- `POST /api/auth/logout/` - Cerrar sesión
- `GET /api/auth/profile/` - Perfil del usuario actual

## 🎯 Características del Modelo

- ✅ Autenticación completa con Django
- ✅ Sistema de roles jerárquico
- ✅ Campos personalizados: minecraft_username, discord_username
- ✅ Sistema de baneo con razones
- ✅ Avatares de usuario
- ✅ Biografías personalizadas
- ✅ Propiedades para verificar permisos
- ✅ Integración con el admin de Django

## 📝 Métodos y Propiedades del Usuario

```python
user.is_player_role  # Verifica si es un rol de jugador
user.is_staff_role   # Verifica si es staff
user.is_developer    # Verifica si es developer (admin total)
user.can_moderate()  # Puede moderar
user.can_build()     # Puede construir en áreas especiales
user.upgrade_role('VIP')  # Actualizar rol
user.get_avatar_url(request)  # Obtener URL del avatar
```

## 🔄 Frontend Ya Configurado

El frontend de Angular ya está configurado con:
- AuthService actualizado para usar las APIs reales
- Login y Register conectados al backend
- Navbar con estados de autenticación
- Action-bar visible solo para usuarios autenticados

## ⚡ Alternativa Rápida (Si no quieres resetear la DB)

Si prefieres no resetear la base de datos ahora, puedes:

1. Mantener el sistema actual simulado en el frontend
2. Implementar el modelo de usuario más adelante en una branch separada
3. El archivo `USER_MODEL_TEMP.py` contiene todo el código necesario

## 📧 Soporte

Si encuentras algún problema durante la implementación, revisa:
- Los logs del servidor Django
- La consola del navegador para errores de frontend
- La configuración de CORS en settings.py
