from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinLengthValidator

class Banner(models.Model):
    name = models.CharField(max_length=100, unique=True, verbose_name='Nombre del Banner')
    description = models.TextField(max_length=500, blank=True, null=True, verbose_name='Descripción')
    image = models.ImageField(upload_to='banners/', verbose_name='Imagen del Banner')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

    def get_image_url(self, request):
        """Retorna la URL de la imagen del banner o un placeholder."""
        from .utils import get_image_url
        return get_image_url(request, self.image)

    class Meta:
        verbose_name = 'Banner'
        verbose_name_plural = 'Banners'
        ordering = ['name']


class User(AbstractUser):
    """
    Modelo de usuario personalizado para Grivyzom
    Extiende AbstractUser para incluir roles y campos personalizados
    """
    
    # Roles del sistema
    class Role(models.TextChoices):
        # Roles de jugadores
        DEFAULT = 'DEFAULT', 'Default'
        USUARIO = 'USUARIO', 'Usuario'
        APRENDIZ = 'APRENDIZ', 'Aprendiz'
        MIEMBRO = 'MIEMBRO', 'Miembro'
        VETERANO = 'VETERANO', 'Veterano'
        VIP = 'VIP', 'VIP'
        VIP_PLUS = 'VIP_PLUS', 'VIP+'
        STREAMER = 'STREAMER', 'Streamer'
        # Roles de Staff
        HELPER = 'HELPER', 'Helper'
        BUILDER = 'BUILDER', 'Builder'
        MODERADOR = 'MODERADOR', 'Moderador'
        ADMIN = 'ADMIN', 'Admin'
        DEVELOPER = 'DEVELOPER', 'Developer'
    
    # Campos personalizados
    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.DEFAULT,
        verbose_name='Rol'
    )
    
    discord_username = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        verbose_name='Usuario de Discord'
    )
    
    minecraft_username = models.CharField(
        max_length=16,
        unique=True,
        blank=True,
        null=True,
        validators=[MinLengthValidator(3)],
        verbose_name='Usuario de Minecraft',
        help_text='Nombre de usuario en Minecraft (3-16 caracteres)'
    )
    
    minecraft_uuid = models.CharField(
        max_length=36,
        unique=True,
        null=True,
        blank=True,
        verbose_name='UUID de Minecraft',
        help_text='UUID del jugador en Minecraft (ej: 550e8400-e29b-41d4-a716-446655440000)'
    )
    
    avatar = models.ImageField(
        upload_to='user_avatars/',
        blank=True,
        null=True,
        verbose_name='Avatar'
    )
    
    bio = models.TextField(
        max_length=500,
        blank=True,
        null=True,
        verbose_name='Biografía'
    )
    
    # Campos para recuperación de contraseña
    password_reset_token = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        verbose_name='Token de Restablecimiento de Contraseña'
    )
    password_reset_expires = models.DateTimeField(
        blank=True,
        null=True,
        verbose_name='Expiración de Token de Restablecimiento'
    )
    
    # Relaciones con Banners
    active_banner = models.ForeignKey(
        Banner,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='active_users',
        verbose_name='Banner Activo'
    )
    
    collected_banners = models.ManyToManyField(
        Banner,
        blank=True,
        related_name='collectors',
        verbose_name='Banners Coleccionados'
    )
    
    date_joined = models.DateTimeField(
        auto_now_add=True,
        verbose_name='Fecha de registro'
    )
    
    last_login = models.DateTimeField(
        auto_now=True,
        verbose_name='Último inicio de sesión'
    )
    
    is_banned = models.BooleanField(
        default=False,
        verbose_name='Baneado'
    )
    
    ban_reason = models.TextField(
        blank=True,
        null=True,
        verbose_name='Razón del baneo'
    )
    
    class Meta:
        verbose_name = 'Usuario'
        verbose_name_plural = 'Usuarios'
        ordering = ['-date_joined']
    
    def __str__(self):
        name = self.minecraft_username or self.username
        return f"{name} ({self.get_role_display()})"
    
    @property
    def is_player_role(self):
        """Verifica si el usuario tiene un rol de jugador"""
        player_roles = [
            self.Role.DEFAULT,
            self.Role.USUARIO,
            self.Role.APRENDIZ,
            self.Role.MIEMBRO,
            self.Role.VETERANO,
            self.Role.VIP,
            self.Role.VIP_PLUS,
            self.Role.STREAMER
        ]
        return self.role in player_roles
    
    @property
    def is_staff_role(self):
        """Verifica si el usuario tiene un rol de staff"""
        staff_roles = [
            self.Role.HELPER,
            self.Role.BUILDER,
            self.Role.MODERADOR,
            self.Role.ADMIN,
            self.Role.DEVELOPER
        ]
        return self.role in staff_roles
    
    @property
    def is_developer(self):
        """Verifica si el usuario es Developer (admin total)"""
        return self.role == self.Role.DEVELOPER
    
    @property
    def can_moderate(self):
        """Verifica si el usuario puede moderar"""
        return self.role in [
            self.Role.MODERADOR,
            self.Role.ADMIN,
            self.Role.DEVELOPER
        ]
    
    @property
    def can_build(self):
        """Verifica si el usuario puede construir en áreas especiales"""
        return self.role in [
            self.Role.BUILDER,
            self.Role.ADMIN,
            self.Role.DEVELOPER
        ]
    
    def get_avatar_url(self, request):
        """Retorna la URL del avatar o un placeholder"""
        from .utils import get_image_url
        return get_image_url(request, self.avatar)
    
    def upgrade_role(self, new_role):
        """Actualiza el rol del usuario"""
        if new_role in self.Role.values:
            self.role = new_role
            self.save()
            return True
        return False


class HeroSection(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField()
    image = models.ImageField(upload_to='hero_images/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title
    
    def get_image_url(self, request):
        """Retorna la URL de la imagen o el placeholder si no existe"""
        from .utils import get_image_url
        return get_image_url(request, self.image)

class GameHeader(models.Model):
    title = models.CharField(max_length=200, default='GRIVYZOM')
    subtitle = models.CharField(max_length=300, default='A WORLD OF ADVENTURE AND CREATIVITY')
    button_text = models.CharField(max_length=100, default='JUGAR AHORA!')
    image = models.ImageField(upload_to='game_header_images/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'Game Header'
        verbose_name_plural = 'Game Headers'

    def __str__(self):
        return f"Game Header - {self.title}"
    
    def get_image_url(self, request):
        """Retorna la URL de la imagen o el placeholder si no existe"""
        from .utils import get_image_url
        return get_image_url(request, self.image)

class Contact(models.Model):
    client_name = models.CharField(max_length=100)
    email = models.EmailField()
    discord = models.CharField(max_length=100, blank=True, null=True)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.client_name


class GalleryCategory(models.Model):
    """
    Categorías para organizar las imágenes de la galería.
    Ejemplos: Screenshots, Builds, Events, Community
    """
    name = models.CharField(max_length=100, verbose_name='Nombre')
    slug = models.SlugField(unique=True, verbose_name='Slug URL')
    description = models.TextField(blank=True, verbose_name='Descripción')
    icon = models.CharField(
        max_length=50, 
        blank=True, 
        verbose_name='Icono CSS',
        help_text='Clase CSS del icono (ej: ci-Camera)'
    )
    order = models.IntegerField(default=0, verbose_name='Orden')
    is_active = models.BooleanField(default=True, verbose_name='Activa')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'Categoría de Galería'
        verbose_name_plural = 'Categorías de Galería'
        ordering = ['order', 'name']

    def __str__(self):
        return self.name


class GalleryImage(models.Model):
    """
    Imágenes de la galería con soporte para categorización y metadatos.
    Solo el staff puede subir imágenes desde el admin.
    """
    category = models.ForeignKey(
        GalleryCategory, 
        on_delete=models.CASCADE,
        related_name='images',
        verbose_name='Categoría'
    )
    title = models.CharField(max_length=200, verbose_name='Título')
    description = models.TextField(blank=True, verbose_name='Descripción')
    image = models.ImageField(
        upload_to='gallery/', 
        verbose_name='Imagen'
    )
    thumbnail = models.ImageField(
        upload_to='gallery/thumbnails/', 
        blank=True, 
        null=True,
        verbose_name='Miniatura',
        help_text='Se genera automáticamente si no se proporciona'
    )
    author = models.CharField(
        max_length=100, 
        blank=True, 
        verbose_name='Autor',
        help_text='Nombre del jugador o builder'
    )
    is_featured = models.BooleanField(
        default=False, 
        verbose_name='Destacada',
        help_text='Las imágenes destacadas aparecen primero'
    )
    order = models.IntegerField(default=0, verbose_name='Orden')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Imagen de Galería'
        verbose_name_plural = 'Imágenes de Galería'
        ordering = ['-is_featured', 'order', '-created_at']

    def __str__(self):
        return f"{self.title} ({self.category.name})"

    def get_image_url(self, request):
        """Retorna la URL de la imagen o un placeholder."""
        from .utils import get_image_url
        return get_image_url(request, self.image)

    def get_thumbnail_url(self, request):
        """Retorna la URL del thumbnail o la imagen principal."""
        from .utils import get_image_url
        if self.thumbnail:
            return get_image_url(request, self.thumbnail)
        return self.get_image_url(request)


class PendingRegistration(models.Model):
    """
    Registro pendiente de verificación en Minecraft.
    Cuando un usuario se registra en la web, se crea un registro aquí
    y debe verificarse en el servidor de Minecraft antes de crear el User.
    """
    
    class Status(models.TextChoices):
        PENDING = 'PENDING', 'Pendiente'
        VERIFIED = 'VERIFIED', 'Verificado'
        EXPIRED = 'EXPIRED', 'Expirado'
        CANCELLED = 'CANCELLED', 'Cancelado'
    
    # Datos del registro (se copian al User cuando se verifica)
    username = models.CharField(
        max_length=30,
        unique=True,
        verbose_name='Nombre de Usuario'
    )
    email = models.EmailField(
        unique=True,
        verbose_name='Email'
    )
    password_hash = models.CharField(
        max_length=128,
        verbose_name='Contraseña (hash)',
        help_text='Contraseña hasheada con Django'
    )
    
    # Verificación
    verification_code = models.CharField(
        max_length=6,
        unique=True,
        verbose_name='Código de Verificación',
        help_text='Código de 6 caracteres alfanuméricos (ej: A7X9K2)'
    )
    minecraft_uuid = models.CharField(
        max_length=36,
        null=True,
        blank=True,
        verbose_name='UUID de Minecraft',
        help_text='Se llena cuando el jugador verifica en Minecraft'
    )
    minecraft_username_verified = models.CharField(
        max_length=16,
        null=True,
        blank=True,
        verbose_name='Username Minecraft Verificado',
        help_text='Nombre en Minecraft del jugador que verificó'
    )
    
    # Estado y tiempos
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING,
        verbose_name='Estado'
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name='Fecha de Creación'
    )
    expires_at = models.DateTimeField(
        verbose_name='Fecha de Expiración',
        help_text='El código expira después de 15 minutos'
    )
    verified_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name='Fecha de Verificación'
    )
    
    # Seguridad
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name='Dirección IP',
        help_text='IP desde donde se solicitó el registro'
    )
    attempts = models.PositiveIntegerField(
        default=0,
        verbose_name='Intentos de Verificación',
        help_text='Número de intentos fallidos de verificación'
    )
    
    # Auto-Login Token (One-Time Token)
    auth_token = models.CharField(
        max_length=128,
        unique=True,
        null=True,
        blank=True,
        verbose_name='Token de Auto-Login',
        help_text='Token de un solo uso para auto-login después de verificar'
    )
    auth_token_used = models.BooleanField(
        default=False,
        verbose_name='Token Usado'
    )
    auth_token_expires = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name='Expiración del Token'
    )
    
    class Meta:
        verbose_name = 'Registro Pendiente'
        verbose_name_plural = 'Registros Pendientes'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.username} - {self.verification_code} ({self.get_status_display()})"
    
    @property
    def is_expired(self):
        """Verifica si el registro ha expirado."""
        from django.utils import timezone
        return timezone.now() > self.expires_at
    
    @property
    def is_pending(self):
        """Verifica si el registro está pendiente y no ha expirado."""
        return self.status == self.Status.PENDING and not self.is_expired
    
    @classmethod
    def generate_verification_code(cls):
        """Genera un código de verificación único de 6 caracteres alfanuméricos."""
        import random
        import string
        chars = string.ascii_uppercase + string.digits
        # Excluir caracteres confusos: 0, O, I, 1, L
        chars = chars.replace('0', '').replace('O', '').replace('I', '').replace('1', '').replace('L', '')
        
        while True:
            code = ''.join(random.choices(chars, k=6))
            if not cls.objects.filter(verification_code=code, status=cls.Status.PENDING).exists():
                return code
    
    def mark_as_expired(self):
        """Marca el registro como expirado."""
        self.status = self.Status.EXPIRED
        self.save()
    
    def verify(self, minecraft_uuid, minecraft_username):
        """
        Verifica el registro y retorna el User creado.
        También genera un One-Time Token (OTT) para auto-login.
        """
        from django.utils import timezone
        from datetime import timedelta
        import secrets
        
        if self.is_expired:
            self.mark_as_expired()
            return None, "El código de verificación ha expirado"
        
        if self.status != self.Status.PENDING:
            return None, f"El registro ya no está pendiente (estado: {self.get_status_display()})"
        
        # Crear el usuario
        user = User.objects.create(
            username=self.username,
            email=self.email,
            password=self.password_hash,  # Ya está hasheada
            minecraft_username=minecraft_username,
            minecraft_uuid=minecraft_uuid,
            role=User.Role.DEFAULT,
            is_active=True,
            is_staff=False,
            is_superuser=False
        )
        
        # Generar One-Time Token para auto-login (512 bits de entropía)
        auth_token = secrets.token_urlsafe(64)
        
        # Marcar como verificado y guardar token
        self.status = self.Status.VERIFIED
        self.verified_at = timezone.now()
        self.minecraft_uuid = minecraft_uuid
        self.minecraft_username_verified = minecraft_username
        self.auth_token = auth_token
        self.auth_token_expires = timezone.now() + timedelta(minutes=5)
        self.auth_token_used = False
        self.save()
        
        return user, None
    
    def consume_auth_token(self):
        """
        Consume el auth_token (marcándolo como usado).
        Retorna True si el token era válido, False si ya fue usado o expiró.
        """
        from django.utils import timezone
        
        if self.auth_token_used:
            return False, "El token ya fue utilizado"
        
        if not self.auth_token:
            return False, "No hay token disponible"
        
        if self.auth_token_expires and timezone.now() > self.auth_token_expires:
            return False, "El token ha expirado"
        
        # Marcar como usado
        self.auth_token_used = True
        self.save()
        
        return True, None


# ============================================================================
# MODELOS DE COMUNIDAD
# ============================================================================

class PostCategory(models.Model):
    """
    Categorías para posts de comunidad.
    Gestionadas por staff desde Django Admin.
    """
    name = models.CharField(
        max_length=50,
        unique=True,
        verbose_name='Nombre'
    )
    slug = models.SlugField(
        max_length=50,
        unique=True,
        verbose_name='Slug URL'
    )
    description = models.TextField(
        max_length=200,
        blank=True,
        verbose_name='Descripción'
    )
    icon = models.CharField(
        max_length=50,
        blank=True,
        default='folder',
        verbose_name='Icono',
        help_text='Nombre del icono Lucide (ej: hammer, book-open, trophy)'
    )
    color = models.CharField(
        max_length=7,
        default='#8b5cf6',
        verbose_name='Color',
        help_text='Color hexadecimal (ej: #8b5cf6)'
    )
    order = models.PositiveIntegerField(
        default=0,
        verbose_name='Orden'
    )
    is_active = models.BooleanField(
        default=True,
        verbose_name='Activa'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = 'Categoría de Post'
        verbose_name_plural = 'Categorías de Posts'
        ordering = ['order', 'name']
    
    def __str__(self):
        return self.name


class CommunityPost(models.Model):
    """
    Posts de la comunidad (blogs, guías, builds, etc.)
    Contenido almacenado en Markdown.
    """
    class Status(models.TextChoices):
        DRAFT = 'DRAFT', 'Borrador'
        PUBLISHED = 'PUBLISHED', 'Publicado'
        HIDDEN = 'HIDDEN', 'Oculto'
        DELETED = 'DELETED', 'Eliminado'
    
    # Autor y categoría
    author = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='community_posts',
        verbose_name='Autor'
    )
    category = models.ForeignKey(
        PostCategory,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='posts',
        verbose_name='Categoría'
    )
    
    # Contenido
    title = models.CharField(
        max_length=150,
        verbose_name='Título'
    )
    slug = models.SlugField(
        max_length=170,
        unique=True,
        verbose_name='Slug URL'
    )
    excerpt = models.CharField(
        max_length=300,
        blank=True,
        verbose_name='Extracto',
        help_text='Resumen corto del post (máx 300 caracteres)'
    )
    content = models.TextField(
        verbose_name='Contenido (Markdown)',
        help_text='Contenido del post en formato Markdown'
    )
    
    # Cover image
    cover_image = models.ImageField(
        upload_to='community/covers/%Y/%m/',
        blank=True,
        null=True,
        verbose_name='Imagen de Portada',
        help_text='Resolución recomendada: 1920x1080'
    )
    
    # Tags (almacenados como JSON array de strings)
    tags = models.JSONField(
        default=list,
        blank=True,
        verbose_name='Etiquetas',
        help_text='Lista de etiquetas sin #'
    )
    
    # Estado y métricas
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PUBLISHED,
        verbose_name='Estado'
    )
    views = models.PositiveIntegerField(
        default=0,
        verbose_name='Vistas'
    )
    is_pinned = models.BooleanField(
        default=False,
        verbose_name='Fijado'
    )
    is_featured = models.BooleanField(
        default=False,
        verbose_name='Destacado'
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='Creado')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='Actualizado')
    published_at = models.DateTimeField(null=True, blank=True, verbose_name='Publicado')
    
    class Meta:
        verbose_name = 'Post de Comunidad'
        verbose_name_plural = 'Posts de Comunidad'
        ordering = ['-is_pinned', '-created_at']
        indexes = [
            models.Index(fields=['status', '-created_at']),
            models.Index(fields=['author', '-created_at']),
            models.Index(fields=['category', '-created_at']),
        ]
    
    def __str__(self):
        return f"{self.title} - {self.author.username}"
    
    @property
    def likes_count(self):
        return self.likes.count()
    
    @property
    def comments_count(self):
        return self.comments.filter(is_deleted=False).count()
    
    @property
    def bookmarks_count(self):
        return self.bookmarks.count()
    
    def save(self, *args, **kwargs):
        from django.utils import timezone
        from django.utils.text import slugify
        
        # Generar slug si no existe
        if not self.slug:
            base_slug = slugify(self.title)
            slug = base_slug
            counter = 1
            while CommunityPost.objects.filter(slug=slug).exclude(pk=self.pk).exists():
                slug = f"{base_slug}-{counter}"
                counter += 1
            self.slug = slug
        
        # Setear published_at cuando se publica
        if self.status == self.Status.PUBLISHED and not self.published_at:
            self.published_at = timezone.now()
        
        super().save(*args, **kwargs)


class PostLike(models.Model):
    """Like en un post"""
    post = models.ForeignKey(
        CommunityPost,
        on_delete=models.CASCADE,
        related_name='likes'
    )
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='post_likes'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = 'Like'
        verbose_name_plural = 'Likes'
        unique_together = ['post', 'user']
    
    def __str__(self):
        return f"{self.user.username} likes {self.post.title}"


class PostComment(models.Model):
    """Comentario en un post (soporta respuestas anidadas)"""
    post = models.ForeignKey(
        CommunityPost,
        on_delete=models.CASCADE,
        related_name='comments'
    )
    author = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='post_comments'
    )
    parent = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='replies'
    )
    content = models.TextField(
        max_length=2000,
        verbose_name='Contenido'
    )
    is_deleted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Comentario'
        verbose_name_plural = 'Comentarios'
        ordering = ['created_at']
    
    def __str__(self):
        return f"Comentario de {self.author.username} en {self.post.title}"


class UserFollow(models.Model):
    """Relación de seguimiento entre usuarios"""
    follower = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='following_set'
    )
    following = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='followers_set'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = 'Seguimiento'
        verbose_name_plural = 'Seguimientos'
        unique_together = ['follower', 'following']
    
    def __str__(self):
        return f"{self.follower.username} sigue a {self.following.username}"


class PostBookmark(models.Model):
    """Post guardado por un usuario"""
    post = models.ForeignKey(
        CommunityPost,
        on_delete=models.CASCADE,
        related_name='bookmarks'
    )
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='bookmarked_posts'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = 'Marcador'
        verbose_name_plural = 'Marcadores'
        unique_together = ['post', 'user']
    
    def __str__(self):
        return f"{self.user.username} guardó {self.post.title}"


# ============================================================================
# MODELOS DE TIENDA / STORE MODELS
# ============================================================================

class ProductCategory(models.Model):
    """
    Categorías de productos en la tienda.
    Ejemplos: Rangos VIP, Cosméticos, Cajas Premium, Funciones Especiales, Items
    """
    name = models.CharField(
        max_length=100,
        unique=True,
        verbose_name='Nombre'
    )
    slug = models.SlugField(
        max_length=100,
        unique=True,
        verbose_name='Slug URL'
    )
    description = models.TextField(
        max_length=500,
        blank=True,
        verbose_name='Descripción'
    )
    product_type = models.CharField(
        max_length=20,
        choices=[
            ('rank', 'Rango'),
            ('cosmetic', 'Cosmético'),
            ('crate', 'Caja'),
            ('feature', 'Función'),
            ('item', 'Item')
        ],
        verbose_name='Tipo de Producto'
    )
    icon = models.CharField(
        max_length=50,
        blank=True,
        verbose_name='Icono',
        help_text='Nombre del icono Lucide (ej: crown, sparkles, box)'
    )
    color = models.CharField(
        max_length=7,
        default='#8b5cf6',
        verbose_name='Color',
        help_text='Color hexadecimal (ej: #8b5cf6)'
    )
    order = models.PositiveIntegerField(
        default=0,
        verbose_name='Orden'
    )
    is_active = models.BooleanField(
        default=True,
        verbose_name='Activa'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Categoría de Producto'
        verbose_name_plural = 'Categorías de Productos'
        ordering = ['order', 'name']

    def __str__(self):
        return f"{self.name} ({self.get_product_type_display()})"


class Product(models.Model):
    """
    Producto en la tienda. Soporta 5 tipos diferentes con campos específicos
    almacenados en JSONField para flexibilidad.

    TIPOS:
    - rank: Rangos VIP (benefits, duration, prefix)
    - cosmetic: Cosméticos (subcategory, preview_url)
    - crate: Cajas de recompensas (possible_items)
    - feature: Funciones especiales (command, duration)
    - item: Items genéricos (quantity)
    """

    class ProductType(models.TextChoices):
        RANK = 'rank', 'Rango'
        COSMETIC = 'cosmetic', 'Cosmético'
        CRATE = 'crate', 'Caja'
        FEATURE = 'feature', 'Función'
        ITEM = 'item', 'Item'

    class Rarity(models.TextChoices):
        COMMON = 'common', 'Común'
        RARE = 'rare', 'Raro'
        EPIC = 'epic', 'Épico'
        LEGENDARY = 'legendary', 'Legendario'

    # Campos básicos (comunes a todos los tipos)
    category = models.ForeignKey(
        ProductCategory,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='products',
        verbose_name='Categoría'
    )

    name = models.CharField(
        max_length=100,
        verbose_name='Nombre',
        help_text='Nombre del producto (ej: VIP+, Partículas de Fuego)'
    )

    slug = models.SlugField(
        max_length=120,
        unique=True,
        verbose_name='Slug URL'
    )

    description = models.TextField(
        max_length=1000,
        verbose_name='Descripción',
        help_text='Descripción completa del producto en Markdown'
    )

    short_description = models.CharField(
        max_length=200,
        blank=True,
        verbose_name='Descripción Corta',
        help_text='Resumen breve para listados'
    )

    product_type = models.CharField(
        max_length=20,
        choices=ProductType.choices,
        verbose_name='Tipo de Producto'
    )

    # Imagen del producto
    image = models.ImageField(
        upload_to='products/%Y/%m/',
        verbose_name='Imagen del Producto',
        help_text='Resolución recomendada: 800x800px (max 5MB)'
    )

    # Precio
    price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        verbose_name='Precio',
        help_text='Precio en la moneda del servidor'
    )

    discount_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        verbose_name='Precio con Descuento',
        help_text='Dejar vacío si no hay descuento'
    )

    # Rareza y características
    rarity = models.CharField(
        max_length=20,
        choices=Rarity.choices,
        default=Rarity.COMMON,
        verbose_name='Rareza'
    )

    # Estado
    is_available = models.BooleanField(
        default=True,
        verbose_name='Disponible',
        help_text='Si está disponible para compra'
    )

    is_featured = models.BooleanField(
        default=False,
        verbose_name='Destacado',
        help_text='Aparece en la sección destacada'
    )

    is_new = models.BooleanField(
        default=False,
        verbose_name='Nuevo',
        help_text='Marca el producto como nuevo'
    )

    stock = models.PositiveIntegerField(
        null=True,
        blank=True,
        verbose_name='Stock',
        help_text='Cantidad disponible (vacío = ilimitado)'
    )

    order = models.PositiveIntegerField(
        default=0,
        verbose_name='Orden de Visualización'
    )

    # Campos específicos por tipo (JSON)
    type_specific_data = models.JSONField(
        default=dict,
        blank=True,
        verbose_name='Datos Específicos del Tipo',
        help_text='Campos adicionales según el tipo de producto'
    )

    # Métricas
    views = models.PositiveIntegerField(
        default=0,
        verbose_name='Vistas'
    )

    purchases = models.PositiveIntegerField(
        default=0,
        verbose_name='Compras'
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='Creado')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='Actualizado')

    # Usuario que creó/modificó (auditoría)
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='products_created',
        verbose_name='Creado Por'
    )

    last_modified_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='products_modified',
        verbose_name='Última Modificación Por'
    )

    class Meta:
        verbose_name = 'Producto'
        verbose_name_plural = 'Productos'
        ordering = ['-is_featured', 'order', '-created_at']
        indexes = [
            models.Index(fields=['product_type', 'is_available']),
            models.Index(fields=['category', '-created_at']),
            models.Index(fields=['-is_featured', 'order']),
        ]

    def __str__(self):
        return f"{self.name} ({self.get_product_type_display()})"

    @property
    def discount_percent(self):
        """Calcula el porcentaje de descuento"""
        if self.discount_price and self.discount_price < self.price:
            return int(((self.price - self.discount_price) / self.price) * 100)
        return 0

    @property
    def final_price(self):
        """Retorna el precio final (con descuento si aplica)"""
        return self.discount_price if self.discount_price else self.price

    @property
    def revenue_potential(self):
        """Retorna el potencial de ingresos basado en stock"""
        if self.stock:
            return float(self.final_price) * self.stock
        return 0  # Ilimitado

    def get_image_url(self, request):
        """Retorna la URL de la imagen del producto"""
        from .utils import get_image_url
        return get_image_url(request, self.image)

    def save(self, *args, **kwargs):
        from django.utils.text import slugify

        # Generar slug si no existe
        if not self.slug:
            base_slug = slugify(self.name)
            slug = base_slug
            counter = 1
            while Product.objects.filter(slug=slug).exclude(pk=self.pk).exists():
                slug = f"{base_slug}-{counter}"
                counter += 1
            self.slug = slug

        # Validar type_specific_data según el tipo
        self._validate_type_specific_data()

        super().save(*args, **kwargs)

    def _validate_type_specific_data(self):
        """Valida que type_specific_data contenga los campos requeridos según el tipo"""
        if not isinstance(self.type_specific_data, dict):
            self.type_specific_data = {}

        # Validaciones por tipo
        if self.product_type == self.ProductType.RANK:
            # Requerido: benefits (list), duration (str), prefix (str)
            if 'benefits' not in self.type_specific_data:
                self.type_specific_data['benefits'] = []
            if 'duration' not in self.type_specific_data:
                self.type_specific_data['duration'] = 'permanent'
            if 'prefix' not in self.type_specific_data:
                self.type_specific_data['prefix'] = ''

        elif self.product_type == self.ProductType.COSMETIC:
            # Requerido: subcategory (str)
            if 'subcategory' not in self.type_specific_data:
                self.type_specific_data['subcategory'] = 'particle'

        elif self.product_type == self.ProductType.CRATE:
            # Requerido: possible_items (list)
            if 'possible_items' not in self.type_specific_data:
                self.type_specific_data['possible_items'] = []

        elif self.product_type == self.ProductType.FEATURE:
            # Requerido: command (str), duration (str)
            if 'command' not in self.type_specific_data:
                self.type_specific_data['command'] = ''
            if 'duration' not in self.type_specific_data:
                self.type_specific_data['duration'] = 'permanent'

        elif self.product_type == self.ProductType.ITEM:
            # Requerido: quantity (int)
            if 'quantity' not in self.type_specific_data:
                self.type_specific_data['quantity'] = 1
class CalendarEvent(models.Model):
    """
    Eventos del calendario (PvP, Torneos, Comunidad, etc.)
    Mapeado para coincidir con el frontend CalendarEvent interface.
    """
    class Category(models.TextChoices):
        PVP = 'pvp', 'PvP'
        EVENTO = 'evento', 'Evento'
        ACTUALIZACION = 'actualizacion', 'Actualización'
        TORNEO = 'torneo', 'Torneo'
        CONSTRUCCION = 'construccion', 'Construcción'
        COMUNIDAD = 'comunidad', 'Comunidad'

    class Status(models.TextChoices):
        UPCOMING = 'upcoming', 'Próximo'
        ONGOING = 'ongoing', 'En Curso'
        COMPLETED = 'completed', 'Finalizado'
        CANCELLED = 'cancelled', 'Cancelado'

    title = models.CharField(max_length=200, verbose_name='Título')
    description = models.TextField(verbose_name='Descripción')
    short_description = models.CharField(max_length=300, blank=True, verbose_name='Descripción Corta')

    # Fechas y Horarios
    date = models.DateField(verbose_name='Fecha')
    start_time = models.TimeField(verbose_name='Hora de Inicio')
    end_time = models.TimeField(blank=True, null=True, verbose_name='Hora de Fin')
    
    # Categorización
    category = models.CharField(
        max_length=20, 
        choices=Category.choices,
        verbose_name='Categoría'
    )
    status = models.CharField(
        max_length=20, 
        choices=Status.choices, 
        default=Status.UPCOMING,
        verbose_name='Estado'
    )

    # Visual
    banner_image = models.ImageField(
        upload_to='events/banners/', 
        blank=True, 
        null=True,
        verbose_name='Banner'
    )
    card_image = models.ImageField(
        upload_to='events/cards/', 
        blank=True, 
        null=True,
        verbose_name='Imagen de Tarjeta'
    )
    color = models.CharField(
        max_length=7, 
        blank=True, 
        verbose_name='Color Personalizado',
        help_text='Color hexadecimal (ej: #ff0000)'
    )

    # Premios (JSON array de objetos EventPrize)
    prizes = models.JSONField(
        default=list, 
        blank=True,
        verbose_name='Premios',
        help_text='Lista de premios en formato JSON'
    )

    # Info Adicional
    location = models.CharField(max_length=200, blank=True, verbose_name='Ubicación/Servidor')
    max_participants = models.PositiveIntegerField(blank=True, null=True, verbose_name='Max Participantes')
    current_participants = models.PositiveIntegerField(default=0, verbose_name='Participantes Actuales')
    requires_registration = models.BooleanField(default=False, verbose_name='Requiere Inscripción')
    registration_url = models.URLField(blank=True, verbose_name='URL de Inscripción')

    grovs_reward = models.PositiveIntegerField(default=0, verbose_name='Recompensa en Grovs')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Evento de Calendario'
        verbose_name_plural = 'Eventos de Calendario'
        ordering = ['date', 'start_time']

    def __str__(self):
        return f"{self.title} ({self.date})"

    def get_image_url(self, request):
        from .utils import get_image_url
        return get_image_url(request, self.card_image)

    def get_banner_url(self, request):
        from .utils import get_image_url
        return get_image_url(request, self.banner_image)


class DownloadableFile(models.Model):
    """Modelo para gestionar archivos descargables de forma segura"""
    title = models.CharField(max_length=200, verbose_name='Título')
    description = models.TextField(blank=True, verbose_name='Descripción')
    file = models.FileField(upload_to='protected_downloads/', verbose_name='Archivo')
    category = models.CharField(max_length=100, blank=True, verbose_name='Categoría')
    
    # Control de acceso
    min_role = models.CharField(
        max_length=20,
        choices=User.Role.choices,
        default=User.Role.DEFAULT,
        verbose_name='Rol Mínimo Requerido'
    )
    is_active = models.BooleanField(default=True, verbose_name='Activo')
    
    # Estadísticas
    download_count = models.PositiveIntegerField(default=0, verbose_name='Contador de Descargas')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Archivo Descargable'
        verbose_name_plural = 'Archivos Descargables'
        ordering = ['-created_at']

    def __str__(self):
        return self.title
