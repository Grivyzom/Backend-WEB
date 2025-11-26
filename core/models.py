# MODELO TEMPORAL - Copiar de vuelta a models.py después de resetear la DB

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
        validators=[MinLengthValidator(3)],
        verbose_name='Usuario de Minecraft',
        help_text='Nombre de usuario en Minecraft (3-16 caracteres)'
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
        return f"{self.minecraft_username} ({self.get_role_display()})"
    
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
    image = models.ImageField(upload_to='hero_images/')
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
    image = models.ImageField(upload_to='game_header_images/')
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