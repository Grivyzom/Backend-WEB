from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import HeroSection, GameHeader, User, Banner, GalleryCategory, GalleryImage, ProductCategory, Product, DownloadableFile

@admin.register(DownloadableFile)
class DownloadableFileAdmin(admin.ModelAdmin):
    list_display = ('title', 'category', 'min_role', 'download_count', 'is_active', 'created_at')
    list_filter = ('category', 'min_role', 'is_active')
    search_fields = ('title', 'description')
    readonly_fields = ('download_count',)

@admin.register(Banner)
class BannerAdmin(admin.ModelAdmin):
    list_display = ('name', 'description', 'created_at')
    search_fields = ('name', 'description')
    list_filter = ('created_at',)

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ('minecraft_username', 'email', 'role', 'is_staff_role', 'is_banned', 'date_joined')
    list_filter = ('role', 'is_banned', 'is_active', 'date_joined')
    search_fields = ('minecraft_username', 'email', 'discord_username', 'username')
    ordering = ('-date_joined',)
    
    fieldsets = (
        (None, {
            'fields': ('username', 'password')
        }),
        ('Información Personal', {
            'fields': ('first_name', 'last_name', 'email', 'minecraft_username', 'discord_username', 'bio', 'avatar')
        }),
        ('Rol y Permisos', {
            'fields': ('role', 'is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
            'description': '⚠️ IMPORTANTE: Solo staff autorizado puede cambiar roles. Los nuevos usuarios siempre comienzan con rol DEFAULT.'
        }),
        ('Banners', {
            'fields': ('active_banner', 'collected_banners')
        }),
        ('Baneo', {
            'fields': ('is_banned', 'ban_reason')
        }),
        ('Fechas Importantes', {
            'fields': ('date_joined', 'last_login')
        }),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'minecraft_username', 'email', 'password', 'role'),
        }),
    )
    
    readonly_fields = ('date_joined', 'last_login')
    
    filter_horizontal = ('collected_banners',)

    def save_model(self, request, obj, form, change):
        # Prevenir que usuarios no autorizados cambien roles a staff
        if not change:  # Si es un nuevo usuario
            obj.role = User.Role.DEFAULT
        super().save_model(request, obj, form, change)


@admin.register(GalleryCategory)
class GalleryCategoryAdmin(admin.ModelAdmin):
    """Admin para gestionar categorías de la galería"""
    list_display = ('name', 'slug', 'order', 'is_active', 'image_count', 'created_at')
    list_filter = ('is_active', 'created_at')
    search_fields = ('name', 'description')
    prepopulated_fields = {'slug': ('name',)}
    ordering = ('order', 'name')
    list_editable = ('order', 'is_active')
    
    def image_count(self, obj):
        return obj.images.count()
    image_count.short_description = 'Imágenes'


@admin.register(GalleryImage)
class GalleryImageAdmin(admin.ModelAdmin):
    """Admin para gestionar imágenes de la galería"""
    list_display = ('title', 'category', 'author', 'is_featured', 'order', 'created_at')
    list_filter = ('category', 'is_featured', 'created_at')
    search_fields = ('title', 'description', 'author')
    ordering = ('-is_featured', 'order', '-created_at')
    list_editable = ('is_featured', 'order')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        (None, {
            'fields': ('title', 'category', 'description')
        }),
        ('Imagen', {
            'fields': ('image', 'thumbnail'),
            'description': 'La miniatura es opcional. Si no se proporciona, se usará la imagen principal.'
        }),
        ('Metadatos', {
            'fields': ('author', 'is_featured', 'order')
        }),
        ('Fechas', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


admin.site.register(HeroSection)
admin.site.register(GameHeader)


# Importar PendingRegistration
from .models import PendingRegistration

@admin.register(PendingRegistration)
class PendingRegistrationAdmin(admin.ModelAdmin):
    """Admin para gestionar registros pendientes de verificación en Minecraft"""
    list_display = ('username', 'email', 'verification_code', 'status', 'created_at', 'expires_at', 'is_expired_display')
    list_filter = ('status', 'created_at')
    search_fields = ('username', 'email', 'verification_code', 'minecraft_username_verified')
    ordering = ('-created_at',)
    readonly_fields = ('password_hash', 'verification_code', 'created_at', 'verified_at', 'ip_address', 'attempts')
    
    fieldsets = (
        ('Datos del Registro', {
            'fields': ('username', 'email', 'password_hash')
        }),
        ('Verificación', {
            'fields': ('verification_code', 'status', 'minecraft_uuid', 'minecraft_username_verified')
        }),
        ('Tiempos', {
            'fields': ('created_at', 'expires_at', 'verified_at')
        }),
        ('Seguridad', {
            'fields': ('ip_address', 'attempts'),
            'classes': ('collapse',)
        }),
    )
    
    def is_expired_display(self, obj):
        return obj.is_expired
    is_expired_display.boolean = True
    is_expired_display.short_description = 'Expirado'
    
    actions = ['mark_as_expired', 'mark_as_cancelled']
    
    def mark_as_expired(self, request, queryset):
        queryset.update(status=PendingRegistration.Status.EXPIRED)
        self.message_user(request, f'{queryset.count()} registro(s) marcado(s) como expirado(s)')
    mark_as_expired.short_description = 'Marcar como expirado'
    
    def mark_as_cancelled(self, request, queryset):
        queryset.update(status=PendingRegistration.Status.CANCELLED)
        self.message_user(request, f'{queryset.count()} registro(s) cancelado(s)')
    mark_as_cancelled.short_description = 'Cancelar registro(s)'


# ============================================================================
# ADMIN DE COMUNIDAD
# ============================================================================

from .models import PostCategory, CommunityPost, PostLike, PostComment, UserFollow, PostBookmark


@admin.register(PostCategory)
class PostCategoryAdmin(admin.ModelAdmin):
    """Admin para gestionar categorías de posts (staff only)"""
    list_display = ('name', 'slug', 'icon', 'color', 'order', 'is_active', 'post_count')
    list_filter = ('is_active',)
    search_fields = ('name', 'description')
    prepopulated_fields = {'slug': ('name',)}
    ordering = ('order', 'name')
    list_editable = ('order', 'is_active')
    
    fieldsets = (
        (None, {
            'fields': ('name', 'slug', 'description')
        }),
        ('Apariencia', {
            'fields': ('icon', 'color'),
            'description': 'Icono = nombre Lucide (ej: hammer, book-open). Color = hex (#8b5cf6)'
        }),
        ('Configuración', {
            'fields': ('order', 'is_active')
        }),
    )
    
    def post_count(self, obj):
        return obj.posts.filter(status='PUBLISHED').count()
    post_count.short_description = 'Posts'


@admin.register(CommunityPost)
class CommunityPostAdmin(admin.ModelAdmin):
    """Admin para gestionar posts de comunidad (CRUD completo para staff)"""
    list_display = ('title', 'author', 'category', 'status', 'is_pinned', 'is_featured', 'views', 'likes_display', 'created_at')
    list_filter = ('status', 'category', 'is_pinned', 'is_featured', 'created_at')
    search_fields = ('title', 'content', 'author__username', 'tags')
    ordering = ('-created_at',)
    readonly_fields = ('views', 'created_at', 'updated_at', 'published_at', 'slug')
    list_editable = ('status', 'is_pinned', 'is_featured')
    autocomplete_fields = ['author', 'category']
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Contenido', {
            'fields': ('title', 'slug', 'excerpt', 'content', 'cover_image')
        }),
        ('Autor y Categoría', {
            'fields': ('author', 'category', 'tags')
        }),
        ('Estado y Visibilidad', {
            'fields': ('status', 'is_pinned', 'is_featured')
        }),
        ('Métricas', {
            'fields': ('views',),
            'classes': ('collapse',)
        }),
        ('Fechas', {
            'fields': ('created_at', 'updated_at', 'published_at'),
            'classes': ('collapse',)
        }),
    )
    
    def likes_display(self, obj):
        return obj.likes_count
    likes_display.short_description = '❤️'
    
    actions = ['publish_posts', 'hide_posts', 'pin_posts', 'feature_posts']
    
    def publish_posts(self, request, queryset):
        queryset.update(status=CommunityPost.Status.PUBLISHED)
        self.message_user(request, f'{queryset.count()} post(s) publicado(s)')
    publish_posts.short_description = '✅ Publicar posts seleccionados'
    
    def hide_posts(self, request, queryset):
        queryset.update(status=CommunityPost.Status.HIDDEN)
        self.message_user(request, f'{queryset.count()} post(s) ocultado(s)')
    hide_posts.short_description = '👁️ Ocultar posts seleccionados'
    
    def pin_posts(self, request, queryset):
        queryset.update(is_pinned=True)
        self.message_user(request, f'{queryset.count()} post(s) fijado(s)')
    pin_posts.short_description = '📌 Fijar posts seleccionados'
    
    def feature_posts(self, request, queryset):
        queryset.update(is_featured=True)
        self.message_user(request, f'{queryset.count()} post(s) destacado(s)')
    feature_posts.short_description = '⭐ Destacar posts seleccionados'


@admin.register(PostComment)
class PostCommentAdmin(admin.ModelAdmin):
    """Admin para moderar comentarios"""
    list_display = ('truncated_content', 'author', 'post', 'parent', 'is_deleted', 'created_at')
    list_filter = ('is_deleted', 'created_at')
    search_fields = ('content', 'author__username', 'post__title')
    ordering = ('-created_at',)
    readonly_fields = ('created_at', 'updated_at')
    list_editable = ('is_deleted',)
    
    def truncated_content(self, obj):
        return obj.content[:50] + '...' if len(obj.content) > 50 else obj.content
    truncated_content.short_description = 'Contenido'
    
    actions = ['delete_comments', 'restore_comments']
    
    def delete_comments(self, request, queryset):
        queryset.update(is_deleted=True)
        self.message_user(request, f'{queryset.count()} comentario(s) eliminado(s)')
    delete_comments.short_description = '🗑️ Eliminar comentarios'
    
    def restore_comments(self, request, queryset):
        queryset.update(is_deleted=False)
        self.message_user(request, f'{queryset.count()} comentario(s) restaurado(s)')
    restore_comments.short_description = '♻️ Restaurar comentarios'


@admin.register(PostLike)
class PostLikeAdmin(admin.ModelAdmin):
    """Admin para ver likes (solo lectura)"""
    list_display = ('user', 'post', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('user__username', 'post__title')
    ordering = ('-created_at',)
    readonly_fields = ('user', 'post', 'created_at')


@admin.register(UserFollow)
class UserFollowAdmin(admin.ModelAdmin):
    """Admin para ver seguimientos"""
    list_display = ('follower', 'following', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('follower__username', 'following__username')
    ordering = ('-created_at',)


@admin.register(PostBookmark)
class PostBookmarkAdmin(admin.ModelAdmin):
    """Admin para ver marcadores"""
    list_display = ('user', 'post', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('user__username', 'post__title')
    ordering = ('-created_at',)


# ============================================================================
# ADMIN DE TIENDA / STORE ADMIN
# ============================================================================

@admin.register(ProductCategory)
class ProductCategoryAdmin(admin.ModelAdmin):
    """Admin para gestionar categorías de productos"""
    list_display = ('name', 'product_type', 'icon', 'color', 'order', 'is_active', 'product_count')
    list_filter = ('product_type', 'is_active')
    search_fields = ('name', 'description')
    prepopulated_fields = {'slug': ('name',)}
    ordering = ('order', 'name')
    list_editable = ('order', 'is_active')

    fieldsets = (
        (None, {
            'fields': ('name', 'slug', 'description', 'product_type')
        }),
        ('Apariencia', {
            'fields': ('icon', 'color'),
            'description': 'Icono = nombre Lucide (ej: crown, sparkles, box). Color = hex (#8b5cf6)'
        }),
        ('Configuración', {
            'fields': ('order', 'is_active')
        }),
    )

    def product_count(self, obj):
        return obj.products.count()
    product_count.short_description = 'Productos'


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    """Admin para gestionar productos de la tienda"""
    list_display = ('name', 'product_type', 'category', 'price', 'discount_price', 'is_available', 'is_featured', 'stock', 'views', 'purchases', 'created_at')
    list_filter = ('product_type', 'category', 'rarity', 'is_available', 'is_featured', 'is_new', 'created_at')
    search_fields = ('name', 'description', 'short_description')
    ordering = ('-is_featured', 'order', '-created_at')
    readonly_fields = ('slug', 'views', 'purchases', 'created_at', 'updated_at', 'created_by', 'last_modified_by', 'discount_percent', 'final_price', 'revenue_potential')
    list_editable = ('is_available', 'is_featured')
    autocomplete_fields = ['category']
    date_hierarchy = 'created_at'

    fieldsets = (
        ('Información Básica', {
            'fields': ('name', 'slug', 'product_type', 'category', 'rarity')
        }),
        ('Descripciones', {
            'fields': ('short_description', 'description')
        }),
        ('Imagen', {
            'fields': ('image',)
        }),
        ('Precio', {
            'fields': ('price', 'discount_price', 'discount_percent', 'final_price')
        }),
        ('Estado', {
            'fields': ('is_available', 'is_featured', 'is_new', 'stock', 'order')
        }),
        ('Datos Específicos del Tipo', {
            'fields': ('type_specific_data',),
            'description': 'JSON con campos específicos según el tipo de producto'
        }),
        ('Métricas', {
            'fields': ('views', 'purchases', 'revenue_potential'),
            'classes': ('collapse',)
        }),
        ('Auditoría', {
            'fields': ('created_at', 'updated_at', 'created_by', 'last_modified_by'),
            'classes': ('collapse',)
        }),
    )

    actions = ['make_available', 'make_unavailable', 'make_featured', 'remove_featured']

    def make_available(self, request, queryset):
        queryset.update(is_available=True)
        self.message_user(request, f'{queryset.count()} producto(s) marcado(s) como disponible(s)')
    make_available.short_description = '✅ Marcar como disponible'

    def make_unavailable(self, request, queryset):
        queryset.update(is_available=False)
        self.message_user(request, f'{queryset.count()} producto(s) marcado(s) como no disponible(s)')
    make_unavailable.short_description = '❌ Marcar como no disponible'

    def make_featured(self, request, queryset):
        queryset.update(is_featured=True)
        self.message_user(request, f'{queryset.count()} producto(s) destacado(s)')
    make_featured.short_description = '⭐ Destacar productos'

    def remove_featured(self, request, queryset):
        queryset.update(is_featured=False)
        self.message_user(request, f'{queryset.count()} producto(s) ya no destacado(s)')
    remove_featured.short_description = '⚪ Quitar de destacados'

    def save_model(self, request, obj, form, change):
        if not change:  # Si es nuevo
            obj.created_by = request.user
        obj.last_modified_by = request.user
        super().save_model(request, obj, form, change)
# ============================================================================
# ADMIN DE CALENDARIO
# ============================================================================

from .models import CalendarEvent

@admin.register(CalendarEvent)
class CalendarEventAdmin(admin.ModelAdmin):
    list_display = ('title', 'date', 'start_time', 'category', 'status', 'requires_registration')
    list_filter = ('category', 'status', 'date')
    search_fields = ('title', 'description', 'location')
    ordering = ('-date', '-start_time')
    date_hierarchy = 'date'
    
    fieldsets = (
        ('Información Básica', {
            'fields': ('title', 'short_description', 'description', 'category', 'status', 'color')
        }),
        ('Fecha y Hora', {
            'fields': ('date', 'start_time', 'end_time')
        }),
        ('Imágenes', {
            'fields': ('banner_image', 'card_image')
        }),
        ('Detalles del Evento', {
            'fields': ('location', 'prizes', 'grovs_reward')
        }),
        ('Inscripción', {
            'fields': ('requires_registration', 'registration_url', 'max_participants', 'current_participants')
        }),
    )
