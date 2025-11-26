from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import HeroSection, GameHeader, User, Banner

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

admin.site.register(HeroSection)
admin.site.register(GameHeader)