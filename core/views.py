from django.shortcuts import render
from django.http import JsonResponse, FileResponse
from django.db.models import F
from .models import HeroSection, GameHeader, User, Contact, Banner, GalleryCategory, GalleryImage, PendingRegistration, PostCategory, CommunityPost, PostLike, PostComment, UserFollow, PostBookmark, CalendarEvent, DownloadableFile
from django.conf import settings
import json
import re
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django_ratelimit.decorators import ratelimit
from .utils import get_image_url
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import make_password
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.urls import reverse
from django.utils import timezone
from PIL import Image
import uuid
import logging

# Configure logger
logger = logging.getLogger(__name__)

def hero_section_api_view(request):
    try:
        # Get the latest HeroSection object
        hero_section = HeroSection.objects.latest('created_at')
        data = {
            'title': hero_section.title,
            'description': hero_section.description,
            'image_url': get_image_url(request, hero_section.image),
        }
        return JsonResponse(data)
    except HeroSection.DoesNotExist:
        return JsonResponse({'message': 'HeroSection data not found.'}, status=404)

def game_header_api_view(request):
    try:
        # Get the latest GameHeader object
        game_header = GameHeader.objects.latest('created_at')
        data = {
            'title': game_header.title,
            'subtitle': game_header.subtitle,
            'button_text': game_header.button_text,
            'image_url': get_image_url(request, game_header.image),
        }
        return JsonResponse(data)
    except GameHeader.DoesNotExist:
        # Return default data instead of 404
        data = {
            'title': 'GRIVYZOM',
            'subtitle': 'A WORLD OF ADVENTURE AND CREATIVITY',
            'button_text': 'JUGAR AHORA!',
            'image_url': request.build_absolute_uri('/static/images/placeholder.svg'),
        }
        return JsonResponse(data)

def public_stats_api_view(request):
    """Vista pública para estadísticas generales del servidor"""
    try:
        total_users = User.objects.count()
        # Por ahora, como no hay integración real con el servidor de Minecraft, 
        # devolvemos un valor simulado o 0.
        # En el futuro esto podría consultar una caché o un servicio externo.
        players_online = 0 
        
        return JsonResponse({
            'total_users': total_users,
            'players_online': players_online,
            'status': 'online'
        })
    except Exception as e:
        logger.error(f"Error en public_stats_api_view: {e}")
        return JsonResponse({'error': 'Error al obtener estadísticas'}, status=500)

def servers_api_view(request):
    """Vista para obtener la lista de servidores de Minecraft"""
    servers = [
        {
            'id': 'survival',
            'name': 'Survival Pro',
            'description': 'Nuestro servidor principal con economía y protecciones.',
            'bannerUrl': request.build_absolute_uri('/static/images/servers/survival_banner.png'),
            'version': '1.20.1',
            'playersOnline': 12,
            'maxPlayers': 100,
            'status': 'online',
            'tags': ['Economía', 'Protecciones', 'PVP'],
            'route': '/servidores/survival'
        },
        {
            'id': 'skyblock',
            'name': 'SkyBlock Classic',
            'description': 'Sobrevive en una isla flotante y expande tu imperio.',
            'bannerUrl': request.build_absolute_uri('/static/images/servers/skyblock_banner.png'),
            'version': '1.20.1',
            'playersOnline': 5,
            'maxPlayers': 50,
            'status': 'online',
            'tags': ['Survival', 'Islas'],
            'route': '/servidores/skyblock'
        }
    ]
    
    return JsonResponse({
        'success': True,
        'servers': servers,
        'lastUpdate': timezone.now().isoformat()
    })

@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(ratelimit(key='ip', rate='5/h', method='POST'), name='dispatch')
class ContactView(View):
    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body)
            contact = Contact.objects.create(
                client_name=data.get('client_name'),
                email=data.get('email'),
                discord=data.get('discord'),
                message=data.get('message'),
            )
            return JsonResponse({'message': 'Información de contacto guardada correctamente.'}, status=201)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON.'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

# ============================================================================
# VISTAS DE AUTENTICACIÓN CON MEDIDAS DE SEGURIDAD
# ============================================================================

def validate_password_strength(password):
    """
    Valida que la contraseña cumpla con requisitos de seguridad:
    - Mínimo 8 caracteres
    - Al menos una letra mayúscula
    - Al menos una letra minúscula
    - Al menos un número
    - Al menos un carácter especial
    """
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres"

    if not re.search(r'[A-Z]', password):
        return False, "La contraseña debe contener al menos una letra mayúscula"

    if not re.search(r'[a-z]', password):
        return False, "La contraseña debe contener al menos una letra minúscula"

    if not re.search(r'\d', password):
        return False, "La contraseña debe contener al menos un número"

    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/;~`]', password):
        return False, "La contraseña debe contener al menos un carácter especial (!@#$%^&*(),.?\":{}|<>_-+=[]\\\/;~`)"

    return True, ""

def validate_minecraft_username(username):
    """
    Valida que el nombre de Minecraft sea válido:
    - 3-16 caracteres
    - Solo letras, números y guiones bajos
    """
    if len(username) < 3 or len(username) > 16:
        return False, "El nombre de Minecraft debe tener entre 3 y 16 caracteres"
    
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "El nombre de Minecraft solo puede contener letras, números y guiones bajos"
    
    return True, ""

def sanitize_input(text):
    """Sanitiza el input del usuario para prevenir inyecciones"""
    if not text:
        return text
    # Eliminar caracteres potencialmente peligrosos
    return re.sub(r'[<>{}]', '', text.strip())

@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(ratelimit(key='ip', rate='3/h', method='POST'), name='dispatch')
class ForgotPasswordView(View):
    """
    Vista para solicitar un enlace de restablecimiento de contraseña.
    Genera un token y envía un correo electrónico al usuario.
    Rate limit: 3 intentos por hora por IP
    """
    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body)
            email = data.get('email', '').strip().lower()

            if not email:
                return JsonResponse({'error': 'El email es requerido.'}, status=400)

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                # Retorna un mensaje genérico para evitar la enumeración de usuarios
                return JsonResponse({'message': 'Si el correo está registrado, recibirás un enlace para recuperar tu contraseña.'}, status=200)

            # Generar un token de restablecimiento de contraseña único
            reset_token = str(uuid.uuid4())
            user.password_reset_token = reset_token
            user.password_reset_expires = timezone.now() + timezone.timedelta(hours=1)  # Token válido por 1 hora
            user.save()

            # Construir el enlace de restablecimiento usando la URL del frontend desde settings
            reset_link = f"{settings.FRONTEND_URL}/reset-password/{reset_token}"

            # Enviar correo electrónico
            subject = 'Restablecimiento de Contraseña para Grivyzom'
            message = f"""
            Hola {user.username},

            Recibimos una solicitud para restablecer la contraseña de tu cuenta Grivyzom.
            Haz clic en el siguiente enlace para establecer una nueva contraseña:

            {reset_link}

            Este enlace expirará en 1 hora. Si no solicitaste un restablecimiento de contraseña, puedes ignorar este correo electrónico de forma segura.

            Saludos,
            El equipo de Grivyzom
            """

            try:
                send_mail(
                    subject,
                    message,
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False,
                )
                logger.info(f"Password reset email sent to {user.email}")
            except Exception as email_error:
                logger.error(f"Failed to send password reset email: {str(email_error)}")
                # En desarrollo con console backend, esto es normal
                if settings.DEBUG:
                    logger.debug(f"Password Reset Link for {user.email}: {reset_link}")

            return JsonResponse({'message': 'Si el correo está registrado, recibirás un enlace para recuperar tu contraseña.'}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido.'}, status=400)
        except Exception as e:
            logger.error(f"Error in ForgotPasswordView: {str(e)}")
            return JsonResponse({'error': 'Error interno del servidor.'}, status=500)

@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(ratelimit(key='ip', rate='5/h', method='POST'), name='dispatch')
class RegisterView(View):
    """
    Vista para registro de nuevos usuarios con verificación en Minecraft.
    Crea un PendingRegistration que debe ser verificado en el servidor de Minecraft.
    Rate limit: 5 intentos por hora por IP
    """

    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body)
            
            # ========== VALIDACIÓN DE CAMPOS REQUERIDOS ==========
            username = sanitize_input(data.get('username', '').strip())
            email = data.get('email', '').strip().lower()
            password = data.get('password', '')
            
            if not all([username, email, password]):
                return JsonResponse({
                    'error': 'Username, email y password son requeridos'
                }, status=400)
            
            # ========== VALIDACIÓN DE EMAIL ==========
            try:
                validate_email(email)
            except ValidationError:
                return JsonResponse({
                    'error': 'Email inválido'
                }, status=400)
            
            # ========== VALIDACIÓN DE CONTRASEÑA ==========
            is_valid, error_msg = validate_password_strength(password)
            if not is_valid:
                return JsonResponse({
                    'error': error_msg
                }, status=400)
            
            # ========== VALIDACIÓN DE USERNAME ==========
            if len(username) < 3 or len(username) > 30:
                return JsonResponse({
                    'error': 'El username debe tener entre 3 y 30 caracteres'
                }, status=400)
            
            if not re.match(r'^[a-zA-Z0-9_]+$', username):
                return JsonResponse({
                    'error': 'El username solo puede contener letras, números y guiones bajos'
                }, status=400)
            
            # ========== VERIFICAR EXISTENCIA EN USERS ==========
            # Usar mensaje genérico para prevenir enumeración de usuarios
            if User.objects.filter(username__iexact=username).exists():
                return JsonResponse({
                    'error': 'Los datos proporcionados no son válidos o ya están en uso'
                }, status=400)

            if User.objects.filter(email__iexact=email).exists():
                return JsonResponse({
                    'error': 'Los datos proporcionados no son válidos o ya están en uso'
                }, status=400)
            
            # ========== LIMPIAR REGISTROS PENDIENTES ANTERIORES ==========
            # Eliminar registros NO verificados (expirados, cancelados) para liberar el username/email
            PendingRegistration.objects.filter(
                username__iexact=username,
                status__in=[
                    PendingRegistration.Status.EXPIRED,
                    PendingRegistration.Status.CANCELLED
                ]
            ).delete()
            
            PendingRegistration.objects.filter(
                email__iexact=email,
                status__in=[
                    PendingRegistration.Status.EXPIRED,
                    PendingRegistration.Status.CANCELLED
                ]
            ).delete()
            
            # Cancelar registros PENDING anteriores del mismo username/email
            PendingRegistration.objects.filter(
                username__iexact=username,
                status=PendingRegistration.Status.PENDING
            ).update(status=PendingRegistration.Status.CANCELLED)
            
            # Ahora eliminar los que acabamos de cancelar
            PendingRegistration.objects.filter(
                username__iexact=username,
                status=PendingRegistration.Status.CANCELLED
            ).delete()
            
            PendingRegistration.objects.filter(
                email__iexact=email,
                status=PendingRegistration.Status.PENDING
            ).update(status=PendingRegistration.Status.CANCELLED)
            
            PendingRegistration.objects.filter(
                email__iexact=email,
                status=PendingRegistration.Status.CANCELLED
            ).delete()
            
            # ========== CREAR REGISTRO PENDIENTE ==========
            verification_code = PendingRegistration.generate_verification_code()
            expires_at = timezone.now() + timezone.timedelta(minutes=15)
            
            # Hashear la contraseña
            password_hash = make_password(password)
            
            # Obtener IP del cliente
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip_address = x_forwarded_for.split(',')[0].strip()
            else:
                ip_address = request.META.get('REMOTE_ADDR')
            
            pending = PendingRegistration.objects.create(
                username=username,
                email=email,
                password_hash=password_hash,
                verification_code=verification_code,
                expires_at=expires_at,
                ip_address=ip_address
            )
            
            return JsonResponse({
                'message': 'Registro pendiente de verificación',
                'pending_id': pending.id,
                'verification_code': verification_code,
                'expires_in_minutes': 15,
                'instructions': 'Entra al servidor de Minecraft y usa /verificar ' + verification_code
            }, status=201)
            
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
        except Exception as e:
            logger.error(f"Error in RegisterView: {str(e)}")
            return JsonResponse({'error': 'Error al registrar usuario'}, status=500)

@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(ratelimit(key='ip', rate='10/m', method='POST'), name='dispatch')
class LoginView(View):
    """
    Vista para login de usuarios con validaciones de seguridad.
    Rate limit: 10 intentos por minuto por IP
    """

    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body)

            identifier = sanitize_input(data.get('username', '').strip())
            password = data.get('password', '')

            if not all([identifier, password]):
                return JsonResponse({
                    'error': 'El identificador y la contraseña son requeridos'
                }, status=400)

            # ========== AUTENTICAR USUARIO POR USERNAME, EMAIL O MINECRAFT USERNAME ==========
            user = None

            # 1. Intento por username
            user = authenticate(request, username=identifier, password=password)

            if user is None:
                # 2. Intento por email
                try:
                    user_by_email = User.objects.get(email__iexact=identifier)
                    user = authenticate(request, username=user_by_email.username, password=password)
                except User.DoesNotExist:
                    pass  # Continuar al siguiente método

            if user is None:
                # 3. Intento por minecraft_username
                try:
                    user_by_minecraft = User.objects.get(minecraft_username__iexact=identifier)
                    user = authenticate(request, username=user_by_minecraft.username, password=password)
                except User.DoesNotExist:
                    pass  # El usuario no se encontró por ningún método

            if user is not None:
                # ========== VERIFICAR ESTADO DEL USUARIO ==========
                if user.is_banned:
                    logger.warning(f"Banned user attempted login: {user.username}")
                    return JsonResponse({
                        'error': 'Usuario bloqueado',
                        'ban_reason': user.ban_reason
                    }, status=403)

                if not user.is_active:
                    logger.warning(f"Inactive user attempted login: {user.username}")
                    return JsonResponse({
                        'error': 'Usuario inactivo. Contacta al administrador.'
                    }, status=403)

                # ========== LOGIN EXITOSO ==========
                logger.info(f"User logged in: {user.username}")
                login(request, user)
                
                # Serializar banner activo
                active_banner_data = None
                if user.active_banner:
                    active_banner_data = {
                        'id': user.active_banner.id,
                        'name': user.active_banner.name,
                        'image_url': user.active_banner.get_image_url(request),
                    }
                
                return JsonResponse({
                    'message': 'Login exitoso',
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'minecraft_username': user.minecraft_username,
                        'email': user.email,
                        'role': user.role,
                        'role_display': user.get_role_display(),
                        'is_staff': user.is_staff_role,
                        'is_player': user.is_player_role,
                        'avatar_url': user.get_avatar_url(request) if user.avatar else None,
                        'active_banner': active_banner_data,
                    }
                }, status=200)
            else:
                logger.warning(f"Failed login attempt for identifier: {identifier[:3]}***")
                return JsonResponse({
                    'error': 'Credenciales inválidas'
                }, status=401)

        except json.JSONDecodeError:
            logger.error("Invalid JSON in login request")
            return JsonResponse({'error': 'JSON inválido'}, status=400)
        except Exception as e:
            logger.error(f"Unexpected error in login: {str(e)}")
            return JsonResponse({'error': 'Error al iniciar sesión'}, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class LogoutView(View):
    """Vista para cerrar sesión"""
    def post(self, request, *args, **kwargs):
        logout(request)
        return JsonResponse({'message': 'Sesión cerrada exitosamente'}, status=200)

class UserProfileView(View):
    """Vista para obtener el perfil del usuario actual"""
    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'No autenticado'}, status=401)
        
        user = request.user
        
        # Serializar banner activo
        active_banner_data = None
        if user.active_banner:
            active_banner_data = {
                'id': user.active_banner.id,
                'name': user.active_banner.name,
                'image_url': user.active_banner.get_image_url(request),
                'description': user.active_banner.description,
            }

        # Serializar banners coleccionados
        collected_banners_data = [
            {
                'id': banner.id,
                'name': banner.name,
                'image_url': banner.get_image_url(request),
                'description': banner.description,
            }
            for banner in user.collected_banners.all()
        ]

        return JsonResponse({
            'user': {
                'id': user.id,
                'username': user.username,
                'minecraft_username': user.minecraft_username,
                'email': user.email,
                'role': user.role,
                'role_display': user.get_role_display(),
                'is_staff': user.is_staff_role,
                'is_player': user.is_player_role,
                'discord_username': user.discord_username,
                'bio': user.bio,
                'avatar_url': user.get_avatar_url(request) if user.avatar else None,
                'date_joined': user.date_joined.isoformat(),
                'active_banner': active_banner_data,
                'collected_banners': collected_banners_data,
            }
        }, status=200)

@method_decorator(csrf_exempt, name='dispatch')
class UpdateProfileView(View):
    """Vista para actualizar la información del perfil"""
    def put(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'No autenticado'}, status=401)
        
        try:
            data = json.loads(request.body)
            user = request.user
            
            # Campos actualizables
            username = data.get('username', '').strip()
            minecraft_username = data.get('minecraft_username', '').strip()
            discord_username = data.get('discord_username', '').strip()
            email = data.get('email', '').strip()
            bio = data.get('bio', '').strip()
            active_banner_id = data.get('active_banner_id')

            # Validaciones
            if username and username != user.username:
                if User.objects.filter(username=username).exists():
                    return JsonResponse({'error': 'El nombre de usuario ya está en uso'}, status=400)
                if len(username) < 3:
                    return JsonResponse({'error': 'El nombre de usuario debe tener al menos 3 caracteres'}, status=400)
                user.username = username
            
            if minecraft_username and minecraft_username != user.minecraft_username:
                if User.objects.filter(minecraft_username=minecraft_username).exists():
                    return JsonResponse({'error': 'El usuario de Minecraft ya está en uso'}, status=400)
                if len(minecraft_username) < 3 or len(minecraft_username) > 16:
                    return JsonResponse({'error': 'El usuario de Minecraft debe tener entre 3 y 16 caracteres'}, status=400)
                user.minecraft_username = minecraft_username
            
            if email and email != user.email:
                if User.objects.filter(email=email).exists():
                    return JsonResponse({'error': 'El email ya está en uso'}, status=400)
                user.email = email
            
            if discord_username is not None:
                user.discord_username = discord_username if discord_username else None
            
            if bio is not None:
                if len(bio) > 500:
                    return JsonResponse({'error': 'La biografía no puede superar los 500 caracteres'}, status=400)
                user.bio = bio if bio else None
            
            # Lógica para actualizar el banner activo
            if active_banner_id is not None:
                if active_banner_id == 0 or active_banner_id is None:  # Permitir desactivar el banner
                    user.active_banner = None
                else:
                    try:
                        # Asegurarse de que el banner exista y pertenezca al usuario
                        new_banner = user.collected_banners.get(id=active_banner_id)
                        user.active_banner = new_banner
                    except Banner.DoesNotExist:
                        return JsonResponse({'error': 'El banner seleccionado no es válido o no te pertenece'}, status=400)

            user.save()
            
            # Serializar banner activo
            active_banner_data = None
            if user.active_banner:
                active_banner_data = {
                    'id': user.active_banner.id,
                    'name': user.active_banner.name,
                    'image_url': user.active_banner.get_image_url(request),
                    'description': user.active_banner.description,
                }

            # Serializar banners coleccionados
            collected_banners_data = [
                {
                    'id': banner.id,
                    'name': banner.name,
                    'image_url': banner.get_image_url(request),
                    'description': banner.description,
                }
                for banner in user.collected_banners.all()
            ]
            
            return JsonResponse({
                'message': 'Perfil actualizado exitosamente',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'minecraft_username': user.minecraft_username,
                    'email': user.email,
                    'role': user.role,
                    'role_display': user.get_role_display(),
                    'is_staff': user.is_staff_role,
                    'is_player': user.is_player_role,
                    'discord_username': user.discord_username,
                    'bio': user.bio,
                    'avatar_url': user.get_avatar_url(request) if user.avatar else None,
                    'date_joined': user.date_joined.isoformat(),
                    'active_banner': active_banner_data,
                    'collected_banners': collected_banners_data,
                }
            }, status=200)
            
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
        except Exception as e:
            return JsonResponse({'error': f'Error al actualizar perfil: {str(e)}'}, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class ChangePasswordView(View):
    """Vista para cambiar la contraseña"""
    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'No autenticado'}, status=401)
        
        try:
            data = json.loads(request.body)
            user = request.user
            
            current_password = data.get('current_password', '')
            new_password = data.get('new_password', '')
            confirm_password = data.get('confirm_password', '')
            
            # Validaciones
            if not current_password:
                return JsonResponse({'error': 'La contraseña actual es requerida'}, status=400)
            
            if not new_password:
                return JsonResponse({'error': 'La nueva contraseña es requerida'}, status=400)
            
            if new_password != confirm_password:
                return JsonResponse({'error': 'Las contraseñas no coinciden'}, status=400)
            
            if len(new_password) < 8:
                return JsonResponse({'error': 'La contraseña debe tener al menos 8 caracteres'}, status=400)
            
            # Verificar contraseña actual
            if not user.check_password(current_password):
                return JsonResponse({'error': 'La contraseña actual es incorrecta'}, status=400)
            
            # Cambiar contraseña
            user.set_password(new_password)
            user.save()
            
            # Mantener la sesión activa después de cambiar contraseña
            from django.contrib.auth import update_session_auth_hash
            update_session_auth_hash(request, user)
            
            return JsonResponse({'message': 'Contraseña actualizada exitosamente'}, status=200)
            
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
        except Exception as e:
            return JsonResponse({'error': f'Error al cambiar contraseña: {str(e)}'}, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class UploadAvatarView(View):
    """Vista para subir/actualizar avatar"""
    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'No autenticado'}, status=401)
        
        try:
            if 'avatar' not in request.FILES:
                return JsonResponse({'error': 'No se ha proporcionado ninguna imagen'}, status=400)

            avatar_file = request.FILES['avatar']
            user = request.user

            # Validar tamaño (max 5MB)
            if avatar_file.size > 5 * 1024 * 1024:
                return JsonResponse({'error': 'La imagen no puede superar los 5MB'}, status=400)

            # Validar tipo de archivo por MIME type
            allowed_types = ['image/jpeg', 'image/png', 'image/jpg', 'image/webp']
            if avatar_file.content_type not in allowed_types:
                return JsonResponse({'error': 'Solo se permiten imágenes JPEG, PNG o WebP'}, status=400)

            # SEGURIDAD: Validar que realmente sea una imagen usando Pillow
            try:
                img = Image.open(avatar_file)
                img.verify()  # Verifica que sea una imagen válida
                avatar_file.seek(0)  # Resetear el puntero después de verify()

                # Validar dimensiones razonables (prevenir imágenes extremadamente grandes)
                if img.size[0] > 4096 or img.size[1] > 4096:
                    return JsonResponse({'error': 'La imagen no puede exceder 4096x4096 píxeles'}, status=400)

                # Validar formato de imagen
                if img.format not in ['JPEG', 'PNG', 'WEBP']:
                    return JsonResponse({'error': 'Formato de imagen no válido'}, status=400)

            except Exception as e:
                logger.warning(f"Invalid image file uploaded: {str(e)}")
                return JsonResponse({'error': 'El archivo no es una imagen válida'}, status=400)

            # Eliminar avatar anterior si existe
            if user.avatar:
                user.avatar.delete(save=False)

            # Guardar nuevo avatar
            user.avatar = avatar_file
            user.save()

            return JsonResponse({
                'message': 'Avatar actualizado exitosamente',
                'avatar_url': user.get_avatar_url(request)
            }, status=200)

        except Exception as e:
            logger.error(f"Error uploading avatar: {str(e)}")
            return JsonResponse({'error': 'Error al subir avatar'}, status=500)
    
    def delete(self, request, *args, **kwargs):
        """Eliminar avatar"""
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'No autenticado'}, status=401)
        
        try:
            user = request.user
            if user.avatar:
                user.avatar.delete(save=True)
                return JsonResponse({'message': 'Avatar eliminado exitosamente'}, status=200)
            else:
                return JsonResponse({'error': 'No hay avatar para eliminar'}, status=400)
        except Exception as e:
            return JsonResponse({'error': f'Error al eliminar avatar: {str(e)}'}, status=500)


@method_decorator(csrf_exempt, name='dispatch')
class ResetPasswordConfirmView(View):
    """
    Vista para confirmar el restablecimiento de contraseña.
    Valida el token y permite al usuario establecer una nueva contraseña.
    """
    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body)
            token = data.get('token', '')
            new_password = data.get('new_password', '')
            confirm_password = data.get('confirm_password', '')

            if not all([token, new_password, confirm_password]):
                return JsonResponse({'error': 'Token y contraseñas son requeridos.'}, status=400)

            if new_password != confirm_password:
                return JsonResponse({'error': 'Las contraseñas no coinciden.'}, status=400)
            
            is_valid, error_msg = validate_password_strength(new_password)
            if not is_valid:
                return JsonResponse({'error': error_msg}, status=400)

            try:
                user = User.objects.get(password_reset_token=token)
            except User.DoesNotExist:
                return JsonResponse({'error': 'Token inválido o expirado.'}, status=400)

            if user.password_reset_expires and user.password_reset_expires < timezone.now():
                user.password_reset_token = None
                user.password_reset_expires = None
                user.save()
                return JsonResponse({'error': 'Token expirado. Solicita uno nuevo.'}, status=400)
            
            user.set_password(new_password)
            user.password_reset_token = None
            user.password_reset_expires = None
            user.save()

            return JsonResponse({'message': 'Contraseña restablecida exitosamente.'}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido.'}, status=400)
        except Exception as e:
            logger.error(f"Error en ResetPasswordConfirmView: {e}")
            return JsonResponse({'error': 'Error interno del servidor.'}, status=500)


# ============================================================================
# VISTAS DE GALERÍA (Públicas)
# ============================================================================

def gallery_categories_api_view(request):
    """
    Lista todas las categorías activas de la galería.
    Endpoint público - no requiere autenticación.
    GET /api/gallery/categories/
    """
    try:
        categories = GalleryCategory.objects.filter(is_active=True)
        data = [
            {
                'id': cat.id,
                'name': cat.name,
                'slug': cat.slug,
                'description': cat.description,
                'icon': cat.icon,
                'image_count': cat.images.count(),
            }
            for cat in categories
        ]
        return JsonResponse({'categories': data}, status=200)
    except Exception as e:
        logger.error(f"Error en gallery_categories_api_view: {e}")
        return JsonResponse({'error': 'Error al obtener categorías.'}, status=500)


def gallery_images_api_view(request):
    """
    Lista las imágenes de la galería con filtros opcionales.
    Endpoint público - no requiere autenticación.
    GET /api/gallery/images/
    GET /api/gallery/images/?category=screenshots
    GET /api/gallery/images/?featured=true
    """
    try:
        images = GalleryImage.objects.select_related('category').all()
        
        # Filtrar por categoría (slug)
        category_slug = request.GET.get('category')
        if category_slug:
            images = images.filter(category__slug=category_slug, category__is_active=True)
        else:
            # Solo mostrar imágenes de categorías activas
            images = images.filter(category__is_active=True)
        
        # Filtrar por destacadas
        featured = request.GET.get('featured')
        if featured and featured.lower() == 'true':
            images = images.filter(is_featured=True)
        
        # Limitar resultados (opcional)
        limit = request.GET.get('limit')
        if limit and limit.isdigit():
            images = images[:int(limit)]
        
        data = [
            {
                'id': img.id,
                'title': img.title,
                'description': img.description,
                'image_url': img.get_image_url(request),
                'thumbnail_url': img.get_thumbnail_url(request),
                'author': img.author,
                'is_featured': img.is_featured,
                'category': {
                    'id': img.category.id,
                    'name': img.category.name,
                    'slug': img.category.slug,
                },
                'created_at': img.created_at.isoformat(),
            }
            for img in images
        ]
        return JsonResponse({'images': data}, status=200)
    except Exception as e:
        logger.error(f"Error en gallery_images_api_view: {e}")
        return JsonResponse({'error': 'Error al obtener imágenes.'}, status=500)


def gallery_image_detail_api_view(request, image_id):
    """
    Obtiene el detalle de una imagen específica.
    Endpoint público - no requiere autenticación.
    GET /api/gallery/images/<id>/
    """
    try:
        image = GalleryImage.objects.select_related('category').get(
            id=image_id, 
            category__is_active=True
        )
        data = {
            'id': image.id,
            'title': image.title,
            'description': image.description,
            'image_url': image.get_image_url(request),
            'thumbnail_url': image.get_thumbnail_url(request),
            'author': image.author,
            'is_featured': image.is_featured,
            'category': {
                'id': image.category.id,
                'name': image.category.name,
                'slug': image.category.slug,
            },
            'created_at': image.created_at.isoformat(),
        }
        return JsonResponse(data, status=200)
    except GalleryImage.DoesNotExist:
        return JsonResponse({'error': 'Imagen no encontrada.'}, status=404)
    except Exception as e:
        logger.error(f"Error en gallery_image_detail_api_view: {e}")
        return JsonResponse({'error': 'Error al obtener imagen.'}, status=500)


# ============================================================================
# VISTAS DE VERIFICACIÓN MINECRAFT
# ============================================================================

def get_mc_api_key():
    """Obtiene la API Key del plugin Minecraft desde settings."""
    return getattr(settings, 'MC_PLUGIN_API_KEY', None)

def verify_mc_api_key(request):
    """Verifica que el request tenga la API Key correcta del plugin."""
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if auth_header.startswith('Bearer '):
        token = auth_header[7:]
        expected_key = get_mc_api_key()
        return expected_key and token == expected_key
    return False


class RegistrationStatusView(View):
    """
    Vista para que el frontend consulte el estado de un registro pendiente.
    Usado para polling después de que el usuario se registra.
    GET /api/auth/registration-status/<pending_id>/
    
    Cuando el estado es VERIFIED, incluye:
    - auth_token: One-Time Token para auto-login
    - user: Datos del usuario creado
    """
    def get(self, request, pending_id, *args, **kwargs):
        try:
            pending = PendingRegistration.objects.get(id=pending_id)
            
            # Si expiró, actualizar estado
            if pending.is_expired and pending.status == PendingRegistration.Status.PENDING:
                pending.mark_as_expired()
            
            response_data = {
                'status': pending.status,
                'status_display': pending.get_status_display(),
                'is_expired': pending.is_expired,
                'username': pending.username,
            }
            
            # Si fue verificado, incluir datos del usuario y auth_token
            if pending.status == PendingRegistration.Status.VERIFIED:
                try:
                    user = User.objects.get(username=pending.username)
                    response_data['user'] = {
                        'id': user.id,
                        'username': user.username,
                        'minecraft_username': user.minecraft_username,
                        'email': user.email,
                        'role': user.role,
                        'role_display': user.get_role_display(),
                    }
                    response_data['verified'] = True
                    
                    # Incluir auth_token solo si no ha sido usado y no ha expirado
                    if pending.auth_token and not pending.auth_token_used:
                        if pending.auth_token_expires and timezone.now() < pending.auth_token_expires:
                            response_data['auth_token'] = pending.auth_token
                        
                except User.DoesNotExist:
                    response_data['verified'] = False
            
            return JsonResponse(response_data, status=200)
            
        except PendingRegistration.DoesNotExist:
            return JsonResponse({'error': 'Registro no encontrado'}, status=404)
        except Exception as e:
            logger.error(f"Error en RegistrationStatusView: {e}")
            return JsonResponse({'error': 'Error al consultar estado'}, status=500)


@method_decorator(csrf_exempt, name='dispatch')
class MinecraftVerifyView(View):
    """
    Vista para que el plugin de Minecraft verifique un registro.
    Requiere API Key de autenticación.
    POST /api/mc/verify-registration/
    
    Body:
    {
        "verification_code": "A7X9K2",
        "minecraft_uuid": "550e8400-e29b-41d4-a716-446655440000",
        "minecraft_username": "PlayerName"
    }
    """
    def post(self, request, *args, **kwargs):
        # Verificar API Key
        if not verify_mc_api_key(request):
            return JsonResponse({'error': 'Unauthorized'}, status=401)
        
        try:
            data = json.loads(request.body)
            
            verification_code = data.get('verification_code', '').strip().upper()
            minecraft_uuid = data.get('minecraft_uuid', '').strip()
            minecraft_username = data.get('minecraft_username', '').strip()
            
            if not all([verification_code, minecraft_uuid, minecraft_username]):
                return JsonResponse({
                    'error': 'verification_code, minecraft_uuid y minecraft_username son requeridos'
                }, status=400)
            
            # Validar formato de UUID
            if not re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', minecraft_uuid):
                return JsonResponse({
                    'error': 'Formato de UUID inválido'
                }, status=400)
            
            # Buscar registro pendiente
            try:
                pending = PendingRegistration.objects.get(
                    verification_code=verification_code,
                    status=PendingRegistration.Status.PENDING
                )
            except PendingRegistration.DoesNotExist:
                return JsonResponse({
                    'error': 'Código de verificación inválido o expirado',
                    'code': 'INVALID_CODE'
                }, status=404)
            
            # Verificar si el UUID ya está en uso
            if User.objects.filter(minecraft_uuid=minecraft_uuid).exists():
                return JsonResponse({
                    'error': 'Este jugador de Minecraft ya tiene una cuenta registrada',
                    'code': 'UUID_IN_USE'
                }, status=400)
            
            # Verificar si el minecraft_username ya está en uso
            if User.objects.filter(minecraft_username__iexact=minecraft_username).exists():
                return JsonResponse({
                    'error': 'Este nombre de Minecraft ya está en uso',
                    'code': 'USERNAME_IN_USE'
                }, status=400)
            
            # Verificar el registro
            user, error = pending.verify(minecraft_uuid, minecraft_username)
            
            if error:
                return JsonResponse({
                    'error': error,
                    'code': 'VERIFICATION_FAILED'
                }, status=400)
            
            return JsonResponse({
                'success': True,
                'message': f'¡Registro completado! Bienvenido {user.username}',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'minecraft_username': user.minecraft_username,
                    'email': user.email,
                    'role': user.role,
                }
            }, status=200)
            
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
        except Exception as e:
            logger.error(f"Error en MinecraftVerifyView: {e}")
            return JsonResponse({'error': 'Error interno del servidor'}, status=500)


class MinecraftPendingInfoView(View):
    """
    Vista para que el plugin consulte información de un registro pendiente.
    Usado para mostrar info al jugador antes de confirmar.
    GET /api/mc/pending-by-code/<code>/
    
    Requiere API Key.
    """
    def get(self, request, code, *args, **kwargs):
        # Verificar API Key
        if not verify_mc_api_key(request):
            return JsonResponse({'error': 'Unauthorized'}, status=401)
        
        try:
            code = code.strip().upper()
            
            try:
                pending = PendingRegistration.objects.get(
                    verification_code=code,
                    status=PendingRegistration.Status.PENDING
                )
            except PendingRegistration.DoesNotExist:
                return JsonResponse({
                    'error': 'Código no encontrado o expirado',
                    'code': 'NOT_FOUND'
                }, status=404)
            
            # Verificar expiración
            if pending.is_expired:
                pending.mark_as_expired()
                return JsonResponse({
                    'error': 'El código ha expirado',
                    'code': 'EXPIRED'
                }, status=400)
            
            # Enmascarar email de forma segura
            email_parts = pending.email.split('@')
            if len(email_parts) == 2:
                email_masked = pending.email[:3] + '***@' + email_parts[1]
            else:
                email_masked = pending.email[:3] + '***'

            return JsonResponse({
                'pending_id': pending.id,
                'username': pending.username,
                'email_masked': email_masked,
                'created_at': pending.created_at.isoformat(),
                'expires_at': pending.expires_at.isoformat(),
                'seconds_remaining': max(0, int((pending.expires_at - timezone.now()).total_seconds()))
            }, status=200)
            
        except Exception as e:
            logger.error(f"Error en MinecraftPendingInfoView: {e}")
            return JsonResponse({'error': 'Error interno del servidor'}, status=500)


@method_decorator(csrf_exempt, name='dispatch')
class MinecraftCancelRegistrationView(View):
    """
    Vista para cancelar un registro pendiente desde Minecraft.
    POST /api/mc/cancel-registration/
    
    Body:
    {
        "verification_code": "A7X9K2"
    }
    """
    def post(self, request, *args, **kwargs):
        # Verificar API Key
        if not verify_mc_api_key(request):
            return JsonResponse({'error': 'Unauthorized'}, status=401)
        
        try:
            data = json.loads(request.body)
            verification_code = data.get('verification_code', '').strip().upper()
            
            if not verification_code:
                return JsonResponse({
                    'error': 'verification_code es requerido'
                }, status=400)
            
            try:
                pending = PendingRegistration.objects.get(
                    verification_code=verification_code,
                    status=PendingRegistration.Status.PENDING
                )
            except PendingRegistration.DoesNotExist:
                return JsonResponse({
                    'error': 'Código no encontrado',
                    'code': 'NOT_FOUND'
                }, status=404)
            
            pending.status = PendingRegistration.Status.CANCELLED
            pending.save()
            
            return JsonResponse({
                'success': True,
                'message': 'Registro cancelado'
            }, status=200)
            
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
        except Exception as e:
            logger.error(f"Error en MinecraftCancelRegistrationView: {e}")
            return JsonResponse({'error': 'Error interno del servidor'}, status=500)


@method_decorator(csrf_exempt, name='dispatch')
class TokenLoginView(View):
    """
    Vista para auto-login usando One-Time Token (OTT).
    Intercambia el auth_token por una sesión de usuario autenticado.
    
    POST /api/auth/token-login/
    
    Body:
    {
        "auth_token": "el_token_de_un_solo_uso"
    }
    
    Medidas de seguridad:
    - Token de un solo uso (se invalida después de usar)
    - Expiración corta (5 minutos)
    - Token criptográficamente seguro (512 bits)
    """
    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body)
            auth_token = data.get('auth_token', '').strip()
            
            if not auth_token:
                return JsonResponse({
                    'error': 'auth_token es requerido'
                }, status=400)
            
            # Buscar el registro con este token
            try:
                pending = PendingRegistration.objects.get(
                    auth_token=auth_token,
                    status=PendingRegistration.Status.VERIFIED
                )
            except PendingRegistration.DoesNotExist:
                return JsonResponse({
                    'error': 'Token inválido',
                    'code': 'INVALID_TOKEN'
                }, status=401)
            
            # Validar y consumir el token
            success, error = pending.consume_auth_token()
            if not success:
                return JsonResponse({
                    'error': error,
                    'code': 'TOKEN_ERROR'
                }, status=401)
            
            # Obtener el usuario
            try:
                user = User.objects.get(username=pending.username)
            except User.DoesNotExist:
                return JsonResponse({
                    'error': 'Usuario no encontrado',
                    'code': 'USER_NOT_FOUND'
                }, status=404)
            
            # Autenticar al usuario (crear sesión)
            login(request, user)
            
            return JsonResponse({
                'success': True,
                'message': '¡Bienvenido a Grivyzom!',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'minecraft_username': user.minecraft_username,
                    'email': user.email,
                    'role': user.role,
                    'role_display': user.get_role_display(),
                    'is_staff': user.is_staff_role,
                    'is_player': user.is_player_role,
                }
            }, status=200)
            
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
        except Exception as e:
            logger.error(f"Error en TokenLoginView: {e}")
            return JsonResponse({'error': 'Error interno del servidor'}, status=500)


# ============================================================================
# VISTAS DE COMUNIDAD
# ============================================================================

class CommunityPostsListView(View):
    """
    Lista posts de comunidad con filtros.
    GET /api/community/posts/
    Query params: ?filter=trending|recent|following&category=slug&page=1
    """
    def get(self, request, *args, **kwargs):
        try:
            filter_type = request.GET.get('filter', 'recent')
            category_slug = request.GET.get('category', None)
            page = int(request.GET.get('page', 1))
            per_page = 12
            
            # Base queryset
            posts = CommunityPost.objects.filter(
                status=CommunityPost.Status.PUBLISHED
            ).select_related('author', 'category')
            
            # Filtrar por categoría
            if category_slug:
                posts = posts.filter(category__slug=category_slug)
            
            # Ordenar según filtro
            if filter_type == 'trending':
                # Trending: posts con más likes en los últimos 7 días
                from django.db.models import Count, Q
                from datetime import timedelta
                week_ago = timezone.now() - timedelta(days=7)
                posts = posts.annotate(
                    recent_likes=Count('likes', filter=Q(likes__created_at__gte=week_ago))
                ).order_by('-is_pinned', '-recent_likes', '-created_at')
            elif filter_type == 'following':
                # Posts de usuarios que sigo (requiere auth)
                if request.user.is_authenticated:
                    following_ids = UserFollow.objects.filter(
                        follower=request.user
                    ).values_list('following_id', flat=True)
                    posts = posts.filter(author_id__in=following_ids)
                posts = posts.order_by('-is_pinned', '-created_at')
            else:
                # Recent (default)
                posts = posts.order_by('-is_pinned', '-created_at')
            
            # Paginación
            start = (page - 1) * per_page
            end = start + per_page
            total = posts.count()
            posts_page = posts[start:end]

            # Optimización: Pre-fetch likes y bookmarks del usuario para evitar N+1 queries
            liked_post_ids = set()
            bookmarked_post_ids = set()
            if request.user.is_authenticated:
                post_ids = [post.id for post in posts_page]
                liked_post_ids = set(PostLike.objects.filter(
                    post_id__in=post_ids,
                    user=request.user
                ).values_list('post_id', flat=True))
                bookmarked_post_ids = set(PostBookmark.objects.filter(
                    post_id__in=post_ids,
                    user=request.user
                ).values_list('post_id', flat=True))

            # Serializar
            posts_data = []
            for post in posts_page:
                post_data = {
                    'id': post.id,
                    'title': post.title,
                    'slug': post.slug,
                    'excerpt': post.excerpt or (post.content[:200] + '...' if len(post.content) > 200 else post.content),
                    'cover_image': get_image_url(request, post.cover_image) if post.cover_image else None,
                    'tags': post.tags,
                    'views': post.views,
                    'likes_count': post.likes_count,
                    'comments_count': post.comments_count,
                    'is_pinned': post.is_pinned,
                    'is_featured': post.is_featured,
                    'created_at': post.created_at.isoformat(),
                    'author': {
                        'id': post.author.id,
                        'username': post.author.username,
                        'minecraft_username': post.author.minecraft_username,
                        'avatar_url': get_image_url(request, post.author.avatar) if post.author.avatar else None,
                        'role': post.author.role,
                        'role_display': post.author.get_role_display(),
                    },
                    'category': {
                        'slug': post.category.slug,
                        'name': post.category.name,
                        'icon': post.category.icon,
                        'color': post.category.color,
                    } if post.category else None,
                }

                # Añadir estado de like/bookmark usando los sets pre-fetched
                if request.user.is_authenticated:
                    post_data['is_liked'] = post.id in liked_post_ids
                    post_data['is_bookmarked'] = post.id in bookmarked_post_ids

                posts_data.append(post_data)
            
            return JsonResponse({
                'posts': posts_data,
                'total': total,
                'page': page,
                'per_page': per_page,
                'total_pages': (total + per_page - 1) // per_page
            })
            
        except Exception as e:
            logger.error(f"Error en CommunityPostsListView: {e}")
            return JsonResponse({'error': 'Error al obtener posts'}, status=500)


@method_decorator(csrf_exempt, name='dispatch')
class CommunityPostCreateView(View):
    """
    Crear post de comunidad.
    POST /api/community/posts/create/
    """
    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)
        
        try:
            data = json.loads(request.body)
            
            title = data.get('title', '').strip()
            content = data.get('content', '').strip()
            excerpt = data.get('excerpt', '').strip()
            category_slug = data.get('category', None)
            tags = data.get('tags', [])
            
            # Validaciones
            if not title or len(title) < 5:
                return JsonResponse({'error': 'El título debe tener al menos 5 caracteres'}, status=400)
            if not content or len(content) < 50:
                return JsonResponse({'error': 'El contenido debe tener al menos 50 caracteres'}, status=400)
            
            # Obtener categoría
            category = None
            if category_slug:
                try:
                    category = PostCategory.objects.get(slug=category_slug, is_active=True)
                except PostCategory.DoesNotExist:
                    pass
            
            # Crear post
            post = CommunityPost.objects.create(
                author=request.user,
                title=title,
                content=content,
                excerpt=excerpt[:300] if excerpt else '',
                category=category,
                tags=tags[:10],  # Máximo 10 tags
                status=CommunityPost.Status.PUBLISHED
            )
            
            return JsonResponse({
                'success': True,
                'message': 'Post creado exitosamente',
                'post': {
                    'id': post.id,
                    'slug': post.slug,
                    'title': post.title
                }
            }, status=201)
            
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
        except Exception as e:
            logger.error(f"Error en CommunityPostCreateView: {e}")
            return JsonResponse({'error': 'Error al crear post'}, status=500)


class PostDetailView(View):
    """
    Detalle de un post.
    GET /api/community/posts/<slug>/
    """
    def get(self, request, slug, *args, **kwargs):
        try:
            post = CommunityPost.objects.select_related('author', 'category').get(
                slug=slug,
                status=CommunityPost.Status.PUBLISHED
            )
            
            # Incrementar vistas
            post.views += 1
            post.save(update_fields=['views'])
            
            data = {
                'id': post.id,
                'title': post.title,
                'slug': post.slug,
                'content': post.content,
                'excerpt': post.excerpt,
                'cover_image': get_image_url(request, post.cover_image) if post.cover_image else None,
                'tags': post.tags,
                'views': post.views,
                'likes_count': post.likes_count,
                'comments_count': post.comments_count,
                'is_pinned': post.is_pinned,
                'is_featured': post.is_featured,
                'created_at': post.created_at.isoformat(),
                'updated_at': post.updated_at.isoformat(),
                'author': {
                    'id': post.author.id,
                    'username': post.author.username,
                    'minecraft_username': post.author.minecraft_username,
                    'avatar_url': get_image_url(request, post.author.avatar) if post.author.avatar else None,
                    'bio': post.author.bio,
                    'role': post.author.role,
                    'role_display': post.author.get_role_display(),
                    'followers_count': post.author.followers_set.count(),
                },
                'category': {
                    'slug': post.category.slug,
                    'name': post.category.name,
                    'icon': post.category.icon,
                    'color': post.category.color,
                } if post.category else None,
            }
            
            # Estado de like/bookmark/follow si autenticado
            if request.user.is_authenticated:
                data['is_liked'] = PostLike.objects.filter(post=post, user=request.user).exists()
                data['is_bookmarked'] = PostBookmark.objects.filter(post=post, user=request.user).exists()
                data['is_following_author'] = UserFollow.objects.filter(
                    follower=request.user, following=post.author
                ).exists() if request.user != post.author else None
            
            return JsonResponse(data)
            
        except CommunityPost.DoesNotExist:
            return JsonResponse({'error': 'Post no encontrado'}, status=404)
        except Exception as e:
            logger.error(f"Error en PostDetailView: {e}")
            return JsonResponse({'error': 'Error al obtener post'}, status=500)


@method_decorator(csrf_exempt, name='dispatch')
class PostLikeView(View):
    """
    Like/Unlike un post.
    POST /api/community/posts/<id>/like/
    """
    def post(self, request, post_id, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)
        
        try:
            post = CommunityPost.objects.get(id=post_id, status=CommunityPost.Status.PUBLISHED)
            
            like, created = PostLike.objects.get_or_create(post=post, user=request.user)
            
            if not created:
                # Ya existe, quitar like
                like.delete()
                return JsonResponse({
                    'success': True,
                    'liked': False,
                    'likes_count': post.likes_count
                })
            
            return JsonResponse({
                'success': True,
                'liked': True,
                'likes_count': post.likes_count
            })
            
        except CommunityPost.DoesNotExist:
            return JsonResponse({'error': 'Post no encontrado'}, status=404)


@method_decorator(csrf_exempt, name='dispatch')
class PostBookmarkView(View):
    """
    Bookmark/Unbookmark un post.
    POST /api/community/posts/<id>/bookmark/
    """
    def post(self, request, post_id, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)
        
        try:
            post = CommunityPost.objects.get(id=post_id, status=CommunityPost.Status.PUBLISHED)
            
            bookmark, created = PostBookmark.objects.get_or_create(post=post, user=request.user)
            
            if not created:
                bookmark.delete()
                return JsonResponse({'success': True, 'bookmarked': False})
            
            return JsonResponse({'success': True, 'bookmarked': True})
            
        except CommunityPost.DoesNotExist:
            return JsonResponse({'error': 'Post no encontrado'}, status=404)


class PostCommentsView(View):
    """
    Listar/Crear comentarios de un post.
    GET/POST /api/community/posts/<id>/comments/
    """
    def get(self, request, post_id, *args, **kwargs):
        try:
            post = CommunityPost.objects.get(id=post_id, status=CommunityPost.Status.PUBLISHED)
            
            comments = PostComment.objects.filter(
                post=post,
                parent=None,
                is_deleted=False
            ).select_related('author').order_by('created_at')
            
            comments_data = []
            for comment in comments:
                comment_data = {
                    'id': comment.id,
                    'content': comment.content,
                    'created_at': comment.created_at.isoformat(),
                    'author': {
                        'id': comment.author.id,
                        'username': comment.author.username,
                        'minecraft_username': comment.author.minecraft_username,
                        'avatar_url': get_image_url(request, comment.author.avatar) if comment.author.avatar else None,
                        'role_display': comment.author.get_role_display(),
                    },
                    'replies': []
                }
                
                # Obtener replies
                for reply in comment.replies.filter(is_deleted=False).select_related('author'):
                    comment_data['replies'].append({
                        'id': reply.id,
                        'content': reply.content,
                        'created_at': reply.created_at.isoformat(),
                        'author': {
                            'id': reply.author.id,
                            'username': reply.author.username,
                            'minecraft_username': reply.author.minecraft_username,
                            'avatar_url': get_image_url(request, reply.author.avatar) if reply.author.avatar else None,
                            'role_display': reply.author.get_role_display(),
                        }
                    })
                
                comments_data.append(comment_data)
            
            return JsonResponse({'comments': comments_data, 'count': len(comments_data)})
            
        except CommunityPost.DoesNotExist:
            return JsonResponse({'error': 'Post no encontrado'}, status=404)
    
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)
    
    def post(self, request, post_id, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)
        
        try:
            post = CommunityPost.objects.get(id=post_id, status=CommunityPost.Status.PUBLISHED)
            data = json.loads(request.body)
            
            content = data.get('content', '').strip()
            parent_id = data.get('parent_id', None)
            
            if not content or len(content) < 2:
                return JsonResponse({'error': 'Comentario muy corto'}, status=400)
            
            parent = None
            if parent_id:
                try:
                    parent = PostComment.objects.get(id=parent_id, post=post, is_deleted=False)
                except PostComment.DoesNotExist:
                    pass
            
            comment = PostComment.objects.create(
                post=post,
                author=request.user,
                content=content[:2000],
                parent=parent
            )
            
            return JsonResponse({
                'success': True,
                'comment': {
                    'id': comment.id,
                    'content': comment.content,
                    'created_at': comment.created_at.isoformat(),
                    'author': {
                        'id': request.user.id,
                        'username': request.user.username,
                        'minecraft_username': request.user.minecraft_username,
                    }
                }
            }, status=201)
            
        except CommunityPost.DoesNotExist:
            return JsonResponse({'error': 'Post no encontrado'}, status=404)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)


class CategoriesListView(View):
    """
    Lista categorías activas.
    GET /api/community/categories/
    """
    def get(self, request, *args, **kwargs):
        categories = PostCategory.objects.filter(is_active=True).order_by('order', 'name')
        
        data = [{
            'slug': cat.slug,
            'name': cat.name,
            'description': cat.description,
            'icon': cat.icon,
            'color': cat.color,
            'posts_count': cat.posts.filter(status='PUBLISHED').count()
        } for cat in categories]
        
        return JsonResponse({'categories': data})


class TopContributorsView(View):
    """
    Top usuarios que más publican.
    GET /api/community/top-contributors/
    """
    def get(self, request, *args, **kwargs):
        from django.db.models import Count, Q
        
        users = User.objects.annotate(
            posts_count=Count('community_posts', filter=Q(community_posts__status='PUBLISHED'))
        ).filter(posts_count__gt=0).order_by('-posts_count')[:10]
        
        data = [{
            'id': user.id,
            'username': user.username,
            'minecraft_username': user.minecraft_username,
            'avatar_url': get_image_url(request, user.avatar) if user.avatar else None,
            'role_display': user.get_role_display(),
            'posts_count': user.posts_count,
            'followers_count': user.followers_set.count(),
        } for user in users]
        
        return JsonResponse({'contributors': data})


class TrendingTagsView(View):
    """
    Tags más usados recientemente.
    GET /api/community/trending-tags/
    """
    def get(self, request, *args, **kwargs):
        from collections import Counter
        from datetime import timedelta
        
        # Posts de los últimos 30 días
        month_ago = timezone.now() - timedelta(days=30)
        posts = CommunityPost.objects.filter(
            status=CommunityPost.Status.PUBLISHED,
            created_at__gte=month_ago
        ).values_list('tags', flat=True)
        
        # Contar tags
        tag_counter = Counter()
        for tags in posts:
            if tags:
                for tag in tags:
                    tag_counter[tag.lower()] += 1
        
        # Top 15 tags
        trending = [{'tag': tag, 'count': count} for tag, count in tag_counter.most_common(15)]
        
        return JsonResponse({'tags': trending})


@method_decorator(csrf_exempt, name='dispatch')
class UserFollowView(View):
    """
    Seguir/Dejar de seguir usuario.
    POST /api/community/users/<id>/follow/
    """
    def post(self, request, user_id, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)
        
        if request.user.id == user_id:
            return JsonResponse({'error': 'No puedes seguirte a ti mismo'}, status=400)
        
        try:
            target_user = User.objects.get(id=user_id)
            
            follow, created = UserFollow.objects.get_or_create(
                follower=request.user,
                following=target_user
            )
            
            if not created:
                follow.delete()
                return JsonResponse({
                    'success': True,
                    'following': False,
                    'followers_count': target_user.followers_set.count()
                })
            
            return JsonResponse({
                'success': True,
                'following': True,
                'followers_count': target_user.followers_set.count()
            })
            
        except User.DoesNotExist:
            return JsonResponse({'error': 'Usuario no encontrado'}, status=404)


class UserProfilePublicView(View):
    """
    Perfil público de un usuario (para popover).
    GET /api/community/users/<id>/
    """
    def get(self, request, user_id, *args, **kwargs):
        try:
            user = User.objects.get(id=user_id)
            
            data = {
                'id': user.id,
                'username': user.username,
                'minecraft_username': user.minecraft_username,
                'avatar_url': get_image_url(request, user.avatar) if user.avatar else None,
                'bio': user.bio,
                'role': user.role,
                'role_display': user.get_role_display(),
                'posts_count': user.community_posts.filter(status='PUBLISHED').count(),
                'followers_count': user.followers_set.count(),
                'following_count': user.following_set.count(),
                'date_joined': user.date_joined.isoformat(),
            }
            
            if request.user.is_authenticated and request.user != user:
                data['is_following'] = UserFollow.objects.filter(
                    follower=request.user, following=user
                ).exists()
            
            return JsonResponse(data)
            
        except User.DoesNotExist:
            return JsonResponse({'error': 'Usuario no encontrado'}, status=404)


# ============================================================================
# VISTAS DE ADMINISTRACIÓN (Solo Staff)
# ============================================================================

def staff_required(view_func):
    """
    Decorador que requiere que el usuario sea parte del staff.
    """
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)
        
        if not request.user.is_staff_role:
            return JsonResponse({'error': 'Acceso denegado. Solo staff.'}, status=403)
        
        return view_func(request, *args, **kwargs)
    return wrapper


class AdminDashboardStatsView(View):
    """
    Estadísticas del dashboard de administración.
    GET /api/admin/stats/
    
    Requiere: Usuario autenticado con rol de staff
    """
    def get(self, request, *args, **kwargs):
        # Verificar autenticación
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)
        
        # Verificar que sea staff
        if not request.user.is_staff_role:
            return JsonResponse({'error': 'Acceso denegado'}, status=403)
        
        try:
            from django.db.models import Count
            from datetime import timedelta
            
            now = timezone.now()
            today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            week_ago = now - timedelta(days=7)
            
            # Estadísticas básicas
            total_users = User.objects.count()
            total_posts = CommunityPost.objects.filter(status='PUBLISHED').count()
            total_gallery_images = GalleryImage.objects.count()
            pending_registrations = PendingRegistration.objects.filter(
                status='PENDING',
                expires_at__gt=now
            ).count()
            
            # Usuarios registrados hoy
            users_today = User.objects.filter(date_joined__gte=today_start).count()
            
            # Posts creados hoy
            posts_today = CommunityPost.objects.filter(
                created_at__gte=today_start,
                status='PUBLISHED'
            ).count()
            
            # Usuarios activos esta semana (que han hecho login)
            active_users_week = User.objects.filter(last_login__gte=week_ago).count()
            
            return JsonResponse({
                'total_users': total_users,
                'total_posts': total_posts,
                'total_gallery_images': total_gallery_images,
                'pending_registrations': pending_registrations,
                'users_today': users_today,
                'posts_today': posts_today,
                'active_users_week': active_users_week,
            })
            
        except Exception as e:
            logger.error(f"Error en AdminDashboardStatsView: {e}")
            return JsonResponse({'error': 'Error al obtener estadísticas'}, status=500)


class AdminUsersListView(View):
    """
    Lista de usuarios para administración.
    GET /api/admin/users/?page=1&search=&role=&status=
    """
    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)
        
        if not request.user.is_staff_role:
            return JsonResponse({'error': 'Acceso denegado'}, status=403)
        
        try:
            from django.db.models import Q
            
            page = int(request.GET.get('page', 1))
            per_page = 20
            search = request.GET.get('search', '').strip()
            role_filter = request.GET.get('role', '')
            status_filter = request.GET.get('status', '')
            
            users = User.objects.all().order_by('-date_joined')
            
            # Filtro de búsqueda
            if search:
                users = users.filter(
                    Q(username__icontains=search) |
                    Q(email__icontains=search) |
                    Q(minecraft_username__icontains=search)
                )
            
            # Filtro por rol
            if role_filter:
                users = users.filter(role=role_filter)
            
            # Filtro por estado
            if status_filter == 'active':
                users = users.filter(is_active=True, is_banned=False)
            elif status_filter == 'banned':
                users = users.filter(is_banned=True)
            elif status_filter == 'inactive':
                users = users.filter(is_active=False)
            
            # Paginación
            total = users.count()
            start = (page - 1) * per_page
            end = start + per_page
            users_page = users[start:end]
            
            # Serializar
            items = [{
                'id': u.id,
                'username': u.username,
                'email': u.email,
                'minecraft_username': u.minecraft_username,
                'discord_username': u.discord_username,
                'role': u.role,
                'role_display': u.get_role_display(),
                'is_staff': u.is_staff_role,
                'is_active': u.is_active,
                'is_banned': u.is_banned,
                'ban_reason': u.ban_reason,
                'date_joined': u.date_joined.isoformat(),
                'last_login': u.last_login.isoformat() if u.last_login else None,
                'avatar_url': get_image_url(request, u.avatar) if u.avatar else None,
            } for u in users_page]
            
            return JsonResponse({
                'items': items,
                'total': total,
                'page': page,
                'per_page': per_page,
                'total_pages': (total + per_page - 1) // per_page
            })
            
        except Exception as e:
            logger.error(f"Error en AdminUsersListView: {e}")
            return JsonResponse({'error': 'Error al obtener usuarios'}, status=500)


@method_decorator(csrf_exempt, name='dispatch')
class AdminUserRoleView(View):
    """
    Cambiar rol de un usuario.
    PUT /api/admin/users/<id>/role/
    Body: { "role": "MODERADOR" }
    """
    def put(self, request, user_id, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)
        
        if not request.user.is_staff_role:
            return JsonResponse({'error': 'Acceso denegado'}, status=403)
        
        # Solo ADMIN y DEVELOPER pueden cambiar roles
        if request.user.role not in ['ADMIN', 'DEVELOPER']:
            return JsonResponse({'error': 'Solo ADMIN/DEVELOPER pueden cambiar roles'}, status=403)
        
        try:
            data = json.loads(request.body)
            new_role = data.get('role', '').strip()
            
            if not new_role:
                return JsonResponse({'error': 'Rol requerido'}, status=400)
            
            # Validar que el rol existe
            valid_roles = [choice[0] for choice in User.Role.choices]
            if new_role not in valid_roles:
                return JsonResponse({'error': 'Rol inválido'}, status=400)
            
            user = User.objects.get(id=user_id)
            
            # No permitir degradar a DEVELOPER a menos que seas DEVELOPER
            if user.role == 'DEVELOPER' and request.user.role != 'DEVELOPER':
                return JsonResponse({'error': 'No puedes modificar el rol de un DEVELOPER'}, status=403)
            
            user.role = new_role
            user.save()
            
            return JsonResponse({
                'message': f'Rol actualizado a {user.get_role_display()}',
                'role': user.role,
                'role_display': user.get_role_display()
            })
            
        except User.DoesNotExist:
            return JsonResponse({'error': 'Usuario no encontrado'}, status=404)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
        except Exception as e:
            logger.error(f"Error en AdminUserRoleView: {e}")
            return JsonResponse({'error': 'Error al cambiar rol'}, status=500)


@method_decorator(csrf_exempt, name='dispatch')
class AdminUserBanView(View):
    """
    Banear/Desbanear un usuario.
    POST /api/admin/users/<id>/ban/
    Body: { "ban": true, "reason": "Motivo del baneo" }
    """
    def post(self, request, user_id, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)
        
        if not request.user.is_staff_role:
            return JsonResponse({'error': 'Acceso denegado'}, status=403)
        
        # Solo MODERADOR+ pueden banear
        if request.user.role not in ['MODERADOR', 'ADMIN', 'DEVELOPER']:
            return JsonResponse({'error': 'Permisos insuficientes'}, status=403)
        
        try:
            data = json.loads(request.body)
            ban = data.get('ban', True)
            reason = data.get('reason', '').strip()
            
            user = User.objects.get(id=user_id)
            
            # No banear a staff de mayor rango
            if user.is_staff_role:
                admin_hierarchy = ['HELPER', 'BUILDER', 'MODERADOR', 'ADMIN', 'DEVELOPER']
                user_rank = admin_hierarchy.index(user.role) if user.role in admin_hierarchy else -1
                my_rank = admin_hierarchy.index(request.user.role) if request.user.role in admin_hierarchy else -1
                
                if user_rank >= my_rank:
                    return JsonResponse({'error': 'No puedes banear a alguien de tu mismo rango o superior'}, status=403)
            
            user.is_banned = ban
            user.ban_reason = reason if ban else None
            user.save()
            
            action = 'baneado' if ban else 'desbaneado'
            return JsonResponse({
                'message': f'Usuario {action} exitosamente',
                'is_banned': user.is_banned
            })
            
        except User.DoesNotExist:
            return JsonResponse({'error': 'Usuario no encontrado'}, status=404)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
        except Exception as e:
            logger.error(f"Error en AdminUserBanView: {e}")
            return JsonResponse({'error': 'Error al banear usuario'}, status=500)


class AdminUsersStatsView(View):
    """
    Estadísticas detalladas de usuarios para el panel de administración.
    GET /api/admin/users/stats/
    
    Retorna:
    - total_users: Total de usuarios registrados
    - online_users: Usuarios con actividad en los últimos 5 minutos
    - staff_online: Staff con actividad reciente
    - staff_total: Total de usuarios con rol de staff
    - banned_users: Usuarios baneados
    - users_today: Nuevos usuarios registrados hoy
    - users_week: Nuevos usuarios esta semana
    """
    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)
        
        if not request.user.is_staff_role:
            return JsonResponse({'error': 'Acceso denegado'}, status=403)
        
        try:
            from django.db.models import Q
            from datetime import timedelta
            
            now = timezone.now()
            today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            week_ago = now - timedelta(days=7)
            five_minutes_ago = now - timedelta(minutes=5)
            
            # Roles de staff
            staff_roles = ['HELPER', 'BUILDER', 'MODERADOR', 'ADMIN', 'DEVELOPER']
            
            # Estadísticas
            total_users = User.objects.count()
            
            # Usuarios "online" = último login en los últimos 5 minutos
            online_users = User.objects.filter(
                last_login__gte=five_minutes_ago,
                is_active=True,
                is_banned=False
            ).count()
            
            # Staff total
            staff_total = User.objects.filter(role__in=staff_roles).count()
            
            # Staff online
            staff_online = User.objects.filter(
                role__in=staff_roles,
                last_login__gte=five_minutes_ago,
                is_active=True
            ).count()
            
            # Usuarios baneados
            banned_users = User.objects.filter(is_banned=True).count()
            
            # Nuevos usuarios hoy
            users_today = User.objects.filter(date_joined__gte=today_start).count()
            
            # Nuevos usuarios esta semana
            users_week = User.objects.filter(date_joined__gte=week_ago).count()
            
            return JsonResponse({
                'total_users': total_users,
                'online_users': online_users,
                'staff_online': staff_online,
                'staff_total': staff_total,
                'banned_users': banned_users,
                'users_today': users_today,
                'users_week': users_week,
            })
            
        except Exception as e:
            logger.error(f"Error en AdminUsersStatsView: {e}")
            return JsonResponse({'error': 'Error al obtener estadísticas'}, status=500)


class AdminUserDetailView(View):
    """
    Detalle completo de un usuario para administración.
    GET /api/admin/users/<id>/
    
    Retorna información detallada del usuario incluyendo:
    - Datos básicos (username, email, minecraft, discord)
    - Rol y permisos
    - Estado (activo, baneado)
    - Estadísticas de actividad
    """
    def get(self, request, user_id, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)
        
        if not request.user.is_staff_role:
            return JsonResponse({'error': 'Acceso denegado'}, status=403)
        
        try:
            user = User.objects.get(id=user_id)
            
            # Estadísticas del usuario
            posts_count = CommunityPost.objects.filter(
                author=user, 
                status='PUBLISHED'
            ).count()
            
            comments_count = PostComment.objects.filter(
                author=user,
                is_deleted=False
            ).count()
            
            followers_count = UserFollow.objects.filter(following=user).count()
            following_count = UserFollow.objects.filter(follower=user).count()
            
            return JsonResponse({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'minecraft_username': user.minecraft_username,
                'minecraft_uuid': user.minecraft_uuid,
                'discord_username': user.discord_username,
                'bio': user.bio,
                'role': user.role,
                'role_display': user.get_role_display(),
                'is_staff': user.is_staff_role,
                'is_active': user.is_active,
                'is_banned': user.is_banned,
                'ban_reason': user.ban_reason,
                'date_joined': user.date_joined.isoformat(),
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'avatar_url': get_image_url(request, user.avatar) if user.avatar else None,
                # Estadísticas
                'stats': {
                    'posts_count': posts_count,
                    'comments_count': comments_count,
                    'followers_count': followers_count,
                    'following_count': following_count,
                }
            })
            
        except User.DoesNotExist:
            return JsonResponse({'error': 'Usuario no encontrado'}, status=404)
        except Exception as e:
            logger.error(f"Error en AdminUserDetailView: {e}")
            return JsonResponse({'error': 'Error al obtener usuario'}, status=500)


@method_decorator(csrf_exempt, name='dispatch')
class AdminGameHeaderView(View):
    """
    Vista admin para gestionar el Game Header.
    GET /api/admin/game-header/ - Obtener el Game Header actual
    POST /api/admin/game-header/ - Crear/actualizar el Game Header
    
    Requiere: Usuario autenticado con rol de staff
    """
    
    def get(self, request, *args, **kwargs):
        """Obtener el Game Header actual"""
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)
        
        if not request.user.is_staff_role:
            return JsonResponse({'error': 'Acceso denegado. Solo staff.'}, status=403)
        
        try:
            game_header = GameHeader.objects.latest('created_at')
            return JsonResponse({
                'id': game_header.id,
                'title': game_header.title,
                'subtitle': game_header.subtitle,
                'button_text': game_header.button_text,
                'image_url': get_image_url(request, game_header.image),
                'created_at': game_header.created_at.isoformat(),
            })
        except GameHeader.DoesNotExist:
            # Retornar valores por defecto si no existe
            return JsonResponse({
                'id': None,
                'title': 'GRIVYZOM',
                'subtitle': 'A WORLD OF ADVENTURE AND CREATIVITY',
                'button_text': 'JUGAR AHORA!',
                'image_url': request.build_absolute_uri('/static/images/placeholder.svg'),
                'created_at': None,
            })
    
    def post(self, request, *args, **kwargs):
        """Crear o actualizar el Game Header"""
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)
        
        if not request.user.is_staff_role:
            return JsonResponse({'error': 'Acceso denegado. Solo staff.'}, status=403)
        
        try:
            # Obtener datos del formulario multipart
            title = request.POST.get('title', 'GRIVYZOM').strip()
            subtitle = request.POST.get('subtitle', 'A WORLD OF ADVENTURE AND CREATIVITY').strip()
            button_text = request.POST.get('button_text', 'JUGAR AHORA!').strip()
            
            # Validaciones básicas
            if not title:
                return JsonResponse({'error': 'El título es requerido'}, status=400)
            
            if len(title) > 200:
                return JsonResponse({'error': 'El título no puede superar los 200 caracteres'}, status=400)
            
            if len(subtitle) > 300:
                return JsonResponse({'error': 'El subtítulo no puede superar los 300 caracteres'}, status=400)
            
            if len(button_text) > 100:
                return JsonResponse({'error': 'El texto del botón no puede superar los 100 caracteres'}, status=400)
            
            # Buscar o crear el Game Header
            try:
                game_header = GameHeader.objects.latest('created_at')
                # Actualizar campos de texto
                game_header.title = title
                game_header.subtitle = subtitle
                game_header.button_text = button_text
            except GameHeader.DoesNotExist:
                # Crear nuevo si no existe
                game_header = GameHeader(
                    title=title,
                    subtitle=subtitle,
                    button_text=button_text
                )
            
            # Procesar imagen si se proporciona
            if 'image' in request.FILES:
                image_file = request.FILES['image']
                
                # Validar tamaño (max 10MB para header)
                if image_file.size > 10 * 1024 * 1024:
                    return JsonResponse({'error': 'La imagen no puede superar los 10MB'}, status=400)
                
                # Validar tipo de archivo
                allowed_types = ['image/jpeg', 'image/png', 'image/jpg', 'image/webp']
                if image_file.content_type not in allowed_types:
                    return JsonResponse({'error': 'Solo se permiten imágenes JPEG, PNG o WebP'}, status=400)
                
                # Eliminar imagen anterior si existe
                if game_header.pk and game_header.image:
                    game_header.image.delete(save=False)
                
                # Guardar nueva imagen
                game_header.image = image_file
            
            game_header.save()
            
            return JsonResponse({
                'success': True,
                'message': 'Game Header actualizado exitosamente',
                'data': {
                    'id': game_header.id,
                    'title': game_header.title,
                    'subtitle': game_header.subtitle,
                    'button_text': game_header.button_text,
                    'image_url': get_image_url(request, game_header.image),
                    'created_at': game_header.created_at.isoformat(),
                }
            })
            
        except Exception as e:
            logger.error(f"Error en AdminGameHeaderView: {e}")
            return JsonResponse({'error': f'Error al actualizar Game Header: {str(e)}'}, status=500)


@method_decorator(csrf_exempt, name='dispatch')
class AdminHeroSectionView(View):
    """
    Vista admin para gestionar el Hero Section.
    GET /api/admin/hero-section/ - Obtener el Hero Section actual
    POST /api/admin/hero-section/ - Crear/actualizar el Hero Section
    
    Requiere: Usuario autenticado con rol de staff
    """
    
    def get(self, request, *args, **kwargs):
        """Obtener el Hero Section actual"""
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)
        
        if not request.user.is_staff_role:
            return JsonResponse({'error': 'Acceso denegado. Solo staff.'}, status=403)
        
        try:
            hero_section = HeroSection.objects.latest('created_at')
            return JsonResponse({
                'id': hero_section.id,
                'title': hero_section.title,
                'description': hero_section.description,
                'image_url': get_image_url(request, hero_section.image),
                'created_at': hero_section.created_at.isoformat(),
            })
        except HeroSection.DoesNotExist:
            return JsonResponse({
                'id': None,
                'title': 'Bienvenido a Grivyzom',
                'description': 'Tu servidor de Minecraft favorito',
                'image_url': request.build_absolute_uri('/static/images/placeholder.svg'),
                'created_at': None,
            })
    
    def post(self, request, *args, **kwargs):
        """Crear o actualizar el Hero Section"""
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)
        
        if not request.user.is_staff_role:
            return JsonResponse({'error': 'Acceso denegado. Solo staff.'}, status=403)
        
        try:
            title = request.POST.get('title', 'Bienvenido a Grivyzom').strip()
            description = request.POST.get('description', '').strip()
            
            if not title:
                return JsonResponse({'error': 'El título es requerido'}, status=400)
            
            if len(title) > 200:
                return JsonResponse({'error': 'El título no puede superar los 200 caracteres'}, status=400)
            
            # Buscar o crear el Hero Section
            try:
                hero_section = HeroSection.objects.latest('created_at')
                hero_section.title = title
                hero_section.description = description
            except HeroSection.DoesNotExist:
                hero_section = HeroSection(title=title, description=description)
            
            # Procesar imagen si se proporciona
            if 'image' in request.FILES:
                image_file = request.FILES['image']
                
                if image_file.size > 10 * 1024 * 1024:
                    return JsonResponse({'error': 'La imagen no puede superar los 10MB'}, status=400)
                
                allowed_types = ['image/jpeg', 'image/png', 'image/jpg', 'image/webp']
                if image_file.content_type not in allowed_types:
                    return JsonResponse({'error': 'Solo se permiten imágenes JPEG, PNG o WebP'}, status=400)
                
                if hero_section.pk and hero_section.image:
                    hero_section.image.delete(save=False)
                
                hero_section.image = image_file
            
            hero_section.save()
            
            return JsonResponse({
                'success': True,
                'message': 'Hero Section actualizado exitosamente',
                'data': {
                    'id': hero_section.id,
                    'title': hero_section.title,
                    'description': hero_section.description,
                    'image_url': get_image_url(request, hero_section.image),
                    'created_at': hero_section.created_at.isoformat(),
                }
            })
            
        except Exception as e:
            logger.error(f"Error en AdminHeroSectionView: {e}")
            return JsonResponse({'error': f'Error al actualizar Hero Section: {str(e)}'}, status=500)


class AdminWebComponentsView(View):
    """
    Vista admin para listar todos los componentes web editables.
    GET /api/admin/web-components/ - Lista de componentes con su estado actual
    
    Requiere: Usuario autenticado con rol de staff
    """
    
    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)
        
        if not request.user.is_staff_role:
            return JsonResponse({'error': 'Acceso denegado. Solo staff.'}, status=403)
        
        try:
            components = []
            
            # Game Header
            try:
                game_header = GameHeader.objects.latest('created_at')
                components.append({
                    'id': 'game-header',
                    'name': 'Game Header',
                    'description': 'Imagen principal del banner de inicio',
                    'icon': 'gamepad-2',
                    'has_data': True,
                    'image_url': get_image_url(request, game_header.image),
                    'title': game_header.title,
                    'updated_at': game_header.created_at.isoformat(),
                })
            except GameHeader.DoesNotExist:
                components.append({
                    'id': 'game-header',
                    'name': 'Game Header',
                    'description': 'Imagen principal del banner de inicio',
                    'icon': 'gamepad-2',
                    'has_data': False,
                    'image_url': request.build_absolute_uri('/static/images/placeholder.svg'),
                    'title': 'Sin configurar',
                    'updated_at': None,
                })
            
            # Hero Section
            try:
                hero_section = HeroSection.objects.latest('created_at')
                components.append({
                    'id': 'hero-section',
                    'name': 'Hero Section',
                    'description': 'Sección hero con slider de imágenes',
                    'icon': 'image',
                    'has_data': True,
                    'image_url': get_image_url(request, hero_section.image),
                    'title': hero_section.title,
                    'updated_at': hero_section.created_at.isoformat(),
                })
            except HeroSection.DoesNotExist:
                components.append({
                    'id': 'hero-section',
                    'name': 'Hero Section',
                    'description': 'Sección hero con slider de imágenes',
                    'icon': 'image',
                    'has_data': False,
                    'image_url': request.build_absolute_uri('/static/images/placeholder.svg'),
                    'title': 'Sin configurar',
                    'updated_at': None,
                })
            
            return JsonResponse({'components': components})

        except Exception as e:
            logger.error(f"Error en AdminWebComponentsView: {e}")
            return JsonResponse({'error': 'Error al obtener componentes'}, status=500)


# ============================================================================
# VISTAS DE TIENDA - ENDPOINTS PÚBLICOS
# ============================================================================

class StoreProductsListView(View):
    """
    Lista productos disponibles para la tienda pública.
    GET /api/store/products/?type=&category=&featured=&limit=

    Público: No requiere autenticación
    """
    def get(self, request, *args, **kwargs):
        try:
            from .models import Product, ProductCategory
            from django.db.models import Q

            # Filtros
            product_type = request.GET.get('type', '')
            category_id = request.GET.get('category', '')
            featured = request.GET.get('featured', '')
            limit = request.GET.get('limit', '')

            # Solo productos disponibles
            products = Product.objects.filter(is_available=True).select_related('category')

            # Aplicar filtros
            if product_type:
                products = products.filter(product_type=product_type)

            if category_id:
                products = products.filter(category_id=category_id)

            if featured == 'true':
                products = products.filter(is_featured=True)

            # Ordenar
            products = products.order_by('-is_featured', 'order', '-created_at')

            # Aplicar límite si existe
            if limit:
                try:
                    products = products[:int(limit)]
                except ValueError:
                    pass

            # Serializar
            items = [{
                'id': str(p.id),
                'name': p.name,
                'slug': p.slug,
                'description': p.description,
                'short_description': p.short_description,
                'price': str(p.price),
                'discount': p.discount_percent,
                'type': p.product_type,
                'image': p.get_image_url(request),
                'available': p.is_available,
                'featured': p.is_featured,
                'category': p.category.slug if p.category else None,
                'rarity': p.rarity,
                'stock': p.stock,
                'type_specific_data': p.type_specific_data,
                'createdAt': p.created_at.isoformat(),
                'updatedAt': p.updated_at.isoformat(),
            } for p in products]

            return JsonResponse({'products': items, 'total': len(items)})

        except Exception as e:
            logger.error(f"Error en StoreProductsListView: {e}")
            return JsonResponse({'error': 'Error al obtener productos'}, status=500)


class StoreProductDetailView(View):
    """
    Detalle de un producto por slug.
    GET /api/store/products/<slug>/

    Público: No requiere autenticación
    """
    def get(self, request, slug, *args, **kwargs):
        try:
            from .models import Product

            product = Product.objects.filter(slug=slug, is_available=True).select_related('category').first()

            if not product:
                return JsonResponse({'error': 'Producto no encontrado'}, status=404)

            # Incrementar vistas
            product.views += 1
            product.save(update_fields=['views'])

            # Serializar
            data = {
                'id': str(product.id),
                'name': product.name,
                'slug': product.slug,
                'description': product.description,
                'short_description': product.short_description,
                'price': str(product.price),
                'discount_price': str(product.discount_price) if product.discount_price else None,
                'discount': product.discount_percent,
                'final_price': str(product.final_price),
                'type': product.product_type,
                'image': product.get_image_url(request),
                'available': product.is_available,
                'featured': product.is_featured,
                'category': {
                    'id': product.category.id,
                    'name': product.category.name,
                    'slug': product.category.slug
                } if product.category else None,
                'rarity': product.rarity,
                'stock': product.stock,
                'type_specific_data': product.type_specific_data,
                'views': product.views,
                'createdAt': product.created_at.isoformat(),
                'updatedAt': product.updated_at.isoformat(),
            }

            return JsonResponse({'product': data})

        except Exception as e:
            logger.error(f"Error en StoreProductDetailView: {e}")
            return JsonResponse({'error': 'Error al obtener producto'}, status=500)


class StoreCategoriesView(View):
    """
    Lista categorías de productos activas.
    GET /api/store/categories/

    Público: No requiere autenticación
    """
    def get(self, request, *args, **kwargs):
        try:
            from .models import ProductCategory

            categories = ProductCategory.objects.filter(is_active=True).order_by('order', 'name')

            items = [{
                'id': c.id,
                'name': c.name,
                'slug': c.slug,
                'description': c.description,
                'product_type': c.product_type,
                'icon': c.icon,
                'color': c.color,
            } for c in categories]

            return JsonResponse({'categories': items})

        except Exception as e:
            logger.error(f"Error en StoreCategoriesView: {e}")
            return JsonResponse({'error': 'Error al obtener categorías'}, status=500)


# ============================================================================
# VISTAS DE ADMINISTRACIÓN DE PRODUCTOS
# ============================================================================

class AdminProductsListView(View):
    """
    Lista productos con paginación y filtros (Admin).
    GET /api/admin/products/?page=1&search=&type=&category=&availability=&featured=

    Requiere: Staff
    """
    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)

        if not request.user.is_staff_role:
            return JsonResponse({'error': 'Acceso denegado'}, status=403)

        try:
            from .models import Product
            from django.db.models import Q

            # Parámetros
            page = int(request.GET.get('page', 1))
            per_page = 20
            search = request.GET.get('search', '').strip()
            product_type = request.GET.get('type', '')
            category_id = request.GET.get('category', '')
            availability = request.GET.get('availability', '')
            featured = request.GET.get('featured', '')

            # Query base
            products = Product.objects.select_related('category', 'created_by').all()

            # Filtros
            if search:
                products = products.filter(
                    Q(name__icontains=search) |
                    Q(description__icontains=search) |
                    Q(short_description__icontains=search)
                )

            if product_type:
                products = products.filter(product_type=product_type)

            if category_id:
                products = products.filter(category_id=category_id)

            if availability == 'available':
                products = products.filter(is_available=True)
            elif availability == 'unavailable':
                products = products.filter(is_available=False)

            if featured == 'true':
                products = products.filter(is_featured=True)

            products = products.order_by('-is_featured', 'order', '-created_at')

            # Paginación
            total = products.count()
            start = (page - 1) * per_page
            end = start + per_page
            products_page = products[start:end]

            # Serializar
            items = [{
                'id': p.id,
                'name': p.name,
                'slug': p.slug,
                'short_description': p.short_description,
                'product_type': p.product_type,
                'product_type_display': p.get_product_type_display(),
                'category': {
                    'id': p.category.id,
                    'name': p.category.name,
                    'slug': p.category.slug
                } if p.category else None,
                'image_url': p.get_image_url(request),
                'price': str(p.price),
                'discount_price': str(p.discount_price) if p.discount_price else None,
                'discount_percent': p.discount_percent,
                'final_price': str(p.final_price),
                'rarity': p.rarity,
                'rarity_display': p.get_rarity_display(),
                'is_available': p.is_available,
                'is_featured': p.is_featured,
                'is_new': p.is_new,
                'stock': p.stock,
                'views': p.views,
                'purchases': p.purchases,
                'created_at': p.created_at.isoformat(),
                'updated_at': p.updated_at.isoformat(),
                'created_by': {
                    'id': p.created_by.id,
                    'username': p.created_by.username
                } if p.created_by else None,
            } for p in products_page]

            return JsonResponse({
                'items': items,
                'total': total,
                'page': page,
                'per_page': per_page,
                'total_pages': (total + per_page - 1) // per_page
            })

        except Exception as e:
            logger.error(f"Error en AdminProductsListView: {e}")
            return JsonResponse({'error': 'Error al obtener productos'}, status=500)


class AdminProductsStatsView(View):
    """
    Estadísticas de productos.
    GET /api/admin/products/stats/

    Requiere: Staff
    """
    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)

        if not request.user.is_staff_role:
            return JsonResponse({'error': 'Acceso denegado'}, status=403)

        try:
            from .models import Product
            from django.db.models import Sum, F
            from decimal import Decimal

            total_products = Product.objects.count()
            available_products = Product.objects.filter(is_available=True).count()
            featured_products = Product.objects.filter(is_featured=True).count()

            # Por tipo
            products_by_type = {}
            for ptype in Product.ProductType.choices:
                count = Product.objects.filter(product_type=ptype[0]).count()
                products_by_type[ptype[0]] = {
                    'count': count,
                    'label': ptype[1]
                }

            # Potencial de ingresos
            revenue_potential = Product.objects.filter(
                stock__isnull=False,
                stock__gt=0,
                is_available=True
            ).aggregate(
                total=Sum(F('stock') * F('price'))
            )['total'] or Decimal('0')

            discounted_products = Product.objects.filter(
                discount_price__isnull=False,
                discount_price__lt=F('price')
            ).count()

            low_stock = Product.objects.filter(
                stock__isnull=False,
                stock__lt=10,
                stock__gt=0
            ).count()

            out_of_stock = Product.objects.filter(stock=0).count()

            return JsonResponse({
                'total_products': total_products,
                'available_products': available_products,
                'featured_products': featured_products,
                'products_by_type': products_by_type,
                'revenue_potential': str(revenue_potential),
                'discounted_products': discounted_products,
                'low_stock': low_stock,
                'out_of_stock': out_of_stock,
            })

        except Exception as e:
            logger.error(f"Error en AdminProductsStatsView: {e}")
            return JsonResponse({'error': 'Error al obtener estadísticas'}, status=500)


@method_decorator(csrf_exempt, name='dispatch')
class AdminProductCreateView(View):
    """
    Crear producto.
    POST /api/admin/products/create/

    Requiere: Staff
    """
    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)

        if not request.user.is_staff_role:
            return JsonResponse({'error': 'Acceso denegado'}, status=403)

        try:
            from .models import Product, ProductCategory
            from decimal import Decimal, InvalidOperation
            import json

            # Obtener datos
            name = request.POST.get('name', '').strip()
            description = request.POST.get('description', '').strip()
            short_description = request.POST.get('short_description', '').strip()
            product_type = request.POST.get('product_type', '').strip()
            category_id = request.POST.get('category_id', '').strip()
            price = request.POST.get('price', '').strip()
            discount_price = request.POST.get('discount_price', '').strip()
            rarity = request.POST.get('rarity', 'common').strip()
            is_available = request.POST.get('is_available', 'true') == 'true'
            is_featured = request.POST.get('is_featured', 'false') == 'true'
            is_new = request.POST.get('is_new', 'false') == 'true'
            stock = request.POST.get('stock', '').strip()
            order = request.POST.get('order', '0').strip()
            type_specific_data_raw = request.POST.get('type_specific_data', '{}')

            # Validaciones
            if not name:
                return JsonResponse({'error': 'El nombre es requerido'}, status=400)

            if len(name) > 100:
                return JsonResponse({'error': 'El nombre no puede superar los 100 caracteres'}, status=400)

            if not description:
                return JsonResponse({'error': 'La descripción es requerida'}, status=400)

            if len(description) > 1000:
                return JsonResponse({'error': 'La descripción no puede superar los 1000 caracteres'}, status=400)

            if short_description and len(short_description) > 200:
                return JsonResponse({'error': 'La descripción corta no puede superar los 200 caracteres'}, status=400)

            valid_types = [choice[0] for choice in Product.ProductType.choices]
            if product_type not in valid_types:
                return JsonResponse({'error': 'Tipo de producto inválido'}, status=400)

            category = None
            if category_id:
                try:
                    category = ProductCategory.objects.get(id=int(category_id))
                except ProductCategory.DoesNotExist:
                    return JsonResponse({'error': 'Categoría no encontrada'}, status=404)

            if not price:
                return JsonResponse({'error': 'El precio es requerido'}, status=400)

            try:
                price_decimal = Decimal(price)
                if price_decimal < 0:
                    return JsonResponse({'error': 'El precio no puede ser negativo'}, status=400)
            except (InvalidOperation, ValueError):
                return JsonResponse({'error': 'Precio inválido'}, status=400)

            discount_price_decimal = None
            if discount_price:
                try:
                    discount_price_decimal = Decimal(discount_price)
                    if discount_price_decimal < 0:
                        return JsonResponse({'error': 'El precio con descuento no puede ser negativo'}, status=400)
                    if discount_price_decimal >= price_decimal:
                        return JsonResponse({'error': 'El precio con descuento debe ser menor al precio normal'}, status=400)
                except (InvalidOperation, ValueError):
                    return JsonResponse({'error': 'Precio con descuento inválido'}, status=400)

            valid_rarities = [choice[0] for choice in Product.Rarity.choices]
            if rarity not in valid_rarities:
                return JsonResponse({'error': 'Rareza inválida'}, status=400)

            stock_int = None
            if stock:
                try:
                    stock_int = int(stock)
                    if stock_int < 0:
                        return JsonResponse({'error': 'El stock no puede ser negativo'}, status=400)
                except ValueError:
                    return JsonResponse({'error': 'Stock inválido'}, status=400)

            try:
                order_int = int(order)
            except ValueError:
                order_int = 0

            if 'image' not in request.FILES:
                return JsonResponse({'error': 'La imagen es requerida'}, status=400)

            image_file = request.FILES['image']

            if image_file.size > 5 * 1024 * 1024:
                return JsonResponse({'error': 'La imagen no puede superar los 5MB'}, status=400)

            allowed_types = ['image/jpeg', 'image/png', 'image/jpg', 'image/webp']
            if image_file.content_type not in allowed_types:
                return JsonResponse({'error': 'Solo se permiten imágenes JPEG, PNG o WebP'}, status=400)

            try:
                type_specific_data = json.loads(type_specific_data_raw)
                if not isinstance(type_specific_data, dict):
                    type_specific_data = {}
            except json.JSONDecodeError:
                return JsonResponse({'error': 'Datos específicos del tipo inválidos (JSON mal formado)'}, status=400)

            # Crear producto
            product = Product(
                name=name,
                description=description,
                short_description=short_description,
                product_type=product_type,
                category=category,
                image=image_file,
                price=price_decimal,
                discount_price=discount_price_decimal,
                rarity=rarity,
                is_available=is_available,
                is_featured=is_featured,
                is_new=is_new,
                stock=stock_int,
                order=order_int,
                type_specific_data=type_specific_data,
                created_by=request.user,
                last_modified_by=request.user
            )

            product.save()

            return JsonResponse({
                'success': True,
                'message': 'Producto creado exitosamente',
                'product': {
                    'id': product.id,
                    'name': product.name,
                    'slug': product.slug,
                    'product_type': product.product_type,
                    'image_url': product.get_image_url(request),
                }
            }, status=201)

        except Exception as e:
            logger.error(f"Error en AdminProductCreateView: {e}", exc_info=True)
            return JsonResponse({'error': f'Error al crear producto: {str(e)}'}, status=500)


@method_decorator(csrf_exempt, name='dispatch')
class AdminProductUpdateView(View):
    """
    Actualizar producto.
    PUT /api/admin/products/<id>/update/

    Requiere: Staff
    """
    def put(self, request, product_id, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)

        if not request.user.is_staff_role:
            return JsonResponse({'error': 'Acceso denegado'}, status=403)

        try:
            from .models import Product, ProductCategory
            from decimal import Decimal, InvalidOperation
            import json

            # Buscar producto
            try:
                product = Product.objects.get(id=product_id)
            except Product.DoesNotExist:
                return JsonResponse({'error': 'Producto no encontrado'}, status=404)

            # Parse multipart FormData de PUT
            from django.http import QueryDict
            if request.content_type and 'multipart/form-data' in request.content_type:
                # Para PUT con multipart, los datos vienen en POST
                data = request.POST
                files = request.FILES
            else:
                data = QueryDict(request.body)
                files = None

            # Actualizar campos
            name = data.get('name', product.name).strip()
            description = data.get('description', product.description).strip()
            short_description = data.get('short_description', product.short_description).strip()
            product_type = data.get('product_type', product.product_type).strip()
            category_id = data.get('category_id', '').strip()
            price_str = data.get('price', str(product.price)).strip()
            discount_price_str = data.get('discount_price', '').strip()
            rarity = data.get('rarity', product.rarity).strip()
            is_available = data.get('is_available', str(product.is_available).lower()) == 'true'
            is_featured = data.get('is_featured', str(product.is_featured).lower()) == 'true'
            is_new = data.get('is_new', str(product.is_new).lower()) == 'true'
            stock_str = data.get('stock', '').strip()
            order_str = data.get('order', str(product.order)).strip()
            type_specific_data_raw = data.get('type_specific_data', '{}')

            # Validaciones (similares a create)
            if not name or len(name) > 100:
                return JsonResponse({'error': 'Nombre inválido'}, status=400)

            if not description or len(description) > 1000:
                return JsonResponse({'error': 'Descripción inválida'}, status=400)

            try:
                price_decimal = Decimal(price_str)
                if price_decimal < 0:
                    return JsonResponse({'error': 'Precio inválido'}, status=400)
            except (InvalidOperation, ValueError):
                return JsonResponse({'error': 'Precio inválido'}, status=400)

            discount_price_decimal = None
            if discount_price_str:
                try:
                    discount_price_decimal = Decimal(discount_price_str)
                    if discount_price_decimal < 0 or discount_price_decimal >= price_decimal:
                        return JsonResponse({'error': 'Precio con descuento inválido'}, status=400)
                except (InvalidOperation, ValueError):
                    return JsonResponse({'error': 'Precio con descuento inválido'}, status=400)

            category = None
            if category_id:
                try:
                    category = ProductCategory.objects.get(id=int(category_id))
                except ProductCategory.DoesNotExist:
                    return JsonResponse({'error': 'Categoría no encontrada'}, status=404)

            stock_int = None
            if stock_str:
                try:
                    stock_int = int(stock_str)
                    if stock_int < 0:
                        return JsonResponse({'error': 'Stock inválido'}, status=400)
                except ValueError:
                    return JsonResponse({'error': 'Stock inválido'}, status=400)

            try:
                order_int = int(order_str)
            except ValueError:
                order_int = 0

            try:
                type_specific_data = json.loads(type_specific_data_raw)
                if not isinstance(type_specific_data, dict):
                    type_specific_data = {}
            except json.JSONDecodeError:
                return JsonResponse({'error': 'Datos específicos inválidos'}, status=400)

            # Actualizar producto
            product.name = name
            product.description = description
            product.short_description = short_description
            product.product_type = product_type
            product.category = category
            product.price = price_decimal
            product.discount_price = discount_price_decimal
            product.rarity = rarity
            product.is_available = is_available
            product.is_featured = is_featured
            product.is_new = is_new
            product.stock = stock_int
            product.order = order_int
            product.type_specific_data = type_specific_data
            product.last_modified_by = request.user

            # Si hay nueva imagen
            if files and 'image' in files:
                image_file = files['image']

                if image_file.size > 5 * 1024 * 1024:
                    return JsonResponse({'error': 'La imagen no puede superar los 5MB'}, status=400)

                allowed_types = ['image/jpeg', 'image/png', 'image/jpg', 'image/webp']
                if image_file.content_type not in allowed_types:
                    return JsonResponse({'error': 'Solo se permiten imágenes JPEG, PNG o WebP'}, status=400)

                # Eliminar imagen anterior
                if product.image:
                    product.image.delete(save=False)

                product.image = image_file

            product.save()

            return JsonResponse({
                'success': True,
                'message': 'Producto actualizado exitosamente',
                'product': {
                    'id': product.id,
                    'name': product.name,
                    'slug': product.slug,
                    'image_url': product.get_image_url(request),
                }
            })

        except Exception as e:
            logger.error(f"Error en AdminProductUpdateView: {e}", exc_info=True)
            return JsonResponse({'error': 'Error al actualizar producto'}, status=500)


@method_decorator(csrf_exempt, name='dispatch')
class AdminProductDeleteView(View):
    """
    Eliminar producto.
    DELETE /api/admin/products/<id>/delete/

    Requiere: ADMIN o DEVELOPER
    """
    def delete(self, request, product_id, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)

        if not request.user.is_staff_role:
            return JsonResponse({'error': 'Acceso denegado'}, status=403)

        if request.user.role not in ['ADMIN', 'DEVELOPER']:
            return JsonResponse({'error': 'Solo ADMIN/DEVELOPER pueden eliminar productos'}, status=403)

        try:
            from .models import Product

            product = Product.objects.get(id=product_id)

            # Eliminar imagen del disco
            if product.image:
                product.image.delete(save=False)

            product_name = product.name
            product.delete()

            return JsonResponse({
                'success': True,
                'message': f'Producto "{product_name}" eliminado exitosamente'
            })

        except Product.DoesNotExist:
            return JsonResponse({'error': 'Producto no encontrado'}, status=404)
        except Exception as e:
            logger.error(f"Error en AdminProductDeleteView: {e}")
            return JsonResponse({'error': 'Error al eliminar producto'}, status=500)


@method_decorator(csrf_exempt, name='dispatch')
class AdminProductToggleAvailabilityView(View):
    """
    Alternar disponibilidad de un producto.
    POST /api/admin/products/<id>/toggle-availability/

    Requiere: Staff
    """
    def post(self, request, product_id, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)

        if not request.user.is_staff_role:
            return JsonResponse({'error': 'Acceso denegado'}, status=403)

        try:
            from .models import Product

            product = Product.objects.get(id=product_id)
            product.is_available = not product.is_available
            product.last_modified_by = request.user
            product.save()

            status = 'disponible' if product.is_available else 'no disponible'

            return JsonResponse({
                'success': True,
                'message': f'Producto marcado como {status}',
                'is_available': product.is_available
            })

        except Product.DoesNotExist:
            return JsonResponse({'error': 'Producto no encontrado'}, status=404)
        except Exception as e:
            logger.error(f"Error en AdminProductToggleAvailabilityView: {e}")
            return JsonResponse({'error': 'Error al cambiar disponibilidad'}, status=500)


@method_decorator(csrf_exempt, name='dispatch')
class AdminProductToggleFeaturedView(View):
    """
    Alternar estado destacado de un producto.
    POST /api/admin/products/<id>/toggle-featured/

    Requiere: Staff
    """
    def post(self, request, product_id, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)

        if not request.user.is_staff_role:
            return JsonResponse({'error': 'Acceso denegado'}, status=403)

        try:
            from .models import Product

            product = Product.objects.get(id=product_id)
            product.is_featured = not product.is_featured
            product.last_modified_by = request.user
            product.save()

            status = 'destacado' if product.is_featured else 'normal'

            return JsonResponse({
                'success': True,
                'message': f'Producto marcado como {status}',
                'is_featured': product.is_featured
            })

        except Product.DoesNotExist:
            return JsonResponse({'error': 'Producto no encontrado'}, status=404)
        except Exception as e:
            logger.error(f"Error en AdminProductToggleFeaturedView: {e}")
            return JsonResponse({'error': 'Error al cambiar estado destacado'}, status=500)


class AdminProductCategoriesView(View):
    """
    Listar categorías de productos disponibles.
    GET /api/admin/products/categories/

    Requiere: Staff
    """
    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)

        if not request.user.is_staff_role:
            return JsonResponse({'error': 'Acceso denegado'}, status=403)

        try:
            from .models import ProductCategory

            categories = ProductCategory.objects.filter(is_active=True).order_by('order', 'name')

            items = [{
                'id': c.id,
                'name': c.name,
                'slug': c.slug,
                'description': c.description,
                'product_type': c.product_type,
                'icon': c.icon,
                'color': c.color,
            } for c in categories]

            return JsonResponse({'categories': items})

        except Exception as e:
            logger.error(f"Error en AdminProductCategoriesView: {e}")
            return JsonResponse({'error': 'Error al obtener categorías'}, status=500)


class AdminProductDetailView(View):
    """
    Detalle de un producto para administración.
    GET /api/admin/products/<id>/

    Requiere: Staff
    """
    def get(self, request, product_id, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Autenticación requerida'}, status=401)

        if not request.user.is_staff_role:
            return JsonResponse({'error': 'Acceso denegado'}, status=403)

        try:
            from .models import Product

            product = Product.objects.select_related('category', 'created_by', 'last_modified_by').get(id=product_id)

            data = {
                'id': product.id,
                'name': product.name,
                'slug': product.slug,
                'description': product.description,
                'short_description': product.short_description,
                'product_type': product.product_type,
                'product_type_display': product.get_product_type_display(),
                'category': {
                    'id': product.category.id,
                    'name': product.category.name,
                    'slug': product.category.slug
                } if product.category else None,
                'image_url': product.get_image_url(request),
                'price': str(product.price),
                'discount_price': str(product.discount_price) if product.discount_price else None,
                'discount_percent': product.discount_percent,
                'final_price': str(product.final_price),
                'rarity': product.rarity,
                'rarity_display': product.get_rarity_display(),
                'is_available': product.is_available,
                'is_featured': product.is_featured,
                'is_new': product.is_new,
                'stock': product.stock,
                'order': product.order,
                'type_specific_data': product.type_specific_data,
                'views': product.views,
                'purchases': product.purchases,
                'created_at': product.created_at.isoformat(),
                'updated_at': product.updated_at.isoformat(),
                'created_by': {
                    'id': product.created_by.id,
                    'username': product.created_by.username
                } if product.created_by else None,
                'last_modified_by': {
                    'id': product.last_modified_by.id,
                    'username': product.last_modified_by.username
                } if product.last_modified_by else None,
            }

            return JsonResponse({'product': data})

        except Product.DoesNotExist:
            return JsonResponse({'error': 'Producto no encontrado'}, status=404)
        except Exception as e:
            logger.error(f"Error en AdminProductDetailView: {e}")
            return JsonResponse({'error': 'Error al obtener producto'}, status=500)

# ============================================================================
# VISTAS DE CALENDARIO
# ============================================================================

def calendar_events_list_api_view(request):
    """
    Lista eventos del calendario.
    Soporta filtros por rango de fechas (start_date, end_date).
    Endpoint público.
    """
    try:
        events = CalendarEvent.objects.all().order_by('date', 'start_time')
        
        # Filtro por rango de fechas
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')
        
        if start_date and end_date:
            events = events.filter(date__range=[start_date, end_date])
            
        data = [
            {
                'id': str(event.id),
                'title': event.title,
                'description': event.description,
                'shortDescription': event.short_description,
                'date': event.date.isoformat(),
                'startTime': event.start_time.strftime('%H:%M'),
                'endTime': event.end_time.strftime('%H:%M') if event.end_time else None,
                'category': event.category,
                'status': event.status,
                'bannerUrl': event.get_banner_url(request),
                'imageUrl': event.get_image_url(request),
                'color': event.color,
                'prizes': event.prizes,
                'location': event.location,
                'maxParticipants': event.max_participants,
                'currentParticipants': event.current_participants,
                'requiresRegistration': event.requires_registration,
                'registrationUrl': event.registration_url,
                'grovs_reward': event.grovs_reward,
            }
            for event in events
        ]
        
        return JsonResponse({'success': True, 'data': {'events': data}}, status=200)
    except Exception as e:
        logger.error(f"Error en calendar_events_list_api_view: {e}")
        return JsonResponse({'success': False, 'error': 'Error loading events'}, status=500)


def calendar_events_categories_api_view(request):
    """
    Lista categorías de eventos.
    """
    try:
        categories = []
        for code, label in CalendarEvent.Category.choices:
             categories.append({
                 'id': code,
                 'name': label,
             })
             
        return JsonResponse({'success': True, 'data': {'categories': categories}}, status=200)
    except Exception as e:
         return JsonResponse({'success': False, 'error': str(e)}, status=500)

def calendar_event_detail_api_view(request, event_id):
    """
    Detalle de un evento específico.
    """
    try:
        event = CalendarEvent.objects.get(id=event_id)
        data = {
                'id': str(event.id),
                'title': event.title,
                'description': event.description,
                'shortDescription': event.short_description,
                'date': event.date.isoformat(),
                'startTime': event.start_time.strftime('%H:%M'),
                'endTime': event.end_time.strftime('%H:%M') if event.end_time else None,
                'category': event.category,
                'status': event.status,
                'bannerUrl': event.get_banner_url(request),
                'imageUrl': event.get_image_url(request),
                'color': event.color,
                'prizes': event.prizes,
                'location': event.location,
                'maxParticipants': event.max_participants,
                'currentParticipants': event.current_participants,
                'requiresRegistration': event.requires_registration,
                'registrationUrl': event.registration_url,
                'grovs_reward': event.grovs_reward,
        }
        return JsonResponse({'success': True, 'data': {'event': data}}, status=200)
    except CalendarEvent.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Event not found'}, status=404)

class DownloadFilesListView(View):
    """Lista de archivos disponibles según el rol del usuario"""
    def get(self, request):
        # Si el usuario es staff, ve todo. Si no, filtramos por activos.
        files = DownloadableFile.objects.filter(is_active=True)
        
        data = [
            {
                'id': f.id,
                'title': f.title,
                'description': f.description,
                'category': f.category,
                'min_role': f.min_role,
                'download_count': f.download_count,
                'created_at': f.created_at.isoformat(),
            }
            for f in files
        ]
        return JsonResponse({'files': data})


class DownloadFileView(View):
    """Vista para descargar un archivo de forma segura"""
    def get(self, request, file_id):
        try:
            file_obj = DownloadableFile.objects.get(id=file_id, is_active=True)
            
            # Verificar permisos básicos
            if file_obj.min_role != User.Role.DEFAULT:
                if not request.user.is_authenticated:
                    return JsonResponse({'error': 'Autenticación requerida'}, status=401)
            
            # Incrementar contador de forma atómica
            DownloadableFile.objects.filter(id=file_id).update(download_count=F('download_count') + 1)
            
            # Servir el archivo
            response = FileResponse(file_obj.file.open(), as_attachment=True)
            return response
            
        except DownloadableFile.DoesNotExist:
            return JsonResponse({'error': 'Archivo no encontrado'}, status=404)
        except Exception as e:
            logger.error(f"Error en DownloadFileView: {e}")
            return JsonResponse({'error': 'Error al procesar la descarga'}, status=500)
