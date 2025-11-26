from django.shortcuts import render
from django.http import JsonResponse
from .models import HeroSection, GameHeader, User, Contact, Banner
from django.conf import settings
import json
import re
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from .utils import get_image_url
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import make_password
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.urls import reverse
from django.utils import timezone
import uuid # Para generar tokens de un solo uso

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

@method_decorator(csrf_exempt, name='dispatch')
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
    """
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres"
    
    if not re.search(r'[A-Z]', password):
        return False, "La contraseña debe contener al menos una letra mayúscula"
    
    if not re.search(r'[a-z]', password):
        return False, "La contraseña debe contener al menos una letra minúscula"
    
    if not re.search(r'\d', password):
        return False, "La contraseña debe contener al menos un número"
    
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
class ForgotPasswordView(View):
    """
    Vista para solicitar un enlace de restablecimiento de contraseña.
    Genera un token y envía un correo electrónico al usuario.
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
            user.password_reset_expires = timezone.now() + timezone.timedelta(hours=1) # Token válido por 1 hora
            user.save()

            # Construir el enlace de restablecimiento (ajusta la URL base a tu frontend)
            reset_link = f"http://localhost:4200/reset-password/{reset_token}" # Frontend URL

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
            
            # TODO: Configurar send_mail en settings.py para producción
            # Actualmente, solo imprimirá el enlace en la consola para desarrollo
            print(f"DEBUG: Password Reset Link for {user.email}: {reset_link}")

            # send_mail(
            #     subject,
            #     message,
            #     settings.DEFAULT_FROM_EMAIL, # Configurar en settings.py
            #     [user.email],
            #     fail_silently=False,
            # )

            return JsonResponse({'message': 'Si el correo está registrado, recibirás un enlace para recuperar tu contraseña.'}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido.'}, status=400)
        except Exception as e:
            print(f"Error en ForgotPasswordView: {e}")
            return JsonResponse({'error': 'Error interno del servidor.'}, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class RegisterView(View):
    """Vista para registro de nuevos usuarios con validaciones de seguridad"""
    
    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body)
            
            # ========== VALIDACIÓN DE CAMPOS REQUERIDOS ==========
            username = sanitize_input(data.get('username', '').strip())
            minecraft_username = sanitize_input(data.get('minecraft_username', username).strip())
            email = data.get('email', '').strip().lower()
            password = data.get('password', '')
            discord_username = sanitize_input(data.get('discord_username', '').strip())
            
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
            
            # ========== VALIDACIÓN DE MINECRAFT USERNAME ==========
            is_valid, error_msg = validate_minecraft_username(minecraft_username)
            if not is_valid:
                return JsonResponse({
                    'error': error_msg
                }, status=400)
            
            # ========== VERIFICAR EXISTENCIA DE USUARIOS ==========
            if User.objects.filter(username__iexact=username).exists():
                return JsonResponse({
                    'error': 'El nombre de usuario ya está en uso'
                }, status=400)
            
            if User.objects.filter(email__iexact=email).exists():
                return JsonResponse({
                    'error': 'El email ya está registrado'
                }, status=400)
            
            if User.objects.filter(minecraft_username__iexact=minecraft_username).exists():
                return JsonResponse({
                    'error': 'El nombre de Minecraft ya está en uso'
                }, status=400)
            
            # ========== CREAR USUARIO CON ROL DEFAULT ==========
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password
            )
            # Asignar campos adicionales después de la creación
            user.minecraft_username = minecraft_username
            user.discord_username = discord_username
            user.role = User.Role.DEFAULT  # SIEMPRE comienza con rol DEFAULT
            user.is_active = True
            user.is_staff = False  # Seguridad: usuarios no son staff por defecto
            user.is_superuser = False  # Seguridad: usuarios no son superuser por defecto
            user.save()
            
            # ========== AUTENTICAR Y HACER LOGIN ==========
            # El usuario ya está autenticado por create_user, pero para asegurar la sesión
            # lo volvemos a autenticar y hacemos login.
            auth_user = authenticate(request, username=username, password=password)
            if auth_user:
                login(request, auth_user)
            
            return JsonResponse({
                'message': 'Usuario registrado exitosamente',
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
            }, status=201)
            
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
        except Exception as e:
            # En producción, no exponer detalles del error
            return JsonResponse({'error': 'Error al registrar usuario'}, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class LoginView(View):
    """Vista para login de usuarios con validaciones de seguridad"""
    
    def post(self, request, *args, **kwargs):
        print("\n[DEBUG] Login attempt received.")
        try:
            data = json.loads(request.body)
            
            identifier = sanitize_input(data.get('username', '').strip())
            password = data.get('password', '')
            
            print(f"[DEBUG] Identifier: '{identifier}', Password length: {len(password)}")

            if not all([identifier, password]):
                print("[DEBUG] Validation failed: Identifier or password missing.")
                return JsonResponse({
                    'error': 'El identificador y la contraseña son requeridos'
                }, status=400)
            
            # ========== AUTENTICAR USUARIO POR USERNAME, EMAIL O MINECRAFT USERNAME ==========
            user = None
            
            # 1. Intento por username
            print(f"[DEBUG] Attempting authentication with username: '{identifier}'")
            user = authenticate(request, username=identifier, password=password)
            if user:
                 print(f"[DEBUG] Success: Authenticated user '{user.username}' via username.")

            if user is None:
                # 2. Intento por email
                print(f"[DEBUG] Failed username auth. Attempting by email: '{identifier}'")
                try:
                    user_by_email = User.objects.get(email__iexact=identifier)
                    print(f"[DEBUG] Found user by email: '{user_by_email.username}'. Authenticating...")
                    print(f"[DEBUG]   - Password hash format: {user_by_email.password.split('$')[0] if '$' in user_by_email.password else 'RAW/UNHASHED'}")
                    user = authenticate(request, username=user_by_email.username, password=password)
                    if user:
                        print(f"[DEBUG] Success: Authenticated user '{user.username}' via email.")
                except User.DoesNotExist:
                    print(f"[DEBUG] No user found with email: '{identifier}'")
                    pass  # Continuar al siguiente método

            if user is None:
                # 3. Intento por minecraft_username
                print(f"[DEBUG] Failed email auth. Attempting by minecraft_username: '{identifier}'")
                try:
                    user_by_minecraft = User.objects.get(minecraft_username__iexact=identifier)
                    print(f"[DEBUG] Found user by minecraft_username: '{user_by_minecraft.username}'. Authenticating...")
                    print(f"[DEBUG]   - Password hash format: {user_by_minecraft.password.split('$')[0] if '$' in user_by_minecraft.password else 'RAW/UNHASHED'}")
                    user = authenticate(request, username=user_by_minecraft.username, password=password)
                    if user:
                        print(f"[DEBUG] Success: Authenticated user '{user.username}' via minecraft_username.")
                except User.DoesNotExist:
                    print(f"[DEBUG] No user found with minecraft_username: '{identifier}'")
                    pass # El usuario no se encontró por ningún método

            if user is not None:
                print(f"[DEBUG] User '{user.username}' authenticated successfully. Checking status...")
                # ========== VERIFICAR ESTADO DEL USUARIO ==========
                if user.is_banned:
                    print(f"[DEBUG] User '{user.username}' is banned.")
                    return JsonResponse({
                        'error': 'Usuario bloqueado',
                        'ban_reason': user.ban_reason
                    }, status=403)
                
                if not user.is_active:
                    print(f"[DEBUG] User '{user.username}' is not active.")
                    return JsonResponse({
                        'error': 'Usuario inactivo. Contacta al administrador.'
                    }, status=403)
                
                # ========== LOGIN EXITOSO ==========
                print(f"[DEBUG] Logging in user '{user.username}'.")
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
                print("[DEBUG] All authentication methods failed.")
                return JsonResponse({
                    'error': 'Credenciales inválidas'
                }, status=401)
                
        except json.JSONDecodeError:
            print("[DEBUG] Error: Invalid JSON in request body.")
            return JsonResponse({'error': 'JSON inválido'}, status=400)
        except Exception as e:
            print(f"[DEBUG] An unexpected error occurred: {e}")
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
            
            # Validar tipo de archivo
            allowed_types = ['image/jpeg', 'image/png', 'image/jpg', 'image/webp']
            if avatar_file.content_type not in allowed_types:
                return JsonResponse({'error': 'Solo se permiten imágenes JPEG, PNG o WebP'}, status=400)
            
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
            return JsonResponse({'error': f'Error al subir avatar: {str(e)}'}, status=500)
    
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
            print(f"Error en ResetPasswordConfirmView: {e}")
            return JsonResponse({'error': 'Error interno del servidor.'}, status=500)
