from django.urls import path
from . import views

urlpatterns = [
    path('hero-section/', views.hero_section_api_view, name='hero_section_api'),
    path('game-header/', views.game_header_api_view, name='game_header_api'),
    path('contact/', views.ContactView.as_view(), name='contact_api'),
    
    # Autenticación
    path('auth/register/', views.RegisterView.as_view(), name='register'),
    path('auth/login/', views.LoginView.as_view(), name='login'),
    path('auth/logout/', views.LogoutView.as_view(), name='logout'),
    path('auth/profile/', views.UserProfileView.as_view(), name='user_profile'),
    
    # Recuperación de contraseña
    path('auth/forgot-password/', views.ForgotPasswordView.as_view(), name='forgot_password'),
    path('auth/reset-password-confirm/', views.ResetPasswordConfirmView.as_view(), name='reset_password_confirm'),
    
    # Gestión de perfil
    path('auth/update-profile/', views.UpdateProfileView.as_view(), name='update_profile'),
    path('auth/change-password/', views.ChangePasswordView.as_view(), name='change_password'),
    path('auth/upload-avatar/', views.UploadAvatarView.as_view(), name='upload_avatar'),
]
