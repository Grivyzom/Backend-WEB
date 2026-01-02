from django.urls import path
from django.http import JsonResponse
from . import views

def api_root(request):
    """Vista raíz de la API que muestra los endpoints disponibles"""
    return JsonResponse({
        'status': 'online',
        'message': 'Grivyzom API v1.0',
        'endpoints': {
            'hero_section': '/api/hero-section/',
            'game_header': '/api/game-header/',
            'public_stats': '/api/stats/public/',
            'servers': '/api/servers/',
            'downloads': '/api/downloads/',
            'contact': '/api/contact/',
            'gallery': {
                'categories': '/api/gallery/categories/',
                'images': '/api/gallery/images/',
                'image_detail': '/api/gallery/images/<id>/',
            },
            'auth': {
                'register': '/api/auth/register/',
                'registration_status': '/api/auth/registration-status/<id>/',
                'login': '/api/auth/login/',
                'logout': '/api/auth/logout/',
                'profile': '/api/auth/profile/',
                'forgot_password': '/api/auth/forgot-password/',
                'reset_password': '/api/auth/reset-password-confirm/',
                'update_profile': '/api/auth/update-profile/',
                'change_password': '/api/auth/change-password/',
                'upload_avatar': '/api/auth/upload-avatar/',
            },
            'minecraft': {
                'verify_registration': '/api/mc/verify-registration/',
                'pending_by_code': '/api/mc/pending-by-code/<code>/',
                'cancel_registration': '/api/mc/cancel-registration/',
            }
        }
    })

urlpatterns = [
    path('', api_root, name='api_root'),
    path('hero-section/', views.hero_section_api_view, name='hero_section_api'),
    path('game-header/', views.game_header_api_view, name='game_header_api'),
    path('stats/public/', views.public_stats_api_view, name='public_stats'),
    path('servers/', views.servers_api_view, name='servers_api'),
    path('contact/', views.ContactView.as_view(), name='contact_api'),
    
    # Descargas
    path('downloads/', views.DownloadFilesListView.as_view(), name='downloads_list'),
    path('downloads/<int:file_id>/', views.DownloadFileView.as_view(), name='download_file'),
    
    # Galería (Público)
    path('gallery/categories/', views.gallery_categories_api_view, name='gallery_categories'),
    path('gallery/images/', views.gallery_images_api_view, name='gallery_images'),
    path('gallery/images/<int:image_id>/', views.gallery_image_detail_api_view, name='gallery_image_detail'),
    
    # Autenticación
    path('auth/register/', views.RegisterView.as_view(), name='register'),
    path('auth/registration-status/<int:pending_id>/', views.RegistrationStatusView.as_view(), name='registration_status'),
    path('auth/login/', views.LoginView.as_view(), name='login'),
    path('auth/token-login/', views.TokenLoginView.as_view(), name='token_login'),
    path('auth/logout/', views.LogoutView.as_view(), name='logout'),
    path('auth/profile/', views.UserProfileView.as_view(), name='user_profile'),
    
    # Recuperación de contraseña
    path('auth/forgot-password/', views.ForgotPasswordView.as_view(), name='forgot_password'),
    path('auth/reset-password-confirm/', views.ResetPasswordConfirmView.as_view(), name='reset_password_confirm'),
    
    # Gestión de perfil
    path('auth/update-profile/', views.UpdateProfileView.as_view(), name='update_profile'),
    path('auth/change-password/', views.ChangePasswordView.as_view(), name='change_password'),
    path('auth/upload-avatar/', views.UploadAvatarView.as_view(), name='upload_avatar'),
    
    # Endpoints para Plugin Minecraft (protegidos por API Key)
    path('mc/verify-registration/', views.MinecraftVerifyView.as_view(), name='mc_verify_registration'),
    path('mc/pending-by-code/<str:code>/', views.MinecraftPendingInfoView.as_view(), name='mc_pending_info'),
    path('mc/cancel-registration/', views.MinecraftCancelRegistrationView.as_view(), name='mc_cancel_registration'),

    # Tienda - Endpoints Públicos
    path('store/products/', views.StoreProductsListView.as_view(), name='store_products'),
    path('store/products/<slug:slug>/', views.StoreProductDetailView.as_view(), name='store_product_detail'),
    path('store/categories/', views.StoreCategoriesView.as_view(), name='store_categories'),

    # Comunidad
    path('community/posts/', views.CommunityPostsListView.as_view(), name='community_posts'),
    path('community/posts/create/', views.CommunityPostCreateView.as_view(), name='community_post_create'),
    path('community/posts/<slug:slug>/', views.PostDetailView.as_view(), name='community_post_detail'),
    path('community/posts/<int:post_id>/like/', views.PostLikeView.as_view(), name='community_post_like'),
    path('community/posts/<int:post_id>/bookmark/', views.PostBookmarkView.as_view(), name='community_post_bookmark'),
    path('community/posts/<int:post_id>/comments/', views.PostCommentsView.as_view(), name='community_post_comments'),
    path('community/categories/', views.CategoriesListView.as_view(), name='community_categories'),
    path('community/top-contributors/', views.TopContributorsView.as_view(), name='community_top_contributors'),
    path('community/trending-tags/', views.TrendingTagsView.as_view(), name='community_trending_tags'),
    path('community/users/<int:user_id>/', views.UserProfilePublicView.as_view(), name='community_user_profile'),
    path('community/users/<int:user_id>/follow/', views.UserFollowView.as_view(), name='community_user_follow'),
    
    # Panel de Administración (Solo Staff)
    path('admin/stats/', views.AdminDashboardStatsView.as_view(), name='admin_stats'),
    path('admin/users/', views.AdminUsersListView.as_view(), name='admin_users'),
    path('admin/users/stats/', views.AdminUsersStatsView.as_view(), name='admin_users_stats'),
    path('admin/users/<int:user_id>/', views.AdminUserDetailView.as_view(), name='admin_user_detail'),
    path('admin/users/<int:user_id>/role/', views.AdminUserRoleView.as_view(), name='admin_user_role'),
    path('admin/users/<int:user_id>/ban/', views.AdminUserBanView.as_view(), name='admin_user_ban'),
    path('admin/game-header/', views.AdminGameHeaderView.as_view(), name='admin_game_header'),
    path('admin/hero-section/', views.AdminHeroSectionView.as_view(), name='admin_hero_section'),
    path('admin/web-components/', views.AdminWebComponentsView.as_view(), name='admin_web_components'),

    # Administración de Productos (Solo Staff)
    path('admin/products/', views.AdminProductsListView.as_view(), name='admin_products'),
    path('admin/products/stats/', views.AdminProductsStatsView.as_view(), name='admin_products_stats'),
    path('admin/products/create/', views.AdminProductCreateView.as_view(), name='admin_product_create'),
    path('admin/products/<int:product_id>/', views.AdminProductDetailView.as_view(), name='admin_product_detail'),
    path('admin/products/<int:product_id>/update/', views.AdminProductUpdateView.as_view(), name='admin_product_update'),
    path('admin/products/<int:product_id>/delete/', views.AdminProductDeleteView.as_view(), name='admin_product_delete'),
    path('admin/products/<int:product_id>/toggle-availability/', views.AdminProductToggleAvailabilityView.as_view(), name='admin_product_toggle_availability'),
    path('admin/products/<int:product_id>/toggle-featured/', views.AdminProductToggleFeaturedView.as_view(), name='admin_product_toggle_featured'),
    path('admin/products/categories/', views.AdminProductCategoriesView.as_view(), name='admin_product_categories'),
    path('events/', views.calendar_events_list_api_view, name='calendar_events_list'),
    path('events/categories/', views.calendar_events_categories_api_view, name='calendar_events_categories'),
    path('events/<int:event_id>/', views.calendar_event_detail_api_view, name='calendar_event_detail'),
]

