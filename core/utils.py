"""
Utilidades para el manejo de imágenes y otros recursos compartidos
"""
from django.conf import settings


def get_image_url(request, image_field, placeholder_name='placeholder.svg'):
    """
    Función universal para obtener la URL de una imagen o devolver un placeholder.
    
    Args:
        request: HttpRequest object para construir URLs absolutas
        image_field: Campo ImageField del modelo
        placeholder_name: Nombre del archivo placeholder (default: 'placeholder.svg')
    
    Returns:
        str: URL absoluta de la imagen o del placeholder
    
    Ejemplos de uso:
        # Uso básico
        image_url = get_image_url(request, hero_section.image)
        
        # Con placeholder personalizado
        image_url = get_image_url(request, game_header.image, 'placeholder-header.jpg')
    """
    if image_field and hasattr(image_field, 'url'):
        try:
            return request.build_absolute_uri(image_field.url)
        except (ValueError, AttributeError):
            pass
    
    # Retornar placeholder si no hay imagen o hay error
    placeholder_url = f"{settings.STATIC_URL}images/{placeholder_name}"
    return request.build_absolute_uri(placeholder_url)


def get_placeholder_url(request, placeholder_name='placeholder.jpg'):
    """
    Obtiene la URL del placeholder especificado.
    
    Args:
        request: HttpRequest object
        placeholder_name: Nombre del archivo placeholder
    
    Returns:
        str: URL absoluta del placeholder
    """
    placeholder_url = f"{settings.STATIC_URL}images/{placeholder_name}"
    return request.build_absolute_uri(placeholder_url)
