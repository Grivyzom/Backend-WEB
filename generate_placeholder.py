# Script para generar placeholder.jpg
# Ejecutar: python generate_placeholder.py

from PIL import Image, ImageDraw, ImageFont
import os

def create_placeholder():
    # Dimensiones Full HD
    width, height = 1920, 1080
    
    # Crear imagen con gradiente
    img = Image.new('RGB', (width, height))
    draw = ImageDraw.Draw(img)
    
    # Crear gradiente de morado
    for y in range(height):
        # Interpolar entre dos colores
        r = int(102 + (118 - 102) * y / height)
        g = int(126 + (75 - 126) * y / height)
        b = int(234 + (162 - 234) * y / height)
        draw.rectangle([(0, y), (width, y + 1)], fill=(r, g, b))
    
    # Agregar círculos decorativos con transparencia
    overlay = Image.new('RGBA', (width, height), (0, 0, 0, 0))
    overlay_draw = ImageDraw.Draw(overlay)
    
    # Círculos decorativos
    overlay_draw.ellipse([(150, 150), (450, 450)], fill=(255, 255, 255, 25))
    overlay_draw.ellipse([(1420, 580), (1820, 980)], fill=(255, 255, 255, 25))
    overlay_draw.ellipse([(860, 440), (1060, 640)], fill=(255, 255, 255, 13))
    
    img = Image.alpha_composite(img.convert('RGBA'), overlay).convert('RGB')
    draw = ImageDraw.Draw(img)
    
    # Intentar cargar una fuente, si no usar la por defecto
    try:
        font_large = ImageFont.truetype("arial.ttf", 100)
        font_medium = ImageFont.truetype("arial.ttf", 50)
        font_small = ImageFont.truetype("arial.ttf", 35)
    except:
        font_large = ImageFont.load_default()
        font_medium = ImageFont.load_default()
        font_small = ImageFont.load_default()
    
    # Texto principal
    text1 = "GRIVYZOM"
    bbox1 = draw.textbbox((0, 0), text1, font=font_large)
    text_width1 = bbox1[2] - bbox1[0]
    draw.text(((width - text_width1) / 2, 400), text1, fill='white', font=font_large)
    
    # Subtexto
    text2 = "Imagen no disponible"
    bbox2 = draw.textbbox((0, 0), text2, font=font_medium)
    text_width2 = bbox2[2] - bbox2[0]
    draw.text(((width - text_width2) / 2, 530), text2, fill=(255, 255, 255, 200), font=font_medium)
    
    # Rectángulo de imagen
    draw.rounded_rectangle([(860, 620), (1060, 770)], radius=10, 
                          fill=(255, 255, 255, 50), outline='white', width=3)
    
    # Círculo (sol/luna en la imagen)
    draw.ellipse([(880, 650), (920, 690)], fill='white')
    
    # Montañas simuladas
    draw.polygon([(860, 770), (900, 710), (940, 770)], fill='white')
    draw.polygon([(920, 770), (960, 700), (1000, 770)], fill=(255, 255, 255, 180))
    draw.polygon([(980, 770), (1020, 720), (1060, 770)], fill='white')
    
    # Texto inferior
    text3 = "Por favor, sube una imagen desde el panel de administración"
    bbox3 = draw.textbbox((0, 0), text3, font=font_small)
    text_width3 = bbox3[2] - bbox3[0]
    draw.text(((width - text_width3) / 2, 850), text3, fill=(255, 255, 255, 150), font=font_small)
    
    # Guardar
    output_path = os.path.join(os.path.dirname(__file__), 'static', 'images', 'placeholder.jpg')
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    img.save(output_path, 'JPEG', quality=85, optimize=True)
    print(f"✅ Placeholder creado: {output_path}")

if __name__ == "__main__":
    try:
        create_placeholder()
    except Exception as e:
        print(f"❌ Error: {e}")
        print("\n⚠️  Requiere PIL/Pillow: pip install Pillow")
