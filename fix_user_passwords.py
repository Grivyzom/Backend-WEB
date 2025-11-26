#!/usr/bin/env python
"""
Script para actualizar usuarios que tengan contraseñas hasheadas incorrectamente.
Esto soluciona el problema de usuarios creados con make_password() en lugar de set_password().
"""

import os
import sys
import django

# Configurar Django
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backendGrivyzom.settings')
django.setup()

from core.models import User

def fix_user_passwords():
    """
    Este script NO puede recuperar contraseñas (están hasheadas).
    Pero podemos resetear contraseñas para usuarios de prueba.
    """
    print("\n=== VERIFICANDO USUARIOS ===\n")
    
    users = User.objects.all()
    print(f"Total de usuarios en la base de datos: {users.count()}")
    
    for user in users:
        print(f"\nUsuario: {user.username}")
        print(f"  - Email: {user.email}")
        print(f"  - Minecraft: {user.minecraft_username}")
        print(f"  - Password hash: {user.password[:50]}...")
        print(f"  - Hash type: {user.password.split('$')[0] if '$' in user.password else 'INVALID'}")
        print(f"  - Is staff: {user.is_staff}")
        print(f"  - Is active: {user.is_active}")
        print(f"  - Role: {user.role}")
    
    print("\n" + "="*60)
    print("IMPORTANTE:")
    print("Si tus usuarios tienen contraseñas hasheadas incorrectamente,")
    print("necesitas resetear sus contraseñas.")
    print("\nOpciones:")
    print("1. Crear usuarios nuevos desde el frontend con el registro corregido")
    print("2. Usar el admin de Django para cambiar contraseñas")
    print("3. Resetear contraseñas manualmente con este script")
    print("="*60)
    
    response = input("\n¿Quieres resetear la contraseña de algún usuario? (s/n): ")
    
    if response.lower() == 's':
        username = input("Ingresa el username del usuario: ")
        try:
            user = User.objects.get(username=username)
            new_password = input("Ingresa la nueva contraseña: ")
            
            # Usar set_password para hashear correctamente
            user.set_password(new_password)
            user.save()
            
            print(f"\n✅ Contraseña actualizada exitosamente para {user.username}")
            print(f"Nueva hash: {user.password[:50]}...")
            
        except User.DoesNotExist:
            print(f"\n❌ Usuario '{username}' no encontrado.")
        except Exception as e:
            print(f"\n❌ Error: {e}")
    
    print("\n¡Script completado!")

if __name__ == '__main__':
    fix_user_passwords()
