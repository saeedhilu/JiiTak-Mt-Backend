from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser

class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ('email', 'username', 'dob', 'is_staff', 'is_active', 'role', 'created_at', 'updated_at')
    search_fields = ('email', 'username')
    readonly_fields = ('created_at', 'updated_at')

    fieldsets = (
        (None, {'fields': ('email', 'username', 'password')}), 
        ('Personal Info', {'fields': ('dob',)}),  # Added dob field under Personal Info
        ('Permissions', {'fields': ('is_staff', 'is_active', 'role')}), 
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'dob','password1', 'password2')}
        ),
    )

admin.site.register(CustomUser, CustomUserAdmin)
