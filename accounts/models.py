from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from rest_framework_simplejwt.tokens import RefreshToken
from accounts.manager import CustomUserManager
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.core.validators import (
    EmailValidator,
    MinLengthValidator,
    MaxLengthValidator,
)
from django.contrib.auth.password_validation import validate_password
from django.utils.timezone import now

class CustomUser(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = (
        ("admin", "Admin"),
        ("user", "User"),
    )
    
    email = models.EmailField(
        unique=True,
        validators=[EmailValidator(message="Enter a valid email address")],
        max_length=255,
        help_text="Required. A valid email address.",
    )
    username = models.CharField(
        max_length=150,
        unique=True,
        validators=[
            MinLengthValidator(5, message="Username must be at least 5 characters long")
        ],
        help_text="Required. At least 5 characters long.",
    )
    password = models.CharField(
        max_length=128,
        validators=[validate_password],
        help_text="Password must be at least 8 characters long, contain an uppercase letter, a number, and a special character.",
    )
    dob = models.DateField(default='2000-11-01')

    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default="member")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = CustomUserManager()
    

    USERNAME_FIELD = "email"

    @property
    def tokens(self) -> dict[str, str]:
        refresh = RefreshToken.for_user(self)
        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }
