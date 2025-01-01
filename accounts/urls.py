from django.urls import path
from .views import *

urlpatterns = [
    path("login/", LoginView.as_view(), name="login"),
    path('password-reset/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('reset/<uidb64>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('users/', UserListView.as_view(), name='user-list'),

]