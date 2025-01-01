from rest_framework import permissions

class IsAdminAndAuthenticated(permissions.BasePermission):
    """
    Custom permission to grant access only to users with the 'admin' role and who are authenticated.
    """

    def has_permission(self, request,view):
        return request.user.is_authenticated and request.user.role == 'admin'