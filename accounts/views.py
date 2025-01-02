from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import *
from .models import CustomUser
from rest_framework.throttling import UserRateThrottle
from rest_framework.exceptions import NotFound
from rest_framework import status
from rest_framework.generics import GenericAPIView, ListAPIView
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.cache import cache
from django.utils.encoding import force_str, force_bytes
from django.core.mail import EmailMessage
from django.conf import settings
from django.template.loader import render_to_string
from .pagination import UserPagination
from rest_framework.filters import SearchFilter
from accounts.models import CustomUser
from django.db.models import Q


class LoginView(APIView):
    """
    Logs in an existing user.
    """

    throttle_classes = [UserRateThrottle]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = CustomUser.objects.get(email=serializer.validated_data["email"])
            tokens = user.tokens
            return Response(
                {
                    "message": "Login successful.",
                    "access": tokens["access"],
                    "refresh": tokens["refresh"],
                    "user": {
                        "email": user.email,
                        "username": user.username,
                        "user_id": user.id,
                        "dob": user.dob,
                        "role":user.role
                    },
                },
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetRequestView(GenericAPIView):
    """
    Sends a password reset email to the provided email.
    """

    serializer_class = PasswordResetRequestSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data["email"]
            print("email is :", email)
            print(settings.REDIS_URL)
            try:
                user = CustomUser.objects.get(email=email)
                token = default_token_generator.make_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                print('uid storinng',uid)
                cache_key = f"password_reset_token_{uid}"

                token_in_cache = cache.get(cache_key)

                if token_in_cache:
                    return Response(
                        {
                            "error": f"A password reset link has already been sent. Please check your email."
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                cache.set(cache_key, token, timeout=86400)

                domain = settings.FRONTEND_URL
                reset_link = f"http://{domain}/reset-password/{uid}/"
                print(reset_link)

                context = {
                    "username": email.split("@")[0],
                    "reset_link": reset_link,
                }

                html_message = render_to_string("password_reset.html", context)

                email_subject = "Password Reset Request"

                email = EmailMessage(
                    subject=email_subject,
                    body=html_message,
                    from_email=settings.EMAIL_HOST_USER,
                    to=[email],
                )
                email.content_subtype = "html"
                email.send()
                print("successfully")
                return Response(
                    {"message": f"A password reset link has been sent succussfully."},
                    status=status.HTTP_200_OK,
                )

            except Exception as e:
                print(f"Error in password reset: {str(e)}")
                return Response(
                    {"error": "An unexpected error occurred."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
        else:
            print("not")
            error_messages = serializer.errors.get("email", "An error occurred")
            return Response(
                {"error": error_messages}, status=status.HTTP_400_BAD_REQUEST
            )


class PasswordResetConfirmView(GenericAPIView):
    """
    Verifies user's email and resets their password.
    """

    serializer_class = PasswordResetConfirmSerializer

    def post(self, request, uidb64, *args, **kwargs):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = CustomUser.objects.get(pk=uid)

            token = cache.get(f"password_reset_token_{uidb64}")

            if not token:
                return Response(
                    {
                        "error": "This token has expired. Please <a href='/login' style='color: blue; text-decoration: underline;''>go to login</a>."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if not default_token_generator.check_token(user, token):
                return Response(
                    {"error": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST
                )

            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user.set_password(serializer.validated_data["password"])

            user.save()
            cache.delete(f"password_reset_token_{uidb64}")
            return Response(
                {"message": "Password reset successful."}, status=status.HTTP_200_OK
            )

        except Exception as e:
            print(f"Error in password reset: {str(e)}")
            return Response(
                {"error": "An unexpected error occurred."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class UserListView(ListAPIView):
    """
    Returns a list of users.
    """

    serializer_class = UserSerializer
    pagination_class = UserPagination
    filter_backends = [SearchFilter]
    search_fields = ["username", "email"]

    def get_queryset(self):
        search_query = self.request.GET.get("search", "")
        page = self.request.GET.get("page", 1)
        cache_key = f"user_list_{search_query}_{page}"

        cached_queryset = cache.get(cache_key)
        if cached_queryset:
            print('cache aan ')
            return cached_queryset

        queryset = CustomUser.objects.filter(
            Q(username__icontains=search_query) | Q(email__icontains=search_query)
        ).order_by("id")

        cache.set(cache_key, queryset, timeout=60 * 5)

        return queryset

    def list(self, request, *args, **kwargs):
        search_query = self.request.GET.get("search", "")
        page = self.request.GET.get("page", 1)
        cache_key = f"user_list_{search_query}_{page}"

        cached_response = cache.get(cache_key)
        if cached_response:
            print('cached 23')
            return Response(cached_response)

        response = super().list(request, *args, **kwargs)

        cache.set(cache_key, response.data, timeout=60 * 5)

        return response
