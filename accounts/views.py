from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import *
from .models import CustomUser
from rest_framework.throttling import UserRateThrottle
from rest_framework.exceptions import NotFound
from rest_framework import status
from rest_framework.generics import GenericAPIView
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.cache import cache
from django.utils.encoding import force_str , force_bytes
from django.core.mail import EmailMessage
from django.conf import settings
from django.template.loader import render_to_string

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
                        "dob" : user.dob
                    },
                },
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class PasswordResetRequestView(GenericAPIView):
    serializer_class = PasswordResetRequestSerializer


    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data['email']
            print('email is :', email )
            try:
                user = CustomUser.objects.get(email=email)
                token = default_token_generator.make_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.pk))

                cache_key = f"password_reset_token_{uid}"

                token_in_cache = cache.get(cache_key)
                
                if token_in_cache:
                    return Response({
                        "error": f"A password reset link has already been sent. Please check your email."
                    }, status=status.HTTP_400_BAD_REQUEST)

                cache.set(cache_key, token, timeout=86400)

                domain = settings.FRONTEND_URL
                reset_link = f"http://{domain}/reset-password/{uid}/"
                print(reset_link)

                context = {
                        'username': email.split('@')[0],
                        'reset_link': reset_link,
                    }

                html_message = render_to_string('password_reset.html', context)

                email_subject = 'Password Reset Request'
                
                email = EmailMessage(
                    subject=email_subject,
                    body=html_message,
                    from_email=settings.EMAIL_HOST_USER,
                    to=[email],
                )
                email.content_subtype = "html"  
                email.send()
                print('successfully')
                return Response({"message": f"A password reset link has been sent succussfully."}, status=status.HTTP_200_OK)
            
            except Exception as e:
                print(f"Error in password reset: {str(e)}")
                return Response({"error": "An unexpected error occurred."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            print('not')
            error_messages = serializer.errors.get('email', 'An error occurred')
            return Response({"error": error_messages}, status=status.HTTP_400_BAD_REQUEST)






class PasswordResetConfirmView(GenericAPIView):
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request, uidb64, *args, **kwargs):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = CustomUser.objects.get(pk=uid)

            token = cache.get(f"password_reset_token_{uidb64}")
            

            if not token:
                return Response({"error": "This token has expired. Please <a href='/login' style='color: blue; text-decoration: underline;''>go to login</a>."}, status=status.HTTP_400_BAD_REQUEST)
            
            if not default_token_generator.check_token(user, token):
                return Response({"error": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)

            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user.set_password(serializer.validated_data['password'])

            

            user.save()

            return Response({"message": "Password reset successful."}, status=status.HTTP_200_OK)   
            
        # except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
        #     print('error is :', err)
        #     return Response({"error": "Invalid link or user."}, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            print(f"Error in password reset: {str(e)}")
            return Response({"error": "An unexpected error occurred."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
