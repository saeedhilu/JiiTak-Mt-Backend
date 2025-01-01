


from rest_framework import serializers
from .models import CustomUser
from django.contrib.auth.password_validation import validate_password





class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = CustomUser
        fields = ("email", "password")

    def validate(self, attrs):
        user = CustomUser.objects.filter(email=attrs["email"]).first()
        print(user.password)
        if not user:
            raise serializers.ValidationError({"email": "Invalid Email."})
        if not user.check_password(attrs["password"]):
            raise serializers.ValidationError({"password": "Invalid credentials."})
        return attrs
class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("No user registered with this email address.")
        return value
    
class PasswordResetConfirmSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True, required=True)




class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = "__all__"