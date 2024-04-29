from rest_framework import serializers
from account.models import User

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['email', 'name', 'password', 'confirm_password']

    def validate(self, attrs):

        # Get the password and confirm password
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')

        # check if both the passwords matches, else raise an exception.
        if password != confirm_password:
            raise serializers.ValidationError("password and confirm password doesn't match")
        return attrs

    def validate_email(self, value):

        # email should be unique, so check if the given email is not already exists in the
        # db. If email already exists raise an exception before saving.
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("user with this email address already exists.")
        return value

    def create(self, validated_data):

        # Once the validations are passed, create the user with given email, name and password
        user = User.objects.create_user(
            email=self.validated_data["email"],
            name=self.validated_data["name"],
            password=self.validated_data["password"]
        )
        user.is_active = False
        user.save(update_fields=['is_active'])
        return user

    def update(self, instance, validated_data):
        instance.name = validated_data.get('name', instance.name)
        instance.save()
        return instance

