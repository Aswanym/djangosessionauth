from django.contrib.auth import authenticate, login, logout
from account.models import User
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from account.account_api.serializers import UserSerializer
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_protect
from django.utils.decorators import method_decorator
from django.conf import settings
from ..utils import send_account_activation_email, send_reset_password_email

@method_decorator(ensure_csrf_cookie, name='dispatch')
class GetCSRFToken(APIView):
    permission_classes = [AllowAny]

    # This decorator serves the purpose of ensuring that a CSRF (Cross-Site Request Forgery)
    # token cookie is set in the response for this specific HTTP method.
    def get(self, request):
        return Response({'success': 'CSRF cookie set'})

@method_decorator(ensure_csrf_cookie, name='dispatch')
class CheckAuthenticatedView(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        if request.user.is_authenticated:
            return Response({'is_authenticated': True})
        else:
            return Response({'is_authenticated': False})

@method_decorator(csrf_protect, name='dispatch')
class RegistrationView(APIView):

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.create(serializer.validated_data)

            # send account activation email

            # create uid for the user using the created userid
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            # create a token using the created user
            token = default_token_generator.make_token(user)

            activation_link = reverse('activate', kwargs={'uid': uid, 'token': token})
            activation_url = f"{settings.SITE_DOMAIN}{activation_link}"

            send_account_activation_email(user.email, activation_url)

            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@method_decorator(csrf_protect, name='dispatch')
class ActivateView(APIView):
    permission_classes = [AllowAny]

@method_decorator(csrf_protect, name='dispatch')
class ActivationConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):

        # Get uid and token from the request body
        uid = request.data.get('uid')
        token = request.data.get('token')

        # If uid or token is not in the request return error msg.
        if not uid or not token:
            return Response({'details': 'Missing uid or token'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            # uid id created from user's pk. so decode the pk from given uid
            uid = force_str(urlsafe_base64_decode(uid))

            # By using the decoded pk get the corresponding user instance
            user_instance = User.objects.get(pk=uid)

            # Token is created using the user instance. so here check the token again using the
            # user_instance and token
            if default_token_generator.check_token(user_instance, token):

                # if the token check is success, check if the user already active and give corresponding msg.
                if user_instance.is_active:
                    return Response({'details': 'Account is already activated.'}, status=status.HTTP_200_OK)

                # If the user is not active make it active.
                user_instance.is_active = True
                user_instance.save(update_fields=['is_active'])
                return Response({'details': 'Account activated'}, status=status.HTTP_200_OK)
            else:
                return Response({'details': 'Invalid activation link'}, status=status.HTTP_400_BAD_REQUEST)

        except User.DoesNotExist:
            return Response({'details': 'Invalid activation link'}, status=status.HTTP_400_BAD_REQUEST)

@method_decorator(csrf_protect, name='dispatch')
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        # Use authenticate() to verify a set of credentials. It takes credentials as keyword arguments,
        # email and password for this case, checks them against each authentication backend, and returns a User object
        # if the credentials are valid for a backend.
        user = authenticate(request, email=email,
                            password=password)

        if user is not None:
            if user.is_active:
                # To log a user in, use login(). It takes an HttpRequest object and a User object. login()
                # saves the user’s ID in the session, using Django’s session framework.
                login(request, user)
                return Response({'detail': 'Logged in successfully'},
                                status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'Email or password is incorrect'},
                            status=status.HTTP_400_BAD_REQUEST)

class UserDetailView(APIView):

    def get(self, request):
        serializer = UserSerializer(request.user)
        data = serializer.data
        data['is_staff'] = request.user.is_staff
        return Response({'detail': 'success', 'data': data}, status=status.HTTP_200_OK)

    def patch(self, request):
        serializer = UserSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ChangePasswordView(APIView):
    def post(self, request):

        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        user = request.user

        # check_password(), Returns True if the given raw string is the correct password for the user.
        if not user.check_password(old_password):
            return Response({'detail': 'Invalid old password'},
                            status=status.HTTP_400_BAD_REQUEST)

        # Sets the user’s password to the given raw string, taking care of the password hashing.
        user.set_password(new_password)
        user.save()
        return Response({'detail': 'Password changed successfully'},
                        status=status.HTTP_200_OK)

class DeleteAccount(APIView):
    def delete(self, request):
        user = request.user
        user.delete()
        logout(request)
        return Response({'detail': 'Account deleted successfully'},
                        status=status.HTTP_204_NO_CONTENT)

class Logout(APIView):

    def post(self, request):
        logout(request)
        return Response({'detail': 'Logged out successfully'},
                        status=status.HTTP_200_OK)

class RestPasswordEmailView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):

        email = request.data.get('email')

        if not User.objects.filter(email=email).exists():
            return Response({'detail': 'User with this email does not exists'},
                            status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.get(email=email)

        # Generate password reset token
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        reset_link = reverse('reset_password',
                             kwargs={'uid': uid, 'token': token})
        reset_url = f'{settings.SITE_DOMAIN}{reset_link}'

        send_reset_password_email(user.email, reset_url)

        return Response({'detail': 'Password rest email sent successfully'},
                        status=status.HTTP_200_OK)


@method_decorator(csrf_protect, name='dispatch')
class RestPasswordView(APIView):
    permission_classes = [AllowAny]


@method_decorator(csrf_protect, name='dispatch')
class ResetPasswordConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):

        # Get uid and token from the request body
        uid = request.data.get('uid')
        token = request.data.get('token')

        # If uid or token is not in the request return error msg.
        if not uid or not token:
            return Response({'details': 'Missing uid or token'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            # uid id created from user's pk. so decode the pk from given uid
            uid = force_str(urlsafe_base64_decode(uid))

            # By using the decoded pk get the corresponding user instance
            user = User.objects.get(pk=uid)

            # Token is created using the user instance. so here check the token again using the
            # user_instance and token
            if default_token_generator.check_token(user, token):

                new_password = request.data.get('new_password')
                if not new_password:
                    return Response({'details': 'New password is required'},
                                    status=status.HTTP_400_BAD_REQUEST)

                # rest user password
                user.set_password(new_password)
                user.save()
                return Response({'details': 'Password reset successful'},
                                status=status.HTTP_200_OK)
            else:
                return Response({'details': 'Invalid reset password link'},
                                status=status.HTTP_400_BAD_REQUEST)

        except User.DoesNotExist:
            return Response({'details': 'Invalid reset password link'},
                            status=status.HTTP_400_BAD_REQUEST)
