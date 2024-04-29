from account.models import User
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from django.urls import reverse
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator


def _get_csrf_token(self):
    response = self.client.get(reverse('csrf_cookie'))
    # send a GET request to csrf_cookie endpoint
    return response.cookies['csrftoken'].value


class RegisterViewTestCase(APITestCase):

    def setUp(self):
        # Define the data dictionary in the setUp method
        self.data = {
            'email': 'test@example.com',
            'name': 'test user',
            'password': 'testpwd',
            'confirm_password': 'testpwd'
        }
        self.invalid_email_data = {
            'email': 'invalid email',
            'name': 'test user',
            'password': 'testpwd',
            'confirm_password': 'testpwd'
        }
        self.mismatch_password_data = {
            'email': 'test@example.com',
            'name': 'test user',
            'password': 'testpwd',
            'confirm_password': 'testpwd1'
        }
        self.csrf_token = _get_csrf_token(self)
        self.csrf_client = APIClient(enforce_csrf_checks=True)

    def test_get_csrf_token(self):
        response = self.client.get(reverse('csrf_cookie'))
        self.assertTrue(response.cookies['csrftoken'].value)
        self.assertEqual(response.data['success'], 'CSRF cookie set')

    def test_register_view_success(self):

        url = reverse('register')
        headers = {
            'X-CSRFToken': self.csrf_token,
            'Cookie': f'csrftoken={self.csrf_token}'
        }
        response = self.csrf_client.post(url, self.data, format='json', headers=headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['email'], self.data['email'])
        self.assertEqual(response.data['name'], self.data['name'])

    def test_register_view_invalid_email(self):

        """Passing an invalid email while registering a user and expecting a 404 bad request."""
        url = reverse('register')
        headers = {
            'X-CSRFToken': self.csrf_token,
            'Cookie': f'csrftoken={self.csrf_token}'
        }
        response = self.csrf_client.post(url, self.invalid_email_data, format='json', headers=headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_view_duplicate_email(self):

        """Registering a user with already existing email and expecting a 404 bad request."""
        User.objects.create_user(email=self.data['email'], name=self.data['name'],
                                 password=self.data['password'])

        url = reverse('register')
        headers = {
            'X-CSRFToken': self.csrf_token,
            'Cookie': f'csrftoken={self.csrf_token}'
        }
        response = self.csrf_client.post(url, self.data, format='json', headers=headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_view_password_mismatch(self):
        """considering the password and confirm password is not match, then expecting a 404 bad request."""
        url = reverse('register')
        headers = {
            'X-CSRFToken': self.csrf_token,
            'Cookie': f'csrftoken={self.csrf_token}'
        }
        response = self.csrf_client.post(url, self.mismatch_password_data, format='json', headers=headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['non_field_errors'][0], "password and confirm password doesn't match")


class ActivationConfirmationViewTestCase(APITestCase):
    def setUp(self):
        self.data = {
            'email': 'test@example.com',
            'name': 'test user',
            'password': 'testpwd',
            'confirm_password': 'testpwd'
        }

        self.csrf_token = _get_csrf_token(self)
        self.csrf_client = APIClient(enforce_csrf_checks=True)

        self.headers = {
            'X-CSRFToken': self.csrf_token,
            'Cookie': f'csrftoken={self.csrf_token}'
        }

    def test_activation_confirmation_success(self):

        """Activation confirmation testing. Once uid and token of user get validated, expecting a 200 ok response
         with appropriate msg."""
        user = User.objects.create(email=self.data['email'], is_active=False)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        data = {
            'uid': uid,
            'token': token
        }

        url = reverse('activation_confirm')
        response = self.csrf_client.post(url, data, format='json', headers=self.headers)
        self.assertEqual(response.data['details'], 'Account activated')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_activation_confirmation_already_active(self):

        """for an already active user, expecting a 200 ok response with appropriate msg."""
        user = User.objects.create(email=self.data['email'], is_active=True)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        data = {
            'uid': uid,
            'token': token
        }

        url = reverse('activation_confirm')
        response = self.csrf_client.post(url, data, format='json', headers=self.headers)
        self.assertEqual(response.data['details'], 'Account is already activated.')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_activation_confirmation_missing_uid_token(self):

        """If uid or token is missing for the confirmation, expecting a 400 bad request with
        appropriate msg."""
        User.objects.create(email=self.data['email'], is_active=False)

        data = {}  # uid and token is missing

        url = reverse('activation_confirm')
        response = self.csrf_client.post(url, data, format='json', headers=self.headers)
        self.assertEqual(response.data['details'], 'Missing uid or token')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_activation_confirmation_incorrect_uid_token(self):
        """If uid or token sent is incorrect, expecting a 400 bad request with
        appropriate msg."""
        User.objects.create(email=self.data['email'], is_active=False)

        data = {
            'uid': 'MY',
            'token': 'jdklsjkjlfjsufskjfjsojfh'
        }  # Given wrong uid and token

        url = reverse('activation_confirm')
        response = self.csrf_client.post(url, data, format='json', headers=self.headers)
        self.assertEqual(response.data['details'], 'Invalid activation link')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

class LoginViewTestCase(APITestCase):

    def setUp(self):

        #  Created a user in the setup
        self.user = User.objects.create_user(email='test@example.com', name='test user', password='testpwd')
        self.user.is_active = True
        self.user.save()

        #  setup dict with correct credentials
        self.correct_credentials = {
            'email': 'test@example.com',
            'password': 'testpwd'
        }

        #  setup dict with incorrect credentials
        self.incorrect_credentials = {
            'email': 'test@example.com',
            'password': 'testpwd1'
        }

        self.csrf_token = _get_csrf_token(self)
        self.csrf_client = APIClient(enforce_csrf_checks=True)

        self.headers = {
            'X-CSRFToken': self.csrf_token,
            'Cookie': f'csrftoken={self.csrf_token}'
        }

    def test_login_success(self):

        """User passing correct credentials while login, expecting a 200 ok with appropriate msg."""
        url = reverse('login')
        response = self.csrf_client.post(url, self.correct_credentials, format='json', headers=self.headers)
        self.assertEqual(response.data['detail'], 'Logged in successfully')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_login_invalid_credentials(self):

        """User passing incorrect credentials(email or password can be wrong) while login, expecting a 400 bad request,
         with appropriate msg."""
        url = reverse('login')
        response = self.csrf_client.post(url, self.incorrect_credentials, format='json', headers=self.headers)
        self.assertEqual(response.data['detail'], 'Email or password is incorrect')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class UserDetailViewTestCase(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(email='test@example.com', name='test user', password='testpwd')
        self.client.force_authenticate(user=self.user)

    def test_get_user_detail(self):
        url = reverse('user_details')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['data']['email'], 'test@example.com')
        self.assertEqual(response.data['data']['name'], 'test user')
        self.assertEqual(response.data['data']['is_staff'], False) # assuming is_staff is false for regular user

    def test_update_user_detail(self):
        url = reverse('user_details')
        data = {
            'name': 'new test user'
        }
        response = self.client.patch(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], data['name'])

class ChangePasswordViewTestCase(APITestCase):

    def setUp(self):
        # setup a user and force authenticate user, because this action can be done only by an authenticated user.
        self.user = User.objects.create_user(email='test@example.com', name='test user', password='testpwd')
        self.client.force_authenticate(user=self.user)

    def test_change_password_success(self):
        """User changing a password, given correct old password and a new password,
        expecting a 200 ok and appropriate msg."""
        data = {
            'old_password': 'testpwd',
            'new_password': 'newtestpwd'
        }

        url = reverse('change_password')
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['detail'], 'Password changed successfully')

    def test_change_password_invalid_old_password(self):
        """User changing a password, given incorrect old password and a new password,
         expecting a 400 bad request and appropriate msg."""

        data = {
            'old_password': 'testpwd111',
            'new_password': 'newtestpwd'
        }

        url = reverse('change_password')
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['detail'], 'Invalid old password')

class DeleteAccountTestCase(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='test@example.com', name='test user', password='testpwd')
        self.client.force_authenticate(user=self.user)

    def test_delete_account(self):

        """delete a user account, expecting a 204 no content and appropriate msg."""
        url = reverse('delete_account')
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(response.data['detail'], 'Account deleted successfully')

class LogoutTestCase(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='test@example.com', name='test user', password='testpwd')
        self.client.force_authenticate(user=self.user)

    def test_delete_account(self):

        """logging out a user, expecting a 200 ok and appropriate msg."""
        url = reverse('logout')
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['detail'], 'Logged out successfully')

class RestPasswordEmailViewTestCase(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(email='test@example.com', name='test user', password='testpwd')

    def test_rest_password_success(self):
        data = {
            'email': self.user.email
        }

        url = reverse('rest_password_email')
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['detail'], 'Password rest email sent successfully')

    def test_rest_password_user_not_exists(self):
        data = {
            'email': "test1@example.com"
        }

        url = reverse('rest_password_email')
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['detail'], 'User with this email does not exists')

class ResetPasswordConfirmViewTestCase(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(email='test@example.com', name='test user', password='testpwd')
        self.uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        self.token = default_token_generator.make_token(self.user)

    def test_password_rest_success(self):
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        token = default_token_generator.make_token(self.user)
        new_password = 'new_testpwd'

        url = reverse('rest_password_confirm')
        data = {
            'uid': uid,
            'token': token,
            'new_password': new_password
        }

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['details'], 'Password reset successful')

    def test_password_rest_no_new_password(self):

        url = reverse('rest_password_confirm')
        data = {
            'uid': self.uid,
            'token': self.token,
        }

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['details'], 'New password is required')

    def test_password_rest_invalid_token(self):

        url = reverse('rest_password_confirm')
        new_password = 'new_testpwd'
        data = {
            'uid': self.uid,
            'token': f'{self.token}wee',
            'new_password': new_password
        }

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['details'], 'Invalid reset password link')

    def test_password_rest_invalid_uid(self):

        url = reverse('rest_password_confirm')
        new_password = 'new_testpwd'

        data = {
            'uid': 'MY',
            'token': self.token,
            'new_password': new_password
        }

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['details'], 'Invalid reset password link')

    def test_password_rest_missing_uid_token(self):

        url = reverse('rest_password_confirm')
        new_password = 'new_testpwd'
        data = {
            'new_password': new_password
        }

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['details'], 'Missing uid or token')

