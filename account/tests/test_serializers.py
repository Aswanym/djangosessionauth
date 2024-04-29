from account.models import User
from account.account_api.serializers import UserSerializer
from rest_framework.test import APITestCase

class UserSerializerTestCase(APITestCase):

    def setUp(self):
        # Define the data dictionary in the setUp method
        self.data = {
            'email': 'test@example.com',
            'name': 'test user',
            'password': 'testpwd',
            'confirm_password': 'testpwd'
        }

        self.wrong_data = {
            'email': 'test@example.com',
            'name': 'test user',
            'password': 'testpwd',
            'confirm_password': 'testpwd1'
        }

    def test_user_serializer_validate_data(self):

        serializer = UserSerializer(data=self.data)
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.errors, {})

    def test_user_serializer_password_mismatch(self):

        serializer = UserSerializer(data=self.wrong_data)
        self.assertFalse(serializer.is_valid())
        self.assertEqual(serializer.errors['non_field_errors'][0],
                         "password and confirm password doesn't match")

    def test_user_serializer_email_validate(self):

        User.objects.create_user(email='test@example.com', name='hari', password='test')

        serializer = UserSerializer(data=self.data)
        self.assertFalse(serializer.is_valid())
        self.assertEqual(serializer.errors['email'][0], "user with this email address already exists.")

    def test_user_serializer_create(self):
        serializer = UserSerializer(data=self.data)
        self.assertTrue(serializer.is_valid())

        user = serializer.create(serializer.validated_data)
        self.assertEqual(user.email, self.data['email'])
        self.assertEqual(user.name, self.data['name'])
        self.assertFalse(user.is_active)

    def test_user_serializer_update(self):

        user = User.objects.create_user(email=self.data['email'], name=self.data['name'], password=self.data['password'])
        data = {'name': 'updated_name'}

        serializer = UserSerializer(user, data=data, partial=True)
        self.assertTrue(serializer.is_valid())

        updated_user = serializer.update(user, serializer.validated_data)
        self.assertEqual(updated_user.name, data['name'])


