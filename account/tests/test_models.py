from django.test import TestCase
from ..models import User

class UserModelTest(TestCase):
    def test_create_user(self):

        email = 'test@example.com'
        name = 'test user'
        password = 'testpwd'

        user = User.objects.create_user(email=email,
                                        name=name,
                                        password=password)

        # assertEqual(first, second, msg=None)
        # Test that first and second are equal. If the values do not compare equal, the test will fail.
        self.assertEqual(user.email, email)
        self.assertEqual(user.name, name)

        # assertTrue(expr, msg=None)
        # Test that expr is true.
        self.assertTrue(user.check_password(password))

        # assertFalse(expr, msg=None)
        # Test that expr is false.
        self.assertFalse(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_admin)

    def test_create_super_user(self):

        email = 'test@example.com'
        name = 'test super user'
        password = 'testsuperpwd'

        user = User.objects.create_superuser(email=email, name=name, password=password)

        self.assertEqual(user.email, email)
        self.assertEqual(user.name, name)
        self.assertTrue(user.check_password(password))
        self.assertFalse(user.is_active)
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_admin)

class UserMethodTest(TestCase):

    def test_get_full_name(self):
        """Test getting the user's full name"""
        user = User(email='test@example.com', name='test user')
        self.assertEqual(user.get_full_name(), 'test user')

    def test_has_perm(self):
        """checking if the user has a specific permission"""
        user = User(email='test@example.com', name='test user')
        self.assertTrue(user.has_perm('some_permission'))

    def test_has_module_perms(self):
        """checking if the user has a module permission"""
        user = User(email='test@example.com', name='test user')
        self.assertTrue(user.has_module_perms('some_app'))

    def test_is_staff(self):
        user = User(email='test@example.com', name='test user')
        self.assertFalse(user.is_staff)



