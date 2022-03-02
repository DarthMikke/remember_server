from django.test import TestCase, Client
from django.shortcuts import reverse

from django.contrib.auth.models import User
from .models import Checklist


# Create your tests here.
class UserAPITestCase(TestCase):
    test_password = 'test_password'

    @classmethod
    def setUpTestData(cls):
        test_user = User.objects.create_user('test_user', 'test@ma.il', cls.test_password)
        cls.test_user = test_user
        cls.user_list = Checklist.objects.create(owner=test_user, name='test list')

    def setUp(self):
        self.client = Client()

    def test_register_user(self):
        test_data = {
            'username': 'new test user',
            'email': 'test@ma.il',
            'password': 'test_password_2',
        }
        response = self.client.post(reverse('api_register'), data=test_data)
        self.assertEqual(response.status_code, 200)

        created_user = User.objects.get(username=test_data['username'])
        self.assertEqual(created_user.username, test_data['username'])
        self.assertEqual(created_user.email, test_data['email'])

    def test_register_user_with_fail(self):
        test_data = {
            'wrong key': 'test data'
        }
        response = self.client.post(reverse('api_register'), test_data)
        self.assertEqual(response.status_code, 401)

    def test_login_user(self):
        test_data = {'username': self.test_user.username, 'password': self.test_password}
        response = self.client.post(reverse('api_login'), test_data)
        self.assertEqual(response.status_code, 200)

    def test_login_user_with_fail(self):
        test_data = {'username': self.test_user.username, 'password': 'wrong_user'}
        response = self.client.post(reverse('api_login'), test_data)
        self.assertEqual(response.status_code, 401)
