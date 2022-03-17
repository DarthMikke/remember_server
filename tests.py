from django.test import TestCase, Client
from django.shortcuts import reverse

from django.contrib.auth.models import User
from .models import Checklist, Profile

import json


# Create your tests here.
class RegisterAPITestCase(TestCase):
    test_password = 'test_password'

    @classmethod
    def setUpTestData(cls):
        test_user = User.objects.create_user('test_user', 'test@ma.il', cls.test_password)
        test_profile = Profile.objects.create(authentication='password', user=test_user)
        cls.test_user = test_profile
        cls.user_list = Checklist.objects.create(owner=test_profile, name='test list')

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
        created_profile = Profile.objects.get(user=created_user)
        self.assertEqual(created_profile.user.username, test_data['username'])
        self.assertEqual(created_profile.user.email, test_data['email'])

    def test_register_user_with_fail(self):
        test_data = {
            'wrong key': 'test data'
        }
        response = self.client.post(reverse('api_register'), test_data)
        self.assertEqual(response.status_code, 401)

    def test_login_user(self):
        test_data = {'username': self.test_user.user.username, 'password': self.test_password}
        response = self.client.post(reverse('api_login'), test_data)
        self.assertEqual(response.status_code, 200)

    def test_login_user_with_fail(self):
        test_data = {'username': self.test_user.user.username, 'password': 'wrong_user'}
        response = self.client.post(reverse('api_login'), test_data)
        self.assertEqual(response.status_code, 401)


class ChecklistAPITestCase(TestCase):
    test_password = 'test_password'

    @classmethod
    def setUpTestData(cls):
        test_user = User.objects.create_user('test_user', 'test@ma.il', cls.test_password)
        test_profile = Profile.objects.create(authentication='password', user=test_user)
        cls.test_user = test_profile
        cls.user_list = Checklist.objects.create(owner=test_profile, name='test list')

        cls.users = [{
            'username': f'test_user{x}',
            'email': f'test_user{x}@example.com',
            'password': 'test_password'
        } for x in range(10)]

        cls.profiles = []
        for user in cls.users:
            instance = User.objects.create_user(user['username'], user['email'], user['password'])
            cls.profiles.append(Profile.from_user(instance))

    def setUp(self):
        self.client = Client()
        test_data = {'username': self.test_user.user.username, 'password': self.test_password}
        response = self.client.post(reverse('api_login'), test_data)
        body = json.loads(response.content)
        self.token = body['access_token']

    def test_add_checklist(self):
        ...

    def test_update_checklist(self):
        ...

    def test_delete_checklist(self):
        ...

    def test_share_checklist(self):
        path = reverse('checklist_share', args=[self.user_list.id])
        response = self.client.post(
            path,
            data={'profile': self.profiles[0].id},
            HTTP_TOKEN=self.token
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.user_list.is_accessible_by(self.profiles[0]), True)

    def test_unshare_checklist(self):
        path = reverse('checklist_share', args=[self.user_list.id])
        response = self.client.post(
            path,
            data={'profile': self.profiles[0].id},
            HTTP_TOKEN=self.token
        )
        path = reverse('checklist_unshare', args=[self.user_list.id])
        response = self.client.post(
            path,
            data={'profile': self.profiles[0].id},
            HTTP_TOKEN=self.token
        )
        self.assertEqual(response.status_code, 200)
        print(response.content)
        self.assertEqual(self.user_list.is_accessible_by(self.profiles[0]), False)


class TaskAPITestCase(TestCase):
    def test_add_task(self):
        ...

    def test_update_task(self):
        ...

    def test_delete_task(self):
        ...

    def test_log_task(self):
        ...

    def test_log_someone_elses_task(self):
        ...


class LogAPITestCase(TestCase):
    def test_log_task(self):
        ...

    def test_log_task_with_note(self):
        ...

    def test_remove_log(self):
        ...


class UserAPITestCase(TestCase):
    test_password = 'test_password'

    @classmethod
    def setUpTestData(cls):
        test_user = User.objects.create_user('test_user', 'test@ma.il', cls.test_password)
        test_profile = Profile.objects.create(authentication='password', user=test_user)
        cls.test_user = test_profile

        cls.users = [{
            'username': f'test_user{x}',
            'email': f'test_user{x}@example.com',
            'password': 'test_password'
        } for x in range(10)]
        cls.profiles = []

        for user in cls.users:
            instance = User.objects.create_user(user['username'], user['email'], user['password'])
            cls.profiles.append(Profile.from_user(instance))

    def setUp(self):
        self.client = Client()
        test_data = {'username': self.test_user.user.username, 'password': self.test_password}
        response = self.client.post(reverse('api_login'), test_data)
        body = json.loads(response.content)
        self.token = body['access_token']

    def test_user_search(self):
        path = reverse('user_search')
        response = self.client.get(
            path + f'?query={self.users[0]["email"]}',
            HTTP_TOKEN=self.token
        )
        self.assertEqual(response.status_code, 200)
        body = json.loads(response.content)
        self.assertEqual(body['total'], 1)
        self.assertEqual(body['profiles'][0]['id'], self.profiles[0].id)

        response = self.client.get(
            path + f'?query={self.users[0]["email"][:5]}',
            HTTP_TOKEN=self.token
        )
        self.assertEqual(response.status_code, 200)
        body = json.loads(response.content)
        self.assertTrue(self.profiles[0].id in [x['id'] for x in body['profiles']])

    def test_user_search_empty(self):
        path = reverse('user_search')
        response = self.client.get(
            path + '?query=',
            HTTP_TOKEN=self.token
        )
        self.assertEqual(response.status_code, 200)
        body = json.loads(response.content)
        self.assertEqual(body['total'], 0)

    def test_user_info(self):
        path = reverse('user_info', args=[self.profiles[1].id])
        response = self.client.get(
            path,
            HTTP_TOKEN=self.token
        )
        self.assertEqual(response.status_code, 200)
        body = json.loads(response.content)
        self.assertEqual(body['id'], self.profiles[1].id)


class ProfileTestCase(TestCase):
    test_password = 'test_password'

    @classmethod
    def setUpTestData(cls):
        test_user1 = User.objects.create_user('test_user', 'test@ma.il', cls.test_password)
        test_profile1 = Profile.objects.create(authentication='password', user=test_user1)
        cls.test_user1 = test_profile1
        test_user2 = User.objects.create_user('test_user_2', 'test@ma.il', cls.test_password)
        test_profile2 = Profile.objects.create(authentication='password', user=test_user2)
        cls.test_user2 = test_profile2

    def setUp(self):
        self.client = Client()

        self.test_checklist = Checklist.objects.create(owner=self.test_user1, name="Test")
        self.not_shared_checklist = Checklist.objects.create(owner=self.test_user1, name="Test 2")

    def test_list_aggregation(self):
        self.test_checklist.share_with(self.test_user2.id)
        self.assertIn(self.test_checklist, self.test_user2.checklists())

    def test_list_aggregation_with_error(self):
        self.assertNotIn(self.not_shared_checklist, self.test_user2.checklists())

    def test_list_sharing(self):
        self.test_checklist.share_with(self.test_user2.id)
        self.assertTrue(self.test_checklist.is_accessible_by(self.test_user1))
        self.assertTrue(self.test_checklist.is_accessible_by(self.test_user2))

    def test_list_sharing_with_error(self):
        self.test_checklist.share_with(self.test_user2.id)
        self.assertTrue(self.not_shared_checklist.is_accessible_by(self.test_user1))
        self.assertFalse(self.not_shared_checklist.is_accessible_by(self.test_user2))
