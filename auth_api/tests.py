import uuid
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User as AbstractUser
from django.utils import timezone
from django.conf import settings
import time
from .models import User, Organisation
from rest_framework.test import APIClient
from rest_framework import status
from django.urls import reverse


class AuthTests(APITestCase):
    def setUp(self):
        self.register_url = reverse('register')
        self.login_url = reverse('login')
        self.user_data = {
            'firstName': 'John',
            'lastName': 'Doe',
            'email': 'john.doe12@example.com',
            'password': 'password123',
            'phone': '212345679078'

        }

    def test_register_user_successfully(self):
        response = self.client.post(self.register_url, self.user_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['status'], 'success')
        self.assertIn('accessToken', response.data['data'])
        self.assertEqual(response.data['data']['user']['firstName'], 'John')
        self.assertEqual(response.data['data']['user']['lastName'], 'Doe')

        org_name = f"{self.user_data['firstName']}'s Organisation"
        self.assertTrue(Organisation.objects.filter(name=org_name).exists())

    def test_login_user_successful(self):
        self.client.post(self.register_url, self.user_data, format='json')
        login_data = {
            'email': self.user_data['email'],
            'password': self.user_data['password'],
        }
        response = self.client.post(self.login_url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'success')
        self.assertIn('accessToken', response.data['data'])
        self.assertEqual(response.data['data']['user']['email'], self.user_data['email'])

    def test_register_user_missing_fields(self):
        for field in ['firstName', 'lastName', 'email', 'password']:
            data = self.user_data.copy()
            data.pop(field)
            response = self.client.post(self.register_url, data, format='json')
            self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
            self.assertIn('errors', response.data)

    def test_register_user_duplicate_email(self):
        self.client.post(self.register_url, self.user_data, format='json')
        response = self.client.post(self.register_url, self.user_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('errors', response.data)


class OrganisationAccessTest(APITestCase):
    def setUp(self):
        self.client = APIClient()

        self.user1 = AbstractUser.objects.create_user(username='user1', email='user1@example.com', password='password')
        self.user2 = AbstractUser.objects.create_user(username='user2', email='user2@example.com', password='password')

        self.user1_profile = User.objects.create(
            firstName='User',
            lastName='One',
            email='user1@example.com',
            password='password',
            owner=self.user1
        )

        self.user2_profile = User.objects.create(
            firstName='User',
            lastName='Two',
            email='user2@example.com',
            password='password',
            owner=self.user2
        )

        self.org1 = Organisation.objects.create(name='Org1', description='Org1 Description')
        self.org1.users.add(self.user1_profile)

        self.org2 = Organisation.objects.create(name='Org2', description='Org2 Description')
        self.org2.users.add(self.user2_profile)

        # Log in user1 and get token
        self.client.login(username='user1@example.com', password='password')
        self.token = str(RefreshToken.for_user(self.user1).access_token)
        print(f'Token for user1: {self.token}')

    def test_organisation_data_access(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.token}')
        response = self.client.get(reverse('organisation-detail', args=[self.org2.orgId]))
        print(f'Status code: {response.status_code}')
        print(f'Response data: {response.data}')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data['message'], 'You do not have access to this organisation')


class TokenGenerationTest(APITestCase):
    def setUp(self):
        self.client = APIClient()

        # Create user and user profile
        self.abstract_user = AbstractUser.objects.create_user(username='testuser@example.com',
                                                              email='testuser@example.com', password='password')
        self.user_profile = User.objects.create(
            user_Id=uuid.uuid4(),  # Generate a UUID for the User model
            firstName='Test',
            lastName='User',
            email='testuser@example.com',
            password='password',
            owner=self.abstract_user  # Link to the AbstractUser
        )

    def test_token_generation(self):
        # Generate token for the AbstractUser
        token = RefreshToken.for_user(self.abstract_user)
        payload = token.payload
        print(f'Token payload: {payload}')
        print(f'AbstractUser ID: {self.abstract_user.id}')
        print(f'User profile ID: {self.user_profile.user_Id}')
        self.assertEqual(payload['user_id'], self.abstract_user.id)

    def test_token_expiration(self):
        # Generate token
        token = RefreshToken.for_user(self.abstract_user)
        access_token = token.access_token

        # Ensure token is valid immediately
        response = self.client.get(reverse('all-organisation'), HTTP_AUTHORIZATION=f'Bearer {access_token}')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Wait for the token to expire
        expiration_time = settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds()
        time.sleep(expiration_time + 1)  # Wait a bit longer than the token lifetime

        # Ensure token is expired
        response = self.client.get(reverse('all-organisation'), HTTP_AUTHORIZATION=f'Bearer {access_token}')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('detail', response.data)
        self.assertEqual(str(response.data['detail']), 'Given token not valid for any token type')