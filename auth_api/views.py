# views.py
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from .serializers import LoginSerializer, RegisterOrganisationSerializers, RegisterUserSerializer, UserSerializer, \
    OrganisationSerializer
from .models import User, Organisation
from rest_framework.decorators import api_view
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User as p
from django.contrib.auth import authenticate, login
from rest_framework.permissions import IsAuthenticated

def index(request):
    return HttpResponse ("HNG11 STAGE2 ")

class RegisterUserView(APIView):
    def get(self, request):
        context = {
            "firstName": "Enter First name",
            "lastName": "Enter Last name",
            "email": "Enter a valid email",
            "password": "Enter password",
            "phone": "Enter phone number",
        }
        return Response(context, status=status.HTTP_200_OK)

    def post(self, request):
        """Create a User"""
        serializer = RegisterUserSerializer(data=request.data)
        if serializer.is_valid():
            try:
                # Creates an AbstractBaseUser
                a = p.objects.create_user(username=serializer.validated_data['email'],
                                          email=serializer.validated_data['email'],
                                          password=serializer.validated_data['password'])
                a.save()

                # Hash the password
                serializer.validated_data['password'] = make_password(serializer.validated_data['password'])

                # Creates a User profile (User Model)
                user = User(**serializer.validated_data)
                user.save()

                # Creates an default Organisation with User name
                org = Organisation.objects.create(name=f"{user.firstName}'s Organisation", description='')
                org.users.add(user)  # Add user to the organisation
                org.save()

                # Assign AbstractBaseUser to User model, i.e the owner of the User Model. OnetoOnerelationship is estabilshed between AbstractBaseUser and User Model
                user.owner = a
                user.save()

                # Generate AccessToken for User
                token = RefreshToken.for_user(a)

                return Response({'status': 'success', 'message': 'Registration successful',
                                 'data': {'accessToken': str(token.access_token), 'user': UserSerializer(user).data}},
                                status=status.HTTP_201_CREATED)

            except Exception as e:
                return Response({'status': 'Bad request', 'message': 'Registration unsuccessful', 'statusCode': 400},
                                status=status.HTTP_400_BAD_REQUEST)

        context = {
            "errors": serializer.errors
        }
        return Response(context, status=status.HTTP_422_UNPROCESSABLE_ENTITY)


@api_view(['POST', 'GET'])
def loginView(request):
    if request.method == 'POST':
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            user = authenticate(request, username=email, password=password)
            if user is not None:
                login(request, user)
                u = User.objects.get(email=email)
                token = RefreshToken.for_user(user)
                context = {
                    "status": "success",
                    "message": "Login successful",
                    "data": {
                        'accessToken': str(token.access_token),
                        'user': UserSerializer(u).data
                    }
                }
                return Response(context, status=status.HTTP_200_OK)
            else:
                context = {
                    "status": "error",
                    "message": "Authetication Failed",
                    'statusCode': 401
                }
                return Response(context, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    else:
        context = {
            'email': "Enter Your email",
            'password': "Enter your password"
        }
        return Response(context, status=status.HTTP_200_OK)


class UserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        try:
            user = User.objects.get(user_Id=pk)
            return Response(
                {'status': 'success', 'message': 'User retrieved successfully', 'data': UserSerializer(user).data},
                status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'status': 'error', 'message': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)


class OrganisationView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = User.objects.get(email=request.user)
        organisations = Organisation.objects.filter(users=user)
        return Response({'status': 'success', 'message': 'Organisations retrieved successfully', 'data': {
            'organisations': OrganisationSerializer(organisations, many=True).data
        }},status=status.HTTP_200_OK)

    def post(self, request):
        serializer = RegisterOrganisationSerializers(data=request.data)
        if serializer.is_valid():
            organisation = serializer.save()
            user = User.objects.get(email=request.user)
            organisation.users.add(user)
            return Response({'status': 'success', 'message': 'Organisation created successfully',
                             'data': OrganisationSerializer(organisation).data}, status=status.HTTP_201_CREATED)
        else:
            return Response(
                {'status': 'Bad Request', 'message': 'Client error', 'statusCode': 400, 'error': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST)


class OrganisationDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):

            user = User.objects.get(email=request.user)
            organisation = Organisation.objects.get(orgId=pk)
            if user in organisation.users.all():
                return Response({'status': 'success', 'message': 'Organisation retrieved successfully',
                                 'data': OrganisationSerializer(organisation).data}, status=status.HTTP_200_OK)

            return Response(
                {'status': 'Bad request', 'message': 'You do not have access to this organisation', 'statusCode': 403},
                status=status.HTTP_403_FORBIDDEN)


class AddUserToOrganisationView(APIView):
    def get(self, request, pk):
        context = {
            'user_Id': "Enter a valid Id"
        }
        return Response(context, status=status.HTTP_200_OK)

    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        user_id = request.data.get('user_Id')
        try:
            organisation = Organisation.objects.get(orgId=pk)
            user = get_object_or_404(User, user_Id=user_id)
            print(user)
            if user:
                organisation.users.add(user)
                organisation.save()
                return Response({'status': 'success', 'message': 'User added to organisation successfully!'},
                                status=status.HTTP_200_OK)
            else:
                return Response({'status': 'Bad Request', 'message': 'Client error', 'statusCode': 400},
                                status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response(
                {'status': 'Bad request', 'message': 'You do not have access to this organisation', 'statusCode': 403},
                status=status.HTTP_403_FORBIDDEN)