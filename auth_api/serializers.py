from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from .models import User, Organisation


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['userId','email', 'firstName', 'lastName', 'email', 'password', 'phone']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate(self, data):
        errors = []
        if not data.get('firstName'):
            errors.append({'field': 'firstName', 'message': 'This field is required'})
        if not data.get('lastName'):
            errors.append({'field': 'lastName', 'message': 'This field is required'})
        if not data.get('email'):
            errors.append({'field': 'email', 'message': 'This field is required'})
        if not data.get('password'):
            errors.append({'field': 'password', 'message': 'This field is required'})
        if User.objects.filter(email=data.get('email')).exists():
            errors.append({'field': 'email', 'message': 'Email already exists'})
        if errors:
            raise serializers.ValidationError({'errors': errors})
        return data


    def validate_phone(self, value):
        """
        Check if the phone number is valid.
        """
        if not value.isdigit():
            raise serializers.ValidationError("Phone number must be digits.")
        elif len(value) <= 10:
            raise serializers.ValidationError("Phone number cannot be less than 10 digits.")
        elif not isinstance(value, str):
            raise serializers.ValidationError("Phone number must be a string.")
        return value


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()


class OrganisationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organisation
        fields = ['orgId', 'name', 'description']


class RegisterOrganisationSerializers(serializers.ModelSerializer):
    name = serializers.CharField(required=True, allow_null=False)
    description = serializers.CharField()

    class Meta:
        model = Organisation
        fields = ['name', 'description']

    def validate_description(self, value):
        if not isinstance(value, str):
            raise serializers.ValidationError("Description must be a string.")
        return value

    def validate(self, data):
        errors = []
        if not data.get('description'):
            errors.append({'field': 'description', 'message': 'This field is required'})
        if Organisation.objects.filter(name=data.get('name')).exists():
            errors.append({'field': 'name', 'message': 'Organisation with name already exists'})
        if errors:
            raise serializers.ValidationError({'errors': errors})
        return data

