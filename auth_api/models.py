import uuid
from django.db import models
from django.contrib.auth import get_user_model

profile = get_user_model()

class User(models.Model):
    user_Id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    firstName = models.CharField(max_length=15, null=False, default=None)
    lastName = models.CharField(max_length=15, null=False, default=None)
    email = models.EmailField(max_length=30, unique=True, null=False, default=None)
    password = models.CharField(max_length=200, default=None, null=False)
    phone = models.CharField(max_length=15, default=None, blank=True, null=True)
    owner = models.OneToOneField(profile, on_delete=models.CASCADE, related_name='Users', default=None, blank=True, null=True)
    def __str__(self):
        return self.firstName + " " + self.lastName

class Organisation(models.Model):
    orgId = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    description = models.TextField(max_length=200, default=None)
    users = models.ManyToManyField(User, related_name='User')

    def __str__(self):
        return self.name