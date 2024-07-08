from django.urls import path
from auth_api.views import AddUserToOrganisationView, OrganisationDetailView, OrganisationView, UserView, loginView, \
    RegisterUserView

urlpatterns = [
    path('auth/register', RegisterUserView.as_view(), name='register'),
    path('auth/login', loginView, name='login'),
    path('api/users/<str:pk>', UserView.as_view(), name='user'),
    path('api/organisations', OrganisationView.as_view(), name='all-organisation'),
    path('api/organisations/<str:pk>', OrganisationDetailView.as_view(), name='organisation-detail'),
    path('api/organisations/<str:pk>/users', AddUserToOrganisationView.as_view(), name='add-user-to-organisation'),

]
