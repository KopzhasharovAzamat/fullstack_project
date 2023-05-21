from django.contrib import admin
from django.urls import path, include
from . import views


urlpatterns = [
    path('register/', views.RegistrationView.as_view()),
    path('login/',views.LoginView.as_view()),
]