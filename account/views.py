# registration
from rest_framework.views import APIView
from rest_framework import permissions
from rest_framework.response import Response
from . import serializers

# login
from rest_framework import status
from rest_framework.authtoken.views import ObtainAuthToken

# logout
from rest_framework.authtoken.models import Token


# register
class RegistrationView(APIView):
    def post(self, request):
        serializer = serializers.RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({'message': 'Registration successful', 'user_id': user.id})
        return Response(serializer.errors, status=400)


# login
class LoginView(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        serializer = serializers.LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({'token': token.key}, status=status.HTTP_200_OK)

# logout
class LogoutView(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        try:
            token = request.META.get('HTTP_AUTHORIZATION').split(' ')[1]
            user_token = Token.objects.get(key=token)
            user_token.delete()
            return Response({'detail': 'Successfully logged out.'}, status=status.HTTP_200_OK)
        except:
            return Response({'detail': 'Invalid token or token not provided.'}, status=status.HTTP_401_UNAUTHORIZED)

# restore