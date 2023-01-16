from rest_framework import permissions
from rest_framework.generics import CreateAPIView

from .serializers import SignUpSerializer
from .models import User


class CreateUserView(CreateAPIView):
    model = User
    permission_classes = (permissions.AllowAny, )
    serializer_class = SignUpSerializer
