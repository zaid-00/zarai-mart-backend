from djoser.serializers import UserCreateSerializer

from .models import User


# serializers.py


class UserCreateSerializer(UserCreateSerializer):
    class Meta(UserCreateSerializer.Meta):
        model = User
        fields = ('id', 'name', 'email', 'phone_number', 'password')
