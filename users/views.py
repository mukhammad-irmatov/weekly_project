from datetime import datetime

from rest_framework import permissions
from rest_framework.exceptions import ValidationError
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from shared.utils import send_email, send_phone_notification
from .serializers import SignUpSerializer
from .models import User, CODE_VERIFIED, INFORMATION_FILLED, DONE, VIA_EMAIL, VIA_PHONE


class CreateUserView(CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (permissions.AllowAny, )
    serializer_class = SignUpSerializer


class VerifyApiView(APIView):
    permission_classes = (IsAuthenticated, )

    def post(self, request, *args, **kwargs):
        user, code = self.request.user, self.request.data.get('code')
        # user = self.request.user
        # code = self.request.data.get('code')
        self.check_verify(user, code)
        return Response(
            data={
                "success": True,
                "auth_status": user.auth_status,
                "access": user.tokens()["access"],
                "refresh": user.tokens()["refresh"]
            }, status=200)

    @staticmethod
    def check_verify(user, code):
        verifies = user.verify_codes.filter(expiration_time__gte=datetime.now(), code=code, is_confirmed=False)
        if not verifies.exists():
            data = {
                'message': "Code is incorrect or expired"
            }
            raise ValidationError(data)
        verifies.update(is_confirmed=True)
        if user.auth_status not in (INFORMATION_FILLED, DONE):
            user.auth_status = CODE_VERIFIED
            user.save()
        return True


class GetNewVerification(APIView):
    permission_classes = (IsAuthenticated, )

    def get(self, request, *args, **kwargs):
        user = self.request.user
        self.check_verification(user)
        if user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)
            send_email(user.email, code)
        elif user.auth_type == VIA_PHONE:
            code = user.create_verify_code(VIA_PHONE)
            # send_phone_notification(user.phone_number, code)
            send_email(user.phone_number, code)
        else:
            data = {
                "message": "You need to enter email or phone_number",
            }
            raise ValidationError(data)
        return Response(
            {
                "success": True
            }
        )


    @staticmethod
    def check_verification(user):
        verifies = user.verify_codes.filter(expiration_time__gte=datetime.now(), is_confirmed=False)
        if verifies.exists():
            data = {
                "message": "You need to wait over expiration time",
            }
            raise ValidationError(data)





