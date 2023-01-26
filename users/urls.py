from django.urls import path
from .views import CreateUserView, VerifyApiView, GetNewVerification, \
    ChangeUserView, LoginView, CustomTokenRefreshView, LogoutView

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('login/refresh/', CustomTokenRefreshView.as_view(), name="token_refresh"),
    path('logout/', LogoutView.as_view(), name="logout"),
    path("signup/", CreateUserView.as_view(), name='signup'),
    path("verify/", VerifyApiView.as_view(), name='verify_code'),
    path('new-verify/', GetNewVerification.as_view(), name='new_verify_code'),
    path('change-user-information/', ChangeUserView.as_view(), name='change_user_information')
]