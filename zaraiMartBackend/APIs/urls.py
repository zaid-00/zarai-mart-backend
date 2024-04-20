from django.urls import path, include
from .views import UserActivationView, SetPasswordView,SendOTPView,verify_otp

urlpatterns = [
    path('auth/', include('djoser.urls')),
    path('auth/', include('djoser.urls.jwt')),
    path('auth/users/activate/<str:uid>/<str:token>/', UserActivationView.as_view(), name='activate_user'),
    path('auth/send-otp/', SendOTPView.as_view(), name='send_otp'),
    path('auth/verify-otp/', verify_otp, name='verify_otp'),
    path('auth/custom-set-password/', SetPasswordView.as_view(), name='temp'),

]
