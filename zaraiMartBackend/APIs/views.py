import requests
from django.utils.decorators import method_decorator
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from django.core.mail import send_mail
from django.http import JsonResponse
from django.utils.crypto import get_random_string
from django.views.decorators.csrf import csrf_exempt
from .models import User


class UserActivationView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, *args, **kwargs):
        uid = kwargs.get('uid')
        token = kwargs.get('token')

        post_url = "http://127.0.0.1:8000/auth/users/activation/"
        post_data = {"uid": uid, "token": token}

        result = requests.post(post_url, data=post_data)
        content = result.text

        return Response(content)


# views.py


@method_decorator(csrf_exempt, name='dispatch')  # Disabling CSRF protection
class SendOTPView(APIView):
    def post(self, request):
        email = request.POST.get('email')
        if email:
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return JsonResponse({'error': 'User with this email does not exist'}, status=400)

            otp = get_random_string(length=4, allowed_chars='1234567890')
            # Send OTP via email
            send_mail(
                'OTP for Password Reset',
                f'Your OTP for password reset is: {otp}',
                'zaidtayyab55@gmail.com',
                [email],
                fail_silently=False,
            )
            user.otp=otp
            user.save()
            return JsonResponse({'message': "OTP Sent"},status=200)
        else:
            return JsonResponse({'error': 'Email is required'}, status=400)

    def http_method_not_allowed(self, request, *args, **kwargs):
        return JsonResponse({'error': 'Only POST method is allowed'}, status=405)


@method_decorator(csrf_exempt, name='dispatch')  # Disabling CSRF protection
class SetPasswordView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        email = request.POST.get('email')
        new_password = request.POST.get('new_password')

        if email and new_password:
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return JsonResponse({'error': 'User with this email does not exist'}, status=400)
            if user.is_otp_verified:
                user.set_password(new_password)
                user.is_otp_verified=False
                user.save()
                send_mail(
                    'Password Reset Successfully',
                    f'You have successfully reset your password',
                    'zaidtayyab55@gmail.com',
                    [email],
                    fail_silently=False,
                )
                return JsonResponse({'success': 'Password has been updated successfully'})
            else:
                return JsonResponse({'error': "OTP isn't verified"},status=400)

        else:
            return JsonResponse({'error': 'Email and new password are required'}, status=400)

    def http_method_not_allowed(self, request, *args, **kwargs):
        return JsonResponse({'error': 'Only POST method is allowed'}, status=405)
@csrf_exempt
def verify_otp(request):
    if request.method == 'POST':
        otp = request.POST.get('otp')
        email = request.POST.get('email')

        user= User.objects.get(email=email)
        if user:
            if user.otp == otp:
                user.is_otp_verified = True
                user.otp=""
                user.save()
                return JsonResponse({'message': 'OTP verified and updated successfully'}, status=200)
            else:
                return JsonResponse({'error': "OTP isn't valid or got expired"}, status=400)
        else:
            return JsonResponse({'error': "User not found for this email"}, status=404)

    return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)