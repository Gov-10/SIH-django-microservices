from ninja import NinjaAPI
from django.contrib.auth.models import User
from .schema import SignupSchema, LoginSchema, TokenSchema
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.exceptions import ValidationError
from django.conf import settings
import requests
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from rest_framework_simplejwt.views import TokenRefreshView

api = NinjaAPI(title="Slayers API docs")

def verify_recaptcha(token: str) -> bool:
    url = "https://www.google.com/recaptcha/api/siteverify"
    payload = {"secret": settings.RECAPTCHA_SECRET_KEY, "response": token}
    r = requests.post(url, data=payload)
    result = r.json()
    return result.get("success", False) and result.get("score", 0.5) >= 0.5

def send_verification_email(user):
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    verify_url = f"{settings.FRONTEND_URL}/verify-email/{uid}/{token}"

    send_mail(
        "Verify your email",
        f"Hi {user.username},\n\nPlease verify your email by clicking this link:\n{verify_url}\n\nThank you!",
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
    )

@api.post("/signup")
def signup(request, data:SignupSchema):
    if not verify_recaptcha(data.recaptcha_token):
        return {"error": "Invalid reCAPTCHA. Please try again."}
    if User.objects.filter(username=data.username).exists():
        raise ValidationError([{"loc": ["username"], "msg" : "Username already exists", "type": "value_error"}])
    if User.objects.filter(email=data.email).exists():
        raise ValidationError([{"loc": ["email"], "msg" : "Email already exists", "type": "value_error"}])
    if data.password1 != data.password2:
        return api.create_response(request, {"error": "Passwords do not match"}, status=400)
    user = User.objects.create_user(
        username=data.username,
        password=data.password1,
        email=data.email,
        first_name=data.first_name,
        last_name=data.last_name,
        is_active=False,
    )
    user.save()
    send_verification_email(user)
    return {"message": "User registered. Please check your email to verify your account."}

@api.get("/verify-email/{uidb64}/{token}")
def verify_email(request, uidb64: str, token: str):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        return api.create_response(request, {"error": "Invalid link"}, status=400)

    if default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        return {"message": "Email verified successfully!"}
    else:
        return api.create_response(request, {"error": "Invalid or expired token"}, status=400)

@api.post("/refresh")
def refresh(request):
    view = TokenRefreshView.as_view()
    return view(request._request)


@api.post("/login", response=TokenSchema)
def login(request, data: LoginSchema):
    if not verify_recaptcha(data.recaptcha_token):
        return api.create_response(request, {"error": "reCAPTCHA failed"}, status=400)

    user = authenticate(username=data.username, password=data.password)
    if user is None:
        return api.create_response(request, {"error": "Invalid credentials"}, status=401)

    if not user.is_active:
        return api.create_response(request, {"error": "Please verify your email first"}, status=403)

    refresh = RefreshToken.for_user(user)
    return {"access": str(refresh.access_token), "refresh": str(refresh)}
