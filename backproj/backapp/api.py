from ninja import NinjaAPI
from django.contrib.auth.models import User
from .schema import SignupSchema, LoginSchema, TokenSchema, JobSchema
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
import json, pika
import os
from .models import MLJob
from django.views.decorators.csrf import csrf_exempt
from django.core.paginator import Paginator
from rest_framework_simplejwt.authentication import JWTAuthentication
from ninja.security import HttpBearer
from rest_framework_simplejwt.exceptions import TokenError

api = NinjaAPI(title="Slayers API docs")

def verify_recaptcha(token: str) -> bool:
    url = "https://www.google.com/recaptcha/api/siteverify"
    payload = {"secret": settings.RECAPTCHA_PRIVATE_KEY, "response": token}
    r = requests.post(url, data=payload)
    result = r.json()
    if not result.get("success", False):
        return False
    if "score" in result:
        return result["score"] >= 0.5
    return True

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

def publish_to_queue(queue_name, message):
    connection = pika.BlockingConnection(
        pika.URLParameters(os.getenv("RABBITMQ_URL"))
    )
    channel = connection.channel()
    channel.queue_declare(queue=queue_name, durable=True)
    channel.basic_publish(
        exchange="",
        routing_key=queue_name,
        body=json.dumps(message),
        properties=pika.BasicProperties(delivery_mode=2),
    )
    connection.close()


@csrf_exempt
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

@csrf_exempt
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

@csrf_exempt
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

class JWTAuth(HttpBearer):
    def authenticate(self, request, token):
        auth = JWTAuthentication()
        try:
            validated_token = auth.get_validated_token(token)
            user = auth.get_user(validated_token)
            return user
        except TokenError:
            return None

@csrf_exempt
@api.post("/submit-job", auth=JWTAuth())
def submit_job(request, data: JobSchema):
    job = MLJob.objects.create(
        user=request.user,
        job_name=data.job_name,
        text_input=data.text_input,
        status="pending"
    )
    publish_to_queue("ml_jobs", {
        "job_id": job.job_id,
        "text_input": data.text_input,
    })
    return {"message": "Job submitted successfully. Processing in background.", "job_id": job.job_id}

@csrf_exempt
@api.get("/job-status/{job_id}", auth=JWTAuth())
def job_status(request, job_id: int):
    user = request.user
    try:
        job = MLJob.objects.get(pk=job_id)
    except MLJob.DoesNotExist:
        return api.create_response(request, {"error": "Job not found"}, status=404)
    if job.user != user:
        return api.create_response(request, {"error": "Unauthorized access"}, status=403)
    return {"status": job.status, "result": job.result}

    
from django.contrib.auth import logout as django_logout
@csrf_exempt
@api.get("/logout")
def logout(request):
    django_logout(request)
    return {"message": "Logout handled on client side by deleting the token."}

@csrf_exempt
@api.get("/jobs", auth=JWTAuth())
def list_jobs(request, page: int = 1, page_size: int = 10):
    user = request.user
    jobs = MLJob.objects.filter(user=user).order_by("-created_at")
    paginator = Paginator(jobs, page_size)
    page_obj = paginator.get_page(page)
    job_list = [{
        "job_id": job.job_id,
        "job_name": job.job_name,
        "status": job.status,
        "result": job.result,
        "created_at": job.created_at
    } for job in page_obj]
    return {
        "jobs": job_list,
        "total_pages": paginator.num_pages,
        "current_page": page
    }
