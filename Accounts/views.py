from django.shortcuts import render,redirect
from django.contrib import messages
from django.contrib.auth import get_user_model, logout, login
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from django.template.loader import get_template
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from . import models
from validate_email import validate_email
from datetime import datetime, timedelta
from django.utils import timezone
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode
import threading



class EmailThread(threading.Thread):

    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send()


def send_activation_email(user, request):
     if user:
                encoded_pk = urlsafe_base64_encode(force_bytes(user.pk))
                token = PasswordResetTokenGenerator().make_token(user)  
                activate_url = reverse(
                    "activate",
                    kwargs={"encoded_pk": encoded_pk, "token": token},
                )

                # send the rest_link as mail to the user.
                message = get_template("activate_email.html")
                context={
                    "activate_link":activate_url,
                    "request": get_current_site(request)
                }
                body=message.render(context)
                subject="Email Address Verification Request"
                mail = EmailMultiAlternatives(
                    subject,
                    body,
                    from_email=settings.EMAIL_ADMIN,
                    to=[user.email],
                    reply_to=['helpme@test.com']
                )
                mail.attach_alternative(body, "text/html")
                EmailThread(mail).start()

def signup(request):
    if request.method == 'POST':
            uname= request.POST.get("username")
            email= request.POST.get("email")
            password= request.POST.get("password")
            confirm_password= request.POST.get("confirm_password")
            if password != confirm_password:
                messages.warning(request, "Password doesn't match")
                return redirect("/account/create")
            User = get_user_model()

            if len(password) < 6:
                messages.warning(request, 'Password should be at least 6 characters')
                return redirect("/account/create")

            if not validate_email(email):
                messages.warning(request,'Enter a valid email address')
                return redirect("/account/create")

            if not uname:
                messages.warning(request,'Username is required')
                return redirect("/account/create")

            if User.objects.filter(email=email).exists():
                messages.warning(request,'Email is taken, choose another one')
                return redirect("/account/create")
            if User.objects.filter(username=uname).exists():
                messages.warning(request,'Username is taken, choose another one')
                return redirect("/account/create")
            User = get_user_model()
            create_user= User.objects.create_user(username=uname,email=email,password=password)
            create_user.save()
            send_activation_email(create_user, request)
            messages.success(request, "Account created please verify email address")
            return redirect("signup")
    else:
        return render(request,"signup.html")

def login_route(request):
    if request.method == 'POST':
            email= request.POST.get("email")
            password= request.POST.get("password")
            User= get_user_model()
            try:
                user=User.objects.get(email=email)
                if user:
                    if not user.check_password(password):
                        login_attempt= request.session.get('login_attempt', 0)
                        request.session['login_attempt'] = login_attempt + 1
                        if login_attempt == 3:
                            request.session['login_attempt'] = 0
                            messages.error(request,'Please reset your password')
                            return redirect("forget_password")
                        messages.error(request,'Password incorrect')
                        return redirect("login")
                        
                    if not user.is_email_verified:
                        url= get_current_site(request)
                        messages.error(request,'Email is not verified, please check your email inbox or <a href="http://{url}/account/resend_confirmation">resend Activation link </a> '.format(url=url))
                        return redirect("login")
                    if user is not None:
                        login(request,user)
                        return redirect("home")
                    
            except User.DoesNotExist:
                messages.error(request, "Invalid credentials")
                return redirect("login")
    else:
        return render(request,"login.html")

def resend_confirmation(request):
        email= request.POST.get("email")
        User= get_user_model()
        if request.method == 'POST':
            try:       
                user=User.objects.get(email=email)
                if user.is_email_verified:
                        messages.warning(request,'Email already confirmed')
                        return redirect("login")
                if not user.is_email_verified:
                        messages.error(request, "Please check your email inbox for activation link")
                        send_activation_email(user, request)
                        return redirect("login")
            except User.DoesNotExist:
                    messages.error(request, "Invalid credentials")
                    return redirect("resend_confirmation")
        else:
            return render(request,"resend_confirmation.html")

def forget_password(request):
    if request.method == 'POST':
        email= request.POST.get("email")
        user = models.User.objects.filter(email=email).first()
        if user:
                encoded_pk = urlsafe_base64_encode(force_bytes(user.pk))
                token = PasswordResetTokenGenerator().make_token(user)  
                # Get current time in local timezone
                current_time = datetime.now(tz=timezone.utc)
                n = 60.00
                # Add 60 minutes to datetime object containing current time
                token_expiry= current_time + timedelta(minutes=n)
                create_token= models.Token.objects.create(user=user,token=token,token_expiry=token_expiry)
                reset_url = reverse(
                    "reset-password",
                    kwargs={"encoded_pk": encoded_pk, "token": token},
                )

                # send the rest_link as mail to the user.
                message = get_template("email.html")
                context={
                    "reset_link":reset_url,
                    "request": get_current_site(request)
                }
                body=message.render(context)
                subject="Your Test Account - Forgot your password?"
                mail = EmailMultiAlternatives(
                    subject,
                    body,
                    from_email=settings.EMAIL_ADMIN,
                    to=[email],
                    reply_to=['helpme@test.com']
                )
                mail.attach_alternative(body, "text/html")
                EmailThread(mail).start()
                
                messages.error(request, "Reset Link Sent")
                return render(request,"forget_password.html")
        else:
            messages.error(request, "Invalid Email Address")
            return render(request,"forget_password.html")

    return render(request,"forget_password.html")

def logout_request(request):
    logout(request)
    messages.info(request, "Logged out successfully!")
    return redirect("login")

def dashboard(request):
    print(request.session.session_key)
    # request.session.set_expiry(60)
    return render(request,"home.html")
def reset_password(request,encoded_pk,token):
     

        if token is None or encoded_pk is None:
            return render(request,"forget_password.html")

        pk = urlsafe_base64_decode(encoded_pk).decode()
        user = models.User.objects.get(pk=pk)

        if request.method == 'POST':
            password= request.POST.get("password")
            confirm_password= request.POST.get("confirm_password")
            if password != confirm_password:
                messages.warning(request, "Password doesn't match")
                return render(render,"reset_password")
            user.set_password(password)
            user.save()
            messages.warning(request, "Password reset sucessfully")
            return redirect("login")

        if not PasswordResetTokenGenerator().check_token(user, token):
            messages.error(request, "Invalid Email Address")
            return render(request,"forget_password.html")
        check_token= models.Token.objects.get(token=token, user=pk)
        if check_token:
            if check_token.is_expired:
                messages.error(request, "It looks like you clicked on an invalid password reset link. Please try again.")
                return redirect("forget_password")
            else:
                return render(request,"reset_password.html")
        else:
            messages.error(request, "Token expired or Invalid")
            return redirect("reset_password")
    
def logout_user(request):
    logout(request)
    messages.add_message(request, messages.SUCCESS,
                         'Successfully logged out')

    return redirect(reverse('login'))

def activate_user(request, encoded_pk, token):
    try:
        pk =  urlsafe_base64_decode(encoded_pk).decode()
        user = models.User.objects.get(pk=pk)

    except Exception as e:
        user = None
        messages.success(request, 'Invalid token')
        return redirect(reverse('login'))


    if user and PasswordResetTokenGenerator().check_token(user, token):
        user.is_email_confirmed = True
        user.save()
        messages.success(request, 'Email verified, you can now login')
        return redirect(reverse('login'))