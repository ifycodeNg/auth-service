from datetime import datetime
from django.utils import timezone
from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    email = models.EmailField(unique=True)
    is_email_confirmed= models.BooleanField(default=False)


    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    def __str__(self):
        return self.email

    @property
    def is_email_verified(self):
        return self.is_email_confirmed


class Token(models.Model):
    user= models.ForeignKey("User", on_delete=models.CASCADE)
    token = models.CharField(max_length=6)
    token_expiry = models.DateTimeField(blank=False, null=False)
   

    def __str__(self):
        return str(self.user)

    @property
    def is_expired(self):
        if datetime.now(tz=timezone.utc) > self.token_expiry:
            return True
        return False