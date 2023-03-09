from django.urls import path
from . import views
urlpatterns = [
    path('create', views.signup, name="signup"),
    path('login', views.login_route, name="login"),
    path('logout', views.logout_request, name="logout"),
    path('forget_password', views.forget_password, name="forget_password"),
    path('resend_confirmation', views.resend_confirmation, name="resend_confirmation"),
    path("password-reset/<str:encoded_pk>/<str:token>",
        views.reset_password,
        name="reset-password",
    ),
    path('activate-user/<str:encoded_pk>/<str:token>',
         views.activate_user, name='activate'),

    path('reset_password', views.reset_password, name="reset_password"),
    path('dashboard', views.dashboard, name="home"),
]