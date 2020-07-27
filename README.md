twofactordjango
This Project will have the Implementation of TOTP validation with google authenticator for Django admin users. Main Aim of the project is add additional security feature for the admin users with TOTP validation.

clone the directory and installed below packages and run it.

How it's works:
The projects is works well with new version django 2.2.5 + version and python 3.7+ , please follow below steps to integrate two factor authentication in django based application. To achieve this we are using

Basic config
```
(venv) kwikl3arn:~/MYPROJECTS$ django-admin.py startproject twofactordjango

(venv) kwikl3arn:~/MYPROJECTS$ pip install django-two-factor-auth
(venv) kwikl3arn:~/MYPROJECTS$ pip install django-two-factor-auth[phonenumbers]
```
Make sure that the requirements already installed on your vitualenviornment

# Make sure the config register on top of the list in INSRALLED_APPS
```
INSTALLED_APPS = [
    'django_otp',
    'django_otp.plugins.otp_static',
    'django_otp.plugins.otp_totp',
    'two_factor',
    # django apps register below
]

MIDDLEWARE = [
    '-------------------------------------------------------',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django_otp.middleware.OTPMiddleware',
    '--------------------------------------------------------'
]

TWO_FACTOR_FORCE_OTP_ADMIN = True
LOGIN_URL = 'two_factor:login'
LOGIN_REDIRECT_URL = '/admin'  # Redirect admin dashboard
Migrate all your installed apps
```
```
from django.urls import path, include, re_path
from two_factor.urls import urlpatterns as tf_urls
from django.views.generic.base import TemplateView

from django.conf import settings
from django.http import HttpResponseRedirect
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.views import redirect_to_login
from django.shortcuts import resolve_url
from django.urls import reverse
from django.utils.http import is_safe_url
from two_factor.admin import AdminSiteOTPRequired, AdminSiteOTPRequiredMixin


class AdminSiteOTPRequiredMixinRedirSetup(AdminSiteOTPRequired):
    def login(self, request, extra_context=None):
        redirect_to = request.POST.get(
            REDIRECT_FIELD_NAME, request.GET.get(REDIRECT_FIELD_NAME)
        )
        # For users not yet verified the AdminSiteOTPRequired.has_permission
        # will fail. So use the standard admin has_permission check:
        # (is_active and is_staff) and then check for verification.
        # Go to index if they pass, otherwise make them setup OTP device.
        if request.method == "GET" and super(
                AdminSiteOTPRequiredMixin, self
        ).has_permission(request):
            # Already logged-in and verified by OTP
            if request.user.is_verified():
                # User has permission
                index_path = reverse("admin:index", current_app=self.name)
            else:
                # User has permission but no OTP set:
                index_path = reverse("two_factor:setup", current_app=self.name)
            return HttpResponseRedirect(index_path)

        if not redirect_to or not is_safe_url(
                url=redirect_to, allowed_hosts=[request.get_host()]
        ):
            redirect_to = resolve_url(settings.LOGIN_REDIRECT_URL)

        return redirect_to_login(redirect_to)


from django.contrib import admin

admin.site.__class__ = AdminSiteOTPRequiredMixinRedirSetup

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include(tf_urls, "two_factor")),
    path('', TemplateView.as_view(template_name="home.html"), name='home'),
]
```
Template config : This changes I have made (you can't find it anywhere)
templates/two_factor/
```
_base.html

_base_focus.html
```
templates/home.html
```
home.html
```
User configuration
Create super user account with following command
```
$ python manage.py createsuperuser
```
Once you have created superuser, login with the admin dashboard, the django-two-factor-auth will force you to enable two factor authentication.

