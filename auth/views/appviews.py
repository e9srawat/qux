from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import User
from django.contrib.auth.views import (
    LoginView,
    PasswordResetCompleteView,
    PasswordResetConfirmView,
    PasswordResetDoneView,
    PasswordResetView,
)
from django.core.mail import EmailMessage
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.template.loader import render_to_string
from django.urls import reverse, reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes
from django.views.generic import TemplateView, View

try:
    from django.utils.encoding import force_text
except ImportError:
    from django.utils.encoding import force_str as force_text

from django.contrib.auth.models import User
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.views.generic import TemplateView, View

from qux.seo.mixin import SEOMixin

from ..forms import (
    BaseSignupForm,
    ChangePasswordForm,
    CompleteProfileForm,
    CustomAuthenticationForm,
    CustomPasswordResetForm,
    CustomSetPasswordForm,
    MagicLinkRequestForm,
    SignupForm,
)
from ..tokens import account_activation_token, magic_link_token

User._meta.get_field("email")._unique = True


class QuxSignupView(View):
    """
    Signup form.
    """

    show_username_signup = getattr(settings, "SHOW_USERNAME_SIGNUP", None)
    template_name = (
        "bs5/signup.html"
        if getattr(settings, "BOOTSTRAP", "bs4") == "bs5"
        else "signup.html"
    )
    form_class = SignupForm if show_username_signup else BaseSignupForm
    activate_user = False

    def post(self, request):
        """
        POST method for Signup form.
        """
        form = self.form_class(request.POST)

        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = self.activate_user
            if not self.show_username_signup:
                user.username = user.email
                counter = 1
                while User.objects.filter(username=user.username).exists():
                    user.username = user.username + str(counter)
                    counter += 1

            user.save()

            to_email = send_signup_verification_email(request, user, form)

            data = {
                "title": "Verify account",
                "messages": [
                    (
                        f"We have sent an account verification email to <b>{to_email}</b> "
                        "to complete your registration."
                    ),
                    (
                        "Check the <b>spam</b> folder if you do not see the email within a "
                        "few minutes of the request."
                    ),
                ],
            }

            return render(request, "message.html", data)

        errors = form.errors.as_data()

        error_messages = []
        for _, field_errors in errors.items():
            for error in field_errors:
                message = (
                    error.message % error.params if error.params else error.message
                )
                error_messages.append(message)

        data = {
            "title": "Invalid credentials.",
            "messages": error_messages,
        }
        return render(request, "message.html", data)

    def get(self, request):
        """
        GET method for Signup form.
        """
        form = self.form_class()
        context = {"form": form}
        return render(request, template_name=self.template_name, context=context)


def send_signup_verification_email(request, user, form):
    mail_subject = "Activate your account."
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = account_activation_token.make_token(user)
    domain = request.build_absolute_uri("/")[:-1]
    activate_url = reverse("qux_auth:activate", kwargs={"uidb64": uid, "token": token})
    data = {
        "user": user,
        # 'domain': current_site.domain,
        "domain": domain,
        "uid": uid,
        "token": token,
        "activate_url": domain + activate_url,
    }
    message = render_to_string("acc_active_email.html", data)
    to_email = form.cleaned_data.get("email")
    email = EmailMessage(mail_subject, message, to=[to_email])
    email.content_subtype = "html"
    email.send()

    return to_email


class QuxActivateView(View):
    """
    Activate account.
    """

    @staticmethod
    def get(request, uidb64, token):
        """
        GET method to activate a user account.
        """
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        if user is not None and account_activation_token.check_token(user, token):
            user.is_active = True
            user.save()
            login(request, user)
            data = {
                "title": "Account verified",
                "messages": [
                    '<a style="color:red" href="/">Click here<a/> to continue to your account.'
                ],
            }
            return render(request, "message.html", data)

        # else
        data = {
            "title": "Invalid URL",
            "messages": [
                "Activation link is invalid!",
            ],
        }
        return render(request, "message.html", data)


class QuxLoginView(SEOMixin, LoginView):
    """
    Login View.
    """

    form_class = CustomAuthenticationForm
    template_name = (
        "bs5/login.html"
        if getattr(settings, "BOOTSTRAP", "bs4") == "bs5"
        else "login.html"
    )
    canonical_url = "/login/"
    extra_context = {
        "submit_btn_text": "Login",
        "base_template": getattr(settings, "ROOT_TEMPLATE", "_blank.html"),
    }

    # show a generic message on login failure
    def form_invalid(self, form) -> HttpResponse:
        messages.error(self.request, "Could not login, invalid credentials!!")
        return super().form_invalid(form)


class QuxChangePasswordView(SEOMixin, TemplateView):
    form_class = ChangePasswordForm
    template_name = (
        "bs5/change-password.html"
        if getattr(settings, "BOOTSTRAP", "bs4") == "bs5"
        else "change-password.html"
    )
    extra_context = {
        "submit_btn_text": "Change Password",
        "base_template": getattr(settings, "ROOT_TEMPLATE", "_blank.html"),
    }

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["form"] = self.form_class(user=self.request.user)
        return ctx

    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def post(self, request):
        form = self.form_class(data=request.POST, user=request.user)
        if form.is_valid():
            user = request.user
            user.set_password(form.cleaned_data.get("new_password"))
            user.save()
            messages.success(request, "Password changed successfully")
            return redirect("/")
        return render(request, self.template_name, context={"form": form})


class QuxPasswordResetView(SEOMixin, PasswordResetView):
    form_class = CustomPasswordResetForm
    template_name = (
        "bs5/password_reset_form.html"
        if getattr(settings, "BOOTSTRAP", "bs4") == "bs5"
        else "password_reset_form.html"
    )
    email_template_name = "password_reset_email.html"
    html_email_template_name = "password_reset_email.html"
    canonical_url = "/password-reset/"
    success_url = reverse_lazy("qux_auth:password_reset_done")
    extra_context = {
        "title": "Reset password",
        "submit_btn_text": "Password Reset",
        "base_template": getattr(settings, "ROOT_TEMPLATE", "_blank.html"),
    }


class QuxPasswordResetDoneView(SEOMixin, PasswordResetDoneView):
    template_name = "password_reset_done.html"
    extra_context = {
        "title": "Reset password",
        "base_template": getattr(settings, "ROOT_TEMPLATE", "_blank.html"),
    }


class QuxPasswordResetConfirmView(PasswordResetConfirmView):
    form_class = CustomSetPasswordForm
    template_name = (
        "bs5/password_reset_form.html"
        if getattr(settings, "BOOTSTRAP", "bs4") == "bs5"
        else "password_reset_form.html"
    )
    success_url = reverse_lazy("qux_auth:password_reset_complete")
    extra_context = {
        "title": "Change password",
        "submit_btn_text": "Change Password",
        "base_template": getattr(settings, "ROOT_TEMPLATE", "_blank.html"),
    }


class QuxPasswordResetCompleteView(PasswordResetCompleteView):

    template_name = "password_reset_complete.html"
    extra_context = {
        "title": "Password changed successfully",
        "base_template": getattr(settings, "ROOT_TEMPLATE", "_blank.html"),
    }


def logout_request(request):
    """
    Function based logout view.
    """
    logout(request)
    messages.info(request, "Logged out successfully!")
    return redirect("/")


def login_request(request):
    """
    Function based login view.
    """
    next_path = request.GET.get("next")
    if request.user.is_authenticated:
        return redirect(settings.LOGIN_REDIRECT_URL)

    if request.method == "POST":
        form = AuthenticationForm(request=request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password")
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                messages.info(request, f"You are now logged in as {username}")
                redirect_to = settings.LOGIN_REDIRECT_URL
                if next_path:
                    redirect_to = next_path
                return redirect(redirect_to)

            messages.error(request, "Invalid username or password.")
        else:
            messages.error(request, "Invalid username or password.")
    form = CustomAuthenticationForm()
    data = {
        # "canonical": reverse('qux_auth:login'),
        "form": form,
    }
    return render(request, "login.html", data)


class MagicLinkRequestView(SEOMixin, TemplateView):
    template_name = (
        "bs5/magic_link_request.html"
        if getattr(settings, "BOOTSTRAP", "bs4") == "bs5"
        else "magic_link_request.html"
    )
    extra_context = {
        "title": "Email sign-in link",
        "submit_btn_text": "Send sign-in link",
        "base_template": getattr(settings, "ROOT_TEMPLATE", "_blank.html"),
    }

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["form"] = MagicLinkRequestForm()
        return ctx

    def get(self, request):
        if request.user.is_authenticated:
            return redirect(settings.LOGIN_REDIRECT_URL)
        return super().get(request)

    def post(self, request):
        form = MagicLinkRequestForm(request.POST)
        if not form.is_valid():
            return self.render_to_response({"form": form})

        email = form.cleaned_data["email"].strip().lower()
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            base_username = email
            candidate_username = base_username
            suffix = 1
            while User.objects.filter(username=candidate_username).exists():
                candidate_username = f"{base_username}{suffix}"
                suffix += 1
            user = User.objects.create(
                username=candidate_username,
                email=email,
                is_active=True,
            )

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = magic_link_token.make_token(user)
        domain = request.build_absolute_uri("/")[:-1]
        next_path = request.GET.get("next") or request.POST.get("next")
        callback_kwargs = {"uidb64": uid, "token": token}
        # Use unified login link callback under /login/link/
        callback_url = reverse("qux_auth:login_link", kwargs=callback_kwargs)
        if next_path:
            callback_url = f"{callback_url}?next={next_path}"

        message = render_to_string(
            "magic_link_email.html",
            {
                "user": user,
                "domain": domain,
                "magic_link_url": domain + callback_url,
            },
        )
        email_obj = EmailMessage(
            subject="Your secure sign-in link",
            body=message,
            to=[email],
        )
        email_obj.content_subtype = "html"
        email_obj.send()

        return render(
            request,
            "message.html",
            {
                "title": "Check your email",
                "messages": [
                    f"We sent a login link to <b>{email}</b>. It expires soon.",
                    "Check spam if you do not see it in a couple of minutes.",
                ],
            },
        )


class MagicLinkLoginView(View):
    @staticmethod
    def get(request, uidb64, token):
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is None or not magic_link_token.check_token(user, token):
            return render(
                request,
                "message.html",
                {
                    "title": "Invalid link",
                    "messages": ["Email sign-in link is invalid"],
                },
            )

        login(request, user)
        # If first-time login (no first_name/last_name), route to complete-profile
        if (
            hasattr(settings, "SHOW_COMPLETE_PROFILE_FORM")
            and settings.SHOW_COMPLETE_PROFILE_FORM
            and not user.first_name
            and not user.last_name
        ):
            next_path = request.GET.get("next")
            url = reverse("qux_auth:complete_profile")
            if next_path:
                url = f"{url}?next={next_path}"
            return redirect(url)

        redirect_to = request.GET.get("next") or settings.LOGIN_REDIRECT_URL
        return redirect(redirect_to)


class CompleteProfileView(LoginRequiredMixin, SEOMixin, TemplateView):
    template_name = (
        "bs5/complete_profile.html"
        if getattr(settings, "BOOTSTRAP", "bs4") == "bs5"
        else "complete_profile.html"
    )
    extra_context = {
        "title": "Complete your profile",
        "submit_btn_text": "Save and continue",
        "base_template": getattr(settings, "ROOT_TEMPLATE", "_blank.html"),
    }

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["form"] = CompleteProfileForm(instance=self.request.user)
        return ctx

    def get(self, request):
        if (
            hasattr(settings, "SHOW_COMPLETE_PROFILE_FORM")
            and settings.SHOW_COMPLETE_PROFILE_FORM
            and request.user.first_name
            and request.user.last_name
        ):
            redirect_to = request.GET.get("next") or settings.LOGIN_REDIRECT_URL
            return redirect(redirect_to)
        return super().get(request)

    def post(self, request):
        form = CompleteProfileForm(request.POST, instance=request.user)
        if not form.is_valid():
            return self.render_to_response({"form": form})
        form.save()
        redirect_to = request.GET.get("next") or settings.LOGIN_REDIRECT_URL
        return redirect(redirect_to)
