from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.views import LoginView
from django.core.exceptions import ValidationError
from django.db.models import Q
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.cache import cache_control

from home.encrypt_util import encrypt, decrypt
from home.forms import RegistrationForm, LoginForm, UpdatePasswordForm, UserPasswordForm
from home.models import UserPassword
from home.utils import generate_random_password


# home page
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def home_page(request):
    if not request.user.is_authenticated:
        return redirect("%s?next=%s" % ("/", request.path))
    return render(request, "pages/home.html")


# user login
class UserLoginView(LoginView):
    form_class = LoginForm
    template_name = "pages/index.html"


def user_login_view(request):
    if request.user.is_authenticated:
        return redirect("/home")
    return UserLoginView.as_view()(request)


# register new user
def register_page(request):
    if request.method == "POST":
        form = RegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(
                request,
                "Account registered successfully. Please log in to your account.",
            )
        else:
            print("Registration failed!")
    else:
        form = RegistrationForm()

    context = {"form": form}
    return render(request, "pages/register.html", context)


# logout
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def logout_view(request):
    if not request.user.is_authenticated:
        return redirect("/")
    logout(request)
    return redirect("/")


# add new password
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def add_new_password(request):
    if not request.user.is_authenticated:
        return redirect("%s?next=%s" % ("/", request.path))
    if request.method == "POST":
        try:
            form = UserPasswordForm(
                request.POST
            )  # Assuming you have a form for UserPassword
            if form.is_valid():
                user_password = form.save(commit=False)
                user_password.password = encrypt(user_password.password)
                user_password.save()
                user_password.user.add(request.user)  # Use add() for ManyToManyField
                # Set the user who created and last updated this password. Since these are ForeignKey fields, you can directly assign them
                user_password.user_created = request.user
                user_password.user_last_updated = request.user
                user_password.save()  # Save again to commit the ForeignKey fields
                application_type = form.cleaned_data["application_type"]
                messages.success(request, f"New password added for {application_type}.")
                return HttpResponseRedirect("/add-password")
        except Exception as error:
            print("Error: ", error)

    return render(request, "pages/add-password.html")


# edit password
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def edit_password(request, pk):
    if not request.user.is_authenticated:
        return redirect("%s?next=%s" % ("/", request.path))
    user_password = UserPassword.objects.get(id=pk)
    user_password.password = decrypt(user_password.password)
    form = UpdatePasswordForm(instance=user_password)

    if request.method == "POST":
        if "delete" in request.POST:
            # delete password
            user_password.delete()
            return redirect("/manage-passwords")
        form = UpdatePasswordForm(request.POST, instance=user_password)

        if form.is_valid():
            try:
                user_password.password = encrypt(user_password.password)
                user_password.user_last_updated = request.user
                form.save()
                messages.success(request, "Password updated.")
                user_password.password = decrypt(user_password.password)
                return HttpResponseRedirect(request.path)
            except ValidationError as e:
                form.add_error(None, e)

    context = {"form": form}
    return render(request, "pages/edit-password.html", context)


# search password
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def search(request):
    if not request.user.is_authenticated:
        return redirect(f"/?next={request.path}")

    logged_in_user = request.user
    logged_in_user_pws = UserPassword.objects.filter(user=logged_in_user)
    if request.method == "POST":
        searched = request.POST.get("password_search", "").strip()
        users_pws = logged_in_user_pws.values()
        if users_pws.filter(
            Q(website_name=searched)
            | Q(application_name=searched)
            | Q(game_name=searched)
            | Q(username__icontains=searched),
            user=request.user,
        ):
            # Perform a case-insensitive search for partial matches across multiple fields
            results = UserPassword.objects.filter(
                Q(website_name__icontains=searched)
                | Q(application_name__icontains=searched)
                | Q(game_name__icontains=searched)
                | Q(username__icontains=searched),
                user=request.user,  # Limit the search to the logged-in user's passwords
            )

            if results.exists():
                return render(request, "pages/search.html", {"passwords": results})
            else:
                messages.error(request, "---YOUR SEARCH RESULT DOESN'T EXIST---")
        else:
            messages.error(request, "Please enter a search term.")

    # Display all passwords if no search was made or if the search was empty
    logged_in_user_pws = UserPassword.objects.filter(user=request.user)
    return render(request, "pages/search.html", {"pws": logged_in_user_pws})


def search_old(request):
    if not request.user.is_authenticated:
        return redirect("%s?next=%s" % ("/", request.path))
    logged_in_user = request.user
    logged_in_user_pws = UserPassword.objects.filter(user=logged_in_user)
    if request.method == "POST":
        searched = request.POST.get("password_search", "")
        users_pws = logged_in_user_pws.values()
        if users_pws.filter(
            Q(website_name=searched)
            | Q(application_name=searched)
            | Q(game_name=searched)
        ):
            user_pw = UserPassword.objects.filter(
                Q(website_name=searched)
                | Q(application_name=searched)
                | Q(game_name=searched)
            ).values()
            return render(request, "pages/search.html", {"passwords": user_pw})
        else:
            messages.error(request, "---YOUR SEARCH RESULT DOESN'T EXIST---")

    return render(request, "pages/search.html", {"pws": logged_in_user_pws})


# all passwords
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def manage_passwords(request):
    if not request.user.is_authenticated:
        return redirect("%s?next=%s" % ("/", request.path))
    sort_order = "asc"
    logged_in_user = request.user
    user_passwords = UserPassword.objects.filter(user=logged_in_user)
    if request.GET.get("sort_order"):
        sort_order = request.GET.get("sort_order", "desc")
        user_passwords = user_passwords.order_by(
            "-date_created" if sort_order == "desc" else "date_created"
        )
    if not user_passwords:
        return render(
            request,
            "pages/manage-passwords.html",
            {"no_password": "No password available. Please add password."},
        )
    return render(
        request,
        "pages/manage-passwords.html",
        {"all_passwords": user_passwords, "sort_order": sort_order},
    )


# generate random password
def generate_password(request):
    password = generate_random_password()
    return JsonResponse({"password": password})
