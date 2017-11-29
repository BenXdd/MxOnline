# _*_ encoding:utf-8 _*_
from django.shortcuts import render
from django.contrib.auth import authenticate, login
from django.contrib.auth.backends import ModelBackend
from django.db.models import Q
from django.views.generic.base import View
from django.contrib.auth.hashers import make_password

from .models import UserProfile, EmailVerifyRecord
from .forms import LoginForm, RegisterForm, ForgetForm, ModifyPwdForm
from utils.email_send import send_register_email
# Create your views here.


# 用来多种方式登录 在setting中需要配置 AUTHENTICATION_BACKENDS
class CustomBackend(ModelBackend):
    def authenticate(self, username=None, password=None, **kwargs):
        try:
            # password在存储的时候是密文 所以不用密码
            # Q这里支持多方式登录
            user = UserProfile.objects.get(Q(username=username) | Q(email=username))
            # AbstractUser中的方法
            if user.check_password(password):
                return user
        except Exception as e:
            return None


# 基于类的方式来编写view  导入from django.views.generic.base import View
class LoginView(View):
    # 如果是get方法的话  继承了view 我们可以直接调用get post方法
    def get(self, request):
        return render(request, "login.html", {})

    def post(self, request):
        # request.POST会把我们页面中的username 和 password 去和我们定义的form去比对
        # 并且我们html中字段的name 需要和我们定义的form字段的name 保持一致
        login_form = LoginForm(request.POST)
        # form校验  检查errors 是否为null
        if login_form.is_valid():
            user_name = request.POST.get("username", "")
            pass_word = request.POST.get("password", "")
            # 如果user存在取出user,否则为null,这里我们只能通过我们的username登录,我们需要自定义
            user = authenticate(username=user_name, password=pass_word)
            if user is not None:
                if user.is_active:
                    # login方法帮助我们登录
                    login(request, user)
                    return render(request, 'index.html', {"login_form": login_form})
                else:
                    return render(request, 'login.html', {"msg": "用户名或者密码错误!"})
            else:
                return render(request, 'login.html', {"msg": "用户名或者密码错误!"})

        else:
            return render(request, 'login.html', {"login_form": login_form})


class RegisterView(View):
    def get(self, request):
        register_form = RegisterForm()
        return render(request, "register.html", {'register_form': register_form})

    def post(self, request):
        register_form = RegisterForm(request.POST)
        # html的name和form中的name要一致
        if register_form.is_valid():
            user_name = request.POST.get("email", "")
            # 如果邮箱已经注册 显示提示信息, 并进行数据回显
            if UserProfile.objects.filter(email=user_name):
                return render(request, 'register.html', {"register_form": register_form, "msg": "用户已经存在"})
            pass_word = request.POST.get("password", "")
            user_profile = UserProfile()
            user_profile.username = user_name
            user_profile.email = user_name
            # 表明用户还未激活
            user_profile.is_active = False
            # 对明文加密 from django.contrib.auth.hashers import make_password
            user_profile.password = make_password(pass_word)
            # 用户保存
            user_profile.save()

            send_register_email(user_name, "register")
            return render(request, 'login.html')
        else:
            return render(request, 'register.html', {"register_form": register_form})


# email激活用户
class ActiveUserView(View):
    def get(self, request, active_code):
        all_records = EmailVerifyRecord.objects.filter(code=active_code)
        if all_records:
            for record in all_records:
                email = record.email
                user = UserProfile.objects.get(email=email)
                user.is_active = True
                user.save()
        else:
            return render(request, 'active_fail.html')
        return render(request, 'login.html')


# 忘记密码
class ForgetPwdView(View):
    def get(self, request):
        forget_form = ForgetForm()
        return render(request, "forgetpwd.html", {"forget_form": forget_form})

    def post(self, request):
        forget_form = ForgetForm(request.POST)
        if forget_form.is_valid():
            email = request.POST.get("email", "")
            send_register_email(email, "forget")
            return render(request, "send_success.html")
        else:
            return render(request, "forgetpwd.html", {"forget_form": forget_form})


# 到达重置密码页面
class ResetView(View):
    def get(self, request, active_code):
        all_records = EmailVerifyRecord.objects.filter(code=active_code)
        if all_records:
            for record in all_records:
                email = record.email
                return render(request, 'password_reset.html', {'email': email})
        else:
            return render(request, 'active_fail.html')
        return render(request, 'login.html')


# 重置密码
class ModifyPwdView(View):
    def post(self, request):
        modify_form = ModifyPwdForm(request.POST)
        if modify_form.is_valid():
            pwd1 = request.POST.get("password1", "")
            pwd2 = request.POST.get("password2", "")
            email = request.POST.get("email", "")
            if pwd1 != pwd2:
                return render(request, "password_reset.html", {'email': email, "msg": "密码不一致"})
            user = UserProfile.objects.get(email=email)
            user.password = make_password(pwd1)
            user.save()
            return render(request, 'login.html')
        else:
            email = request.POST.get("email", "")
            return render(request, "password_reset.html", {'email': email, "modify_form": modify_form})

