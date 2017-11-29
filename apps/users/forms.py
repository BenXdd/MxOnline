# _*_ coding: utf-8 _*_
__date__ = '2017/11/21 14:41'
from django import forms
from captcha.fields import CaptchaField


class LoginForm(forms.Form):
    # 为什么要使用form:
    #     1.如果不用form post请求会写很多东西
    #     2.form可以对我们的表单进行validate
    # required=True该字段必须存在
    username = forms.CharField(required=True)
    password = forms.CharField(required=True, min_length=5)


class RegisterForm(forms.Form):
    # 里面包含email的正则
    email = forms.EmailField(required=True)
    password = forms.CharField(required=True, min_length=5)
    captcha = CaptchaField(error_messages={'invalid': u"验证码错误"})


class ForgetForm(forms.Form):
    # 里面包含email的正则
    email = forms.EmailField(required=True)
    captcha = CaptchaField(error_messages={'invalid': u"验证码错误"})


class ModifyPwdForm(forms.Form):
    password1 = forms.CharField(required=True, min_length=5)
    password2 = forms.CharField(required=True, min_length=5)
