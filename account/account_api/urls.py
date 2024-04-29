from django.urls import path
from .views import RegistrationView, ActivateView, ActivationConfirmView, \
    GetCSRFToken, LoginView, UserDetailView, ChangePasswordView, DeleteAccount,\
    Logout, RestPasswordEmailView, RestPasswordView, ResetPasswordConfirmView, \
    CheckAuthenticatedView

urlpatterns = [
    path('account/csrf_cookie/', GetCSRFToken.as_view(),
         name='csrf_cookie'),
    path('account/check_auth/', CheckAuthenticatedView.as_view(),
         name='check_auth'),
    path('account/registration/', RegistrationView.as_view(),
         name='register'),
    path('account/activate/<str:uid>/<str:token>', ActivateView.as_view(),
         name='activate'),
    path('account/activate/', ActivationConfirmView.as_view(),
         name='activation_confirm'),
    path('account/login/', LoginView.as_view(),
         name='login'),
    path('account/user_details/', UserDetailView.as_view(),
         name='user_details'),
    path('account/change_password/', ChangePasswordView.as_view(),
         name='change_password'),
    path('account/delete_account/', DeleteAccount.as_view(),
         name='delete_account'),
    path('account/logout/', Logout.as_view(),
         name='logout'),
    path('account/rest_password/', RestPasswordEmailView.as_view(),
         name='rest_password_email'),
    path('account/reset_password/<str:uid>/<str:token>', RestPasswordView.as_view(),
         name='reset_password'),
    path('account/reset_password_confirmation/', ResetPasswordConfirmView.as_view(),
         name='rest_password_confirm'),
]
