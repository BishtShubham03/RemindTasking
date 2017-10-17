import falcon
from falcon_cors import CORS

from project.api.Logins import Login, LogOut
from project.api.UserAccounts import Register, ActivateAccount, ResendAccountActivationOTP, ForgotPassword, ResetPassword, ResendResetPasswordOTP, ChangePassword


cors = CORS(allow_origins_list=['http://127.0.0.1:8889'],
            allow_all_headers=True,
            allow_methods_list=['GET', 'POST', 'OPTIONS', 'PUT', 'DELETE'])


app = falcon.API(middleware=[cors.middleware])

login = Login()
logout = LogOut()
register_user = Register()
activate_account = ActivateAccount()
resend_account_OTP = ResendAccountActivationOTP()
forgot_pass = ForgotPassword()
reset_pass = ResetPassword()
resend_reset_OTP = ResendResetPasswordOTP()
change_pass = ChangePassword()

app.add_route("/api/login/", login)
app.add_route("/api/logout/", logout)
app.add_route("/api/register/", register_user)
app.add_route("/api/activate-account/", activate_account)
app.add_route("/api/resend-account-activation-otp/", resend_account_OTP)
app.add_route("/api/forgot-password/", forgot_pass)
app.add_route("/api/resend-otp/", resend_reset_OTP)
app.add_route("/api/reset-password/", reset_pass)
app.add_route("/api/change-password/", change_pass)