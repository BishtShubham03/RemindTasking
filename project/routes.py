import falcon
from falcon_cors import CORS

from project.api.Logins import Login, LogOut
from project.api.UserAccounts import Register, ActivateAccount, ResendAccountActivationOTP


cors = CORS(allow_origins_list=['http://127.0.0.1:8000','localhost'],
            allow_all_headers=True,
            allow_methods_list=['GET', 'POST', 'OPTIONS', 'PUT', 'DELETE'])


app = falcon.API(middleware=[cors.middleware])

login = Login()
logout = LogOut()
register_user = Register()
activate_account = ActivateAccount()
resend_account_OTP = ResendAccountActivationOTP()


app.add_route("/api/login/", login)
app.add_route("/api/logout/", logout)
app.add_route("/api/register/", register_user)
app.add_route("/api/activate-account/", activate_account)
app.add_route("/api/resend-account-activation-otp/", resend_account_OTP)
