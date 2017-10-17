WEBSITE_BASE_URL = '127.0.0.1'
WEBSITE_BASE_PORT = 8000
FalconEnvironment = 'DEV'
# DB username : postgres
# and password : postgres
SQLALCHEMY_DATABASE_URI = 'postgres://postgres:postgres@localhost:5432/remind_db'


REFRESH_TOKEN_SECRET_KEY = b'_-=\xba\xd0u\rI\x9e\xa8\x0f\x9e\x9c-Q\x18~\xa44\x18'
REFRESH_TOKEN_AGE = 7776000  # token is valid for 3 months.

ACCESS_TOKEN_SECRET_KEY = b'_-=\xba\xdd0u\rI\x9e\x5a8\x0f\x9e\x59c-Q\x18~\xad44\x18'
ACCESS_TOKEN_AGE = 900  # token is valid for 15 min

ADMIN_REFRESH_TOKEN_SECRET_KEY = b'_-=\xba\xd0u\rI\x9e\xa8\x0f\x9e\x9c-Q\x18~\xa44\x18'
ADMIN_REFRESH_TOKEN_AGE = 864000  # token is valid for 3 months.

ADMIN_ACCESS_TOKEN_SECRET_KEY = b'_-=\xba\xdd0u\rI\x9e\x5a8\x0f\x9e\x59c-Q\x18~\xad44\x18'
ADMIN_ACCESS_TOKEN_AGE = 900  # token is valid for 15 min

SECURITY_PASSWORD_SALT = b"xxx"

COMMUNICATION_EMAIL = 'shubhambisht03@hotmail.com'

# Sparkpost api key: 8cc4f80ad9d7b37a7d9578f4dcff1cca833b8be8
SPARK_POST_API_KEY = '8cc4f80ad9d7b37a7d9578f4dcff1cca833b8be8'
MAIL_DEFAULT_SENDER = 'shubhambisht03@gmail.com'
MAIL_SERVER = 'smtp.sparkpostmail.com'
MAIL_USE_TLS = True
MAIL_USERNAME ='SMTP_Injection'
MAIL_PASSWORD='79399154b486314e77721e24ecf5be002e293d9a'
MAIL_PORT = 587
# (Alternative Port: 2525)
# Authentication:AUTH LOGIN




ALERT_EMAIL = 'shubhambisht03@gmail.com'
