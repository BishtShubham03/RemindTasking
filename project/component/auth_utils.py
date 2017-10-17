import psycopg2
from project.config import SQLALCHEMY_DATABASE_URI
from itsdangerous import BadSignature, SignatureExpired
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from base64 import b64decode

conn = psycopg2.connect(SQLALCHEMY_DATABASE_URI)
cursor = conn.cursor()


def is_active(user_id):
    query = "SELECT active FROM public.user WHERE id={}".format(user_id)
    cursor.execute(query)
    return cursor.fetchone()[0]


def get_authorized_user(token, secret_key):
    s = Serializer(secret_key)
    try:
        data = s.loads(fetch_token(token))
        user_id = data['id']
        created = data['created']
    except (SignatureExpired, BadSignature) as e:
        user_id = None
        created = None
    return user_id, created


def fetch_token(token):
    try:
        split = token.split(' ')
        access_token = ''
        if len(split) == 1:
            temp_token = b64decode(split[0])
            decoded_temp_token = temp_token.decode('ascii')
            access_token, _ = str(decoded_temp_token).split(':', 1)
        elif len(split) == 2:
            if split[0].strip().lower() == 'basic':
                temp_token = b64decode(split[1])
                decoded_temp_token = temp_token.decode('ascii')
                access_token, _ = str(decoded_temp_token).split(':', 1)
    except Exception:
        access_token = ''
    return access_token


def validate_refresh_token(user_id, created):
    query = "SELECT * FROM public.token_manager WHERE user_id={} AND created='{}'".format(
        user_id, created)
    cursor.execute(query)
    return cursor.fetchone()


def generate_access_token(user_id, created, secret_key, age):
    s = Serializer(secret_key, expires_in=age)
    access_token = s.dumps({'id': user_id, 'created': created})
    return access_token.decode('ascii')
