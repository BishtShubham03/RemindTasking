import falcon
import hashlib
import hmac
import json
import re

from base64 import b64decode, b64encode
from email_validator import validate_email, EmailNotValidError, EmailSyntaxError
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import BadSignature, SignatureExpired

from project.component.email import tech_alert_mail
from project.component.loggings import set_up_logging
from project.model.models import *
from project.model.models import AuthUser

logger = set_up_logging()


def validate_auth_req(func):
    def wrapper(*args):
        try:
            resp = args[2]
            access_token = args[1].get_header('Authorization')
            refresh_token = args[1].get_header('Refresh-Token')
            user = AuthUser(access_token, refresh_token)
            user.try_access_token()
            if user.id:
                if user.is_active():
                    func(*args, user.id, user.access_token)
                else:
                    resp.status = falcon.HTTP_203
                    resp.body = json.dumps(
                        {'status': False,
                            'message': 'User is disabled in database.',
                            'token': {'access_token': ''}})
                    logger.error("[validate_token] User {} is disabled in db".format(user.id))
            else:
                user.try_refresh_token()
                if user.id:
                    if user.db_cross_validated():
                        logger.info("[validate_token] Valid Refresh Token for {}".format(user.id))
                        func(*args, user.id, user.access_token)
                    else:
                        resp.status = falcon.HTTP_203
                        resp.body = json.dumps(
                            {'status': False,
                                'message': 'Unauthorized access',
                                'token': {'access_token': ''}})
                        logger.critical("[validate_token] Expired Refresh Token")
                else:
                    resp.status = falcon.HTTP_203
                    resp.body = json.dumps(
                        {'status': False,
                            'message': 'Unauthorized access',
                            'token': {'access_token': ''}})
                    logger.error("[validate_token] Invalid Access & Refresh Token")
        except Exception as e:
            resp.status = falcon.HTTP_203
            resp.body = json.dumps(
                {'status': False,
                    'message': 'Unauthorized access',
                    'token': {'access_token': ''}})
            logger.critical(
                "[validate_token]  Unknown Exception: {}, args: {}, message: {}, user: {}".format(
                    type(e), e.args, e, user.id))
            tech_alert_mail(type(e), e.args, e)
    return wrapper


def validate_token(func):
    def wrapper(*args):
        try:
            resp = args[2]
            base64_access_token = args[1].get_header('Authorization')
            access_token, password = get_token_or_username_password(base64_access_token)
            user_id, created = verify_access_token(access_token)
            user_check = session.query(User).filter_by(id=user_id).first()

            if user_id:
                if not user_check.active:
                    resp.status = falcon.HTTP_203
                    resp.body = json.dumps({'status': False, 'message': 'User is disabled in database.',
                                            'token': {'access_token': ''}})
                    logger.error("[validate_token] User is disabled in database. user_id {}".format(user_id))
                else:
                    func(*args, user_id, access_token)
                    logger.info("[validate_token] Valid Access Token for user_id {}".format(user_id))

            else:
                refresh_token = args[1].get_header('Refresh-Token')
                token_or_username, password = get_token_or_username_password(refresh_token)
                user_id, created = verify_refresh_token(token_or_username)

                if user_id:
                    print("check db for refresh token")
                    is_valid_refresh_token = session.query(TokenManager).filter(and_(TokenManager.user_id == user_id, TokenManager.created == created)).first()
                    if is_valid_refresh_token:
                        access_token = generate_access_token(user_id, created)
                        logger.info("[validate_token] Valid Refresh Token for user_id {}".format(user_id))
                        func(*args, user_id, access_token)
                    else:
                        resp.status = falcon.HTTP_203
                        resp.body = json.dumps({'status': False, 'message': 'Unauthorized access', 'token': {'access_token': ''}})
                        logger.critical("[validate_token] Expired Refresh Token")
                else:
                    resp.status = falcon.HTTP_203
                    resp.body = json.dumps({'status': False, 'message': 'Unauthorized access', 'token': {'access_token': ''}})
                    logger.error("[validate_token] Invalid Access & Refresh Token")

        except Exception as e:
            resp.status = falcon.HTTP_203
            resp.body = json.dumps({'status': False, 'message': 'Unauthorized access', 'token': {'access_token': ''}})
            logger.critical(
                "[validate_token] Invalid Token for user_id {} with [error]: type: {}, args: {}, message: {}".format(
                    user_id, type(e), e.args, e))
            tech_alert_mail(type(e), e.args, e)
            session.rollback()

    return wrapper


def validate_login_detail(func):
    def wrapper(*args):
        try:
            resp = args[2]
            authorization_header = args[1].get_header('Authorization')
            email, password = get_token_or_username_password(authorization_header)
            if email and validate_email(email, check_deliverability=False):
                email = email.lower()
                user = session.query(User).filter_by(email=email).first()
            else:
                user = None
                logger.error("[validate_login_detail] Try to login with Invalid/Null Email ID : {}".format(email))
            if user:
                if user.active:
                    signed_password = get_hmac_digest(password)
                    is_valid_password = is_password_valid(signed_password, user.password)
                    if is_valid_password:
                        if user.confirmed:
                            logger.info("[validate_login_detail] Valid Login Detail for user_id {}".format(user.id))
                            func(*args, user)
                        else:
                            resp.status = falcon.HTTP_203
                            resp.body = json.dumps({'status': True, 'confirmed': False, 'message': 'Please verify your account.'})
                            logger.critical("[validate_login_detail] Inactive account for user_id {}".format(user.id))
                        return
                    else:
                        resp.status = falcon.HTTP_203
                        status = False
                        message = 'Wrong password. Try again.'
                        logger.error("[validate_login_detail] Wrong Password for user_id {}".format(user.id))

                else:
                    resp.status = falcon.HTTP_203
                    status = False
                    message = 'Your account is disabled, Contact Community Team.'
                    logger.critical("[validate_login_detail] Disable account login for user_id {}".format(user.id))

            else:
                resp.status = falcon.HTTP_203
                status = False
                message = "Sorry, CoWrks Connect doesn't recognize that email."
                logger.info("[validate_login_detail] Invalid Email id {}".format(email))

        except (EmailNotValidError, EmailSyntaxError) as e:
            cause = 'Error key: ' + str(e.args[0])
            message = 'Invalid Email ID'
            status = False
            resp.status = falcon.HTTP_203
            logger.critical("Validate Login: Invalid/Null Email with Email ID : {}".format(email))

        except Exception as e:
            resp.status = falcon.HTTP_203
            message = 'Something went wrong, Please try again',
            status = False
            logger.info("[validate_login_detail] email {} with [error]: type: {}, args: {}, message: {}".format(email, type(e), e.args, e))
            tech_alert_mail(type(e), e.args, e)
            session.rollback()
        resp.body = json.dumps({'status': status,
                                'message': message,
                                'data': {}
                                })
    return wrapper


def is_password_valid(signed_password, db_password,):

    return hash.pbkdf2_sha512.verify(signed_password, db_password )


def verify_access_token(token):
    s = Serializer(ACCESS_TOKEN_SECRET_KEY)
    try:
        data = s.loads(token)
    except SignatureExpired:
        return None, None
    except BadSignature:
        return None, None
    user_id = data['id']
    created = data['created']
    return user_id, created


def verify_refresh_token(token):

    s = Serializer(REFRESH_TOKEN_SECRET_KEY)
    try:
        data = s.loads(token)
    except SignatureExpired:
        return None, None
    except BadSignature:
        return None, None
    user_id = data['id']
    created = data['created']
    return user_id, created


def get_token_or_username_password(authorization_header):
    try:
        split = authorization_header.split(' ')
        username = ''
        password = ''
        if len(split) == 1:
            temp_token = b64decode(split[0])
            decoded_temp_token = temp_token.decode('ascii')
            username, password = str(decoded_temp_token).split(':', 1)

        elif len(split) == 2:
            if split[0].strip().lower() == 'basic':
                temp_token = b64decode(split[1])
                decoded_temp_token = temp_token.decode('ascii')
                username, password = str(decoded_temp_token).split(':', 1)
    except:
        username = ''
        password = ''
    return username, password


def generate_refresh_token(user_id, created):
    s = Serializer(REFRESH_TOKEN_SECRET_KEY, expires_in=REFRESH_TOKEN_AGE)
    refresh_token = s.dumps({'id': user_id, 'created': created})
    return refresh_token.decode('ascii')


def generate_access_token(user_id, created):
    s = Serializer(ACCESS_TOKEN_SECRET_KEY, expires_in=ACCESS_TOKEN_AGE)
    access_token = s.dumps({'id': user_id, 'created':created})
    return access_token.decode('ascii')


# user_type = 0  for normal user, user_type = 1 for admin user
def get_token_manager_secret_key(user_id, user_type=0):
    created = str(datetime.now())
    save_secret_key = TokenManager(user_id, created, user_type)
    session.add(save_secret_key)
    session.commit()

    return created


def get_hmac_digest(password):
    encoded_password = password.encode('utf-8')
    hash_password = hmac.new(SECURITY_PASSWORD_SALT, encoded_password, hashlib.sha512)
    digest = b64encode(hash_password.digest())
    signed_password = digest.decode('ascii')
    # hash.pbkdf2_sha512.verify(signed, dbPassword)
    return signed_password
