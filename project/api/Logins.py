import json
from project.component.token import validate_token, validate_login_detail, generate_refresh_token, \
    get_token_manager_secret_key, generate_access_token, verify_access_token
from project.model.models import *
import falcon
from project.component.email import tech_alert_mail
from project.component.loggings import set_up_logging
logger = set_up_logging()


class Login:
    @validate_login_detail
    def on_get(self, req, res, user):
        try:
            refresh_token_manager_created = get_token_manager_secret_key(user.id)
            refresh_token = generate_refresh_token(user.id, refresh_token_manager_created)
            access_token = generate_access_token(user.id, refresh_token_manager_created)
            account_name = user.account.name
            res.status = falcon.HTTP_200
            res.body = json.dumps({'status': True,
                                   'confirmed': True,
                                   'data': {
                                            'duration': REFRESH_TOKEN_AGE,
                                            'first_name': user.first_name,
                                            'last_name': user.last_name,
                                            'email': user.email,
                                            },
                                   'token': {'access_token' : access_token,
                                             'refresh_token': refresh_token},
                                   'message': 'success'
                                   })

            logger.info("Login Successful with user_id {}".format(user.id))

        except Exception as e:
            res.status = falcon.HTTP_203
            res.body = json.dumps({'status': False,
                                   'message': 'Something went wrong, Please try again',
                                   'data': {}
                                   })
            logger.critical("Unable to send token detail for user_id {} with [error]: type: {}, args: {}, message: {}".format(user.id, type(e), e.args, e))
            tech_alert_mail(type(e), e.args, e)
            session.rollback()


class LogOut:
    @validate_token
    def on_get(self, req, res, user_id, access_token):

        try:
            user_id, created = verify_access_token(access_token)
            session.query(TokenManager).filter(and_(TokenManager.user_id == user_id, TokenManager.created == created, TokenManager.user_type == 0)).delete()
            session.commit()

            res.status = falcon.HTTP_200
            res.body = json.dumps({'message': 'success', 'status': True,
                                   'token': {'access_token': '',
                                             'refresh_token': ''}})

            logger.info("Log Out Successful with user_id {}".format(user_id))

        except Exception as e:
            res.status = falcon.HTTP_203
            res.body = json.dumps({'status': False,
                                   'message': 'Something went wrong, Please try again'
                                   })
            logger.critical("Unable to delete token detail for user_id {} with [error]: type: {}, args: {}, message: {}".format(user_id, type(e), e.args, e))
            tech_alert_mail(type(e), e.args, e)
            session.rollback()
