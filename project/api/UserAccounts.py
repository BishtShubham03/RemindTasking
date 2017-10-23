import falcon
import json
import re
import string
from email_validator import validate_email, EmailNotValidError, EmailSyntaxError

from project.component.otp import *
from project.component.token import validate_token, get_hmac_digest
from project.component.loggings import set_up_logging
from project.component.date_util import validate_date
from project.component.email import send_email
from project.model.models import *
# from project.component.response import *

logger = set_up_logging()


class Register(object):
    def on_post(self, req, res):
        try:
            logger.info("User Request Details,\
                remote Address: {}, user agent: {}".format(req.remote_addr, req.user_agent))
            json_data = json.loads(req.stream.read().decode('utf8'))
            email = validate_email(json_data['email'].lower(), check_deliverability=False)['email']
            small_first_name = json_data['first_name']
            first_name = string.capwords(small_first_name)
            small_last_name = json_data.get('last_name', None)
            last_name = string.capwords(small_last_name) if small_last_name is not None else ''

            password = json_data['password']

            date_of_birth = None if json_data['date_of_birth'] is "" else json_data['date_of_birth']
            phone_number = None if json_data['phone_number'] is "" else json_data['phone_number']

            if validate_date(date_text=date_of_birth) or not date_of_birth:

                if re.search(r'^(?=.*?\d)(?=.*?[A-Za-z])[A-Za-z\d@#$%^&*+-=!~`()]{8,}$', password):
                    is_registered_user = session.query(User).filter_by(email=email).first()
                    if is_registered_user:
                        status = False
                        message = 'This Email ID is already registered with us.'
                        res.status = falcon.HTTP_203
                        logger.error("Email ID is already registered as {}".format(email))

                    else:
                        signed_password = get_hmac_digest(password)
                        user = User(
                            first_name=first_name,
                            last_name=last_name,
                            email=email,
                            password=signed_password,
                            confirmed=False,
                            date_of_birth=date_of_birth,
                            phone_number=phone_number
                        )

                        user.active = True
                        session.add(user)
                        session.commit()

                        otp_type = 1
                        otp = generate_and_save_otp(user.id, otp_type)
                        print(otp)
                        # body = str(otp) + " : Activation Code to Activate Account"
                        # subject = "Activate Account"
                        # full_name = user.first_name + ' ' + user.last_name
                        # params = {'name':full_name, 'otp': otp, 'email': user.email, 'body': body}

                        # send_email(params, subject)

                        status = True
                        message = 'You have been registered successfully.OTP sent to emailID'
                        res.status = falcon.HTTP_201
                        logger.info("Register Account Successfully with Email ID {}".format(email))

                else:
                    status = False
                    message = 'Password should be at least 8 characters long and alphanumeric.'
                    res.status = falcon.HTTP_203
                    logger.critical("Register: Invalid Password with Email ID {}".format(email))

            else:
                status = False
                message = 'Invalid Date of Birth Format'
                res.status = falcon.HTTP_203
                logger.critical("Register: Invalid DOB {} Email ID : {}".format(date_of_birth, email))

        except ValueError as e:
            cause = 'literal Error: {} '.format(str(e))
            res.status = falcon.HTTP_203
            message = 'Server type conversion Error.'
            res.body = json.dumps({'status': False,
                                   'message': 'Server type conversion Error.'
                                   })
            logger.critical('Value conversion error.\
                             cause {} '.format(cause))
            session.rollback()

        except UnboundLocalError as e:
            cause = "variable referenced Error: {} ".format(str(e))
            res.status = falcon.HTTP_203
            message = 'Server variable referenced Error.'
            res.body = json.dumps({'status': False,
                                   'message': 'Server variable referenced Error.'
                                   })
            logger.critical('variable Error.\
                             cause {}'.format(cause))

            session.rollback()

        except (EmailNotValidError, EmailSyntaxError) as e:
            cause = 'Error key: ' + str(e.args[0])
            status = False
            message = 'Invalid Email ID'
            res.status = falcon.HTTP_203
            logger.critical("Account: Invalid/Null Email ID : {}".format(json_data['email']))
            tech_alert_mail(type(e), message, cause)

        except KeyError as e:
            cause = 'Error key: ' + str(e.args[0])
            res.status = falcon.HTTP_203
            message = 'Server key Error.'
            res.body = json.dumps({'status': False,
                                   'message': 'Server key Error.'
                                   })
            logger.critical('Key error cause {}'.format(e.args[0]))
            session.rollback()

        except Exception as e:
            status = False
            message = 'Invalid Input Data. Please contact the community team.'
            res.status = falcon.HTTP_203
            logger.critical("Account: type: {}, args: {}, message: {}".format(type(e), e.args, e))
            session.rollback()

        res.body = json.dumps({'status': status, 'message': message})


class ActivateAccount:
    def on_post(self, req, res):
        try:
            logger.info("User Request Details,\
                remote Address: {}, user agent: {}".format(req.remote_addr, req.user_agent))
            json_data = json.loads(req.stream.read().decode('utf8'))
            otp_type = 1
            try:
                email = json_data['email'].lower()
            except Exception:
                status = False
                message = 'Invalid Email ID, please use valid email ID.'
                res.status = falcon.HTTP_203
                res.body = json.dumps({'status': status, 'message': message})
                logger.error("Account Activation: Invalid Email ID")
                return

            try:
                otp = int(json_data['otp'])
            except Exception:
                status = False
                message = 'Invalid Activation Code, please try again.'
                res.status = falcon.HTTP_203
                res.body = json.dumps({'status': status, 'message': message})
                logger.error("Account: Used character instead of Int OTP email {}".format(email))
                return

            user = session.query(User).filter_by(email=email).first()
            if user:
                if not user.confirmed:
                    clear_expired_otps(otp_type=otp_type, expiry_interval=86400, user_id=user.id)
                    otp_detail = session.query(Otp).filter(and_(Otp.user_id == user.id, Otp.otp_type == otp_type)).first()

                    if otp_detail:
                        if otp_detail.attempt < 3:
                            if otp_detail.otp == otp:

                                user.confirmed = True
                                user.confirmed_at = datetime.now()
                                session.commit()

                                session.delete(otp_detail)
                                session.commit()

                                subject = "Your account has been activated successfully"
                                message = 'Your account has been activated. You can now log in'

                                full_name = user.first_name + ' ' + user.last_name
                                params = {'name': full_name, 'email': user.email, 'otp': otp}

                                send_email(subject=subject,
                                           params=params)

                                status = True
                                res.status = falcon.HTTP_201

                                logger.info("Account Activation: with email {}".format(email))

                            else:
                                # Increase count for no. of attempt
                                otp_detail.attempt = otp_detail.attempt + 1
                                otp_detail.modified = datetime.now()
                                session.add(otp_detail)
                                session.commit()

                                status = False
                                message = 'Wrong Activation Code, please try again.'
                                res.status = falcon.HTTP_203
                                logger.error("Account: Wrong Activation Code with email {}".format(email))

                        else:
                            session.delete(otp_detail)
                            session.commit()

                            otp = generate_and_save_otp(user.id, otp_type)
                            subject = str(otp) + " : Activation Code to Activate Account"

                            full_name = user.first_name + ' ' + user.last_name
                            params = {'name': full_name, 'email': user.email, 'otp': otp}
                            send_email(subject, params)
                            status = False
                            message = 'Maximum attempts has been reached. Please check mail for new OTP'
                            res.status = falcon.HTTP_201
                            logger.info("Account: Maximum allowed attemp exceeded with email {}".format(email))

                    else:
                        otp = generate_and_save_otp(user.id, otp_type)
                        subject = str(otp) + " : Activation Code to Activate Account"
                        full_name = user.first_name + ' ' + user.last_name
                        params = {'name': full_name, 'email': user.email, 'otp': otp}
                        send_email(subject, params)
                        status = False
                        message = 'Your Activation Code is expired. Please check mail for new OTP'
                        res.status = falcon.HTTP_201
                        logger.error("Account Activation: OTP Expired with email {}".format(email))
                else:
                    status = False
                    message = 'Account already activated'
                    res.status = falcon.HTTP_203
                    logger.error("Account: Account Already activated with email {}".format(email))

            else:
                status = False
                message = 'Enter a registered email ID'
                res.status = falcon.HTTP_203
                logger.critical("Account Activated: Invalid email ID: {}".format(email))

            res.body = json.dumps({'status': status, 'message': message})

        except Exception as e:
            res.status = falcon.HTTP_203
            res.body = json.dumps({'status': False,
                                   'message': 'Something went wrong, Please try again'
                                   })
            logger.critical(
                "couldnt activate email {} with [error]: type: {}, args: {}, message: {}".format(
                    email, type(e), e.args, e))
            session.rollback()


class ResendAccountActivationOTP:
    def on_post(self, req, res):
        try:
            logger.info("User Request Details,\
                remote Address: {}, user agent: {}".format(req.remote_addr, req.user_agent))
            json_data = json.loads(req.stream.read().decode('utf8'))
            email = json_data['email'].lower()
            user = session.query(User).filter_by(email=email).first()
            otp_type = 1
            if user:
                if not user.confirmed:
                    # Delete all expire OTP
                    clear_expired_otps(otp_type=otp_type, expiry_interval=86400, user_id=user.id)
                    otp_detail = session.query(Otp).filter(and_(Otp.user_id == user.id, Otp.otp_type == otp_type)).first()

                    if otp_detail:
                        otp = otp_detail.otp
                    else:
                        otp = generate_and_save_otp(user.id, otp_type)

                    template_name = 'account-activation-otp-resend'
                    subject = str(otp) + " : Activation Code to Activate Account"

                    argument_dictionary = {
                        'first_name': user.first_name,
                        'otp': otp
                    }
                    full_name = user.first_name + ' ' + user.last_name
                    name_with_email = {'address': {'name': full_name, 'email': user.email}}
                    send_email(template_name, name_with_email, subject, argument_dictionary)

                    status = True
                    message = 'Activation Code has been sent to ' + user.email
                    res.status = falcon.HTTP_201
                    logger.critical("Resend Account Activation OTP: Successful for email ID: {}".format(email))
                else:
                    status = False
                    message = 'Account already activated'
                    res.status = falcon.HTTP_203
                    logger.error("Account Activation: Account Already activated with email {}".format(email))
            else:
                status = False
                message = 'Enter a registered email ID'
                res.status = falcon.HTTP_203
                logger.critical("Resend Account Activation OTP: Invalid email ID: {}".format(email))

            res.body = json.dumps({'status': status, 'message': message})

        except KeyError as e:
            cause = 'Error key: ' + str(e.args[0])
            res.status = falcon.HTTP_203
            message = 'Server key Error.'
            res.body = json.dumps({'status': False,
                                   'message': 'Server key Error.'
                                   })
            logger.critical('Key error in start Dict \
                             cause {}'.format(e.args[0]))
            tech_alert_mail(type(e), message, cause)
            session.rollback()

        except Exception as e:
            res.status = falcon.HTTP_203
            res.body = json.dumps({'status': False,
                                   'message': 'Something went wrong, Please try again'
                                   })
            logger.critical(
                "Resend Account Activation OTP: Unable to resend OTP for email {} with [error]: type: {}, args: {}, message: {}".format(
                    email, type(e), e.args, e))
            session.rollback()


class UserDetails:
    @validate_token
    def on_get(self, req, res, user_id, access_token):
        try:
            logger.info("User Request Details,\
                remote Address: {}, user agent: {}".format(req.remote_addr, req.user_agent))
            user = session.query(User).filter_by(id=user_id).first()

            if user:
                data = {
                    'user_id': user.id,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'email': user.email,
                    'date_of_birth': str(user.date_of_birth),
                    'phone_number': user.phone_number,

                }
                status = True
                message = 'Successfully fetched user details'
                res.status = falcon.HTTP_200
                logger.info("User Details: get for user_id {}".format(user_id))

            else:
                status = False
                message = 'Invalid User ID'
                data = {}
                res.status = falcon.HTTP_203
                logger.critical("User not available In Database with user_id {}".format(user_id))

            res.body = json.dumps({'status': status, 'message': message, 'data': data,
                                   'token': {'access_token': access_token}})

        except Exception as e:
            res.status = falcon.HTTP_203
            res.body = json.dumps({'status': False,
                                   'message': 'Something went wrong, Please try again'
                                   })
            logger.critical("User Details: unable to get details for user_id {} with\
             [error]: type: {}, args: {}, message: {}".format(user_id, type(e), e.args, e))
            session.rollback()
