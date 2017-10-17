import falcon
import json
import re
import string
from email_validator import validate_email, EmailNotValidError, EmailSyntaxError

from project.component.otp import *
from project.component.token import validate_token, get_hmac_digest, is_password_valid
from project.component.loggings import set_up_logging
from project.component.date_util import validate_date
from project.component.email import send_email
from project.model.models import *
from project.component.response import *

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
                        logger.error("Register Account: Email ID is already registered as {}".format(email))

                    else:
                        
                        if True:
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

                            template_name = 'account-activation'
                            otp_type = 1
                            otp = generate_and_save_otp(user.id, otp_type)
                            subject = str(otp) + " : Activation Code to Activate Account"

                            argument_dictionary = {
                                'first_name': user.first_name,
                                'otp': otp
                            }
                            full_name = user.first_name + ' ' + user.last_name
                            name_with_email = {'address': {'name': full_name, 'email': user.email}}
                            send_email(template_name, name_with_email, subject, argument_dictionary)


                            status = True
                            message = 'You have been registered successfully. Activation Code has been sent to your registered email ID.'
                            res.status = falcon.HTTP_201
                            logger.info("Register Account Successfully with Email ID {}".format(email))

                        else:
                            status = False
                            message = 'Account ID is not valid. Please contact the team.'
                            res.status = falcon.HTTP_203
                            logger.critical("Register Account: Invalid with Email ID {}".format( email))
                else:
                    status = False
                    message = 'Password should be at least 8 characters long and alphanumeric.'
                    res.status = falcon.HTTP_203
                    logger.critical("Register Account: Invalid Password with Email ID {}".format(email))

            else:
                status = False
                message = 'Invalid Date of Birth Format'
                res.status = falcon.HTTP_203
                logger.critical("Register Account: Invalid DOB format {} with Email ID : {}".format(date_of_birth, email))

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
            logger.critical("Register Account: Invalid/Null Email with Email ID : {}".format(json_data['email']))
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
            logger.critical("Register Account: [error]: type: {}, args: {}, message: {}".format(type(e), e.args, e))
            
            session.rollback()

        res.body = json.dumps({'status': status, 'message': message})


class EditProfile(object):
    @validate_token
    def on_put(self, req, res, user_id, access_token):
        try:
            logger.info("User Request Details,\
                remote Address: {}, user agent: {}".format(req.remote_addr, req.user_agent))
            user = session.query(User).filter_by(id=user_id).first()
            if user:
                date_of_birth = req.params['date_of_birth']
                phone_number = req.params['phone_number']
                date_of_birth, phone_number = self._verify_params(date_of_birth, phone_number)
                logger.info('fetched dob and phone number {}'.format(phone_number))
                user.date_of_birth = date_of_birth
                user.phone_number = phone_number
                session.commit()
                status = True
                message = 'Profile has been edited successfully'
                res.status = falcon.HTTP_201
                logger.info("Profile has been edited successfully with User ID : {}".format(user_id))
            else:
                status = False
                message = 'Could not fetch user profile'
                res.status = falcon.HTTP_203
                logger.critical("Could not fetch user profile with User ID : {}".format(user_id))
        except ValueError as e:
            status = False
            cause = 'literal Error: {} '.format(str(e))
            res.status = falcon.HTTP_203
            message = 'Invalid attribute values'
            res.body = json.dumps({'status': False,
                                   'message': 'Invalid attribute values'
                                   })
            logger.critical('Invalid attribute values.\
                             cause {} '.format(cause))
                        session.rollback()
        except KeyError as e:
            status = False
            res.status = falcon.HTTP_203
            message = 'Missing attributes: {}'.format(e)
            res.body = json.dumps({'status': False,
                                   'message': message
                                   })
            logger.critical(message)
                        session.rollback()
        except Exception as e:
            status = False
            message = 'Invalid Input Data. Please contact the community team.'
            res.status = falcon.HTTP_203
            logger.critical("Edit Account: [error]: type: {}, args: {}, message: {}".format(type(e), e.args, e))
            
            session.rollback()
        res.body = json.dumps({'status': status, 'message': message, 'token': {'access_token' : access_token}})

    def _verify_params(self, dob, phone):
        logger.info('Params for verification: {} and {}'.format(dob, phone))
        # workaround - req object never showing the body, so had to pass empty string in
        # request params
        if dob == 'dummy':
            dob = None
        if phone == 'dummy':
            phone = None

        if dob and not validate_date(date_text=dob):
            raise ValueError
        if phone and not re.search(r'^\+?[\d\s-]*$', phone):
            raise ValueError('Phone number should a string with intigers and may or may not start with a + sign')
        return dob, phone

        


class ActivateAccount:
    def on_post(self, req, res):
        try:
            logger.info("User Request Details,\
                remote Address: {}, user agent: {}".format(req.remote_addr, req.user_agent))
            json_data = json.loads(req.stream.read().decode('utf8'))
            otp_type = 1
            try:
                email = json_data['email'].lower()
            except:
                status = False
                message = 'Invalid Email ID, please use valid email ID.'
                res.status = falcon.HTTP_203
                res.body = json.dumps({'status': status, 'message': message})
                logger.error("Account Activation: Invalid Email ID")
                return

            try:
                otp = int(json_data['otp'])
            except:
                status = False
                message = 'Invalid Activation Code, please try again.'
                res.status = falcon.HTTP_203
                res.body = json.dumps({'status': status, 'message': message})
                logger.error("Account Activation: Used character instead of Int OTP email {}".format(email))
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
                                template_name = "account-activation-successful"

                                message = 'Your account has been activated. You can now log in'


                                argument_dictionary = {
                                    'first_name': user.first_name,
                                    'otp': otp
                                }
                                full_name = user.first_name + ' ' + user.last_name
                                name_with_email = {'address': {'name': full_name, 'email': user.email}}
                                community_email = user.account.center.email
                                send_email(template_name=template_name
                                           , email=name_with_email
                                           , subject=subject
                                           , argument_dictionary=argument_dictionary
                                           , cc_email=community_email)

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
                                logger.error("Account Activation: Wrong Activation Code with email {}".format(email))

                        else:
                            session.delete(otp_detail)
                            session.commit()

                            otp = generate_and_save_otp(user.id, otp_type)
                            subject = str(otp) + " : Activation Code to Activate Account"
                            
                            argument_dictionary = {
                                'first_name': user.first_name,
                                'otp': otp
                            }
                            full_name = user.first_name + ' ' + user.last_name
                            name_with_email = {'address': {'name': full_name, 'email': user.email}}
                            send_email(name_with_email, subject, argument_dictionary)
                            status = False
                            message = 'Maximum allowed attempts has been reached. Please check mail for new OTP'
                            res.status = falcon.HTTP_201

                            logger.info("Account Activation: Maximum allowed attemp exceeded with email {}".format(email))

                    else:
                        otp = generate_and_save_otp(user.id, otp_type)
                        subject = str(otp) + " : Activation Code to Activate Account"
                        argument_dictionary = {
                            'first_name': user.first_name,
                            'otp': otp
                        }
                        full_name = user.first_name + ' ' + user.last_name
                        name_with_email = {'address': {'name': full_name, 'email': user.email}}
                        send_email(name_with_email, subject, argument_dictionary)
                        status = False
                        message = 'Your Activation Code has been expired. Please check mail for new OTP'
                        res.status = falcon.HTTP_201
                        logger.error("Account Activation: OTP Expired with email {}".format(email))
                else:
                    status = False
                    message = 'Account already activated'
                    res.status = falcon.HTTP_203
                    logger.error("Account Activated: Account Already activated with email {}".format(email))

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
                "Account Activation: Unable to activate account for email {} with [error]: type: {}, args: {}, message: {}".format(
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


class ForgotPassword:
    def on_post(self, req, res):
        try:
            logger.info("User Request Details,\
                remote Address: {}, user agent: {}".format(req.remote_addr, req.user_agent))
            json_data = json.loads(req.stream.read().decode('utf8'))
            email = json_data['email'].lower()
            user = session.query(User).filter_by(email=email).first()
            otp_type = 0
            if user:
                otp = generate_and_save_otp(user.id, otp_type)
                template_name = 'reset-password-request'
                subject = str(otp) + " : OTP to Reset Password"

                argument_dictionary = {
                    'first_name': user.first_name,
                    'otp': otp
                }
                full_name = user.first_name + ' ' + user.last_name
                name_with_email = {'address': {'name': full_name, 'email': user.email}}
                send_email(template_name, name_with_email, subject, argument_dictionary)

                status = True
                message = 'OTP has been sent to ' + user.email
                res.status = falcon.HTTP_201
                logger.info("Forgot Password: OTP sent to email ID: {}".format(email))

            else:
                status = False
                message = 'Enter a registered email ID'
                res.status = falcon.HTTP_203
                logger.critical("Forgot Password: Invalid email ID: {}".format(email))

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

        except Exception as e:
            res.status = falcon.HTTP_203
            res.body = json.dumps({'status': False,
                                   'message': 'Something went wrong, Please try again'
                                   })
            logger.critical("Forgot Password: unable to send OTP for email {} with [error]: type: {}, args: {}, message: {}".format(
                    email, type(e), e.args, e))
            
            session.rollback()


class ResendResetPasswordOTP:
    def on_post(self, req, res):
        try:
            logger.info("User Request Details,\
                remote Address: {}, user agent: {}".format(req.remote_addr, req.user_agent))
            json_data = json.loads(req.stream.read().decode('utf8'))
            email = json_data['email'].lower()
            user = session.query(User).filter_by(email=email).first()
            otp_type = 0
            if user:
                # Delete all expire OTP
                clear_expired_otps(otp_type=otp_type, expiry_interval=900, user_id=user.id)
                otp_detail = session.query(Otp).filter(and_(Otp.user_id == user.id, Otp.otp_type == otp_type)).first()
                if otp_detail:
                    otp = otp_detail.otp
                else:
                    otp = generate_and_save_otp(user.id, otp_type)

                template_name = 'resend-reset-password-otp'
                subject = str(otp) + " : OTP to Reset Password"
                argument_dictionary = {
                    'first_name': user.first_name,
                    'otp': otp
                }
                full_name = user.first_name + ' ' + user.last_name
                name_with_email = {'address': {'name': full_name, 'email': user.email}}
                send_email(template_name, name_with_email, subject, argument_dictionary)

                status = True
                message = 'OTP has been sent to ' + user.email
                res.status = falcon.HTTP_201
                logger.info("Resend Reset Password OTP: OTP sent to email ID: {}".format(email))
            else:
                status = False
                message = 'Enter a registered email ID'
                res.status = falcon.HTTP_203
                logger.info("Resend Reset Password OTP: Invalid email ID: {}".format(email))

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


        except Exception as e:
            res.status = falcon.HTTP_203
            res.body = json.dumps({'status': False,
                                   'message': 'Something went wrong, Please try again'
                                   })
            logger.critical("Unable to send OTP for email {} with [error]: type: {}, args: {}, message: {}".format(
                    email, type(e), e.args, e))

            session.rollback()


class ResetPassword:
    def on_post(self, req, res):
        try:
            logger.info("User Request Details,\
                remote Address: {}, user agent: {}".format(req.remote_addr, req.user_agent))
            json_data = json.loads(req.stream.read().decode('utf8'))
            email = json_data['email'].lower()
            user = session.query(User).filter_by(email=email).first()
            otp_type = 0
            if user:
                user_id = user.id
                otp = int(json_data['otp'])

                # Delete all expire OTP
                clear_expired_otps(otp_type=otp_type, expiry_interval=86400, user_id=user_id)
                otp_detail = session.query(Otp).filter(and_(Otp.user_id == user_id, Otp.otp_type == otp_type)).first()

                if otp_detail:
                    if otp_detail.attempt < 3:
                        if otp_detail.otp == otp:

                            new_password = json_data['new_password']

                            if re.search(r'^(?=.*?\d)(?=.*?[A-Za-z])[A-Za-z\d@#$%^&*+-=!~`()]{8,}$', new_password):
                                password_digest = get_hmac_digest(new_password)
                                user.password = hash.pbkdf2_sha512.encrypt(password_digest)
                                session.add(user)
                                session.commit()

                                # DELETE OTP
                                session.delete(otp_detail)
                                session.commit()

                                subject = "Password reset completed"

                                template_name = 'reset-password-confirmation'
                                argument_dictionary = {
                                    'first_name': user.first_name
                                }

                                full_name = user.first_name + ' ' + user.last_name
                                name_with_email = {'address': {'name': full_name, 'email': user.email}}
                                send_email(template_name, name_with_email, subject, argument_dictionary)

                                status = True
                                message = 'Your password has been reset. You can now log in with your new password.'
                                res.status = falcon.HTTP_202
                                logger.info("Reset Password: Successful for email {}".format(email))

                            else:
                                status = False
                                message = 'Password should be 8 characters long and alphanumeric.'
                                res.status = falcon.HTTP_203
                                logger.error("Reset Password: Fail for email {} due to invalid password".format(email))

                        else:
                            # Increase count for no. of attempt
                            otp_detail.attempt = otp_detail.attempt + 1
                            otp_detail.modified = datetime.now()
                            session.add(otp_detail)
                            session.commit()

                            status = False
                            message = 'Wrong OTP, please try again'
                            res.status = falcon.HTTP_203
                            logger.error("Reset Password: Wrong OTP for email {}".format(email))

                    else:
                        # DELETE OTP
                        session.delete(otp_detail)
                        session.commit()

                        otp = generate_and_save_otp(user_id, otp_type)
                        template_name = 'resend-reset-password-otp'
                        subject = str(otp) + " : OTP to Reset Password"
                        argument_dictionary = {
                            'first_name': user.first_name,
                            'otp': otp
                        }
                        full_name = user.first_name + ' ' + user.last_name
                        name_with_email = {'address': {'name': full_name, 'email': user.email}}
                        send_email(template_name, name_with_email, subject, argument_dictionary)

                        status = False
                        message = 'Maximum allowed attempts has been reached. Please check mail for new OTP'
                        res.status = falcon.HTTP_201
                        logger.error("Reset Password: Maximum attempt exceeded for OTP for email {}".format(email))

                else:
                    otp = generate_and_save_otp(user_id, otp_type)
                    template_name = 'resend-reset-password-otp'
                    subject = str(otp) + " : OTP to Reset Password"
                    argument_dictionary = {
                        'first_name': user.first_name,
                        'otp': otp
                    }
                    full_name = user.first_name + ' ' + user.last_name
                    name_with_email = {'address': {'name': full_name, 'email': user.email}}
                    send_email(template_name, name_with_email, subject, argument_dictionary)
                    status = False
                    message = 'OTP has expired. Please check your email for a new OTP'
                    res.status = falcon.HTTP_201
                    logger.error("Reset Password: OTP expired for email {}".format(email))

            else:
                status = False
                message = 'Enter a registered email ID'
                res.status = falcon.HTTP_203
                logger.critical("Reset Password: Invalid email {}".format(email))

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


        except Exception as e:
            res.status = falcon.HTTP_203
            res.body = json.dumps({'status': False,
                                   'message': 'Something went wrong, Please try again'
                                   })
            logger.critical(
                "Reset Password: for email {} with [error]: type: {}, args: {}, message: {}".format(
                    email, type(e), e.args, e))

            session.rollback()


class ChangePassword:
    @validate_token
    def on_post(self, req, res, user_id, access_token):
        try:
            logger.info("User Request Details,\
                remote Address: {}, user agent: {}".format(req.remote_addr, req.user_agent))
            json_data = json.loads(req.stream.read().decode('utf8'))
            user = session.query(User).filter_by(id=user_id).first()
            old_password = json_data['old_password']
            signed_password = get_hmac_digest(old_password)
            is_valid_password = is_password_valid(signed_password, user.password)

            if is_valid_password:
                new_password = json_data['new_password']
                if re.search(r'^(?=.*?\d)(?=.*?[A-Za-z])[A-Za-z\d@#$%^&*+-=!~`()]{8,}$', new_password):
                    new_password_digest = get_hmac_digest(new_password)
                    user.password = hash.pbkdf2_sha512.encrypt(new_password_digest)
                    session.commit()

                    # Delete all valid token for user
                    temp = session.query(TokenManager).filter(TokenManager.user_id == user_id).delete()
                    session.commit()
                    template_name = 'change-password-confirmation'
                    subject = 'Password Changed'
                    argument_dictionary = {
                        'first_name': user.first_name
                    }
                    full_name = user.first_name + ' ' + user.last_name
                    name_with_email = {'address': {'name': full_name, 'email': user.email}}
                    send_email(template_name, name_with_email, subject, argument_dictionary)
                    status = True
                    message = 'Password successfully changed.'
                    res.status = falcon.HTTP_201
                    logger.info("Change Password: successful for user_id {}".format(user_id))

                else:
                    status = False
                    message = 'Password should be 8 characters long and alphanumeric.'
                    res.status = falcon.HTTP_203
                    logger.error("Change Password: Fail due to invalid password for user_id {}".format(user_id))
            else:
                status = False
                message = 'Old password is incorrect.'
                res.status = falcon.HTTP_203
                logger.critical("Change Password: Fail due to wrong old password for user_id {}".format(user_id))

            res.body = json.dumps({'status': status, 'message': message, 'token': {'access_token' : access_token}})

        except KeyError as e:
            cause = 'Error key: ' + str(e.args[0])
            res.status = falcon.HTTP_203
            message = 'Server key Error.'
            res.body = json.dumps({'status': False,
                                   'message': 'Server key Error.'
                                   })
            logger.critical('Key error in start Dict \
                             cause {}'.format(e.args[0]))
            session.rollback()

        except Exception as e:
            res.status = falcon.HTTP_203
            res.body = json.dumps({'status': False,
                                   'message': 'Something went wrong, Please try again'
                                   })
            logger.critical("Change Password: unable to change password user_id {} with \
             [error]: type: {}, args: {}, message: {}".format(
                user_id, type(e), e.args, e))
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
                    'company_name': user.account.name,
                    'center_name': user.account.center.name,
                    'center_id': user.account.center_id,
                    # taking user printer credits from the papercut server
                    'date_of_birth': str(user.date_of_birth),
                    'phone_number': user.phone_number,
                    'city_id': user.city_id,
                    'city_name': user.city.name,
                    'floor_id': user.account.floor_id

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