from datetime import datetime, timedelta
from project.model.models import *
from random import randint


def generate_and_save_otp(user_id, otp_type):

    otp = randint(100000, 999999)
    # Remove all old otp request data by user and then add it
    session.query(Otp).filter(and_(Otp.user_id == user_id, Otp.otp_type == otp_type)).delete()

    save_otp = Otp(user_id, otp, otp_type)
    session.add(save_otp)
    session.commit()
    return otp

def clear_expired_otps(otp_type, expiry_interval, user_id):
    """ deletes all expired OTPs

    Args:
        otp_type: OTP type (int)
        expiry_interval: expiry interval for OTP in seconds (int)
    """

    allow_time = datetime.now() - timedelta(seconds=expiry_interval)
    session.query(Otp).filter(and_(Otp.created < allow_time, Otp.otp_type == otp_type,
                                   Otp.user_id == user_id)).delete()
