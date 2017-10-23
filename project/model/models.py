
# import falcon
from datetime import datetime
# from itsdangerous import (TimedJSONWebSignatureSerializer
#                           as Serializer, BadSignature, SignatureExpired)

from sqlalchemy import create_engine, Column, Integer, SmallInteger, String, ForeignKey, Boolean, DateTime, Date, Table, or_, and_, Text, ARRAY
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref, sessionmaker
from project.config import *
from project.component import auth_utils
# from passlib.handlers import pbkdf2
# import passlib.handlers.pbkdf2
from passlib import hash

from project.component.loggings import set_up_db_logging

logger = set_up_db_logging()


# Create a DBAPI connection
engine = create_engine(SQLALCHEMY_DATABASE_URI, echo=False)

# create a configured "Session" class
Session = sessionmaker(bind=engine)

# create a Session
session = Session()

try:
    session.commit()
except Exception:
    session.rollback()

# Declare an instance of the Base class for mapping tables
Base = declarative_base()


class AuthUser:
    """
    User class for authentication.
    Has the attributes and methods usefull for authentication
    """

    def __init__(self, access_token, refresh_token):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.id = None

    def is_active(self):
        if self.id:
            return auth_utils.is_active(self.id)
        else:
            raise Exception('User ID is None')

    def try_refresh_token(self):
        self.id, self.created = auth_utils.get_authorized_user(
            self.refresh_token, REFRESH_TOKEN_SECRET_KEY)

    def try_access_token(self):
        self.id, self.created = auth_utils.get_authorized_user(
            self.access_token, ACCESS_TOKEN_SECRET_KEY)
        if self.id:
            self.access_token = auth_utils.generate_access_token(
                self.id, self.created, ACCESS_TOKEN_SECRET_KEY, ACCESS_TOKEN_AGE)

    def db_cross_validated(self):
        if auth_utils.validate_refresh_token(self.id, self.created):
            self.access_token = auth_utils.generate_access_token(
                self.id, self.created, ACCESS_TOKEN_SECRET_KEY, ACCESS_TOKEN_AGE)
            return True
        else:
            return False


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True)
    first_name = Column(String(80))
    password = Column(String(255))
    active = Column(Boolean(), default=False)
    created = Column(DateTime(), default=datetime.now)
    confirmed_at = Column(DateTime())
    user_profile = relationship("UserProfile", back_populates="user")
    confirmed = Column(Boolean(), default=False)
    date_of_birth = Column(Date())
    phone_number = Column(String(20), default=None)

    # Added on 25-11-2016
    modified = Column(DateTime(), default=datetime.now)

    # Added on 30-10-2016 for generate otp for given user
    otp = relationship("Otp", back_populates="user")

    # Added on 12-11-2016
    token_manager = relationship("TokenManager", back_populates="user")
    reminders = relationship("Reminders", back_populates="user")

    def __init__(self, first_name, last_name, email, password,
                 phone_number, date_of_birth, confirmed):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.password = hash.pbkdf2_sha512.encrypt(password)
        self.phone_number = phone_number
        self.date_of_birth = date_of_birth
        self.confirmed = confirmed


class UserProfile(Base):
    """Model class for additional profile info abouot the user"""

    __tablename__ = 'user_profile'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    job_title = Column(String(80), default=None)
    profile_picture = Column(String(255), default=None)
    website = Column(String(255), default=None)
    about_me = Column(Text, default=None)
    created = Column(DateTime(), default=datetime.now)
    modified = Column(DateTime(), default=datetime.now)

    user = relationship("User", back_populates="user_profile")
    # user_skills = relationship("UserSkills", back_populates="user_profile")
    # user_interests = relationship("UserInterests", back_populates="user_profile")

    def __init__(self, user_id, job_title=None, profile_picture=None, website=None, about_me=None):
        self.job_title = job_title
        self.profile_picture = profile_picture
        self.website = website
        self.user_id = user_id
        self.about_me = about_me


class TokenManager(Base):
    __tablename__ = 'token_manager'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    created = Column(DateTime(), default=datetime.now)
    user_type = Column(SmallInteger, default=0)
    user = relationship("User", back_populates="token_manager")

    def __init__(self, user_id, created, user_type=0):
        self.user_id = user_id
        self.created = created
        self.user_type = user_type


class Otp(Base):
    __tablename__ = 'otp'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    otp = Column(Integer)
    otp_type = Column(SmallInteger, default=0)
    attempt = Column(SmallInteger, default=0)
    created = Column(DateTime(), default=datetime.now)
    modified = Column(DateTime(), default=datetime.now)

    user = relationship("User", back_populates="otp")

    def __init__(self, user_id, otp, otp_type):
        self.user_id = user_id
        self.otp = otp
        self.otp_type = otp_type


# Added on 25-11-2016
class UserHistory(Base):
    __tablename__ = 'user_history'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, default=0)
    email = Column(String(255))
    first_name = Column(String(80))
    last_name = Column(String(80))
    card = Column(String(15), default=None)
    password = Column(String(255))
    active = Column(Boolean(), default=False)
    confirmed = Column(Boolean(), default=False)
    date_of_birth = Column(Date())
    conf_credits = Column(Integer(), default=0)
    phone_number = Column(String(20), default=None)
    created = Column(DateTime(), default=datetime.now)
    modified = Column(DateTime(), default=datetime.now)
    confirmed_at = Column(DateTime())
    transfer_date = Column(DateTime(), default=datetime.now)


class Reminders(Base):
    """docstring for Reminders"""
    __tablename__ = 'reminders'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    message = Column(String(255), default=None)
    execution_time = Column(DateTime)
    user = relationship("User", back_populates="reminders")


class RemindersHistory(Base):
    """docstring for Reminders history"""
    __tablename__ = 'reminders_history'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    message = Column(String(255), default=None)
    execution_time = Column(DateTime)

# Close the connection
engine.dispose()