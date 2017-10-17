import datetime
import logging
import logging.handlers
import os
import sys

# Logging Levels
# https://docs.python.org/3/library/logging.html#logging-levels
# CRITICAL	50
# ERROR	40
# WARNING	30
# INFO	20
# DEBUG	10
# NOTSET	0


def set_up_logging():
    file_path = sys.modules[__name__].__file__
    project_path = os.path.dirname(os.path.dirname(os.path.dirname(file_path)))
    log_location = project_path + '/logs/backend/'
    if not os.path.exists(log_location):
        os.makedirs(log_location)

    file_location = log_location + 'backend-logs'
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(message)s] [--> %(pathname)s [%(process)d]:]')

    if len(logger.handlers) is 0:
        lhandler = logging.handlers.TimedRotatingFileHandler(filename=file_location, when='D', interval=1
                                                             , backupCount=0, encoding=None, delay=False
                                                             , atTime=datetime.time(hour=1,
                                                                                    minute=0,
                                                                                    second=0))
        lhandler.suffix = '%Y-%m-%d'
        lhandler.setFormatter(formatter)
        logger.addHandler(lhandler)
    return logger


def set_up_db_logging():
    file_path = sys.modules[__name__].__file__
    project_path = os.path.dirname(os.path.dirname(os.path.dirname(file_path)))
    log_location = project_path + '/logs/db/'
    if not os.path.exists(log_location):
        os.makedirs(log_location)

    file_location = log_location + 'db-logs'

    logger = logging.getLogger('sqlalchemy.engine')
    logger.setLevel(logging.WARNING)
    if len(logger.handlers) is 0:
        lhandler = logging.handlers.TimedRotatingFileHandler(filename=file_location, when='D', interval=1
                                                             , backupCount=0, encoding=None, delay=False
                                                             , atTime=datetime.time(hour=1,
                                                                                    minute=0,
                                                                                    second=0))
        logger.addHandler(lhandler)
        lhandler.suffix = '%Y-%m-%d'
    return logger

