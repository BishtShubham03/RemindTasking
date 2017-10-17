import datetime

from project.component.loggings import set_up_logging
logger = set_up_logging()

def validate_date(date_text):
    try:
        datetime.datetime.strptime(date_text, '%Y-%m-%d')
    except ValueError:
        logger.critical("Date format is wrong, should be YYYY-MM-DD")
        return False
    except TypeError:
        logger.critical("Date format is None")
        return False

    return True
