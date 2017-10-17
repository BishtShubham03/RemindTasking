from .sparkpostmail import sendSparkPostMail
from threading import Thread
from project.component.loggings import set_up_logging
from project.config import *
from datetime import datetime
import time
from project.config import COMMUNICATION_EMAIL


logger = set_up_logging()



def send_email(template_name, email, subject, argument_dictionary,
               attachments=[{}], cc_email=COMMUNICATION_EMAIL,):
    start_time = time.time()
    thr = Thread(target=send_email_via_thread, args=[template_name, email, subject,
                 argument_dictionary, attachments, cc_email])
    thr.start()
    overhead = time.time() - start_time
    logger.info("email in second = {}".format(overhead))
    return thr


def send_email_via_thread(template_name, email, subject, argument_dictionary,
                          attachments, cc_email=COMMUNICATION_EMAIL):
    try:
        start_time = time.time()

        if attachments == [{}]:
            # function to send email to a specified email ID
        else:
            # with arguments
            # (template_name, email, cc_email, subject,
            #                  argument_dictionary, attachments)

        overhead = time.time() - start_time
        logger.info("Email sent time in second = {}".format(overhead))

    except Exception as e:
        cause = str(e)
        logger.error("Email error : cause {}".format(cause))

