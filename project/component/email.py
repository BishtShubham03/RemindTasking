from .sparkpostmail import sendSparkPostMail
from threading import Thread
from project.component.loggings import set_up_logging
from project.config import *
from datetime import datetime
import time
from project.config import FalconEnvironment, COMMUNITY_EMAIL
# from celery import Celery

logger = set_up_logging()

# celery_app = Celery('project', broker='amqp://devuser:rabbitdev321@localhost/devuser_vhost',
#                     backend='rpc://', result_persistent=True)

# celery_app.conf.update(
#     result_expires=86400,
# )


def send_email(template_name, email, subject, argument_dictionary,
               attachments=[{}], cc_email=COMMUNITY_EMAIL,):
    start_time = time.time()
    thr = Thread(target=send_email_via_thread, args=[template_name, email, subject,
                 argument_dictionary, attachments, cc_email])
    thr.start()
    overhead = time.time() - start_time
    logger.info("Thread Creation Time for email in second = {}".format(overhead))
    return thr


# @celery_app.task(bind=True)
# add 'self' param also when bind=true.
def send_email_via_thread(template_name, email, subject, argument_dictionary,
                          attachments, cc_email=COMMUNITY_EMAIL):
    try:
        start_time = time.time()

        if attachments == [{}]:
            sendSparkPostMail(template_name, email, cc_email, subject, argument_dictionary)
        else:
            sendSparkPostMail(template_name, email, cc_email, subject,
                              argument_dictionary, attachments)

        overhead = time.time() - start_time
        logger.info("Email sent time in second = {}".format(overhead))

    except Exception as e:
        cause = str(e)
        logger.error("Tech Email error : cause {}".format(cause))


def tech_alert_mail(incident_type, incident_args, incident_detail):
    try:
        start_time = time.time()
        template_name = 'api-alert-mail'
        subject = "Critical Incident Alert at " + str(datetime.now())
        new_incident_type = str(incident_type).replace("'", "_")
        new_incident_type = str(new_incident_type).replace('"', "_")
        new_incident_args = str(incident_args).replace("'", "_")
        new_incident_args = str(new_incident_args).replace('"', "_")
        new_incident_detail = str(incident_detail).replace("'", "_")
        new_incident_detail = str(new_incident_detail).replace('"', "_")

        argument_dictionary = {
            'incident_type': new_incident_type,
            'incident_args': new_incident_args,
            'incident_detail': new_incident_detail
        }

        # temp_argument_dictionary = {}
        name_with_email = {'address': {'name': 'Server Alert', 'email': TECH_ALERT_EMAIL}}

        if FalconEnvironment == 'PROD':
            subject = '[PROD] ' + str(subject)

        # if FalconEnvironment == 'PROD' or FalconEnvironment == 'DEV':
        #     send_email(template_name, name_with_email, subject, argument_dictionary)

        send_email(template_name, name_with_email, subject, argument_dictionary)

        overhead = time.time() - start_time
        logger.info("Email sent time in second = {}".format(overhead))

    except Exception as e:
        cause = str(e)
        logger.error("Tech Email error : cause {}".format(cause))
