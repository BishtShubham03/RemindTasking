import os
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.executors.pool import ThreadPoolExecutor, ProcessPoolExecutor
from config import db_name, mongouser, mongopass
# from apscheduler.jobstores.mongodb import MongoDBJobStore
from utils import send_push_notification
from utils.logger import setup_logger
from utils.slack_integration import slack_message


logger = setup_logger(__name__)


class APS_Schedule(object):
    """docstring for APS_Schedule"""

    def __init__(self):
        executors = {
            'default': ThreadPoolExecutor(20),
            'processpool': ProcessPoolExecutor(5)
        }

        # jobstores = {
        #     'mongo': MongoDBJobStore(collection='SchedularJobs', database='chatdb',
        #                              host=db_name, port=27017,
        #                              username=mongouser, password=mongopass),
        # }

        job_defaults = {
            'coalesce': True,
            'max_instances': 5,
            'misfire_grace_time': 1000
        }
        self.scheduler = BackgroundScheduler(
            executors=executors, job_defaults=job_defaults)

        self.scheduler.start()
        print('Press Ctrl+{0} to exit'.format('Break' if os.name == 'nt' else 'C'))
        # Execution will block here until Ctrl+C (Ctrl+Break on Windows) is pressed.

    def add_execution_reminder(self, fcm_tokens, msg_title, msg_body, execution_time,
                              user_id, notif_type, type_id):
        try:
            self.scheduler.add_job(_send_notification, 'date', run_date=execution_time,
                                   args=[fcm_tokens, msg_title, msg_body,
                                         user_id, notif_type, type_id],
                                   id=str(type_id), replace_existing=True)
            return True
        except Exception as e:
            print(str(e))
            logger.critical(
                "couldnt add the job from schedular with exception : {}".format(str(e)))

    def remove_execution_reminder(self, job_id, job_type):
        try:
            print('before deleting the job.')
            job_del = self.scheduler.remove_job(str(job_id))
            print(job_del, 'after delete')
            return True

        except Exception as e:
            logger.critical(
                "couldnt remove the job from schedular with exception : {}".format(str(e)))

    def pause_jobs(self):
        try:
            self.scheduler.pause()
            return True
        except Exception as e:
            logger.error("couldnt pause the schedular with exception : {}".format(str(e)))

    def resume_jobs(self):
        try:
            self.scheduler.resume()
            return True
        except Exception as e:
            logger.error("couldnt resume the schedular with exception : {}".format(str(e)))

    def shutdown_schedular(self):
        try:
            sch = self.scheduler.shutdown()
            return sch
        except Exception as e:
            logger.error("couldnt shutdown the schedular with exception : {}".format(str(e)))
