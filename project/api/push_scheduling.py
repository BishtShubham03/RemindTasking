import tornado.web
from libs.db import DbOps
from utils.logger import setup_logger
from libs.APSchedular import apiSchedule
from utils.slack_integration import slack_message
from libs.auth import verify_jwt


logger = setup_logger(__name__)
db_instance = DbOps()

APS = apiSchedule.APS_Schedule()


class BookingScheduling(tornado.web.RequestHandler):

    @verify_jwt
    def post(self):
        try:
            args = tornado.escape.json_decode(self.request.body)
            msg_title = args.get('message_title', '')
            msg_body = args.get('message_body', '')
            execution_time = args.get('execution_time', None)
            type_id = args.get('type_id', None)
            notif_type = args.get('notif_type', '')
            user_id = args.get('user_id', '')
            print('inside sched vbjknkns')

            # ToDo check for the condition for the None fcm data
            tokens = db_instance.get_fcm_token(uid=user_id).data.get("fcm_tokens", None)
            if tokens:
                fcm_tokens = [token for token in tokens]
            else:
                fcm_tokens = None

            if msg_body and fcm_tokens:
                save_job = db_instance.schedule_add_job(
                    user_id, msg_body, execution_time, type_id, notif_type)

                if save_job.status:
                    APS.add_execution_booking(fcm_tokens, msg_title, msg_body,
                                              execution_time, user_id, notif_type, type_id)
                    logger.info(
                        "Stored job in Schedular, user {}  and jobID {}".format(user_id, type_id))
                    self.write({'status': True,
                                'message': "successfully added Job to the databse/schedular."})
                else:
                    self.write({'status': True,
                                'message': save_job.message})
            else:
                logger.error("All the details are mandatory in Booking Scheduling\
                    for user_id {}".format(user_id))
                self.write({'status': True,
                            'message': "couldn't add the scheduling for booking."})

        except Exception as e:
            self.set_status(203)
            message = "couldn't add scheduling job."
            self.write({'status': False,
                        'message': message})
            cause = "[POSTMAN-SCHEDULING]" + str(e)
            slack_message('dmalert', cause)
            print("from add booking scheduling", str(e))
            logger.critical("couldn't add the scheduling for booking..with cause {}".format(str(e)))

    @verify_jwt
    def delete(self):
        try:
            args = tornado.escape.json_decode(self.request.body)

            type_id = args.get('type_id', None)
            notif_type = args.get('notif_type', '')
            user_id = args.get('user_id', '')
            APS.remove_execution_booking(type_id, notif_type)
            logger.info("Deleted the booking job after from APS for user {}".format(user_id))
            # Delete the job from the mongoDB database.
            db_instance.schedule_remove_job(user_id, type_id, notif_type)
            logger.info("job deleting from mongoDB with ID : {}".format(type_id))
            self.write({'status': True,
                        'message': "successfully deleted the users Job from databse"})
        except Exception as e:
            self.set_status(203)
            message = "couldn't delete scheduling job."
            self.write({'status': False,
                        'message': message})
            cause = "[SCHEDULING-DELETE]" + str(e)
            slack_message('dmalert', cause)
            logger.critical(
                "couldn't delete the scheduling for booking..with cause {}".format(str(e)))
