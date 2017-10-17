
from project.component.loggings import setup_logger
from libs.APSchedular import apiSchedule

logger = setup_logger(__name__)

APS = apiSchedule.APS_Schedule()


class BookingScheduling(object):

    def on_post(self, req, res):
        try:
            args = json.loads(req.stream.read().decode('utf8'))
            msg_title = args.get('message_title', '')
            msg_body = args.get('message_body', '')
            execution_time = args.get('execution_time', None)
            type_id = args.get('type_id', None)
            notif_type = args.get('notif_type', '')
            user_id = args.get('user_id', '')
            print('inside sched vbjknkns')

            # save_job = db_instance.schedule_add_job(
            #     user_id, msg_body, execution_time, type_id, notif_type)

                if save_job.status:
                    APS.add_execution_booking(fcm_tokens, msg_title, msg_body,
                                              execution_time, user_id, notif_type, type_id)
                    logger.info(
                        "Stored job in Schedular, user {}  and jobID {}".format(user_id, type_id))
                    status = True
                    message = "successfully added Job to the databse/schedular."

                    res.body = json.dumps({'status': status, 'message': message})
                else:
                    status = True
                    message = "not saved"
                    res.body = json.dumps({'status': status, 'message': message})
            else:
                logger.error("All the details are mandatory in Booking Scheduling\
                    for user_id {}".format(user_id))
                status = True
                message = "couldn't add the scheduling for booking."

        except Exception as e:
            self.set_status(203)
            message = "couldn't add scheduling job."
            self.write({'status': False,
                        'message': message})
            cause = "[SCHEDULING]" + str(e)
            logger.critical("couldn't add the scheduling for booking..with cause {}".format(str(e)))


    def on_delete(self, req, res):
        try:
            args = json.loads(req.stream.read().decode('utf8'))
            type_id = args.get('type_id', None)
            notif_type = args.get('notif_type', '')
            user_id = args.get('user_id', '')
            APS.remove_execution_booking(type_id, notif_type)
            logger.info("Deleted the booking job after from APS for user {}".format(user_id))
            # Delete the job from the  database.
            # db_instance.schedule_remove_job(user_id, type_id, notif_type)
            logger.info("job deleting from  with ID : {}".format(type_id))
            
            res.body = json.dumps({'status': status, 'message': message})

        except Exception as e:
            self.set_status(203)
            message = "couldn't delete scheduling job."

            cause = "[SCHEDULING]" + str(e)
            logger.critical(
                "couldn't delete the scheduling for booking..with cause {}".format(str(e)))
