from sparkpost import SparkPost
from project.config import SPARK_POST_API_KEY
from project.component.templating import render_template
from project.config import FalconEnvironment
# from random import randint

sparky = SparkPost(SPARK_POST_API_KEY)


html_file = {
    'account-activation': 'AccountActivationOTP.html',
    'account-activation-successful': 'AccountActivationSuccessful.html',
    'account-activation-otp-resend': 'AccountActivationOTP.html',
    'booking-cancellation': 'BookingCancel.html',
    'booking-confirmation': 'BookingConfirmation.html',
    'change-password-confirmation': 'ChangePasswordConfirmation.html',
    'create-ticket': 'TicketConfirmation.html',
    'reset-password-confirmation': 'ResetPasswordConfirmation.html',
    'resend-reset-password-otp': 'ResetPasswordOTP.html',
    'reset-password-request': 'ResetPasswordOTP.html',
    'admin-booking-cancellation': 'AdminBookingCancel.html',
    'admin-guest-booking-confirmation': 'AdminGuestBookingConfirmation.html',
    'admin-guest-registration': 'AdminGuestRegistration.html',
    'api-alert-mail': 'APIAlertMail.html'
}

otp_template = {'account-activation', 'account-activation-otp-resend', 'resend-reset-password-otp',
                'reset-password-request'}
resend_otp_template = {'account-activation-otp-resend', 'resend-reset-password-otp'}
# This Function will send hosted template mail using SparkPost
# For Reset Password Request Mail:
#                 template_name= 'reset-password'
#                 email = receiver's email id
#                 argument_dictionary ={
#                                            'first_name': first_name,
#                                            'recover_url': recover_url
#                                     }
#                     attachments  N/A
#
# For Password Reset Confirmation Mail:
#                 template_name= 'password-reset-confirmation'
#                 email = receiver's email id
#                 argument_dictionary ={
#                                         'first_name': first_name
#                                     }
#                     attachments  N/A
#
# For Change Password Confirmation Mail:
#                 template_name= 'change-password-confirmation'
#                 email = receiver's email id
#                 argument_dictionary ={
#                                         'first_name': first_name
#                                     }
#                     attachments  N/A
#
# For Account Activation Mail:
#                 template_name= 'account-activation'
#                 email = receiver's email id
#                 argument_dictionary ={
#                                         'confirm_url': confirm_url
#                                     }
#                     attachments  N/A
#
# For Booking Confirmation Mail:
#                 template_name= 'booking-confirmation'
#                 email = receiver's email id
#                 argument_dictionary = {
#                                             'first_name': first_name,
#                                             'room_name':room_name,
#                                             'booking_date':booking_date,
#                                             'start_time':start_time,
#                                             'duration':duration,
#                                             'credits_used':credits_used,
#                                             'credits_remain':credits_remain
#                                         }
#                     attachments = [{
#                                         "name": "index.html",
#                                         "type": "text/plain",
#                                         "filename": "D:/community-web/community_web/project/templates/index_soome_random_name.html"
#                                     }]


allow_cc_template = ['account-activation-successful', 'booking-cancellation',
                     'booking-confirmation', 'create-ticket']


def sendSparkPostMail(template_name, email, cc_email, subject, argument_dictionary, attachments=[{}]):
    # if template_name != 'booking-confirmation':
    #     response = sparky.transmissions.send(
    #         recipients=[email],
    #         cc=[COMMUNITY_EMAIL],
    #         # bcc=['harshad.kavathiya@cowrks.com'],
    #         subject=subject,
    #         campaign=template_name,
    #         template=template_name,
    #         track_opens=True,
    #         track_clicks=True,
    #         substitution_data=argument_dictionary,
    #         attachments=attachments
    #     )
    # else:
    file_location = 'project/view/email/' + html_file[template_name]
    with open(file_location, 'r') as content_file:
        # with open('bookingMailTemplate.txt',mode='r') as content_file:
        content = content_file.read()

    rendered_html_data = render_template(content, argument_dictionary)

    if FalconEnvironment == 'DEV':
        subject = '[DEV] ' + str(subject)

    elif FalconEnvironment == 'TEST':
        subject = '[TEST] ' + str(subject)

    # sendAmazonSESMail(email, subject, rendered_html_data)
    if template_name in otp_template:
        if template_name in resend_otp_template:
            final_sparkportmail(template_name, email, subject, rendered_html_data, attachments)

    else:
        final_sparkportmail(template_name, email, cc_email, subject, rendered_html_data, attachments)



    # Following code randomly sent mail via Amazon and Sparkpost, but as of now sending mail via sparkpost only
    # if attachments == [{}]:
    #     by_spark = randint(0, 1)
    #
    # else:
    #     by_spark = 1
    #
    # if by_spark:
    #     final_sparkportmail(template_name, email, subject, rendered_html_data, attachments)
    #
    # else:
    #     if template_name in allow_cc_template:
    #         sendAmazonSESMail(email, subject, rendered_html_data, COMMUNITY_EMAIL)
    #     else:
    #         sendAmazonSESMail(email, subject, rendered_html_data)


def final_sparkportmail(template_name, email, cc_email, subject, rendered_html_data,attachments=[{}]):
    allow_cc_template = ['account-activation-successful', 'booking-cancellation', 'booking-confirmation', 'create-ticket', 'admin-booking-cancellation', 'admin-guest-booking-confirmation']

    if attachments==[{}]:
        if template_name in allow_cc_template:
            response = sparky.transmissions.send(
                recipients=[email],
                cc=cc_email,
                html=rendered_html_data,
                from_email='CoWrks Connect<support@cowrks.com>',
                subject=subject,
                campaign=template_name,
                reply_to='CoWrks Connect<support@cowrks.com>',
                track_opens=True,
                track_clicks=True,
                # substitution_data=argument_dictionary
            )
        else:
            response = sparky.transmissions.send(
                recipients=[email],
                html=rendered_html_data,
                from_email='CoWrks Connect<support@cowrks.com>',
                subject=subject,
                campaign=template_name,
                reply_to='CoWrks Connect<support@cowrks.com>',
                track_opens=True,
                track_clicks=True,
            )
    else:
        if template_name in allow_cc_template:
            response = sparky.transmissions.send(
                recipients=[email],
                cc=cc_email,
                html=rendered_html_data,
                from_email='CoWrks Connect<support@cowrks.com>',
                subject=subject,
                attachments=attachments,
                campaign=template_name,
                reply_to='CoWrks Connect<support@cowrks.com>',
                track_opens=True,
                track_clicks=True,
            )
        else:
            response = sparky.transmissions.send(
                recipients=[email],
                html=rendered_html_data,
                from_email='CoWrks Connect<support@cowrks.com>',
                subject=subject,
                attachments=attachments,
                campaign=template_name,
                reply_to='CoWrks Connect<support@cowrks.com>',
                track_opens=True,
                track_clicks=True,
                # substitution_data=argument_dictionary
            )
    return response
