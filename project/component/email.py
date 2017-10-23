# from sparkpostmail import sendSparkPostMail
from threading import Thread
from project.component.loggings import set_up_logging
from project.config import *
from datetime import datetime
import time
from project.config import COMMUNICATION_EMAIL

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


logger = set_up_logging()


email_content = """
            <head>
              <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
              <title>html title</title>
              <style type="text/css" media="screen">
                table{
                    background-color: #AAD373;
                    empty-cells:hide;
                }
                td.cell{
                    background-color: white;
                }
              </style>
            </head>
            <body>
              <table style="border: blue 1px solid;">
                <tr><td class="cell">Cell 1.1</td><td class="cell">Cell 1.2</td></tr>
                <tr><td class="cell">Cell 2.1</td><td class="cell"></td></tr>
              </table>
            </body>
            """


def send_email(params, subject, cc_email=COMMUNICATION_EMAIL,):
    start_time = time.time()
    thr = Thread(target=send_email_via_thread, args=[template_name, email, subject,
                                                     argument_dictionary, attachments, cc_email])
    thr.start()
    overhead = time.time() - start_time
    logger.info("email in second = {}".format(overhead))
    return thr


def send_email_via_thread(params, subject, cc_email=COMMUNICATION_EMAIL):
    try:
        TO = params['email']
        text = params['body']
        start_time = time.time()
        MESSAGE = MIMEMultipart('alternative')
        MESSAGE['subject'] = "hello" + params['name']
        MESSAGE['To'] = TO
        MESSAGE['From'] = COMMUNICATION_EMAIL
        # MESSAGE.preamble = """
        #         Your mail reader does not support the report format.
        #         Please visit us <a href="http://www.mysite.com">online</a>!
        #         """
        # Record the MIME type text/html.
        HTML_BODY = MIMEText(text, 'plain')

        # Attach parts into message container.
        # According to RFC 2046, the last part of a multipart message, in this case
        # the HTML message, is best and preferred.
        MESSAGE.attach(HTML_BODY)

        # The actual sending of the e-mail
        server = smtplib.SMTP('smtp.gmail.com:587')

        if attachments == [{}]:
            pass
            # function to send email to a specified email ID
        else:
            password = "mypassword"
            server.starttls()
            server.login(FROM, password)
            server.sendmail(FROM, [TO], MESSAGE.as_string())
            server.quit()
            # with arguments
            # (template_name, email, cc_email, subject,
            #                  argument_dictionary, attachments)

        overhead = time.time() - start_time
        logger.info("Email sent time in second = {}".format(overhead))

    except Exception as e:
        cause = str(e)
        logger.error("Email error : cause {}".format(cause))


def py_mail(SUBJECT, BODY, TO, FROM):
    """With this function we send out our html email"""

    # Create message container - the correct MIME type is multipart/alternative here!
    

    # Print debugging output when testing
    if __name__ == "__main__":
        server.set_debuglevel(1)

    # Credentials (if needed) for sending the mail

