
from project.component.util import process_reply
import time
import os
import json
from time import strftime
from datetime import datetime
from config import REMINDER_FOLDER


def _convert_ampm(quantity):
    if type(quantity) is str:
        temp_quant = datetime.strptime(quantity, "%I:%M %p")
    elif type(quantity) is datetime:
        return quantity.strftime("%I:%M %p")
    return datetime.strftime(temp_quant, "%H:%M")


def set_reminder(auth, refresh_token, params, resolved_query, speech):
    print('in reminder func', speech, params)
    time_object = datetime.strptime(params['time'], "%H:%M:%S")

    params['time'] = _convert_ampm(time_object)
    # print(params['time'])
    text = process_reply(resolved_query, params)
    ret = 'Reminder : ' + text[10:]
    print(ret)

    data = 'reminder at ' + \
        strftime("%H:%M:%S") + ' : ' + text[10:] + ' -by- ' + speech[-13:]
    file_name = REMINDER_FOLDER.rstrip('/') + '/' + time.strftime("%Y%m%d") + '.txt'
    root.info('feedback data storing' + str(file_name))
    if not os.path.exists(REMINDER_FOLDER):
        os.makedirs(REMINDER_FOLDER)
    with open(file_name, 'a+') as f:
        json.dump(data, f)
        f.write('\n')

    return {'rmsg': ret, 'contexts': '', 'buttontext': [], 'table': []}
