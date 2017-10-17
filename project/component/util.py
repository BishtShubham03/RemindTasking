from random import choice
from string import ascii_uppercase, digits, ascii_lowercase
import json
import os
import re



def format_names(names):
    """Return names in formatted way."""
    d = ''
    for n in range(len(names)):
        if n + 1 == len(names):
            d = d + ' and ' + names[n]
            break
        if n != 0:
            d = d + ' , ' + names[n]
        else:
            d = d + names[n]
    return d.title()


def get_names(query):
    """Get the names from the Query."""
    names = re.findall(r'@(\w+)', query)
    if len(names) > 1:
        return format_names(names)
    else:
        return names[0].title()


def session_id_gen():
    session = ''.join(
        choice(ascii_uppercase + digits + ascii_lowercase)
        for i in range(20))
    return session


def convert_asterisk_to_brace(msg):
    out_reply = ''
    temp_list = msg.split('**')
    assert len(temp_list) % 2 != 0, 'Reply from api.ai is not formatted correctly'
    if len(temp_list) == 1:
        return msg
    while True:

        if not len(temp_list) <= 1:
            out_reply += temp_list.pop(0) + '{'
            out_reply += temp_list.pop(0) + '}'
        else:
            return out_reply + temp_list.pop(0)


def process_reply(msg, fillers):
    print(msg, fillers)
    msg = convert_asterisk_to_brace(msg)
    assert type(fillers) == dict, 'fillers should be dictionary'
    for key, val in fillers.items():
        if type(val) == list:
            fillers[key] = ' - '.join(val)
    return msg.format(**fillers)



def handleList(listData, *args):
    for item in listData:
        if ((type(item) == dict)):
            findType(item, *args)
        elif(type(item) == list):
            handleList(item)
        else:
            pass


def findType(data, *args):
    global dic
    for key, x in data.items():
        if ((type(x) is dict)):
            findType(x, *args)
        elif(type(x) is list):
            handleList(x, *args)
        else:
            if key in args:
                dic[key] = x


