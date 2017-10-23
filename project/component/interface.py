import apiai
import json
import os
import time

import gevent

from project.component.loggings import set_up_logging
from config import API_ID, BACKUP_FOLDER
from chatbot import actions as chat_actions
from core import util

logger = set_up_logging()

actions = {**chat_actions}


class Interface:
    """Acts as the interface between api, dialogFLow and GUI."""

    def __init__(self, auth, refresh_token, data):
        self._session_id = data.get('session_id', '')
        self.msg = data.get('msg', '')
        self.token = auth
        self.refresh_token = refresh_token
        self.contexts = data.get('contexts', '')
        self.time_zone = data.get('time_zone', 'Asia/Kolkata')

    @staticmethod
    def backup(data):
        """Backing up all the queries."""
        val = []
        fname = time.strftime("%Y%m%d") + '.bak'
        backup_path = BACKUP_FOLDER.rstrip('/') + '/' + fname
        logger.info('Backing up ' + str(backup_path))
        if not os.path.exists(BACKUP_FOLDER):
            logger.info('Createing Backup folder')
            os.makedirs(BACKUP_FOLDER)
        try:
            with open(backup_path, 'r') as f:
                val += json.load(f)
        except FileNotFoundError:
            logger.debug('No backup file available')
        except json.decoder.JSONDecodeError:
            logger.debug('Not json format')
        with open(backup_path, 'w+') as f:
            val.append(data)
            json.dump(val, f)

    @staticmethod
    def get_current_prompt(resp):
        try:
            tcontext = resp['result']['contexts']
            return [name['name'] for name in tcontext if 'params' in name['name']]
        except KeyError:
            return ['']

    @staticmethod
    def get_users_last_prompt(resp):
        try:
            tcontext = resp['result']['contexts']
            return [name['parameters']['last_prompt'] for name
                    in tcontext
                    if name['name'] == 'user_data']
        except KeyError:
            return ['']

    def get_reply(self):
        client = apiai.ApiAI(API_ID, self._session_id)
        request = client.text_request()
        request.contexts = self.contexts
        request.query = self.msg
        request.time_zone = self.time_zone
        # TODO - file sending or printing
        try:
            resp = json.loads(request.getresponse().read().decode('utf-8'))
            self.backup(resp)
        except json.decoder.JSONDecodeError:
            resp = {}
        # print(json.dumps(resp, indent=2))
        status = resp.get('status', 404)
        result = resp.get('result', {})
        if (status['code'] == 200 and
                status['errorType'] == 'success' and
                result != ''):
            rmsg = result.get('fulfillment', {}).get('speech', '')
            raction = result.get('action', '')
            rparams = result.get('parameters', {})
            user_message = result.get('resolvedQuery', '')
            current_prompt = self.get_current_prompt(resp)
            users_last_prompt = self.get_users_last_prompt(resp)
            logger.info('rmsg is --> {}'.format(rmsg))
            logger.info('raction is --> {}'.format(raction))
            logger.info('resolvedQuery is --> {}'.format(user_message))
            logger.info('current_prompt is --> {}'.format(current_prompt))
            logger.info('users_last_prompt is --> {}'.format(users_last_prompt))
            try:
                if not resp['result']['actionIncomplete']:
                    logger.info('ActionComplete, calling action {}'.format(raction))
                    reply = actions[raction](
                        self.token,
                        self.refresh_token,
                        rparams,
                        rmsg,
                        user_message)
                else:
                    logger.info('Action InComplete - {}'.format(raction))
                    reply = self.escape_user_if_in_loop(
                        current_prompt,
                        users_last_prompt, rmsg)
            except KeyError:
                # TODO - this exception is not accurate
                # TODO - remove context from all the replies if its not required
                logger.debug('API.AI default functions')
                reply = {'rmsg': rmsg, 'contexts': '', 'buttontext': [], 'table': []}
            return {'session_id': self._session_id, **reply}
        else:
            logger.error('Error response from api.ai: ' + str(resp))
            return {'session_id': self._session_id, 'status': False}

    def escape_user_if_in_loop(self, current_prompt, users_last_prompt, rmsg):
        out_last_prompt = current_prompt[0]
        if users_last_prompt[0] in current_prompt and current_prompt != ['']:
            self._session_id = util.session_id_gen()
            self.empty_last_prompt()
            return self.get_reply()
        reply = {'rmsg': rmsg,
                 'contexts': {'parameters': {}, 'lifespan': 0, 'name': ''},
                 'buttontext': [],
                 'table': [],
                 'last_prompt': out_last_prompt}
        return reply

    def empty_last_prompt(self):
        for val in self.contexts:
            # TODO - known error because we passing empty string as contextgit status
            try:
                if val['name'] == 'user_data':
                    val['parameters']['last_prompt'] = ''
            except TypeError:
                pass
