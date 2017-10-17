import json
import falcon


def dump_error(response, **kwargs):
    """Dumps falcon error response"""

    response.status = falcon.HTTP_203
    status = False
    dump_dict = {'status': status,
                 'token': {'access_token': kwargs.get('access_token', '')},
                 'message': kwargs.get('message', 'error')
                 }
    if kwargs.get('data') is not None:
        dump_dict['data'] = kwargs.get('data')
    response.body = json.dumps(dump_dict)


def dump_success(response, **kwargs):
    """Dumps falcon success response"""

    response.status = falcon.HTTP_201
    status = True
    dump_dict = {'status': status,
                 'token': {'access_token': kwargs.get('access_token', '')},
                 'message': kwargs.get('message', 'success')
                 }
    if kwargs.get('data') is not None:
        dump_dict['data'] = kwargs.get('data')
    response.body = json.dumps(dump_dict)
