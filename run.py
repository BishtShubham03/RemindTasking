import os
import mimetypes
from wsgiref import simple_server
from project.routes import *
from project.config import WEBSITE_BASE_URL, WEBSITE_BASE_PORT
from project.component import *

if __name__ == "__main__":
    def static(req, res, static_dir='static', index_file='index.html'):
        path = static_dir + req.path
        if req.path == '/':
            path += index_file
        if os.path.isfile(path):
            res.content_type = mimetypes.guess_type(path)[0]
            res.status = falcon.HTTP_200
            res.stream = open(path)
        else:
            res.status = falcon.HTTP_404


    app.add_sink(static)

    host = WEBSITE_BASE_URL
    port = WEBSITE_BASE_PORT
    httpd = simple_server.make_server(host, port, app)
    print("Serving on %s:%s" % (host, port))
    httpd.serve_forever()