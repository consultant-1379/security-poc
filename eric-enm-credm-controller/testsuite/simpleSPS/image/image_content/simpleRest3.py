import sys
import time
import http.server
import socketserver
import subprocess
#import time
from urllib.parse import parse_qs

#k8p api
#from kubernetes import client, config

# call the restServer with hostname as argument
# python ./simpleRest.py hostname"

HOST_NAME = sys.argv[1] # !!!REMEMBER TO CHANGE THIS!!!
PORT_NUMBER = 80 # Maybe set this to 9000.
SCRIPT_PATH = '/tmp/'

# entry points for REST
HELLO="/hello"
RUNFILE="/run"  # ?name=<scriptname>
GETPODS="/pods"

class ScriptRunner(object):
    def __init__(self):
        self.result = False
        #self.has_nonexec = False
        #self._previously_run_scripts = {}

    def run_script(self, script_name, script_args=[""]):
        script_path = SCRIPT_PATH + script_name + ".sh"

        # elucgem
        print("script: %s %s" % (script_path, script_args ))

        cmd = script_path
        #start_time = time.time(
        p = subprocess.Popen( ['/bin/sh', cmd, script_args[0]], 
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        p.wait()
        #p.wait(timeout in seconds) raise TimeoutExpired
        result = (p.returncode, p.communicate())
        return_code = result[0]
        output = result[1][0].strip()

        if result[0] != 0:
             print("WARNING %s exited with status %d" % (cmd, result[0]))

        # elucgem
        print("script return: %d" % (return_code))
        print("script output:")
        for word in output.decode('utf-8').split('\n'):
           print(word)

        return (True, return_code, output)


class HTTPStatusError(Exception):
    """Exception wrapping a value from http.server.HTTPStatus"""

    def __init__(self, status, description=None):
        """
        Constructs an error instance from a tuple of
        (code, message, description), see http.server.HTTPStatus
        """
        super(HTTPStatusError, self).__init__()
        self.code = status.code
        self.message = status.message
        self.explain = description


class MyHandler(http.server.BaseHTTPRequestHandler):

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_GET(self):
        """Respond to a GET request."""

        #cmd = self.path
        # check valid scripts

#from urlparse import urlparse, parse_qs
#query_components = parse_qs(urlparse(self.path).query)
#imsi = query_components["imsi"] 

        # Extract values from the query string
        path, _, query_string = self.path.partition('?')
        param = parse_qs(query_string)

        print(("[START]: Received GET for %s with query: %s" % (path, param)))

        result = [0]
        try:
            # Handle the possible request paths

            if path == HELLO:
                 # elucgem
                 print("got %s" % (path))
                 result = [True, 0, "-"+HOST_NAME+" Hello!"]

            if path == RUNFILE:
                 # elucgem
                 print("got %s" % (path))
                 val1 = param["name"]
                 #val2 = "pippo"
                 #val3 = "pluto"
                 # elucgem
                 print("run: %s " % (val1[0]))
                 #result = ScriptRunner().run_script(val1[0], [val2 ,val3])
                 result = ScriptRunner().run_script(val1[0])
#            elif path == PIPPO:
#                response = self.route_voices(path, query)
#            else:
#                response = self.route_not_found(path, query)

#            if path == GETPODS:
#                 # elucgem
#                 print("got %s" % (path))
#
#                 # Configs can be set in Configuration class directly or using helper utility
#                 config.load_kube_config()
#
#                 v1 = client.CoreV1Api()
#                 print("Listing pods with their IPs:")
#                 ret = v1.list_pod_for_all_namespaces(watch=False)
#                 for i in ret.items:
#                    print("%s\t%s\t%s" % (i.status.pod_ip, i.metadata.namespace, i.metadata.name))
#
#                 result = [True, 0, "PODS!"]

        except HTTPStatusError as err:
            # Respond with an error and log debug
            # information
            if sys.version_info >= (3, 0):
                self.send_error(err.code, err.message, err.explain)
            else:
                self.send_error(err.code, err.message)

        # elucgem
        #print "run: %s" % path
        #result = ScriptRunner().run_script(path)

        if result[0]:
            # elucgem
            print("result ok")
            self.send_response(200)
        else:
            # elucgem
            print("result NOT OK")
            self.send_response(503)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><head><title>Execution of REST.</title></head>")
        self.wfile.write(bytes("<body><p>path: " + path + "</p>","utf-8"))
        # If someone went to "http://something.somewhere.net/foo/bar/",
        # then s.path equals "/foo/bar/".
        self.wfile.write(bytes("<p>result code: "+str(result[1])+"</p>","utf-8"))
        self.wfile.write(bytes("<p>result output: "+str(result[2])+"</p>","utf-8"))
        self.wfile.write(b"</body></html>")


if __name__ == '__main__':
    server_class = http.server.HTTPServer
    httpd = server_class((HOST_NAME, PORT_NUMBER), MyHandler)
    print(time.asctime(), "Server Starts - %s:%s" % (HOST_NAME, PORT_NUMBER))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print(time.asctime(), "Server Stops - %s:%s" % (HOST_NAME, PORT_NUMBER))

