
import threading
import web

class WebGUI(threading.Thread):
    """ Run a GUI with monitoring features as a local web server """

    def __init__(self, parent):
        threading.Thread.__init__(self)
        self.parent = parent
        self.urls = (
            '/', 'index', 
            '', 'index')

    def run(self):
        self.app = web.application(self.urls, globals())
        self.app.run()


class index:
	def GET(self):
		return "This would be the front page of the application"