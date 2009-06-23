
import web
#from AliceAPI import xAlice, xAliceConfig, xPeer, xFlow
from AliceAPIFake import xAlice, xAliceConfig, xPeer, xFlow

class WebGUI():
    """ Run a GUI with monitoring features as a local web server """

    def __init__(self):
        self.x_alice_config = xAliceConfig()
        self.x_alice = xAlice.connect_server(self.x_alice_config)
        self.packet_data = dict()
        self.urls = (
            '/', 'index', 
            '', 'index',
            'config[/]?', 'config')
        
    def main(self):
        self.app = web.application(self.urls, globals())
        self.app.run()


class info_utility:
    def display_client_info(self):
        html = '''<table>'''
        for key, value in WebGUI.x_alice.get_client_info():
            html = html + '''<tr><td>''' + key + '''</td><td>''' 
            html = html + value + '''</td></tr>'''
        html = html + '''</table>'''
        return html
    
    def display_server_info(self):
        html = '''<table>'''
        for key, value in WebGUI.x_alice.get_server_info():
            html = html + '''<tr><td>''' + key + '''</td><td>''' 
            html = html + value + '''</td></tr>'''
        html = html + '''</table>'''
        return html
    
    def display_peer_list(self):
        html = '''<table>'''
        for peer in WebGUI.x_alice.get_peers():
            for flow_tuple in WebGUI.x_alice.active_flows():
                html = html + '''<tr><td>''' + + flow_tuple[0] + + '''</td>'''
                html = html + '''<td>''' + flow_tuple[1] + '''</td>''' 
                html = html + '''<td>''' + flow_tuple[2] + '''</td>''' 
                html = html + '''<td>''' + flow_tuple[3] + '''</td></tr>'''
        html = html + '''</table>'''
        return html
        
    # flow = xFlow object
    # packet_type = dropped, injected, modified
    def make_histogram(self, flow, bin_size, packet_type):
        # Count packets into bins
        # Return histogram
    
    # Pass in all flows and get bin size used if all of these were
    # plotted on same graph
    # flows = list of xFlows objects
    def get_hist_bin_size(self, flows):
        # Find min and max timestamp
        # Divide by number of bins (~100?)
        # Adjust to nice round number
        # Return bin size (in minutes) 
        
    def make_graph_data(self, histogram, units):
        # For each bin in histogram
        # Get x from histogram bin
        # Get y from histogram value
        # Return canvas-formatted graph data (for line drawing)
        
    def make_graph(self):
        info_utility.update_packet_data()
        # Get bin size for all flows
        # For each flow considered
        # Make a histogram
        # Make graph data
        # Make legend
        # Finally, plot to canvas
        
    def update_packet_data(self):
        # For each active flow
        for p in WebGUI.x_alice.get_peers:
            for f in p.active_flows:
                # If flow does not exist in dictionary object, add
                flow_ip = f.flow_tuple[0] + ":" + str(f.flow_tuple[1]) + "::" + f.flow_tuple[2] + ":" + str(f.flow_tuple[3])
                if self.packet_data[flow_ip] :
                    pass
                else
                    self.packet_data[flow_ip] = dict()
                    self.packet_data[flow_ip]['dropped'] = list()
                    self.packet_data[flow_ip]['injected'] = list()
                    self.packet_data[flow_ip]['modified'] = list()
                    self.packet_data[flow_ip]['total count'] = 0
                
                # Each active flow has 4 lists of packets: dropped, injected, 
                # modified, total count
                self.packet_data[flow_ip]['dropped'].extend(f.get_new_dropped())
                self.packet_data[flow_ip]['injected'].extend(f.get_new_injected())
                self.packet_data[flow_ip]['modified'].extend(f.get_new_modified())    
                self.packet_data[flow_ip]['total count']  = self.packet_data[flow_ip]['total count'] + get_new_packet_count() 

    
class index:
	def GET(self):
        page = '''<html><head><title>Switzerland</title></head>
        <body>'''
        page = page + info_utility.display_client_info()
        page = page + info_utility.display_server_info()
        
        page = '''
            <canvas id="cnvPacketGraph" width="600" height="400">
            </canvas>
        '''
        page = page + make_graph()
        page = page + '''
            </body>
            </html>
        '''
        return page

# List mutable configuration parameters, allow to change
class config:
    def GET(self):  
        page = '''<p>Tweakable Options</p>
                    <form name="frmMutableOpt" id="frmMutableOpt"><table>'''
                    
        for opt in WebGUI.x_alice_config.tweakable_options
            page = page + '''<tr><td>''' + opt + '''</td>'''
            page = page + '''<td><input name="''' + opt +  '''"''' 
            page = page + ''' value="''' + WebGUI.x_alice_config.get_option(opt) 
            page = page + '''"/></td></tr>'''
        
        page = page + '''</table><br/>
                    <input type="submit" value="Save changes"/></form>
                    <p>Immutable Options</p>
                    <table>'''
                    
        for opt in WebGUI.x_alice_config.immutable_options
            page = page + '''<tr><td>''' + opt + '''</td>'''
            page = page + '''<td>''' + WebGUI.x_alice_config.get_option(opt) + '''</td></tr>'''
         
        return page