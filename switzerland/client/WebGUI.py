
import web
import decimal

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


class line_graph:
    def __init__(   self, 
                    graph_xbins=100, 
                    width=600, 
                    height=400,
                    graph_ybins=50):  
                    
        self.graph_xbins = graph_xbins
        self.graph_ybins = graph_ybins
        self.width = width
        self.height = height
        # These get set automatically when the data gets processed
        self.max_timestamp = None
        self.min_timestamp = None
        self.bin_size = None
        self.packet_data = dict()
        self.gui_flows = None
    
    # flow = xFlow object
    # packet_type = dropped, injected, modified
    def make_histogram(self, packet_list):
        histogram = list()
        for i in graph_xbins:
            histogram.append(0)
            
        # Count packets into bins
        for packet_ts in [p[0] for p in packet_list]:
            i =  packet_ts - self.min_timestamp
            i = int(i/self.bin_size)
            histogram[i] = histogram + 1
            
        # Return histogram
        return histogram
    
            
    # Pass in all flows and get bin size used if all of these were
    # plotted on same graph
    # flows = list of xFlows objects
    def get_hist_bin_size(self):
        
        # Find min and max timestamp
        all_timestamps = list()
        for ip, fl in self.gui_flows :
            ts_list = [p[0] for p in self.packet_data[ip]['dropped']]
            # Rather than concatenating ALL the timestamps, we
            # only need the mins and maxes.
            all_timestamps.extend((min(ts_list), max(ts_list)))
            ts_list = [p[0] for p in self.packet_data[ip]['injected']]
            all_timestamps.extend((min(ts_list), max(ts_list)))
            ts_list = [p[0] for p in self.packet_data[ip]['modified']]
            all_timestamps.extend((min(ts_list), max(ts_list)))
        
        self.max_timestamp = compute_utility.find_max(all_timestamps)
        self.min_timestamp = compute_utility.find_min(all_timestamps)
        range_timestamp = self.max_timestamp - self.min_timestamp

        # Divide by number of bins (~100?)
        self.bin_size = range_timestamp / graph_xbins
                
        # Adjust to nice round number
        self.bin_size = round(self.bin_size,int(-math.floor(math.log10(self.bin_size)))) 
        
        # Return bin size (in seconds) 
        return self.bin_size
    
    def make_graph_data(self, name, histogram):
        # Set scaling factor
        # For each bin in histogram
        i = 0
        xhtml = '''var x_''' + name + ''' = new Array('''
        yhtml = '''var y_''' + name + ''' = new Array('''
        for b in histogram:
            # Get x from histogram bin
            # Get y from histogram value
            xhtml = xhtml + (i * (self.width/self.graph_xbins)) + ''','''
            yhtml = yhtml + b + ''','''
            i = i + 1
        
        xhtml = xhtml[:-1]
        yhtml = yhtml[:-1]
        xhtml = xhtml + ''');'''
        yhtml = yhtml + ''');'''
        html = xhtml + "\n" + yhtml + "\n"
        # Return canvas-formatted graph data (for line drawing)
        return html
    
    def update_packet_data(self):
        # For each active flow
        for p in WebGUI.x_alice.get_peers:
            for f in p.active_flows:
                # If flow does not exist in dictionary object, add
                flow_ip = f.flow_tuple[0] + ":" + str(f.flow_tuple[1]) + "::" + f.flow_tuple[2] + ":" + str(f.flow_tuple[3])
                if self.packet_data[flow_ip] :
                    pass
                else:
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
    
    def make_graph(self, name, width, height):
        info_utility.update_packet_data()
        # Update which flows we care about
        # For now, all of them.  Will update to those selected by GUI
        self.gui_flows = dict()
        
        for p in WebGUI.x_alice.get_peers:
            for f in p.active_flows:
                flow_ip = f.flow_tuple[0] + ":" + str(f.flow_tuple[1]) + "::" + f.flow_tuple[2] + ":" + str(f.flow_tuple[3])
                self.gui_flows[flow_ip] = f
        
        # Get bin size for all flows
        get_hist_bin_size()
        self.histograms = dict()
        
        graph_data_html = ""
        line_names = dict()
        # For each flow considered
        for ip, fl in self.gui_flows:
            # Make a histogram
            self.histograms[ip] = dict()
            self.histograms[ip]['dropped'] = make_histogram(self.packet_data[ip]['dropped'])
            self.histograms[ip]['injected'] = make_histogram(self.packet_data[ip]['injected'])
            self.histograms[ip]['modified'] = make_histogram(self.packet_data[ip]['modified'])
        
        # Get maximum y value (# of packets)
        self.y_hist_max = compute_utility.find_max(self.histograms)
        
        for ip, fl in self.gui_flows:
            line_name = ip.replace(":","_")
            # Make graph data
            graph_data_html = graph_data_html + make_graph_data(line_name + "_dr", self.histogram[ip]['dropped'], width, height)
            graph_data_html = graph_data_html + make_graph_data(line_name + "_in", self.histogram[ip]['injected'], width, height)
            graph_data_html = graph_data_html + make_graph_data(line_name + "_mo", self.histogram[ip]['modified'], width, height)
            line_names[line_name] = line_name
            
            
        # Finally, plot to canvas    


class compute_utility:
    def find_max( struct):
        if isinstance(struct, dict):
            return find_max(struct.values())
        if isinstance(struct, list) or isinstance(struct, sequence) or isinstance(struct, set):
            item = struct[0]
            if isinstance(item, str) or isinstance(item, int):
                return max(struct)
            else:
                if len(struct) == 1:
                    return find_max(item)
                else:
                    m2 = find_max(struct[1:])
                    m1 = find_max(item)
                    if m1 >= m2:
                        return m1
                    else:
                        return m2
                
    def find_min( struct):
        if isinstance(struct, dict):
            return find_min(struct.values())
        if isinstance(struct, list) or isinstance(struct, sequence) or isinstance(struct, set):
            item = struct[0]
            if isinstance(item, str) or isinstance(item, int):
                return min(struct)
            else:
                if len(struct) == 1:
                    return find_min(item)
                else:
                    m2 = find_min(struct[1:])
                    m1 = find_min(item)
                    if m1 >= m2:
                        return m1
                    else:
                        return m2    
       
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
        


    
class index:
	def GET(self):
        page = '''<html><head><title>Switzerland</title></head>
        <body>'''
        page = page + info_utility.display_client_info()
        page = page + info_utility.display_server_info()
        
        width = 600
        height = 400
        page = '''
            <canvas id="cnvPacketGraph" width="''' + width + '''" height="''' + height + '''">
            </canvas>
        '''
        page = page + make_graph("cnvPacketGraph", width, height)
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