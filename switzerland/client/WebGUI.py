#!/usr/bin/env python
import web
import time
import math

#from AliceAPI import xAlice, xAliceConfig, xPeer, xFlow
from AliceAPIFake import xAlice, xAliceConfig, xPeer, xFlow

singleton_webgui = None


class line_graph:
    def __init__(   self, 
                    canvas_id="cid",
                    canvas_context="jg",
                    width=600, 
                    height=400,
                    graph_xbins=50, 
                    graph_ybins=50):  
                    
        self.graph_xbins = graph_xbins
        self.graph_ybins = graph_ybins
        self.width = width
        self.height = height
        # These get set automatically when the data gets processed
        self.max_timestamp = None
        self.min_timestamp = None
        self.bin_size = None
        self.y_hist_max = None
        
        self.gui_flows = None
        # JavaScript canvas context name
        self.canvas_context = canvas_context
        # HTML element ID of canvas element
        self.canvas_id = canvas_id
        self.draw_colors = ["#ff0000", "#0000ff", "#009933", "#660066", 
            "#ff6600", "#6699ff", "#ffcc33", "#00cc00", "#cc3300", "#606060"]
    
    # flow = xFlow object
    # packet_type = dropped, injected, modified
    def make_histogram(self, packet_list):
        histogram = list()
        for i in range(0,self.graph_xbins):
            histogram.append(0)
            
        # Count packets into bins
        for packet_ts in [p[0] for p in packet_list]:
            i =  packet_ts - self.min_timestamp
            i = int(i/self.bin_size)
            print "bin number", i
            histogram[i] = histogram[i] + 1
            
        # Return histogram
        return histogram
    
            
    def get_y_hist_max(self, include_total=True):
        all_packcount = list()
        for ip in self.gui_flows:
            if include_total:
                all_packcount.extend([p[1] for p in singleton_webgui.packet_data[ip]['total count']])
            else:
                all_packcount.extend(self.histograms[ip]['modified'])
                all_packcount.extend(self.histograms[ip]['injected'])
                all_packcount.extend(self.histograms[ip]['dropped'])
                
        self.y_hist_max = max(all_packcount)
        
    # Pass in all flows and get bin size used if all of these were
    # plotted on same graph
    # flows = list of xFlows objects
    def get_hist_xbin_size(self):
        
        # Find min and max timestamp
        all_timestamps = list()
        
        for ip in self.gui_flows :
            ts_list = [p[0] for p in singleton_webgui.packet_data[ip]['dropped']]
            # Rather than concatenating ALL the timestamps, we
            # only need the mins and maxes.
            all_timestamps.extend((min(ts_list), max(ts_list)))
            ts_list = [p[0] for p in singleton_webgui.packet_data[ip]['injected']]
            all_timestamps.extend((min(ts_list), max(ts_list)))
            ts_list = [p[0] for p in singleton_webgui.packet_data[ip]['modified']]
            all_timestamps.extend((min(ts_list), max(ts_list)))
            print "total count", singleton_webgui.packet_data[ip]['total count']

        
        self.max_timestamp = max(all_timestamps)
        self.min_timestamp = min(all_timestamps)
        print "max ts", self.max_timestamp, "min ts", self.min_timestamp
        
        range_timestamp = self.max_timestamp - self.min_timestamp

        # Divide by number of bins (~100?)
        self.bin_size = range_timestamp / self.graph_xbins
                
        # Adjust to nice round number
        binlog = math.log10(self.bin_size)
        self.bin_size = round(self.bin_size + (5 * 10**(binlog-1)) ,int(-math.floor(binlog))) 
        
        print "rough bin size", str(range_timestamp / self.graph_xbins), "bin size", self.bin_size
        # Return bin size (in seconds) 
        return self.bin_size
    
    def make_graph_data(self, name, histogram, point_shape="circle"):
        
        i = 0
        html = "/* " + name + " " + point_shape + "*/\n"
        html = html + self.canvas_context + ".beginPath();\n"
        phtml = ""
        
        # For each bin in histogram
        for b in histogram:
            # Get x from histogram bin
            # Get y from histogram value
            x = str(int(i * (self.width/self.graph_xbins))) 
            y = str(self.height - int(b * (self.height/self.y_hist_max))) 
            if i == 0:
                html = html + self.canvas_context + ".moveTo(" + x + "," + y + ");\n"
            else:
                html = html + self.canvas_context + ".lineTo(" + x + "," + y + ");\n"
            phtml = phtml + self.make_point_html(x, y, point_shape)
            i = i + 1
        html = html + self.canvas_context + ".stroke();\n\n"  
        #html = html + phtml      

        # Return canvas-formatted graph data (for line drawing)
        return html
    
    def make_total_pkt_count_graph_data(self, name, tuples):
        i = 0
        xhtml = "var x_" + name + " = new Array("
        yhtml = "var y_" + name + " = new Array("
        for t in tuples:
            xhtml = xhtml + str(t[0] * (self.width/self.graph_xbins)) + ","
            yhtml = yhtml + str(t[1] * (self.y_hist_max/self.graph_ybins)) + ","
        
        xhtml = xhtml[:-1]
        yhtml = yhtml[:-1]
        xhtml = xhtml + ");"
        yhtml = yhtml + ");"
        html = xhtml + "\n" + yhtml + "\n"    
        
    def update_packet_data(self):
        # For each active flow
        peers = singleton_webgui.x_alice.get_peers()
        for p in peers:
            flows = p.active_flows()
            for f in flows:
                # If flow does not exist in dictionary object, add
                flow_ip = str(f.flow_tuple[0]) + ":" + str(f.flow_tuple[1]) + "::" + str(f.flow_tuple[2]) + ":" + str(f.flow_tuple[3])
                if singleton_webgui.packet_data.get(flow_ip) :
                    pass
                else:
                    singleton_webgui.packet_data[flow_ip] = dict()
                    singleton_webgui.packet_data[flow_ip]['dropped'] = list()
                    singleton_webgui.packet_data[flow_ip]['injected'] = list()
                    singleton_webgui.packet_data[flow_ip]['modified'] = list()
                    singleton_webgui.packet_data[flow_ip]['total count'] = list()
                
                print flow_ip
                
                
                # Each active flow has 4 lists of packets: dropped, injected, 
                # modified, total count
                singleton_webgui.packet_data[flow_ip]['dropped'].extend(f.get_new_dropped())
                singleton_webgui.packet_data[flow_ip]['injected'].extend(f.get_new_injected())
                singleton_webgui.packet_data[flow_ip]['modified'].extend(f.get_new_modified())    
                singleton_webgui.packet_data[flow_ip]['total count'].extend([(time.time(),  f.get_new_packet_count()) ])
                
        
    def make_point_html(self, x, y, shape="circle"):
        
        if shape == "triangle":
            html = self.canvas_context + ".translate(" + x + "," + y + ");\n"
            html = html + self.canvas_context + ".beginPath();\n"
            html = html + self.canvas_context + ".moveTo(-2, -2);\n"
            html = html + self.canvas_context + ".lineTo(-2, 2);\n"
            html = html + self.canvas_context + ".lineTo(0, 2);\n"
            html = html + self.canvas_context + ".fill();\n"
            html = html + self.canvas_context + ".translate(0,0);\n"
            
        elif shape == "x":
            html = self.canvas_context + ".translate(" + x + "," + y + ");\n"
            html = html + self.canvas_context + ".beginPath();\n"
            html = html + self.canvas_context + ".moveTo(-2, -2);\n"
            html = html + self.canvas_context + ".lineTo(2, 2);\n"
            html = html + self.canvas_context + ".moveTo(-2, 2);\n"
            html = html + self.canvas_context + ".lineTo(2, -2);\n"
            html = html + self.canvas_context + ".stroke();\n"
            html = html + self.canvas_context + ".translate(0,0);\n"
            
        elif shape == "square":
            html = self.canvas_context + ".translate(" + x + "," + y + ");\n"
            html = html + self.canvas_context + ".fillRect(-2, -2, 2, 2);\n"  
            html = html + self.canvas_context + ".translate(0,0);\n"        
    
        elif shape == "circle":
            html = self.canvas_context + ".translate(" + x + "," + y + ");\n"
            html = html + self.canvas_context + ".beginPath();\n"
            html = html + self.canvas_context + ".arc(0, 0, -2, -2);\n"
            html = html + self.canvas_context + ".fill();\n"
            html = html + self.canvas_context + ".translate(0,0);\n"
        
        else:
            pass
        
        
        return html
        
        
    def make_graph(self):
        self.update_packet_data()
        # Update which flows we care about
        # For now, all of them.  Will update to those selected by GUI
        self.gui_flows = dict()
        peers = singleton_webgui.x_alice.get_peers()
        for p in peers:
            flows = p.active_flows()
            for f in flows:
                flow_ip = f.flow_tuple[0] + ":" + str(f.flow_tuple[1]) + "::" + f.flow_tuple[2] + ":" + str(f.flow_tuple[3])
                self.gui_flows[flow_ip] = f
        
        # Get bin size for all flows
        self.get_hist_xbin_size()
        self.histograms = dict()

        
        graph_data_html = ""
        line_names = dict()
        # For each flow considered
        for ip in self.gui_flows:
            # Make a histogram
            self.histograms[ip] = dict()
            self.histograms[ip]['dropped'] = self.make_histogram(singleton_webgui.packet_data[ip]['dropped'])
            self.histograms[ip]['injected'] = self.make_histogram(singleton_webgui.packet_data[ip]['injected'])
            self.histograms[ip]['modified'] = self.make_histogram(singleton_webgui.packet_data[ip]['modified'])
        
        i = 0
        # Get maximum y value (# of packets)
        self.get_y_hist_max(False)
        print "y max", self.y_hist_max
        
        for ip in self.gui_flows:
            line_name = ip.replace(":","_")
            line_name = line_name.replace(".","_")
            # Make graph data
            graph_data_html = graph_data_html + self.canvas_context + '''.fillStyle = "''' + self.draw_colors[i%len(self.draw_colors)] + '''"\n'''
            graph_data_html = graph_data_html + self.canvas_context + '''.strokeStyle = "''' + self.draw_colors[i%len(self.draw_colors)] + '''"\n'''            
            graph_data_html = graph_data_html + self.make_graph_data(line_name + "_dr", self.histograms[ip]['dropped'], "x")
            graph_data_html = graph_data_html + self.make_graph_data(line_name + "_in", self.histograms[ip]['injected'], "triangle")
            graph_data_html = graph_data_html + self.make_graph_data(line_name + "_mo", self.histograms[ip]['modified'], "square")
            line_names[line_name] = line_name
            i = i + 1
            
        html = '''
<canvas id="''' + self.canvas_id + '''" width="''' + str(self.width+10) + '''" height="''' + str(self.height+10) + '''">       
    Canvas is not supported.
</canvas>
<script type="text/javascript">
<!--
    function drawgraph_''' + self.canvas_id + '''() {
        var canvas_''' + self.canvas_id + ''' = document.getElementById("''' + self.canvas_id + '''");
        if (canvas_''' + self.canvas_id + '''.getContext) {            
            var ''' + self.canvas_context + ''' = canvas_''' + self.canvas_id + '''.getContext('2d');
''' + graph_data_html + '''  
        } else {
            alert('You need Safari or Firefox 1.5+ to see this demo.');
        }
    }
    
    drawgraph_''' + self.canvas_id + '''();
//-->
</script>
        '''    
        # Finally, plot to canvas 
        return html   



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
        info_hash = singleton_webgui.x_alice.get_client_info()
        for key in info_hash:
            html = html + '''<tr><td>''' + key + '''</td><td>''' 
            html = html + str(info_hash[key]) + '''</td></tr>'''
        html = html + '''</table>'''
        return html
    
    def display_server_info(self):
        html = '''<table>'''
        info_hash = singleton_webgui.x_alice.get_server_info()
        for key in info_hash:
            html = html + '''<tr><td>''' + key + '''</td><td>''' 
            html = html + str(info_hash[key])  + '''</td></tr>'''
        html = html + '''</table>'''
        return html
    
    def display_peer_list(self):
        html = '''<table>'''
        for peer in singleton_webgui.x_alice.get_peers():
            for f in peer.active_flows():
                html = html + '''<tr><td>''' + str(f.flow_tuple[0]) + '''</td>'''
                html = html + '''<td>''' + str(f.flow_tuple[1]) + '''</td>''' 
                html = html + '''<td>''' + str(f.flow_tuple[2]) + '''</td>''' 
                html = html + '''<td>''' + str(f.flow_tuple[3]) + '''</td></tr>'''
        html = html + '''</table>'''
        return html

    
class index:
    def GET(self):
        page = '''<html><head><title>Switzerland</title></head><body>'''
        i = info_utility()
        page = page + i.display_client_info()
        page = page + i.display_server_info()
        page = page + i.display_peer_list()
        
        graph = line_graph()
        page = page + graph.make_graph()
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
                    
        for opt in singleton_webgui.x_alice_config.tweakable_options:
            page = page + '''<tr><td>''' + opt + '''</td>'''
            page = page + '''<td><input name="''' + opt +  '''"''' 
            page = page + ''' value="''' + WebGUI.x_alice_config.get_option(opt) 
            page = page + '''"/></td></tr>'''
        
        page = page + '''</table><br/>
                    <input type="submit" value="Save changes"/></form>
                    <p>Immutable Options</p>
                    <table>'''
                    
        for opt in WebGUI.x_alice_config.immutable_options:
            page = page + '''<tr><td>''' + opt + '''</td>'''
            page = page + '''<td>''' + WebGUI.x_alice_config.get_option(opt) + '''</td></tr>'''
         
        return page
    

class WebGUI():
    """ Run a GUI with monitoring features as a local web server """

    def __init__(self):
        self.x_alice_config = xAliceConfig()
        self.x_alice = xAlice(self.x_alice_config)
        self.packet_data = dict()
        self.urls = (
            '/', 'index', 
            '', 'index',
            'config[/]?', 'config')
        
    def main(self):
        self.app = web.application(self.urls, globals())
        self.app.run()


if __name__ == "__main__":
    singleton_webgui = WebGUI()
    singleton_webgui.main()