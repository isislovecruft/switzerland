#!/usr/bin/env python
import web
import time
import math
import sys
sys.path.append("..") 

#from AliceAPI import xAlice, xAliceConfig, xPeer, xFlow
from AliceAPIFake import xAlice, xAliceConfig, xPeer, xFlow

singleton_webgui = None
debug_output = False
canvas_message = "Your browser does not support canvas."


class line_graph:
    def __init__(   self, 
                    canvas_id="cid",
                    canvas_context="jg",
                    width=800, 
                    height=400,
                    graph_xbins=50, 
                    graph_ybins=20):  
                    
        self.graph_xbins = graph_xbins
        self.graph_xbins_actual = graph_xbins
        self.graph_ybins = graph_ybins
        self.graph_ybins_actual = graph_ybins
        self.width = width
        self.height = height
        # These get set automatically when the data gets processed
        self.max_timestamp = None
        self.min_timestamp = None
        self.y_hist_max = None
        self.x_bin_size = None # in seconds
        self.y_bin_size = None # in packets
        self.x_bin_pixels = None
        self.y_bin_pixels = None
        self.y_margin = 5
        self.x_margin = 10
        self.x_axis_margin = 25
        self.y_axis_margin = 20
        self.graph_height = height - (self.y_axis_margin + 2 * self.y_margin)
        self.graph_width = width - (self.x_axis_margin + 2 * self.x_margin)
        
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
        for i in range(0,self.graph_xbins_actual):
            histogram.append(0)
            
        # Count packets into bins
        for packet_ts in [p[0] for p in packet_list]:
            i =  packet_ts - self.min_timestamp
            i = int(i/self.x_bin_size)
            if i < len(histogram):
                histogram[i] = histogram[i] + 1
            else:
                if debug_output:
                    ''' This data is preserved for the next reload '''
                    print "index", i, "out of range"
                else:
                    pass
            
        # Return histogram
        return histogram
    
            
    def get_y_hist_max(self, include_total=True):
        all_packcount = list()
        for ip in self.gui_flows:
            print "get_y_hist_max gui flow", ip
            if include_total:
                all_packcount.extend([p[1] for p in singleton_webgui.packet_data[ip]['total count']])
            else:
                all_packcount.extend(self.histograms[ip]['modified'])
                all_packcount.extend(self.histograms[ip]['injected'])
                all_packcount.extend(self.histograms[ip]['dropped'])
            print all_packcount
                
        self.y_hist_max = max(all_packcount)
        
    def get_min_max_time(self):
        # Find min and max timestamp
        all_timestamps = list()
        
        for ip in self.gui_flows :
            print "xx ip", ip
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
        
    # Pass in all flows and get bin size used if all of these were
    # plotted on same graph
    # flows = list of xFlows objects
    def get_hist_xbin_size(self):
        
        range_timestamp = self.max_timestamp - self.min_timestamp
        print "x calculations"
        
        (self.graph_xbins_actual, self.x_bin_size) = self.get_round_bin_size(range_timestamp, self.graph_xbins)
        
        print "rough bin size", str(range_timestamp / self.graph_xbins), "bin size", self.x_bin_size
        # Return bin size (in seconds) 
        return self.x_bin_size
    
    def get_round_bin_size(self, range, bins):
        est_bin_size = float(range) / float(bins)
        print "range:", range, "bins:", bins, "est bin size:", est_bin_size
        binlog = int(-math.floor(math.log10(est_bin_size)))
        actual_bin_size = math.ceil(est_bin_size) 
        actual_bins = math.ceil((int(range) / est_bin_size))
        print "actual bins:", actual_bins
        return (actual_bins, actual_bin_size)    

        
    def make_graph_data(self, name, histogram, point_shape="circle"):
        
        i = 0
        self.x_bin_pixels = int(self.graph_width/self.graph_xbins_actual)
        print "width:", self.graph_width, "xbins_actual:", self.graph_xbins_actual, "x_bin_pixels:", self.x_bin_pixels
    
        (self.graph_ybins_actual, self.y_bin_size) = self.get_round_bin_size(self.y_hist_max, self.graph_ybins)
            
        self.y_bin_pixels = int(self.graph_height/self.graph_ybins_actual)
        
        
        html = "/* " + name + " " + point_shape + "*/\n"
        xhtml = "var x_" + name + " = new Array("
        yhtml = "var y_" + name + " = new Array("
        
        # For each bin in histogram
        for b in histogram:
            # Get x from histogram bin
            # Get y from histogram value
            
            x = str(i * (self.x_bin_pixels) + self.x_axis_margin + self.x_margin)
            y = b * self.y_bin_pixels / self.y_bin_size
            
            y = str(self.height - (y + self.y_axis_margin + self.y_margin))
            xhtml = xhtml + x + ","
            yhtml = yhtml + y + ","
            i = i + 1
            
        xhtml = xhtml[:-1]
        yhtml = yhtml[:-1]
        xhtml = xhtml + ");"
        yhtml = yhtml + ");"
        
        html = xhtml + "\n" + yhtml + "\n"  
        html = html + "make_line(" + self.canvas_context + ", x_" + name + ", y_" + name +", '" + point_shape +"')\n"
        # Return canvas-formatted graph data (for line drawing)
        return html
        
    def flow_key(self, f):
        return str(f.flow_tuple[0]) + ":" + str(f.flow_tuple[1]) + "::" + str(f.flow_tuple[2]) + ":" + str(f.flow_tuple[3]) + "|" + str(f.flow_tuple[4])         
    
    def update_active_flows(self):
        peers = singleton_webgui.x_alice.get_peers()
        for p in peers:
            flows = p.new_flows()
            if isinstance(flows, list):
                for f in flows:
                    ip = self.flow_key(f)
                    if singleton_webgui.active_flows.get(ip):
                        pass
                    else:
                        singleton_webgui.active_flows[ip] = f
        for f in singleton_webgui.active_flows:
            if singleton_webgui.active_flows[f].is_active():
                pass
            else:
                del singleton_webgui.active_flows[f]
          
    def delete_old_packets(self, packet_list, cutoff_time):
        new_packet_list = list()
        for index, packet in enumerate(packet_list): 
            if packet[0] > cutoff_time:
                new_packet_list.append(packet)
        packet_list = None
        return new_packet_list

                
    def update_packet_data(self):
        # For each active flow

        peers = singleton_webgui.x_alice.get_peers()

        for flow_ip in singleton_webgui.active_flows:
            # If flow does not exist in dictionary object, add
            f = singleton_webgui.active_flows[flow_ip]
            if singleton_webgui.packet_data.get(flow_ip) :
                pass
            else:
                print "Adding", flow_ip
                singleton_webgui.packet_data[flow_ip] = dict()
                singleton_webgui.packet_data[flow_ip]['dropped'] = list()
                singleton_webgui.packet_data[flow_ip]['injected'] = list()
                singleton_webgui.packet_data[flow_ip]['modified'] = list()
                singleton_webgui.packet_data[flow_ip]['total count'] = list()
            
            # Each active flow has 4 lists of packets: dropped, injected, 
            # modified, total count
            
            self.cutoff_time = time.time() - singleton_webgui.save_window
            
            singleton_webgui.packet_data[flow_ip]['dropped'].extend(f.get_new_dropped_packets())
            singleton_webgui.packet_data[flow_ip]['injected'].extend(f.get_new_injected_packets())
            singleton_webgui.packet_data[flow_ip]['modified'].extend(f.get_new_modified_packets())  
            
            print "dropped, adding", singleton_webgui.packet_data[flow_ip]['dropped']  
            
            singleton_webgui.packet_data[flow_ip]['dropped'] = \
                self.delete_old_packets(singleton_webgui.packet_data[flow_ip]['dropped'], self.cutoff_time)
            singleton_webgui.packet_data[flow_ip]['injected'] = \
                self.delete_old_packets(singleton_webgui.packet_data[flow_ip]['injected'], self.cutoff_time)
            singleton_webgui.packet_data[flow_ip]['modified'] = \
                self.delete_old_packets(singleton_webgui.packet_data[flow_ip]['modified'], self.cutoff_time)
            print "dropped, trimmed", singleton_webgui.packet_data[flow_ip]['dropped']
            
            
            singleton_webgui.packet_data[flow_ip]['total count'].extend([(time.time(),  f.get_new_packet_count()) ])
                
    def make_legend(self):
        i = 0
        html = "<table>\n"
        shtml = '''<script type="text/javascript">

function gen_legend_''' + self.canvas_id + '''() {
'''
        for ip in self.gui_flows:
            line_name = ip.replace(":","_")
            line_name = line_name.replace(".","_")
            html = html + '''<tr><td><canvas id="leg_''' + line_name + '''_dr" height="20" width="50">''' + canvas_message + '''</canvas></td><td>'''
            html = html + '''</td><td>'''  + ip + ''' dropped</td></tr>\n'''
            html = html + '''<tr><td><canvas id="leg_''' + line_name + '''_in" height="20" width="50">''' + canvas_message + '''</canvas></td><td>'''
            html = html + '''</td><td>'''  + ip + ''' inserted</td></tr>\n'''
            html = html + '''<tr><td><canvas id="leg_''' + line_name + '''_mo" height="20" width="50">''' + canvas_message + '''</canvas></td><td>'''
            html = html + '''</td><td>'''  + ip + ''' modified</td></tr>\n'''
            shtml = shtml + '''legend_entry("leg_''' + line_name + '''_dr", 50, 20, "''' + self.draw_colors[i%len(self.draw_colors)] + '''", "x");\n'''
            shtml = shtml + '''legend_entry("leg_''' + line_name + '''_in", 50, 20, "''' + self.draw_colors[i%len(self.draw_colors)] + '''", "triangle");\n'''
            shtml = shtml + '''legend_entry("leg_''' + line_name + '''_mo", 50, 20, "''' + self.draw_colors[i%len(self.draw_colors)] + '''", "square");\n'''
            i = i + 1
        html = html + "</table>\n"
        
        shtml = shtml + '''
}
gen_legend_''' + self.canvas_id + '''();
</script>'''
        
        return (html + shtml)
        
    def make_graph(self):
        self.update_active_flows()        
        
        # Update which flows we care about
        # For now, all of them.  Will update to those selected by GUI
        self.gui_flows = dict()
        for f in singleton_webgui.active_flows:
            self.gui_flows[f] = singleton_webgui.active_flows[f]
            
        self.update_packet_data()
        self.get_min_max_time()
        
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
            line_name = line_name.replace("|","_")
            # Make graph data
            graph_data_html = graph_data_html + self.canvas_context + '''.fillStyle = "''' + self.draw_colors[i%len(self.draw_colors)] + '''"\n'''
            graph_data_html = graph_data_html + self.canvas_context + '''.strokeStyle = "''' + self.draw_colors[i%len(self.draw_colors)] + '''"\n'''            
            graph_data_html = graph_data_html + self.make_graph_data(line_name + "_dr", self.histograms[ip]['dropped'], "x")
            graph_data_html = graph_data_html + self.make_graph_data(line_name + "_in", self.histograms[ip]['injected'], "triangle")
            graph_data_html = graph_data_html + self.make_graph_data(line_name + "_mo", self.histograms[ip]['modified'], "square")
            line_names[line_name] = line_name
            i = i + 1
            
        html = '''

<canvas id="''' + self.canvas_id + '''" width="''' + str(self.width) + '''" height="''' + str(self.height) + '''">       
    Canvas is not supported.
</canvas>
''' + self.dump_graph_info() + '''
<script type="text/javascript">
<!--
    function drawgraph_''' + self.canvas_id + '''() {
        var canvas_''' + self.canvas_id + ''' = document.getElementById("''' + self.canvas_id + '''");
        if (canvas_''' + self.canvas_id + '''.getContext) {            
            var ''' + self.canvas_context + ''' = canvas_''' + self.canvas_id + '''.getContext('2d');
            draw_axes(''' + self.canvas_context + ''',  // canvas context
                    ''' + str(self.x_margin) + ''',     
                    ''' + str(self.y_margin) + ''', 
                    ''' + str(self.x_axis_margin) + ''',        // left hand margin for axis info
                    ''' + str(self.y_axis_margin) + ''',        // bottom margin for axis info
                    ''' + str(self.width) + ''',                // canvas element width
                    ''' + str(self.height) + ''',               // canvas element height
                    ''' + str(self.graph_xbins_actual) + ''',   // number of x histogram bins
                    ''' + str(self.graph_ybins) + ''',          // number of y levels
                    ''' + str(self.x_bin_pixels)  + ''',        // number of pixels per x bin
                    ''' + str(self.x_bin_size) + ''',           // number of seconds per x bin
                    ''' + str(self.y_bin_pixels) + ''', 
                    ''' + str(self.y_bin_size) + ''');          // number of packets per y bin 
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
    
    def dump_graph_info(self):
        html = '''        <br>
        self.graph_height ''' + str(self.graph_height) + '''<br>
        self.graph_width ''' + str(self.graph_width) + '''<br>
        self.graph_xbins ''' + str(self.graph_xbins) + '''<br>
        self.graph_xbins_actual ''' + str(self.graph_xbins_actual) + '''<br>
        self.graph_ybins ''' + str(self.graph_ybins) + '''<br>
        self.graph_ybins_actual ''' + str(self.graph_ybins_actual) + '''<br>
        self.y_hist_max ''' + str(self.y_hist_max) + '''<br>
        range ''' + str(self.max_timestamp - self.min_timestamp)+ '''<br>
        self.max_timestamp ''' + str(self.max_timestamp)+ '''<br>
        self.min_timestamp ''' + str(self.min_timestamp)+ '''<br>
        time ''' + str(time.time())+ '''<br>
        self.cutoff_time ''' + str(self.cutoff_time)+ '''<br>
        self.x_bin_pixels ''' + str(self.x_bin_pixels) + '''<br>
        self.x_bin_size ''' + str(self.x_bin_size) + '''<br>
        self.y_bin_pixels ''' + str(self.y_bin_pixels) + '''<br>
        self.y_bin_size ''' + str(self.y_bin_size) + '''<br>
        <br>
        '''
        return html
 
    
class index:
    def GET(self):
        render = web.template.render('templates')
        client_info = render.client_info(singleton_webgui.x_alice.get_client_info())
        server_info = render.server_info(singleton_webgui.x_alice.get_server_info())
        active_flows = render.flow_list(singleton_webgui.active_flows)
        graph = line_graph() 
        graph_html = graph.make_graph()       
        return render.dashboard(client_info, 
            server_info,
            active_flows,
            graph.make_legend(),
            graph_html)

# List mutable configuration parameters, allow to change
class config:
    def GET(self):  
        page = '''<p>Tweakable Options</p>
                    <form name="frmMutableOpt" id="frmMutableOpt">\n<table>\n'''
                    
        for opt in singleton_webgui.x_alice_config.tweakable_options:
            page = page + '''<tr><td>''' + opt + '''</td>'''
            page = page + '''<td><input name="''' + opt +  '''"''' 
            page = page + ''' value="''' + WebGUI.x_alice_config.get_option(opt) 
            page = page + '''"/></td></tr>\n'''
        
        page = page + '''</table>\n<br/>\n
                    <input type="submit" value="Save changes"/></form>\n
                    <p>Immutable Options</p>\n
                    <table>\n'''
                    
        for opt in WebGUI.x_alice_config.immutable_options:
            page = page + '''<tr><td>''' + opt + '''</td>'''
            page = page + '''<td>''' + WebGUI.x_alice_config.get_option(opt) + '''</td></tr>\n'''
        
        page = page + "<table>\n"
         
        return page
    

class WebGUI():
    """ Run a GUI with monitoring features as a local web server """

    def __init__(self):
        self.x_alice_config = xAliceConfig()
        self.x_alice = xAlice(self.x_alice_config)
        self.packet_data = dict()
        self.active_flows = dict()
        self.save_window = 60 * 60  # Number of seconds to save (1 hour default)
        self.refresh_interval = 10  # Number of seconds between refresh
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