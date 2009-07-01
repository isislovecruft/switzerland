#!/usr/bin/env python
import web
import time
import math

#from AliceAPI import xAlice, xAliceConfig, xPeer, xFlow
from AliceAPIFake import xAlice, xAliceConfig, xPeer, xFlow

singleton_webgui = None
debug_output = False


class line_graph:
    def __init__(   self, 
                    canvas_id="cid",
                    canvas_context="jg",
                    width=800, 
                    height=400,
                    graph_xbins=50, 
                    graph_ybins=20):  
                    
        self.use_round_numbers = True
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
        print "x calculations"
        if self.use_round_numbers:
            (self.graph_xbins_actual, self.x_bin_size) = self.get_round_bin_size(range_timestamp, self.graph_xbins)
        else:
            self.x_bin_size = self.get_bin_size(range_timestamp,self.graph_xbins)
        print "rough bin size", str(range_timestamp / self.graph_xbins), "bin size", self.x_bin_size
        # Return bin size (in seconds) 
        return self.x_bin_size
    
    def get_bin_size(self, range, bins):
        bin_size = float(range) / float(bins)
        bin_size = math.ceil(bin_size) 
        if bin_size < 1:
            bin_size = 1
        return bin_size
    
    def get_round_bin_size(self, range, bins):
        est_bin_size = float(range) / float(bins)
        print "range:", range, "bins:", bins, "est bin size:", est_bin_size
        binlog = int(-math.floor(math.log10(est_bin_size)))
        actual_bin_size = math.ceil(est_bin_size) 
        if actual_bin_size == 0:
            actual_bin_size = 1
        actual_bins = math.ceil((int(range) / est_bin_size))
        print "actual bins:", actual_bins
        return (actual_bins, actual_bin_size)    

        
    def make_graph_data(self, name, histogram, point_shape="circle"):
        
        i = 0
        self.x_bin_pixels = int(self.graph_width/self.graph_xbins_actual)
        print "width:", self.graph_width, "xbins_actual:", self.graph_xbins_actual, "x_bin_pixels:", self.x_bin_pixels
        if self.use_round_numbers:
            (self.graph_ybins_actual, self.y_bin_size) = self.get_round_bin_size(self.y_hist_max, self.graph_ybins)
        else:
            self.y_bin_size = self.x_bin_size = self.get_bin_size(self.y_hist_max,self.graph_ybins)
            
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
            print "y:", y 
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
    
 
        
    def delete_old_packets(self, packet_list, cutoff_time) :
        for packet in packet_list:
            if packet[0] < cutoff_time:
                packet_list.remove(packet)
  
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
                cutoff_time = time.time() - singleton_webgui.save_window
                self.delete_old_packets(singleton_webgui.packet_data[flow_ip]['dropped'], cutoff_time)
                self.delete_old_packets(singleton_webgui.packet_data[flow_ip]['injected'], cutoff_time)
                self.delete_old_packets(singleton_webgui.packet_data[flow_ip]['modified'], cutoff_time)
                singleton_webgui.packet_data[flow_ip]['dropped'].extend(f.get_new_dropped())
                singleton_webgui.packet_data[flow_ip]['injected'].extend(f.get_new_injected())
                singleton_webgui.packet_data[flow_ip]['modified'].extend(f.get_new_modified())    
                singleton_webgui.packet_data[flow_ip]['total count'].extend([(time.time(),  f.get_new_packet_count()) ])
                
    
    def js_graph_functions(self):
        html = '''
<script type="text/javascript">    

    function draw_axes(ctx, x_mar, y_mar, x_ax_mar, y_ax_mar, width, height, 
            x_bins, y_bins, x_bin_pixels, x_bin_size, y_bin_pixels, y_bin_size) {
            
        var graph_height = height - (2 * y_mar + y_ax_mar);
        var graph_width = width - (2 * x_mar + x_ax_mar);
        
        ctx.strokeStyle = 'black';
        ctx.textAlign = 'center';

        ctx.beginPath();
        ctx.moveTo(x_mar + x_ax_mar, y_mar);
        ctx.lineTo(x_mar + x_ax_mar, height - (y_mar + y_ax_mar));
        ctx.lineTo(width - (x_mar), height - (y_mar + y_ax_mar));
        
        
        
        // Draw the y axis numbers and hash marks
        for (i = 0; i < y_bins; i++) {
            var y = y_mar + y_ax_mar + (y_bin_pixels * i);
            ctx.moveTo((x_mar + x_ax_mar - 5), height - y);
            ctx.lineTo((x_mar + x_ax_mar + 5), height - y);   
            if (i % 5 == 0) {
                ctx.save();
                var label = i * y_bin_size;
                var len = ctx.mozMeasureText(label); 
                ctx.translate(x_mar , height - y);
                ctx.mozTextStyle = "8pt Arial, Helvetica"
                ctx.mozDrawText(Math.round(label*10)/10);
                ctx.restore();
            }       
        }
    
        // Draw the x axis numbers and hash marks
        for (i = 0; i < x_bins; i++){
            var x = x_mar + x_ax_mar + (x_bin_pixels * i);
            ctx.moveTo(x, height - (y_mar + y_ax_mar - 5));
            ctx.lineTo(x, height - (y_mar + y_ax_mar + 5));
            
            if (i % 5 == 0) {
                ctx.save();
                var label = x_bin_size * i;
                var len = ctx.mozMeasureText(label); 
                ctx.translate(x - len/2 , height - (y_mar + y_ax_mar - 14));
                ctx.mozTextStyle = "8pt Arial, Helvetica"
                ctx.mozDrawText(Math.round(label*10)/10);
                ctx.restore();
            }
            // FF 3.5 standard instead of ctx.MozDrawText
            //ctx.fillText(bin_pixels * i, x, y_ax_mar - 12);
        }
        

        ctx.stroke();
    }

    function make_point(ctx, x, y, shape){
        switch(shape) {
        
        case "x":
            ctx.beginPath();
            ctx.moveTo(x-3, y-3);
            ctx.lineTo(x+3, y+3);
            ctx.moveTo(x-3, y+3);
            ctx.lineTo(x+3, y-3);
            ctx.stroke();
            break;
        case "circle":
            ctx.beginPath();
            ctx.arc(x, y, 3, 0, Math.PI*2, true);
            ctx.fill();
            break;
        case "triangle":
            ctx.beginPath();
            ctx.moveTo(x-3, y+2);
            ctx.lineTo(x+3, y+2);
            ctx.lineTo(x, y-3);
            ctx.fill();  
            break;
        case "square":
            ctx.beginPath();
            ctx.moveTo(x-3, y-3);
            ctx.lineTo(x+3, y-3);
            ctx.lineTo(x+3, y+3);
            ctx.lineTo(x-3, y+3);
            ctx.fill(); 
            break;
        }
    }
    
    function make_line(ctx, x_array, y_array, shape){
        if (x_array.length != y_array.length) {
            alert("Lengths of data arrays do not match!");
            return;
        }
        ctx.beginPath();
        ctx.moveTo(x_array[0], y_array[0]);       
        for (var i = 0; i < x_array.length; i++){ 
            ctx.lineTo(x_array[i], y_array[i]);
        }
        ctx.stroke();
        make_point(ctx, x_array[0], y_array[0], shape);        
        for (var i = 0; i < x_array.length; i++){ 
            make_point(ctx, x_array[i], y_array[i], shape); 
        }
    }
</script>
            
        '''
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
        ''' + str(self.max_timestamp - self.min_timestamp)+ '''<br>
        self.x_bin_pixels ''' + str(self.x_bin_pixels) + '''<br>
        self.x_bin_size ''' + str(self.x_bin_size) + '''<br>
        self.y_bin_pixels ''' + str(self.y_bin_pixels) + '''<br>
        self.y_bin_size ''' + str(self.y_bin_size) + '''<br>
        <br>
        '''
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
        html = '''<table>\n'''
        info_hash = singleton_webgui.x_alice.get_client_info()
        for key in info_hash:
            html = html + '''<tr><td>''' + key + '''</td><td>''' 
            html = html + str(info_hash[key]) + '''</td></tr>\n'''
        html = html + '''</table>\n'''
        return html
    
    def display_server_info(self):
        html = '''<table>\n'''
        info_hash = singleton_webgui.x_alice.get_server_info()
        for key in info_hash:
            html = html + '''<tr><td>''' + key + '''</td><td>''' 
            html = html + str(info_hash[key])  + '''</td></tr>\n'''
        html = html + '''</table>\n'''
        return html
    
    def display_peer_list(self):
        html = '''<table>\n'''
        for peer in singleton_webgui.x_alice.get_peers():
            for f in peer.active_flows():
                html = html + '''<tr><td>''' + str(f.flow_tuple[0]) + '''</td>'''
                html = html + '''<td>''' + str(f.flow_tuple[1]) + '''</td>''' 
                html = html + '''<td>''' + str(f.flow_tuple[2]) + '''</td>''' 
                html = html + '''<td>''' + str(f.flow_tuple[3]) + '''</td></tr>\n'''
        html = html + '''</table>\n'''
        return html

    
class index:
    def GET(self):
        page = '''<html><head><title>Switzerland</title></head><body>\n'''
        i = info_utility()
        page = page + i.display_client_info()
        page = page + i.display_server_info()
        page = page + i.display_peer_list()
        graph = line_graph()        
        page = page + graph.js_graph_functions()
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
        self.save_window = 60 * 60  # Number of seconds to save (1 hour default)
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