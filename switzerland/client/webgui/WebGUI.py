#!/usr/bin/env python
import web
import time
import math
import sys
import logging
sys.path.append("..") 

#from AliceAPI import xAlice, xAliceConfig, xPeer, xFlow, xPacket
from AliceAPIFake import xAlice, xAliceConfig, xPeer, xFlow, xPacket

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
        for i in range(0,int(self.graph_xbins_actual)):
            histogram.append(0)
 
        #try: 
        if isinstance(packet_list[0][1], xPacket):  
            # Handle detailed packet lists
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
            # Handle total packet (not detailed) list
            packet_list.sort()
            updated_packet_list = list()
            
            prev_time = self.min_timestamp
            
            for p in packet_list:
                num_packets = p[1]
                cur_time = p[0]
                time_range = cur_time - prev_time
                for i in range(num_packets):
                    new_time = prev_time + i * (time_range/num_packets) 
                    updated_packet_list.append(new_time)
                prev_time = cur_time
                    
            for packet_ts in updated_packet_list:
                i =  packet_ts - self.min_timestamp
                i = int(i/self.x_bin_size)
                if i < len(histogram):
                    histogram[i] = histogram[i] + 1
                else:
                    if debug_output:
                        ''' This data is preserved for the next reload '''
                        print "index", i, "out of range"    
            
        #except:
        #    print "Something is wrong with the incoming packet data."
        #    print "Check to make sure that the packet_list is not None."
            
        # Return histogram
        return histogram
    
            
    def get_y_hist_max(self, include_total=True):
        all_packcount = list()
        for ip in self.gui_flows:
            print "get_y_hist_max gui flow", ip
            if include_total:
                all_packcount.extend(self.histograms[ip]['total'])
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
            print "total count", singleton_webgui.packet_data[ip]['total']
            
        self.max_timestamp = max(all_timestamps)
        self.min_timestamp = min(all_timestamps)
        print "max ts", self.max_timestamp, "min ts", self.min_timestamp
        
    # Pass in all flows and get bin size used if all of these were
    # plotted on same graph
    # flows = list of xFlows objects
    def get_hist_xbin_size(self):
        
        range_timestamp = self.max_timestamp - self.min_timestamp
        print "x calculations"
        
        (self.graph_xbins_actual, self.x_bin_size) = \
            self.get_round_bin_size(range_timestamp, self.graph_xbins)
        
        print "rough bin size", str(range_timestamp / self.graph_xbins), \
            "bin size", self.x_bin_size
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
      
        (self.graph_ybins_actual, self.y_bin_size) = \
            self.get_round_bin_size(self.y_hist_max, self.graph_ybins)
            
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
        html = html + "make_line(" + self.canvas_context + ", x_" + name \
            + ", y_" + name +", '" + point_shape +"')\n"
        # Return canvas-formatted graph data (for line drawing)
        return html
        
    def flow_key(self, f):
        return str(f.flow_tuple[0]) + ":" + str(f.flow_tuple[1]) + "::" \
            + str(f.flow_tuple[2]) + ":" + str(f.flow_tuple[3]) \
            + "|" + str(f.flow_tuple[4])         
    
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
                singleton_webgui.packet_data[flow_ip]['total'] = list()
            
            # Each active flow has 4 lists of packets: dropped, injected, 
            # modified, total count
            
            self.cutoff_time = time.time() - singleton_webgui.web_app_config['save_window'][0]
            
            singleton_webgui.packet_data[flow_ip]['dropped'].extend( \
                f.get_new_dropped_packets())
            singleton_webgui.packet_data[flow_ip]['injected'].extend( \
                f.get_new_injected_packets())
            singleton_webgui.packet_data[flow_ip]['modified'].extend( \
                f.get_new_modified_packets())  
            
            singleton_webgui.packet_data[flow_ip]['total'].extend(
                [(time.time(),  f.get_new_packet_count()) ])
            
            
            singleton_webgui.packet_data[flow_ip]['dropped'] = \
                self.delete_old_packets(
                    singleton_webgui.packet_data[flow_ip]['dropped'], 
                        self.cutoff_time)
            singleton_webgui.packet_data[flow_ip]['injected'] = \
                self.delete_old_packets(
                    singleton_webgui.packet_data[flow_ip]['injected'], 
                    self.cutoff_time)
            singleton_webgui.packet_data[flow_ip]['modified'] = \
                self.delete_old_packets(
                singleton_webgui.packet_data[flow_ip]['modified'], 
                self.cutoff_time)
            singleton_webgui.packet_data[flow_ip]['total'] = \
                self.delete_old_packets(
                singleton_webgui.packet_data[flow_ip]['total'], 
                self.cutoff_time)

    
    # Legend for the graph
    # precondition: gui_flows must be set            
    def make_legend(self):
        i = 0
        entries = list()
        for ip in self.gui_flows:
            line_name = ip.replace(":","_")
            line_name = line_name.replace(".","_")
            entries.append((ip, '''leg_''' + line_name + '''_dr''', ip + ''' dropped''', self.draw_colors[i%len(self.draw_colors)], "x"))
            entries.append((ip, '''leg_''' + line_name + '''_in''', ip + ''' injected''', self.draw_colors[i%len(self.draw_colors)], "triangle"))
            entries.append((ip, '''leg_''' + line_name + '''_mo''', ip + ''' modified''', self.draw_colors[i%len(self.draw_colors)], "square"))
            entries.append((ip, '''leg_''' + line_name + '''_to''', ip + ''' total''', self.draw_colors[i%len(self.draw_colors)], ""))
            i = i + 1
        render = web.template.render('templates')
        return render.packet_graph_legend(self.canvas_id,
            entries)
     
    # Return graph HTML to render graph with HTML canvas element   
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
            self.histograms[ip]['dropped'] = \
                self.make_histogram(singleton_webgui.packet_data[ip]['dropped'])
            self.histograms[ip]['injected'] = \
                self.make_histogram(singleton_webgui.packet_data[ip]['injected'])
            self.histograms[ip]['modified'] = \
                self.make_histogram(singleton_webgui.packet_data[ip]['modified'])
            self.histograms[ip]['total'] = \
                self.make_histogram(singleton_webgui.packet_data[ip]['total'])           
        
        i = 0
        # Get maximum y value (# of packets)
        self.get_y_hist_max(True)
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
            graph_data_html = graph_data_html + self.make_graph_data(line_name + "_to", self.histograms[ip]['total'], "total")
            line_names[line_name] = line_name
            i = i + 1
        
        # Use a temporary dict to pass all fo the graph variables to the
        # JavaScript function
        graph_opts = dict()
        graph_opts['canvas_id'] = self.canvas_id
        graph_opts['canvas_context'] = self.canvas_context
        graph_opts['x_margin'] = self.x_margin
        graph_opts['y_margin'] = self.y_margin
        graph_opts['x_axis_margin'] = self.x_axis_margin
        graph_opts['y_axis_margin'] = self.y_axis_margin
        graph_opts['width'] = self.width
        graph_opts['height'] = self.height
        graph_opts['graph_xbins_actual'] = self.graph_xbins_actual
        graph_opts['graph_ybins'] = self.graph_ybins
        graph_opts['x_bin_pixels'] = self.x_bin_pixels
        graph_opts['x_bin_size'] = self.x_bin_size
        graph_opts['y_bin_pixels'] = self.y_bin_pixels
        graph_opts['y_bin_size'] = self.y_bin_size
      
        # Finally, plot to canvas 
        # return html   
        render = web.template.render('templates')
        return render.packet_graph(graph_opts,
            graph_data_html)
    
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
        graph = line_graph() 
        # Call make_graph FIRST to load data into structures
        graph_html = graph.make_graph() 
        client_info = render.client_info(singleton_webgui.x_alice.get_client_info())
        server_info = render.server_info(singleton_webgui.x_alice.get_server_info())
        active_flows = render.flow_list(singleton_webgui.active_flows)      
        legend = graph.make_legend()
        return render.dashboard(client_info, 
            server_info,
            active_flows,
            legend,
            graph_html,
            singleton_webgui.web_app_config['refresh_interval'][0])

# List mutable configuration parameters, allow to change
class config:
    def GET(self):  
        render = web.template.render('templates', globals={'logging': logging})
        return render.config(singleton_webgui.x_alice_config, 
            singleton_webgui.x_alice_config.tweakable_options,
            singleton_webgui.x_alice_config.immutable_options,
            singleton_webgui.web_app_config)
    
    def POST(self):  
        webin = web.input()
        if webin.form == "frmApplicationOpt":
            # Edit web application variables
            message = "Changes saved."
            try:
                singleton_webgui.web_app_config['save_window'][0] = int(webin.save_window)
            except:
                message = "The save window must be a number of seconds."
            try:
                singleton_webgui.web_app_config['refresh_interval'][0] = int(webin.refresh_interval)
            except:
                message = "The refresh interval must be a number of seconds."
                
        else:
            # Edit tweakable variables
            message = "Changes saved."
            try:
                #lvl =  singleton_webgui.LOG_LEVELS.get(webin.log_level, logging.NOTSET)
                singleton_webgui.x_alice_config.set_option("log_level", int(webin.log_level))
            except:
                message = "The log_level must be a valid python logging log level (e.g. logging.DEBUG)"
            try:
                singleton_webgui.x_alice_config.set_option("seriousness",  int(webin.seriousness))
            except:
                message = "Seriousness must be an integer."
            try:
                singleton_webgui.x_alice_config.set_option("do_cleaning", bool(webin.do_cleaning))
            except:
                message = "The refresh interval must be a number of seconds."
            
        render = web.template.render('templates', globals={'logging': logging})
        return render.config(singleton_webgui.x_alice_config, 
            singleton_webgui.x_alice_config.tweakable_options,
            singleton_webgui.x_alice_config.immutable_options,
            singleton_webgui.web_app_config, message)

    

class WebGUI():
    """ Run a GUI with monitoring features as a local web server """
    
    # From python logging module documentation
    # http://docs.python.org/library/logging.html
                
    def __init__(self):
        self.x_alice_config = xAliceConfig()
        self.x_alice = xAlice(self.x_alice_config)
        self.packet_data = dict()
        self.active_flows = dict()
        self.web_app_config = dict()
        self.web_app_config['save_window'] = [60 * 60, "Save window", "Number of seconds to save"]
        self.web_app_config['refresh_interval'] = [10, "Refresh interval", "Number of seconds between refresh"]
        self.urls = (
            '/', 'index', 
            '', 'index',
            '/config', 'config')
        
    def main(self):
        self.app = web.application(self.urls, globals())
        self.app.run()


if __name__ == "__main__":
    singleton_webgui = WebGUI()
    singleton_webgui.main()