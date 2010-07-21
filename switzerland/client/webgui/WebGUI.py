#!/usr/bin/env python

# Run as
# ./switzerland/client/webgui/WebGUI.py --fake
# Where --fake optionally specifies the bogus demo
# that can run without a network

import web
import time
import math
import sys
import os
import logging
import getopt
import socket as s
import switzerland.common.Flow

from switzerland.common.Flow import print_flow_tuple
from switzerland.client.AliceConfig import AliceConfig

# singleton_webgui is the most important object!  All data that persists between
# calls to this web application server is tied to this instance.
singleton_webgui = None
debug_output = False
web_py_server = '0.0.0.0'
web_py_port = '8080'

# The line_graph class represents the line graph and all of its data.
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
        # Get the maximum y value (packets) that we represent in the graph
        self.y_hist_max = None
        self.x_bin_size = None # in seconds
        self.y_bin_size = None # in packets
        # how many pixels per bin
        self.x_bin_pixels = None 
        self.y_bin_pixels = None
        # blank margin
        self.y_margin = 5   
        self.x_margin = 10
        # margin allowance for drawing axes and labels
        self.x_axis_margin = 35 
        self.y_axis_margin = 30
        # actual height of graph-- size of image minus the margins
        self.graph_height = height - (self.y_axis_margin + 2 * self.y_margin)
        self.graph_width = width - (self.x_axis_margin + 2 * self.x_margin)
        
        
        
        # JavaScript canvas context name
        self.canvas_context = canvas_context
        # HTML element ID of canvas element
        self.canvas_id = canvas_id
        # Cycle through these colors (10 colors) so we have some contrast
        # in the lines in the graph
        self.draw_colors = ["#ff0000", "#0000ff", "#009933", "#660066", 
            "#ff6600", "#6699ff", "#ffcc33", "#00cc00", "#cc3300", "#606060"]

    # Turn the incoming packet data into a histogram
    # The histogram is an array of bins, where each bin contains the total number
    # packets for that time segment as well as packet information for each
    # dropped, modified, injected packet in that segment
    def make_histogram(self, packet_list):
        histogram = list()
        
        # Create the empty histogram
        for i in range(0,int(self.graph_xbins_actual)):
            histogram.append([0,list()])
 
        try: 
            # This if block will happen if the packet type is
            # injected, modified, or dropped
            if isinstance(packet_list[0][1], xPacket):  
                # Handle detailed packet lists
                # Count packets into bins
                #for packet_ts in [p[0] for p in packet_list]:
                for p in packet_list:
                    packet_ts = p[0]
                    i =  packet_ts - self.min_timestamp
                    i = int(i/self.x_bin_size)
                    if i < len(histogram):
                        # Increase the packet count
                        histogram[i][0] = histogram[i][0] + 1
                        # Add the packet detail to the list
                        histogram[i][1].append(p[1])
                    else:
                        if debug_output:
                            ''' This data is preserved for the next reload '''
                            print "index", i, "out of range"
            else:
                # Handle total packet (not detailed) list
                # This else block will happen if the packet type is just a
                # total packet count
                packet_list.sort()
                updated_packet_list = list()
                
                prev_time = self.min_timestamp
                
                for p in packet_list:
                    num_packets = int(p[1])
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
                        histogram[i][0] = histogram[i][0] + 1
                    else:
                        if debug_output:
                            ''' This data is preserved for the next reload '''
                            print "index", i, "out of range"    
                
        except:
            # Prints right to console
            # TODO: use logging consistent with switzerland-client (?)
            print "Something is wrong with the incoming packet data."
            print "Check to make sure that the packet_list is not None."
            
        # Return histogram
        return histogram
    
    # Get maximum y value in histograms, so we can continue to adjust vertical
    # size of graph        
    def get_y_hist_max(self, include_total=True):
        all_packcount = list()
        for ip in singleton_webgui.packet_data.active_flows:
            if self.histograms[ip]['total'] != None:
                all_packcount.extend([p[0] for p in self.histograms[ip]['total']])
            if self.histograms[ip]['modified'] != None:
                all_packcount.extend([p[0] for p in self.histograms[ip]['modified']])
            if self.histograms[ip]['injected'] != None:
                all_packcount.extend([p[0] for p in self.histograms[ip]['injected']])
            if self.histograms[ip]['dropped'] != None:
                all_packcount.extend([p[0] for p in self.histograms[ip]['dropped']])
                          
        if len(all_packcount) > 0:
            self.y_hist_max = max(all_packcount)
        else:
            self.y_hist_max = 0
    
    # The minimum and maximum timestamps become the range of the x-axis of the 
    # graph    
    def get_min_max_time(self):

        all_timestamps = list()
        
        for ip in singleton_webgui.packet_data.active_flows :
            ts_list = [p[0] for p in singleton_webgui.packet_data.packet_data[ip]['dropped']]
            # Rather than concatenating ALL the timestamps, we
            # only need the mins and maxes.
            if len(ts_list) > 0 :
                all_timestamps.extend((min(ts_list), max(ts_list)))
            ts_list = [p[0] for p in singleton_webgui.packet_data.packet_data[ip]['injected']]
            if len(ts_list) > 0 :
                all_timestamps.extend((min(ts_list), max(ts_list)))
            ts_list = [p[0] for p in singleton_webgui.packet_data.packet_data[ip]['modified']]
            if len(ts_list) > 0 :
                all_timestamps.extend((min(ts_list), max(ts_list)))
            ts_list = [p[0] for p in singleton_webgui.packet_data.packet_data[ip]['total']]
            if len(ts_list) > 0 :
                all_timestamps.extend((min(ts_list), max(ts_list)))

        if len(all_timestamps) > 0:    
            self.max_timestamp = max(all_timestamps)
            self.min_timestamp = min(all_timestamps)
        else:
            # If we have no data yet, set to safe value of 0
            self.max_timestamp = 0
            self.min_timestamp = 0        

        
    # Get bin size (for x-axis, in seconds) used if all of these were
    # plotted on same graph
    def get_hist_xbin_size(self):
        range_timestamp = self.max_timestamp - self.min_timestamp
        
        (self.graph_xbins_actual, self.x_bin_size) = \
            self.get_round_bin_size(range_timestamp, self.graph_xbins)

        # Return bin size (in seconds) 
        return self.x_bin_size
    
    # Round the bin size to a whole number, or a nice round number which 
    # we get using log base 10
    def get_round_bin_size(self, range, bins):
        assert bins > 0
        
        est_bin_size = float(range) / float(bins)
        if est_bin_size > 0:

            binlog = int(-math.floor(math.log10(est_bin_size)))
            actual_bin_size = math.ceil(est_bin_size) 
            actual_bins = math.ceil((int(range) / est_bin_size))

            return (actual_bins, actual_bin_size)    
        return (1,1) # Empty data set

    # Use the data to create JavaScript statements which will be sent to the 
    # web page and used to create the graph
    def make_graph_data(self, name, histogram, point_shape="circle", 
        color="black"):
        
        if histogram == None:
            return ""
        if len(histogram) == 0:
            return ""
        
        (source_ip, source_port, dest_ip, dest_port, proto, 
            packet_type, packet_type_long) = self.split_name(name)
        
        assert self.graph_xbins_actual > 0
        
        i = 0
        self.x_bin_pixels = int(self.graph_width/self.graph_xbins_actual)
 
        (self.graph_ybins_actual, self.y_bin_size) = \
            self.get_round_bin_size(self.y_hist_max, self.graph_ybins)
            
        assert self.y_bin_size > 0
            
        self.y_bin_pixels = int(self.graph_height/self.graph_ybins_actual)
        
        html = "\n"
        xhtml = "new Array("
        yhtml = "new Array("
        
        for bin in histogram:
            
            # Get x from histogram bin
            # Get y from histogram value
            
            x = str(i * (self.x_bin_pixels) + self.x_axis_margin + self.x_margin)
            y = bin[0] * self.y_bin_pixels / self.y_bin_size
            
            y = str(self.height - (y + self.y_axis_margin + self.y_margin))
            xhtml = xhtml + x + ","
            yhtml = yhtml + y + ","
            i = i + 1
            
        xhtml = xhtml[:-1]
        yhtml = yhtml[:-1]
        xhtml = xhtml + ")"
        yhtml = yhtml + ")"
        indent = "            "
        html = html + self.canvas_id + "_data['" + name + "']" 
        html = html + " = new FlowData(\n" + indent
        html = html + xhtml  + ",\n" + indent + yhtml + ",\n" + indent + self.canvas_context
        html = html + ",\n" + indent + "'" + point_shape + "', '" + color + "',\n" + indent + "'" + name + "',\n "
        html = html + indent + "'" + source_ip + "', '" + source_port + "',\n "
        html = html + indent + "'" + dest_ip+ "', '" + dest_port + "' , '" + proto + "', '" + packet_type + "');\n\n"
        
        # Return JavaScript graph data (for line drawing)
        return html
    
    # Given the flow name format used for hashes (underscores instead of 
    # periods and colons), turn the flow name back into its constituent parts    
    def split_name(self, flow_name):
        tuple = flow_name.replace("__", "_").split("_")
        
        source_ip = ".".join(tuple[0:4])
        dest_ip = ".".join(tuple[5:9])
        source_port = tuple[4]
        dest_port = tuple[9]
        if len(tuple) > 10:
            proto = tuple[10]
        else:
            proto = ""
        if len(tuple) > 11:
            packet_type = tuple[11]
            if packet_type == "mo":
                packet_type_long = "modified"
            elif packet_type == "in":
                packet_type_long = "injected"
            elif packet_type == "dr":
                packet_type_long = "dropped"
            else:
                packet_type_long = "total"
        else:
            packet_type = ""
            packet_type_long = ""
        return (source_ip, source_port, dest_ip, dest_port, proto, packet_type, packet_type_long)
            
    # Legend for the graph         
    def make_legend(self):
        i = 0
        entries = list()
        for flow_name in singleton_webgui.packet_data.active_flows:

            (source_ip, source_port, dest_ip, dest_port, proto, packet_type, packet_type_long) = self.split_name(flow_name)
            # List each flow once only. 
            entries.append(('''leg_''' + flow_name + '''_to''', source_ip, source_port, dest_ip, dest_port, proto, '''total''' ))
            i = i + 1

        render = web.template.render('templates')
        return render.packet_graph_legend(self.canvas_id,
            entries, singleton_webgui.packet_data.visible_flows)
     
    # Return graph HTML to render graph with HTML canvas element   
    def make_graph(self):
    
        # Update data and active flows
        # singleton_webgui object persists between calls to the web application
        singleton_webgui.packet_data.update_active_flows()        
        singleton_webgui.packet_data.update_packet_data()
        self.get_min_max_time()
        
        if self.max_timestamp != 0:
        
            # Get bin size for all flows
            self.get_hist_xbin_size()
            self.histograms = dict()

            indent = "         "
            graph_data_html = indent + "var " + self.canvas_id + "_data = new Array();\n"
            
            flow_names = dict()
            # For each flow considered
            for flow_name in singleton_webgui.packet_data.active_flows:

                # Make a histogram for each packet type
                self.histograms[flow_name] = dict()
                if singleton_webgui.packet_data.visible_flows.get(flow_name + "_dr") == 'on':
                    self.histograms[flow_name]['dropped'] = \
                        self.make_histogram(singleton_webgui.packet_data.packet_data[flow_name]['dropped'])
                else: 
                    self.histograms[flow_name]['dropped'] = None
                if singleton_webgui.packet_data.visible_flows.get(flow_name + "_in") == 'on':
                    self.histograms[flow_name]['injected'] = \
                        self.make_histogram(singleton_webgui.packet_data.packet_data[flow_name]['injected'])
                else: 
                    self.histograms[flow_name]['injected'] = None
                if singleton_webgui.packet_data.visible_flows.get(flow_name + "_mo") == 'on':
                    self.histograms[flow_name]['modified'] = \
                        self.make_histogram(singleton_webgui.packet_data.packet_data[flow_name]['modified'])
                else: 
                    self.histograms[flow_name]['modified'] = None                
                if singleton_webgui.packet_data.visible_flows.get(flow_name + "_to") == 'on':
                    self.histograms[flow_name]['total'] = \
                        self.make_histogram(singleton_webgui.packet_data.packet_data[flow_name]['total'])           
                else: 
                    self.histograms[flow_name]['total'] = None 
            i = 0
            # Save our histogram to the persistent object
            singleton_webgui.packet_data.current_histograms = self.histograms
            # Get maximum y value (# of packets)
            self.get_y_hist_max(True)
            
            for flow_name in singleton_webgui.packet_data.active_flows:

                color = self.draw_colors[i%len(self.draw_colors)];
                
                h = self.make_graph_data(flow_name + "_dr", self.histograms[flow_name]['dropped'], "x", color );
                graph_data_html = graph_data_html + h
                
                h = self.make_graph_data(flow_name + "_in", self.histograms[flow_name]['injected'], "triangle", color );
                graph_data_html = graph_data_html + h
                                
                h = self.make_graph_data(flow_name + "_mo", self.histograms[flow_name]['modified'], "square", color );
                graph_data_html = graph_data_html + h  
                              
                h = self.make_graph_data(flow_name + "_to", self.histograms[flow_name]['total'], "total", color );
                graph_data_html = graph_data_html + h 
                               
                flow_names[flow_name] = flow_name
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
            graph_opts['min_timestamp'] = self.min_timestamp
          
            # Finally, plot to canvas 
            # return html   
            render = web.template.render('templates')
            return render.packet_graph(graph_opts, 
                graph_data_html, self.canvas_id + "_data")
        
        else:
            return "No data yet."        
                    
    
    # This function is not used except for debugging
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
 
# The ajax_server is a web page which receives and responds to ajax 
# requests from the web application
class ajax_server:
    def GET(self):
        webin = web.input()
        command = webin.command
        print "command", command
        render = web.template.render('templates/ajax_response')
        if command == 'packetInfo':
            return self.packet_info(webin, render)
        if command == 'updateGraph':
            return self.update_graph(webin, render)
        if command == 'updateLegend':
            return self.update_legend(webin, render)
        else:
            return("command " + command)
     
    # Update the graph data from incoming switzerland data and send new
    # JavaScript to the browser   
    def update_graph(self, webin, render):
        graph = line_graph() 
        # Call make_graph FIRST to load data into structures
        graph_html = graph.make_graph() 
        singleton_webgui.packet_data.current_graph = graph
        return graph_html
    
    # Send a new legend to the browser (important as flows change)
    def update_legend(self, webin, render):
        legend_html = singleton_webgui.packet_data.current_graph.make_legend()
        return legend_html
    
    # Send packet info details to the browser
    # TODO: xPacket is not implemented so we have no good data to send.    
    def packet_info(self, webin, render):
        flow_name = webin.flowId
        hist_bin = webin.histBinId
        flow_name = flow_name[:-3]
        modified = singleton_webgui.packet_data.current_histograms[flow_name]['modified'][int(hist_bin)][1]
        injected = singleton_webgui.packet_data.current_histograms[flow_name]['injected'][int(hist_bin)][1]
        dropped = singleton_webgui.packet_data.current_histograms[flow_name]['dropped'][int(hist_bin)][1]
        pi = render.packet_info(modified, injected, dropped)
        return pi
        
class index:
    def GET(self):
        return self.main()

    def POST(self):
        return self.main()
        
    def main(self):
        # This is called only when we first call up the page
        # After that all changes come through ajax calls (or going to another 
        # page and coming back)
        render = web.template.render('templates', globals={'Flow': switzerland.common.Flow})
        menu = render.menu("main")
        graph = line_graph() 
        # Call make_graph FIRST to load data into structures
        graph_html = graph.make_graph() 
        singleton_webgui.packet_data.current_graph = graph
        client_info = render.client_info(singleton_webgui.x_alice.get_client_info())
        server_info = render.server_info(singleton_webgui.x_alice.get_server_info())
        active_flows = render.flow_list(singleton_webgui.packet_data.active_flows)      
        active_peers = render.peer_list(singleton_webgui.packet_data.active_peers)      
        legend = graph.make_legend()
        return render.dashboard(menu, 
            client_info, 
            server_info,
            active_flows,
            active_peers,
            legend,
            graph_html,
            singleton_webgui.web_app_config['refresh_interval'][0])

# List mutable configuration parameters, allow to change
# TODO: Options are not serialized between invocations of the client
class config:
    def GET(self):  
        return self.main()    
        
    def POST(self):  
        webin = web.input()
        message = ""
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
                #lvl =  self.LOG_LEVELS.get(webin.log_level, logging.NOTSET)
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
        
        return self.main(message)
    
    def main(self, message=""):
        render = web.template.render('templates', globals={'logging': logging})
        menu = render.menu("config")
        tweakable_options = singleton_webgui.x_alice_config.tweakable_options()
        immutable_options = singleton_webgui.x_alice_config.immutable_options()
        return render.config(menu, 
            singleton_webgui.x_alice_config, 
            tweakable_options,
            immutable_options,
            singleton_webgui.web_app_config,
            message)

# Turn a flow tuple into a suitable hash key (replace . and : with _)    
def flow_key(f):
    t = print_flow_tuple(f.flow_tuple)
            
    return str(t[0].replace(".","_")) + "_" + str(t[1]) + "__" \
        + str(t[2].replace(".","_")) + "_" + str((t[3])) \
        + "_" + str(t[4])        
        
        
# Packet data persists between web page calls
# Persistent data belongs in this object.
class packet_data:
    
    def __init__(self):
        self.packet_data = dict()
        self.active_flows = dict()
        # Flow visibility is currently handled in the client
        # Currently all flows have visibility "on" as far as the 
        # server is concerned.
        self.visible_flows = dict()
        self.active_peers = list()
        self.current_histograms = None
        self.current_graph = None

    def init_visible_flows(self):
        self.update_active_flows()
        for flow_name in self.active_flows:
            self.visible_flows[flow_name + "_mo"] = "on"
            self.visible_flows[flow_name + "_dr"] = "on"
            self.visible_flows[flow_name + "_in"] = "on"
            self.visible_flows[flow_name + "_to"] = "on"

    def update_active_flows(self):
        peers = singleton_webgui.x_alice.get_peers()
        for p in peers:
            # Only add a peer that is not in the list yet
            try:
                self.active_peers.index(s.inet_ntoa(p.ip))
            except:
                self.active_peers.append(s.inet_ntoa(p.ip))
                
            flows = p.new_flows()
            if isinstance(flows, list):
                for f in flows:
                    flow_name = flow_key(f)
                    if self.active_flows.get(flow_name):
                        pass
                    else:
                        self.active_flows[flow_name] = f
                        self.visible_flows[flow_name + "_mo"] = "on"
                        self.visible_flows[flow_name + "_dr"] = "on"
                        self.visible_flows[flow_name + "_in"] = "on"
                        self.visible_flows[flow_name + "_to"] = "on"
                        print "ADDING", flow_name
        del_flows = list()
        for f in self.active_flows:
            if self.active_flows[f].is_active():
                pass
            else:
                del_flows.append(f)

        for f in del_flows:
            del self.active_flows[f]    
          
    # If packets are older than cutoff time (usually an hour) delete them    
    def delete_old_packets(self, packet_list, cutoff_time):
        new_packet_list = list()
        for index, packet in enumerate(packet_list): 
            if packet[0] > cutoff_time:
                new_packet_list.append(packet)
            else:
                if debug_output:
                    print "Deleting packet..."
        packet_list = None
        return new_packet_list

                
    def update_packet_data(self):
        
        # For each active flow
        for flow_ip in self.active_flows:
            # If flow does not exist in dictionary object, add
            f = self.active_flows[flow_ip]
            if self.packet_data.get(flow_ip) :
                pass
            else:
                self.packet_data[flow_ip] = dict()
                self.packet_data[flow_ip]['dropped'] = list()
                self.packet_data[flow_ip]['injected'] = list()
                self.packet_data[flow_ip]['modified'] = list()
                self.packet_data[flow_ip]['total'] = list()
            
            # Each active flow has 4 lists of packets: dropped, injected, 
            # modified, total count
            
            self.cutoff_time = time.time() - singleton_webgui.web_app_config['save_window'][0]
            
            self.packet_data[flow_ip]['dropped'].extend( \
                f.get_new_dropped_packets())
            self.packet_data[flow_ip]['injected'].extend( \
                f.get_new_injected_packets())
            self.packet_data[flow_ip]['modified'].extend( \
                f.get_new_modified_packets())  
            
            
            pack_count = f.get_new_packet_count()
            self.packet_data[flow_ip]['total'].extend( \
                [(time.time(), pack_count) ])
            
            self.packet_data[flow_ip]['dropped'] = \
                self.delete_old_packets(
                    self.packet_data[flow_ip]['dropped'], 
                        self.cutoff_time)
            self.packet_data[flow_ip]['injected'] = \
                self.delete_old_packets(
                    self.packet_data[flow_ip]['injected'], 
                    self.cutoff_time)
            self.packet_data[flow_ip]['modified'] = \
                self.delete_old_packets(
                self.packet_data[flow_ip]['modified'], 
                self.cutoff_time)
            self.packet_data[flow_ip]['total'] = \
                self.delete_old_packets(
                self.packet_data[flow_ip]['total'], 
                self.cutoff_time)
            
    
class WebGUI():
                
    def __init__(self):
        self.x_alice_config = ClientConfig()
        self.x_alice = xAlice(self.x_alice_config)
        self.packet_data = packet_data()
        
        self.web_app_config = dict()
        self.web_app_config['save_window'] = [60 * 60, 
            "Save window", "Number of seconds to save"]
        self.web_app_config['refresh_interval'] = [20, 
            "Refresh interval", "Number of seconds between refresh"]
        self.urls = (
            '/', 'index', 
            '', 'index',
            '/ajax_server', 'ajax_server',
            '/ajax_server/', 'ajax_server',
            '/config', 'config')
        
    def main(self):

        self.app = web.application(self.urls, globals())
 
        if len(sys.argv) > 1:
            alice_opts = sys.argv
            sys.argv[1:] = []
        # Use 127.0.0.1 instead of 0.0.0.0 to make accessible outside of localhost
        sys.argv.insert(1, web_py_server + ":" + web_py_port)
        self.app.run()

if __name__ == "__main__":

    # We have to change the working directory to the directory of the WebGUI script
    # If we don't, the script can't find all of the static and template files
    pathname = os.path.dirname(sys.argv[0])
    os.chdir(os.path.abspath(pathname))
    
    try:
        optlist, args = getopt.gnu_getopt(sys.argv[1:], 'Fa:w:s:p:i:l:u:L:P:f:b:hqv', 
                    ['fake', 'webaddr=', 'webport=',
                    'server=', 'port=', 'interface=', 'ip=', 'help',
                    'private-ip=', 'public-ip=', 'logfile=', 'pcap-logs=',
                    'quiet', 'uncertain-time', 'verbose', 'buffer='])
    except:
        print "raised exception"
        AliceConfig().usage();
    
    useFake = False
    newArgList = []
    newArgList.append(sys.argv[0])

    for option, argument in optlist:
        if option in ("-F", "--fake"):
            useFake = True
        elif option in ("-a", "--webaddr"):
            web_py_server = argument
        elif option in ("-w", "--webport"):
            web_py_port = argument
        else:
            newArgList.append(option)
            if argument is not None and len(argument) > 0:
                newArgList.append(argument)
    
    sys.argv = newArgList   
    # Use AliceAPIFake instead of AliceAPI when you have no peers or no internet connection
    # It generates somewhat reasonable random data
    
    if useFake:
        from switzerland.client.AliceAPIFake import xAlice, ClientConfig, xPeer, xFlow, xPacket
    else:
        from switzerland.client.AliceAPI import xAlice, ClientConfig, xPeer, xFlow, xPacket

    singleton_webgui = WebGUI()
    singleton_webgui.packet_data.init_visible_flows()
    singleton_webgui.main()
