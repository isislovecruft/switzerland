
/* FlowGraph Object representing the whole graph */
function FlowGraph(
                   canvas_context,
                   canvas_element,
                   canvas_id,
                   flow_data, 
                   x_margin,
                   y_margin,
                   x_axis_margin,
                   y_axis_margin,
                   width,
                   height,
                   graph_xbins_actual,
                   graph_ybins,
                   x_bin_pixels,
                   x_bin_size,
                   y_bin_pixels,
                   y_bin_size,
                   min_timestamp) {
               
   this.canvas_context = canvas_context;
   this.canvas_element = canvas_element;
   this.flow_data = flow_data; 
   this.x_margin = x_margin; 
   this.y_margin = y_margin;
   this.x_axis_margin = x_axis_margin;
   this.y_axis_margin = y_axis_margin;
   this.width = width;
   this.height = height;
   this.graph_xbins_actual = graph_xbins_actual;
   this.graph_ybins = graph_ybins;
   this.x_bin_pixels = x_bin_pixels;
   this.x_bin_size = x_bin_size;
   this.y_bin_pixels = y_bin_pixels;
   this.y_bin_size = y_bin_size;
   this.min_timestamp = min_timestamp;
   this.canvas_element.idName = canvas_id;
   this.canvas_element.started = false;
   this.canvas_element.addEventListener('mousemove', ev_mousemove, false);
}


/* This code is from 
    http://dev.opera.com/articles/view/html5-canvas-painting/
    */
    
var ev_mousemove = function (ev) {
    var x, y;
    
    var canvas_element = document.getElementById(ev.target.id);
    var context;
    
    if (canvas_element.getContext) {            
        context = canvas_element.getContext('2d');     
    }
    else {
        alert('You need Safari or Firefox 1.5+ to see this graph.');
    }
    
    // Get the mouse position relative to the canvas element.
    if (ev.layerX || ev.layerX == 0) { // Firefox
        x = ev.layerX;
        y = ev.layerY;
    } else if (ev.offsetX || ev.offsetX == 0) { // Opera
        x = ev.offsetX;
        y = ev.offsetY;
    }
    // The event handler works like a drawing pencil which tracks the mouse 
    // movements. We start drawing a path made up of lines.
    if (!ev.target.started) {
        context.beginPath();
        context.moveTo(x, y);
        ev.target.started = true;
    } else {
        context.lineTo(x, y);
        context.stroke();
    }
}



FlowGraph.prototype.DrawAxes = function() {

    var graph_height = this.height - (2 * this.y_margin + this.y_axis_margin);
    var graph_width = this.width - (2 * this.x_margin + this.x_axis_margin);

    this.canvas_context.strokeStyle = 'black';
    this.canvas_context.textAlign = 'center';

    this.canvas_context.beginPath();
    this.canvas_context.moveTo(this.x_margin + this.x_axis_margin, this.y_margin);
    this.canvas_context.lineTo(this.x_margin + this.x_axis_margin, this.height - (this.y_margin + this.y_axis_margin));
    this.canvas_context.lineTo(this.width - (this.x_margin), this.height - (this.y_margin + this.y_axis_margin));

    // Draw the y axis numbers and hash marks
    for (i = 0; i < this.graph_ybins; i++) {
        var y = this.y_margin + this.y_axis_margin + (this.y_bin_pixels * i);

        if (i % 5 == 0) {
            this.canvas_context.moveTo((this.x_margin + this.x_axis_margin - 5), this.height - y);
            this.canvas_context.lineTo((this.x_margin + this.x_axis_margin + 5), this.height - y);
            this.canvas_context.save();
            var label = i * this.y_bin_size;
            var len = this.canvas_context.mozMeasureText(label);
            this.canvas_context.translate(this.x_axis_margin + 2 - len, this.height - y + 4);
            this.canvas_context.mozTextStyle = "8pt Arial, Helvetica"
            this.canvas_context.mozDrawText(Math.round(label * 10) / 10);
            this.canvas_context.restore();
        }
        else {
            this.canvas_context.moveTo((this.x_margin + this.x_axis_margin - 3), this.height - y);
            this.canvas_context.lineTo((this.x_margin + this.x_axis_margin + 3), this.height - y);
        }
    }

    var rad = (Math.PI / 180) * -90;
    var label = "No. of Packets";
    var len = this.canvas_context.mozMeasureText(label);
    this.canvas_context.save();
    this.canvas_context.translate(this.x_margin, this.height - graph_height / 2);
    this.canvas_context.rotate(rad);
    this.canvas_context.mozDrawText(label);
    this.canvas_context.restore();

    // Draw the x axis numbers and hash marks
    for (i = 0; i < this.graph_xbins_actual; i++) {
        var x = this.x_margin + this.x_axis_margin + (this.x_bin_pixels * i);

        if (i % 5 == 0) {
            this.canvas_context.moveTo(x, this.height - (this.y_margin + this.y_axis_margin - 5));
            this.canvas_context.lineTo(x, this.height - (this.y_margin + this.y_axis_margin + 5));
            this.canvas_context.save();
            var label = epoch_to_time((this.x_bin_size * i) + this.min_timestamp, this.x_bin_size);
            var len = this.canvas_context.mozMeasureText(label);
            this.canvas_context.translate(x - len / 2, this.height - (this.y_margin + this.y_axis_margin - 18));
            this.canvas_context.mozTextStyle = "8pt Arial, Helvetica"
            //This line will display seconds instead of time 
            //label = Math.round(this.x_bin_size * i * 10) / 10; 
            this.canvas_context.mozDrawText(label);
            this.canvas_context.restore();
        }
        else {
            this.canvas_context.moveTo(x, this.height - (this.y_margin + this.y_axis_margin - 3));
            this.canvas_context.lineTo(x, this.height - (this.y_margin + this.y_axis_margin + 3));
        }
        // moz*Text* are deprecated in 3.5, but necessary for 
        // Firefox 3.0 and compatible
        // For Firefox 3.5 standard instead of this.canvas_context.MozDrawText
        // this.canvas_context.fillText(bin_pixels * i, x, this.y_axis_margin - 12);
        // TODO: Either update to filltext or add browser detection code
    }

    //label = "No. of Seconds";
    label = "Time";
    len = this.canvas_context.mozMeasureText(label);
    this.canvas_context.save();
    this.canvas_context.translate(graph_width / 2 - len / 2, this.height - 2);
    this.canvas_context.mozDrawText(label);
    this.canvas_context.restore();

    this.canvas_context.stroke();
}


FlowGraph.prototype.Draw = function() {
    if (this.canvas_context) {            
        this.canvas_context.save();
        this.DrawAxes();

        for (var f in this.flow_data) {
            this.flow_data[f].Draw();
        }
        this.canvas_context.restore();
    } else {
        // Error message should have already been displayed.
    }
}

FlowGraph.prototype.DrawLegend = function() {
    this.canvas_context.save();
    for (var f in this.flow_data) {
        var canvas_id = "leg_" + this.flow_data[f].name;
        this.flow_data[f].DrawLegend(canvas_id);
    }
    this.canvas_context.restore();
}

/* FlowData object representing just one flow */

function FlowData(x_list, y_list, context, shape, color, name, 
    source_ip, source_port, dest_ip, dest_port, protocol, packet_type ) {
 
    this.canvas_context = context;
    this.x_list = x_list;
    this.y_list = y_list;
    this.shape = typeof(shape) == 'undefined' ? '' : shape;
    this.color = typeof(color) == 'undefined' ? 'black' : color;
    this.packet_type = typeof(packet_type) == 'undefined' ? 'to' : packet_type;
    this.name = name;
    this.source_ip = source_ip;
    this.dest_ip = dest_ip;
    this.source_port = source_port;
    this.dest_port = dest_port;
    this.protocol = protocol;
}


FlowData.prototype.Draw = function() {
    if (this.x_list.length != this.y_list.length) {
        alert("Lengths of data arrays do not match!\nx: "+ this.x_list.length + " y:" + this.y_list.length);
        return;
    }
    this.canvas_context.fillStyle = this.color;
    this.canvas_context.strokeStyle = this.color;
    this.canvas_context.beginPath();
    this.canvas_context.moveTo(this.x_list[0], this.y_list[0]);       
    for (var i = 0; i < this.x_list.length; i++){ 
        this.canvas_context.lineTo(this.x_list[i], this.y_list[i]);
    }
    this.canvas_context.stroke();
    make_point(this.canvas_context, this.x_list[0], this.y_list[0], this.shape);        
    for (var i = 0; i < this.x_list.length; i++){ 
        make_point(this.canvas_context, this.x_list[i], this.y_list[i], this.shape); 
    }
}

FlowData.prototype.DrawLegend = function(canvas_id) {
    this.legend = new FlowDataLegend(this.shape, this.color, canvas_id);
    this.legend.Draw();
}   



/* FlowDataLegend object representing just the legend for one flow */

function FlowDataLegend(shape, color, canvas_id, width, height) {
    this.shape = typeof(shape) == 'undefined' ? '' : shape;
    this.color = typeof(color) == 'undefined' ? 'black' : color;
    this.width = typeof(width) == 'undefined' ? 50 : width;
    this.height = typeof(height) == 'undefined' ? 10 : height;
    this.canvas_id = canvas_id;
}

FlowDataLegend.prototype.Draw = function() {
    // Was the context set in the constructor?
    if (typeof(this.canvas_id) == 'undefined') {
        // exit silently
        return;
    }   
    this.legend_context = document.getElementById(this.canvas_id).getContext('2d');
    this.legend_context.fillStyle = this.color;
    this.legend_context.strokeStyle = this.color;
    make_point(this.legend_context, this.width/2, this.height/2, this.shape); 
    this.legend_context.beginPath();
    this.legend_context.moveTo(0, this.height/2);
    this.legend_context.lineTo(this.width, this.height/2);
    this.legend_context.stroke(); 
}



