
// FlowGraph Object representing the whole graph
function FlowGraph(
                   canvasContext,
                   canvasElement,
                   canvasId,
                   flowData, 
                   xMargin,
                   yMargin,
                   xAxisMargin,
                   yAxisMargin,
                   width,
                   height,
                   graphXBins,
                   graphYBins,
                   xBinPixels,
                   xBinSize,
                   yBinPixels,
                   yBinSize,
                   minTimestamp) {
               
   this.canvasContext = canvasContext;
   this.canvasElement = canvasElement;
   // flowData is an object representing all of the data points and flow
   // information coming from the application server
   this.flowData = flowData;
   // xMargin/yMargin are whitespace around the edges
   this.xMargin = xMargin; 
   this.yMargin = yMargin;
   // xAxisMargin/yAxisMargin are the space at the left and bottom allowed
   // for the axes and labels
   this.xAxisMargin = xAxisMargin;
   this.yAxisMargin = yAxisMargin;
   this.width = width;
   this.height = height;
   // graphXBins/graphYBins are the number of bins along each axis
   this.graphXBins = graphXBins;
   this.graphYBins = graphYBins;
   // xBinPixels/yBinPixels are number of pixels per bin
   this.xBinPixels = xBinPixels;
   // xBinSize is the number of seconds per bin
   this.xBinSize = xBinSize;
   this.yBinPixels = yBinPixels;
   // yBinSize is the number of packets per bin
   this.yBinSize = yBinSize;
   // minTimestamp becomes the value of x at the origin
   this.minTimestamp = minTimestamp;
   // make this object accessible from calls on the canvas element
   this.canvasElement.graphObject = this;
   // event listener for mouseover
   this.canvasElement.addEventListener('mousemove', evMouseMove, false);
   // the snapshot keeps a copy of the graph for quick redraw
   this.snapshotCanvas = document.createElement('canvas');
   this.snapshotCanvas.width = width;
   this.snapshotCanvas.height = height;
}

FlowGraph.prototype.DrawAxes = function(drawText) {

    if (typeof(drawText) == 'undefined') { drawText = true; }
    
    var graphheight = this.height - (2 * this.yMargin + this.yAxisMargin);
    var graphwidth = this.width - (2 * this.xMargin + this.xAxisMargin);

    this.canvasContext.strokeStyle = 'black';
    this.canvasContext.fillStyle = 'black';
    this.canvasContext.textAlign = 'center';

    this.canvasContext.beginPath();
    this.canvasContext.moveTo(this.xMargin + this.xAxisMargin, this.yMargin);
    this.canvasContext.lineTo(this.xMargin + this.xAxisMargin, this.height - (this.yMargin + this.yAxisMargin));
    this.canvasContext.lineTo(this.width - (this.xMargin), this.height - (this.yMargin + this.yAxisMargin));

    // Draw the y axis numbers and hash marks
    for (i = 0; i < this.graphYBins; i++) {
        var y = this.yMargin + this.yAxisMargin + (this.yBinPixels * i);

        if (i % 5 == 0) {
            this.canvasContext.moveTo((this.xMargin + this.xAxisMargin - 5), this.height - y);
            this.canvasContext.lineTo((this.xMargin + this.xAxisMargin + 5), this.height - y);
            if (drawText) {
                this.canvasContext.save();
                var label = i * this.yBinSize;
                var len = this.canvasContext.mozMeasureText(label);
                this.canvasContext.translate(this.xAxisMargin + 2 - len, this.height - y + 4);
                this.canvasContext.mozTextStyle = "8pt Arial, Helvetica"
                this.canvasContext.mozDrawText(Math.round(label * 10) / 10);
                this.canvasContext.restore();
            }
        }
        else {
            this.canvasContext.moveTo((this.xMargin + this.xAxisMargin - 3), this.height - y);
            this.canvasContext.lineTo((this.xMargin + this.xAxisMargin + 3), this.height - y);
        }
    }

    if (drawText) {
        var rad = (Math.PI / 180) * -90;
        var label = "No. of Packets";
        var len = this.canvasContext.mozMeasureText(label);
        this.canvasContext.save();
        this.canvasContext.translate(this.xMargin, this.height - graphheight / 2);
        this.canvasContext.rotate(rad);
        this.canvasContext.mozDrawText(label);
        this.canvasContext.restore();
    }

    // Draw the x axis numbers and hash marks
    for (i = 0; i < this.graphXBins; i++) {
        var x = this.xMargin + this.xAxisMargin + (this.xBinPixels * i);

        if (i % 5 == 0) {
            this.canvasContext.moveTo(x, this.height - (this.yMargin + this.yAxisMargin - 5));
            this.canvasContext.lineTo(x, this.height - (this.yMargin + this.yAxisMargin + 5));
            if (drawText) {
                this.canvasContext.save();
                var label = epochToTime((this.xBinSize * i) + this.minTimestamp, this.xBinSize);
                var len = this.canvasContext.mozMeasureText(label);
                this.canvasContext.translate(x - len / 2, this.height - (this.yMargin + this.yAxisMargin - 18));
                this.canvasContext.mozTextStyle = "8pt Arial, Helvetica"
                //This line will display seconds elapsed instead of time 
                //label = Math.round(this.xBinSize * i * 10) / 10; 
                this.canvasContext.mozDrawText(label);
                this.canvasContext.restore();
            }
        }
        else {
            this.canvasContext.moveTo(x, this.height - (this.yMargin + this.yAxisMargin - 3));
            this.canvasContext.lineTo(x, this.height - (this.yMargin + this.yAxisMargin + 3));
        }
        // moz*Text* are deprecated in 3.5, but necessary for 
        // Firefox 3.0
        // For Firefox 3.5 standard instead of this.canvasContext.MozDrawText
        // this.canvasContext.fillText(binPixels * i, x, this.yAxisMargin - 12);
        // TODO: Either update to filltext or add browser detection code when 3.5 becomes standard
    }

    if (drawText) {
        label = "Time";
        len = this.canvasContext.mozMeasureText(label);
        this.canvasContext.save();
        this.canvasContext.translate(graphwidth / 2 - len / 2, this.height - 2);
        this.canvasContext.mozDrawText(label);
        this.canvasContext.restore();
    }
    this.canvasContext.stroke();
}

// This function (RedrawData) clears the background before drawing the graph.
// Draw does not clear the background. 
FlowGraph.prototype.RedrawData = function() {
    if (this.canvasContext) {
        var drawWidth = this.width - (this.xMargin + this.xAxisMargin);
        var drawHeight = this.height - (this.yMargin + this.yAxisMargin);
        //this.canvasContext.clearRect(this.xMargin + this.xAxisMargin, 0, drawWidth, drawHeight);
        this.canvasContext.clearRect(0, 0, this.width, this.height);
        this.DrawAxes(true);

        for (var fd in this.flowData) {
            if (this.activeFlows[fd]!= false) {
                if(typeof(this.flowData[fd].Draw) == 'function') {
                    this.flowData[fd].Draw();
                }
            }
        }
        this.snapshotCanvas.getContext('2d').clearRect(0,0,this.width,this.height);
        this.snapshotCanvas.getContext('2d').drawImage(this.canvasElement,0,0);
    } else {
        // No canvas support error message should have already been displayed.
    }
}

FlowGraph.prototype.Draw = function() {
    if (this.canvasContext) {    
        this.DrawAxes(true);
        for (var fd in this.flowData) {
            
                if (this.activeFlows[fd]!= false) {
                
                // Workaround for Prototype object modifications without
                // locking in to Prototype object modifications
                // http://www.prototypejs.org/api/array
                if(typeof(this.flowData[fd].Draw) == 'function') {
                    this.flowData[fd].Draw();
                }
            }
        }
        this.snapshotCanvas.getContext('2d').drawImage(this.canvasElement,0,0);
    } else {
        // No canvas support error message should have already been displayed.
    }
}



// FindCollision finds where the mouse position (passed as x,y) intersects
// with a data point
FlowGraph.prototype.FindCollision = function(x, y) {
    for (var fd in this.flowData) {
        if (this.activeFlows[fd]!= false) { 
            if (typeof(this.flowData[fd].FindCollision) == 'function') {
                var retVal = this.flowData[fd].FindCollision(x,y);
                
                if (typeof(retVal) != 'undefined') {
                    return retVal
                }
            }
        }    
    }
}

// Draw the mini-canvasses for the legend
FlowGraph.prototype.DrawLegend = function() {

    for (var fd in this.flowData) {
        var canvasId = "leg_" + this.flowData[fd].name;
        if (typeof(this.flowData[fd].DrawLegend) == 'function') {
            this.flowData[fd].DrawLegend(canvasId);
        }
        else {
            //alert("type of flowdata " + typeof(this.flowData[fd].DrawLegend))
        }
    }

}


// FlowData object representing just one flow
function FlowData(xList, yList, context, shape, color, name, 
    source_ip, source_port, dest_ip, dest_port, protocol, packet_type ) {
 
    this.canvasContext = context;
    this.xList = xList;
    this.yList = yList;
    this.shape = typeof(shape) == 'undefined' ? '' : shape;
    this.color = typeof(color) == 'undefined' ? 'black' : color;
    this.packet_type = typeof(packet_type) == 'undefined' ? 'to' : packet_type;
    this.name = name;
    this.source_ip = source_ip;
    this.dest_ip = dest_ip;
    this.source_port = source_port;
    this.dest_port = dest_port;
    this.protocol = protocol;
    this.active = true;
}


FlowData.prototype.Draw = function() {
    if (this.xList.length != this.yList.length) {
        alert("Lengths of data arrays do not match!\nx: "+ this.xList.length + " y:" + this.yList.length);
        return;
    }
    this.canvasContext.fillStyle = this.color;
    this.canvasContext.strokeStyle = this.color;
    this.canvasContext.beginPath();
    this.canvasContext.moveTo(this.xList[0], this.yList[0]);       
    for (var i = 0; i < this.xList.length; i++){ 
        this.canvasContext.lineTo(this.xList[i], this.yList[i]);
    }
    this.canvasContext.stroke();
    makePoint(this.canvasContext, this.xList[0], this.yList[0], this.shape);        
    for (var i = 0; i < this.xList.length; i++){ 
        makePoint(this.canvasContext, this.xList[i], this.yList[i], this.shape); 
    }
}

// Create and draw the legend entry (a small canvas)
FlowData.prototype.DrawLegend = function(canvasId) {
    this.legend = new FlowDataLegend(this.shape, this.color, canvasId);
    this.legend.Draw();
}   

// Find if the mouse position (at x,y) corresponds with a data point
FlowData.prototype.FindCollision = function(x, y) {
    for (var i = 0; i < this.xList.length; i++){ 
        if (withinDistance(x, y, this.xList[i], this.yList[i], 3) ) {
            return {x:this.xList[i], y:this.yList[i], flow:this, bin:i};
        }
    }
    // return nothing (undefined)
}

// FlowDataLegend object representing the legend for one flow 

function FlowDataLegend(shape, color, canvasId, width, height) {
    this.shape = typeof(shape) == 'undefined' ? '' : shape;
    this.color = typeof(color) == 'undefined' ? 'black' : color;
    this.width = typeof(width) == 'undefined' ? 50 : width;
    this.height = typeof(height) == 'undefined' ? 10 : height;
    this.canvasId = canvasId;
}

FlowDataLegend.prototype.Draw = function() {
    // Was the context set in the constructor?
    if (typeof(this.canvasId) == 'undefined') {
        // exit silently
        return;
    }
    if (document.getElementById(this.canvasId)) {   
        this.legendContext = document.getElementById(this.canvasId).getContext('2d');
        this.legendContext.fillStyle = this.color;
        this.legendContext.strokeStyle = this.color;
        makePoint(this.legendContext, this.width/2, this.height/2, this.shape); 
        this.legendContext.beginPath();
        this.legendContext.moveTo(0, this.height/2);
        this.legendContext.lineTo(this.width, this.height/2);
        this.legendContext.stroke(); 
    }
}



