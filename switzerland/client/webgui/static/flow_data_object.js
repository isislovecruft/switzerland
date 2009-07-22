
/* FlowGraph Object representing the whole graph */
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
   this.flowData = flowData; 
   this.xMargin = xMargin; 
   this.yMargin = yMargin;
   this.xAxisMargin = xAxisMargin;
   this.yAxisMargin = yAxisMargin;
   this.width = width;
   this.height = height;
   this.graphXBins = graphXBins;
   this.graphYBins = graphYBins;
   this.xBinPixels = xBinPixels;
   this.xBinSize = xBinSize;
   this.yBinPixels = yBinPixels;
   this.yBinSize = yBinSize;
   this.minTimestamp = minTimestamp;
   this.canvasElement.started = false;
   this.canvasElement.graphObject = this;
   this.canvasElement.addEventListener('mousemove', evMouseMove, false);
}





FlowGraph.prototype.DrawAxes = function(drawText) {

    if (typeof(drawText) == 'undefined') { drawText = true; }
    
    var graphheight = this.height - (2 * this.yMargin + this.yAxisMargin);
    var graphwidth = this.width - (2 * this.xMargin + this.xAxisMargin);

    this.canvasContext.strokeStyle = 'black';
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
                //This line will display seconds instead of time 
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
        // TODO: Either update to filltext or add browser detection code
    }

    //label = "No. of Seconds";
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

FlowGraph.prototype.RedrawData = function() {
    if (this.canvasContext) {
      var drawWidth = this.width - (this.xMargin + this.xAxisMargin);
      var drawHeight = this.height - (this.yMargin + this.yAxisMargin);
      this.canvasContext.clearRect(this.xMargin + this.xAxisMargin, 0, drawWidth, drawHeight);
      this.DrawAxes(false);      
      for (var f in this.flowData) {
            this.flowData[f].Draw();
        }

    } else {
        // Error message should have already been displayed.
    }
}

FlowGraph.prototype.Draw = function() {
    if (this.canvasContext) {            

        this.DrawAxes(true);

        for (var f in this.flowData) {
            this.flowData[f].Draw();
        }

    } else {
        // Error message should have already been displayed.
    }
}




FlowGraph.prototype.FindCollision = function(x, y) {
    for (var f in this.flowData) {
            var retVal = this.flowData[f].FindCollision(x,y);
            
            if (typeof(retVal) != 'undefined') {
                //alert("Collision: "+ retVal.x + ", " +retVal.y);
                return retVal
            }
            
    }
}

FlowGraph.prototype.DrawLegend = function() {
    this.canvasContext.save();
    for (var f in this.flowData) {
        var canvasId = "leg_" + this.flowData[f].name;
        this.flowData[f].DrawLegend(canvasId);
    }
    this.canvasContext.restore();
}

/* FlowData object representing just one flow */

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

FlowData.prototype.ClearPoints = function() {
    if (this.xList.length != this.yList.length) {
        alert("Lengths of data arrays do not match!\nx: "+ this.xList.length + " y:" + this.yList.length);
        return;
    }
    this.canvasContext.fillStyle = this.color;
    this.canvasContext.strokeStyle = this.color;
         
    for (var i = 0; i < this.xList.length; i++){ 
        clearPoint(this.canvasContext, this.xList[i], this.yList[i]); 
    }
}

FlowData.prototype.DrawLegend = function(canvasId) {
    this.legend = new FlowDataLegend(this.shape, this.color, canvasId);
    this.legend.Draw();
}   

FlowData.prototype.FindCollision = function(x, y) {
    for (var i = 0; i < this.xList.length; i++){ 
        if (withinDistance(x, y, this.xList[i], this.yList[i], 3) ) {
            return {x:this.xList[i], y:this.yList[i], flow:this};
        }
    }
    // return nothing (undefined)
}

/* FlowDataLegend object representing just the legend for one flow */

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
    this.legendContext = document.getElementById(this.canvasId).getContext('2d');
    this.legendContext.fillStyle = this.color;
    this.legendContext.strokeStyle = this.color;
    makePoint(this.legendContext, this.width/2, this.height/2, this.shape); 
    this.legendContext.beginPath();
    this.legendContext.moveTo(0, this.height/2);
    this.legendContext.lineTo(this.width, this.height/2);
    this.legendContext.stroke(); 
}



