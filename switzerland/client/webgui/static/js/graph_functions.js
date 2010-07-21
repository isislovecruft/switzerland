/*
    Switzerland 
    http://www.eff.org/testyourisp/switzerland
*/

// Draw a data point
function makePoint(ctx, x, y, shape) {
    switch (shape) {

    case "x":
        ctx.beginPath();
        ctx.moveTo(x - 3, y - 3);
        ctx.lineTo(x + 3, y + 3);
        ctx.moveTo(x - 3, y + 3);
        ctx.lineTo(x + 3, y - 3);
        ctx.stroke();
        break;
    case "circle":
        ctx.beginPath();
        ctx.arc(x, y, 3, 0, Math.PI * 2, true);
        ctx.fill();
        break;
    case "triangle":
        ctx.beginPath();
        ctx.moveTo(x - 3, y + 2);
        ctx.lineTo(x + 3, y + 2);
        ctx.lineTo(x, y - 3);
        ctx.fill();
        break;
    case "square":
        ctx.beginPath();
        ctx.moveTo(x - 3, y - 3);
        ctx.lineTo(x + 3, y - 3);
        ctx.lineTo(x + 3, y + 3);
        ctx.lineTo(x - 3, y + 3);
        ctx.fill();
        break;
    }
}

// Highlight a data point with a yellow circle
function highlightPoint(ctx, x, y) {
    ctx.save();
    ctx.fillStyle = "#eeee00";
    ctx.strokeStyle = "#eeee00";
    ctx.beginPath();
    ctx.arc(x, y, 6, 0, Math.PI * 2, true);
    ctx.fill();
    ctx.restore();
}

// Turn an epoch into a human-readable time
function epochToTime(epoch, binSize) {

    var ep = parseInt(epoch);
    //alert("Epoch: " + ep);
    if (ep < 10000000000) {
        ep *= 1000;
    }
    var d = new Date();
    d.setTime(ep);
    h = "" + d.getHours();
    if (h.length == 1) {
        h = "0" + h;
    }
    m = "" + d.getMinutes();
    //alert ("min " + m + " min length " + m.length);
    if (m.length == 1) {
        m = "0" + m;
    }
    s = "" + d.getSeconds();
    if (s.length == 1) {
        s = "0" + s;
    }

    if (binSize * 5 > 60) {
        return (h + ":" + m);
    }
    return (h + ":" + m + ":" + s);
}


// The mouse position retrieval code here is based on code at
// "Creating an HTML 5 canvas painting application" by Mihai Sucan (17 Mar 2009)
// http://dev.opera.com/articles/view/html5-canvas-painting/ 
    
// This code is triggered by a mousemove event on the graph canvas
// evMouseMove checks if the mouse is over a data point and highlights
// that point.  It also makes an ajax call to the web application for
// detailed packet information.
var evMouseMove = function (ev) {
    var x, y;
    
    var canvasElement = document.getElementById(ev.target.id);
    var graphObject = ev.target.graphObject;
    
    var context;
    
    if (canvasElement.getContext) {            
        context = canvasElement.getContext('2d');     
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
     
    var retObj = graphObject.FindCollision(x,y);
 
    if (typeof(retObj) != 'undefined') {

        graphObject.canvasContext.fillStyle = 'white';        
        graphObject.canvasContext.fillRect(0, 0, graphObject.width, graphObject.height);

        graphObject.canvasContext.drawImage(graphObject.snapshotCanvas,0,0);

        highlightPoint(context, retObj.x, retObj.y, retObj.flow.shape);
       
        
        retObj.flow.Draw();
        enableContext(retObj.flow.name,retObj.bin);
    } 
    else {
    	disableContext();
    }
}

// This is used to find collisions
// Save some CPU by not taking the square root
function withinDistance(x1, y1, x2, y2, dist) {
    if (Math.pow((x1-x2),2) + Math.pow((y1-y2),2) < Math.pow(dist,2)) {
        return true;
    }
    return false;
}

// If a flow is checked or unchecked in the legend, all of the related packet
// type flows are updated (modified, dropped, injected)
function updateFlow(legendForm, graphObj, activeFlows){
    for (var i = 0; i < legendForm.elements.length; i++) {
        if (legendForm.elements[i].type == 'checkbox') {
            if (legendForm.elements[i].name.search('cb_leg_') > -1) {
                elName = legendForm.elements[i].name;
                flowName = elName.substring(7, elName.length - 3);

                if (legendForm.elements[i].checked) {
                    activeFlows[flowName + '_to'] = true;
                    activeFlows[flowName + '_mo'] = true;
                    activeFlows[flowName + '_dr'] = true;
                    activeFlows[flowName + '_in'] = true;
                }
                else {
                    activeFlows[flowName + '_to'] = false;
                    activeFlows[flowName + '_mo'] = false;
                    activeFlows[flowName + '_dr'] = false;
                    activeFlows[flowName + '_in'] = false;
                }
            }
        }
    }

    graphObj.activeFlows = activeFlows;

    graphObj.RedrawData();
}

// Check all checkboxes in the legend
function checkLegend(legendForm, checkboxValue, graphObj, activeFlows) {   
    for (var i = 0; i < legendForm.elements.length; i++ ) {
        if (legendForm.elements[i].type == 'checkbox') {
            legendForm.elements[i].checked = checkboxValue;
        }
    }
    updateFlow(legendForm, graphObj, activeFlows);
}

