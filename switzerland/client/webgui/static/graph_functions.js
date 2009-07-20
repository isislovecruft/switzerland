/*
    Switzerland 
    http://www.eff.org/testyourisp/switzerland
*/

function draw_axes(ctx, 
        x_mar, y_mar, 
        x_ax_mar, y_ax_mar, 
        width, height, 
        x_bins, y_bins, 
        x_bin_pixels, x_bin_size, 
        y_bin_pixels, y_bin_size, 
        min_timestamp) {
        
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
  
        if (i % 5 == 0) {
            ctx.moveTo((x_mar + x_ax_mar - 5), height - y);
            ctx.lineTo((x_mar + x_ax_mar + 5), height - y); 
            ctx.save();
            var label = i * y_bin_size;
            var len = ctx.mozMeasureText(label); 
            ctx.translate(x_ax_mar + 2 - len, height - y + 4);
            ctx.mozTextStyle = "8pt Arial, Helvetica"
            ctx.mozDrawText(Math.round(label*10)/10);
            ctx.restore();
        }    
        else {
            ctx.moveTo((x_mar + x_ax_mar - 3), height - y);
            ctx.lineTo((x_mar + x_ax_mar + 3), height - y); 
        }   
    }
    
    var rad=(Math.PI/180)*-90;
    var label = "No. of Packets";
    var len = ctx.mozMeasureText(label); 
    ctx.save();
    ctx.translate(x_mar,  height - graph_height/2);
    ctx.rotate(rad);
    ctx.mozDrawText(label);
    ctx.restore();

    // Draw the x axis numbers and hash marks
    for (i = 0; i < x_bins; i++){
        var x = x_mar + x_ax_mar + (x_bin_pixels * i);

        if (i % 5 == 0) {
            ctx.moveTo(x, height - (y_mar + y_ax_mar - 5));
            ctx.lineTo(x, height - (y_mar + y_ax_mar + 5));
            ctx.save();
            var label = epoch_to_time((x_bin_size * i) + min_timestamp, x_bin_size);
            var len = ctx.mozMeasureText(label); 
            ctx.translate(x - len/2 , height - (y_mar + y_ax_mar - 18));
            ctx.mozTextStyle = "8pt Arial, Helvetica"
            //This line will display seconds instead of time 
            //label = Math.round(x_bin_size * i * 10) / 10; 
            ctx.mozDrawText(label);
            ctx.restore();
        }
        else {
            ctx.moveTo(x, height - (y_mar + y_ax_mar - 3));
            ctx.lineTo(x, height - (y_mar + y_ax_mar + 3));
        }
        // moz*Text* are deprecated in 3.5, but necessary for 
        // Firefox 3.0 and compatible
        // For Firefox 3.5 standard instead of ctx.MozDrawText
        // ctx.fillText(bin_pixels * i, x, y_ax_mar - 12);
        // TODO: Either update to filltext or add browser detection code
    }
    
    //label = "No. of Seconds";
    label = "Time";
    len = ctx.mozMeasureText(label); 
    ctx.save();
    ctx.translate( graph_width/2 - len/2, height - 2);
    ctx.mozDrawText(label);
    ctx.restore();

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

function legend_entry(id, width, height, color, shape) {
    var canvas = document.getElementById(id);
    if (canvas.getContext) {            
        var ctx = canvas.getContext('2d');
        ctx.fillStyle = color;
        ctx.strokeStyle = color;
        make_point(ctx, width/2, height/2, shape); 
        ctx.beginPath();
        ctx.moveTo(0, height/2);
        ctx.lineTo(width, height/2);
        ctx.stroke(); 
    }
}

function check_legend(legend_form, checkbox_value) {   
    for (var i = 0; i < legend_form.elements.length; i++ ) {
        if (legend_form.elements[i].type == 'checkbox') {
            legend_form.elements[i].checked = checkbox_value;
        }
    }
}

function check_legend_group(legend_form, group_str, checkbox_value) {
    for (var i = 0; i < legend_form.elements.length; i++ ) {
        if (legend_form.elements[i].type == 'checkbox') {
            if (legend_form.elements[i].name.search(group_str) > -1) {
                legend_form.elements[i].checked = checkbox_value;
            }
        }
    }
}

function epoch_to_time(epoch, bin_size) {

    var ep = parseInt(epoch);
    //alert("Epoch: " + ep);
    if (ep < 10000000000) { ep *= 1000; }
    var d = new Date();
    d.setTime(ep);
    h = "" + d.getHours();
    if (h.length == 1) { h = "0" + h; }
    m = "" + d.getMinutes();
    //alert ("min " + m + " min length " + m.length);
    if (m.length == 1) { m = "0" + m; }
    s = "" + d.getSeconds();
    if (s.length == 1) { s = "0" + s; }
    
    if (bin_size * 5 > 60) {
        return (h + ":" +m);
    }
    return (h + ":" + m + ":" + s);
}
