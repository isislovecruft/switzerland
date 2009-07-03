/*
    Switzerland 
    http://www.eff.org/testyourisp/switzerland
*/

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
        // moz*Text* are deprecated in 3.5, but necessary for 
        // Firefox 3.0 and compatible
        // For Firefox 3.5 standard instead of ctx.MozDrawText
        // ctx.fillText(bin_pixels * i, x, y_ax_mar - 12);
        // TODO: Either update to filltext or add browser detection code
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
