/*
    Switzerland 
    http://www.eff.org/testyourisp/switzerland
*/


function make_point(ctx, x, y, shape) {
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

function make_line(ctx, x_array, y_array, shape) {
    if (x_array.length != y_array.length) {
        alert("Lengths of data arrays do not match!");
        return;
    }
    ctx.beginPath();
    ctx.moveTo(x_array[0], y_array[0]);
    for (var i = 0; i < x_array.length; i++) {
        ctx.lineTo(x_array[i], y_array[i]);
    }
    ctx.stroke();
    make_point(ctx, x_array[0], y_array[0], shape);
    for (var i = 0; i < x_array.length; i++) {
        make_point(ctx, x_array[i], y_array[i], shape);
    }
}

function check_legend(legend_form, checkbox_value) {
    for (var i = 0; i < legend_form.elements.length; i++) {
        if (legend_form.elements[i].type == 'checkbox') {
            legend_form.elements[i].checked = checkbox_value;
        }
    }
}

function check_legend_group(legend_form, group_str, checkbox_value) {
    for (var i = 0; i < legend_form.elements.length; i++) {
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

    if (bin_size * 5 > 60) {
        return (h + ":" + m);
    }
    return (h + ":" + m + ":" + s);
}






