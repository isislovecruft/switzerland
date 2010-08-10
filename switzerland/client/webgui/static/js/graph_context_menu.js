// Based on http://luke.breuer.com/tutorial/javascript-context-menu-tutorial.htm 
// by Luke Breuer <labreuer@gmail.com>

// Depends on prototype.js (Make sure to load it first.)

var replaceSystemContextMenu = false;
var mouseOverContextMenu = false;
var noContextMenu = false;
var graphContextMenuFlowName;
var graphContextMenuBin;
var graphContextDetailWindow = null;
var graphContextMenu = $('graphcontextmenu');

function initContextMenu() {
	graphContextMenu.onmouseover = function() {
		mouseOverContextMenu = true;
	}
	graphContextMenu.onmouseout = function() {
		mouseOverContextMenu = false;
	}
	$('graph').onmousedown = contextMouseDown;
	$('graph').oncontextmenu = contextShow;
}

function contextMouseDown(event){
	if (noContextMenu || mouseOverContextMenu) {
		return;
	}
	if (event == null) {
		event = window.event;
	}
	var target = event.target != null ? event.target : event.srcElement;
	
	if (event.button == 2){
		replaceSystemContextMenu = true;
	}
	else {
		if (!mouseOverContextMenu) {
			graphContextMenu.style.display = 'none';
		}
	}
}

function closeContext() {
	graphContextMenu.style.display = 'none';
	mouseOverContextMenu = false;
}

function contextShow(event) { 
	if (noContextMenu || mouseOverContextMenu) {
		return;
	}
	
	if (event == null) {
		event = window.event; 
	}
	
	// we assume we have a standards compliant browser, but check if we have IE 
	var target = event.target != null ? event.target : event.srcElement; 
	
	if (replaceSystemContextMenu) { 	
		// document.body.scrollTop does not work in IE 
		var scrollTop = document.body.scrollTop ? document.body.scrollTop : document.documentElement.scrollTop; 
		var scrollLeft = document.body.scrollLeft ? document.body.scrollLeft : document.documentElement.scrollLeft; 
		
		// hide the menu first to avoid an "up-then-over" visual effect 
		graphContextMenu.style.display = 'none'; 
		graphContextMenu.style.left = event.clientX + scrollLeft + 'px'; 
		graphContextMenu.style.top = event.clientY + scrollTop + 'px'; 
		graphContextMenu.style.display = 'block'; 
		
		replaceSystemContextMenu = false; 
		
		return false; 
		 
	} 
}

function disableContext() { 
	noContextMenu = true; 
	closeContext(); 
	return false; 
} 

function enableContext(flowname, bin) { 
	graphContextMenuFlowName = flowname;
	graphContextMenuBin = bin;
	noContextMenu = false; 
	mouseOverContextMenu = false; // this gets left enabled when "disable menus" is chosen 
	return false; 
} 

function openDetailWindow() {

	graphContextDetailWindow = window.open('/static/packet_detail.html',
				'Packet detail',
				'width=600,height=400,copyhistory=no,menubar=no,directories=no,resizable=yes,scrollbars=yes');

	getPacketInfo(graphContextMenuFlowName,
			graphContextMenuBin,
			graphContextDetailWindow);
}
	
function openWireshark(packetType) {
	launchWireshark(graphContextMenuFlowName,
			graphContextMenuBin, packetType);
}

initContextMenu();


