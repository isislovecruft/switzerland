
// The functions in this file depend on the prototype library
// http://www.prototypejs.org/

// Get detailed packet information (returns HTML)
function getPacketInfo(flowId, histBinId, packetWin) {
    
    new Ajax.Request('/ajax_server', {
	method: 'get',
	parameters: {command: 'packetInfo', histBinId: histBinId, flowId: flowId},
	onSuccess: function(transport) {
		packetWin.document.write(transport.responseText);
	},
	onFailure: function(transport) {
		alert("Something has gone wrong with getting packet details.")
	}}
    );
}

function launchWireshark(flowId, histBinId) {
    
    new Ajax.Request('/ajax_server', {
	method: 'get',
	parameters: {command: 'launchWireshark', histBinId: histBinId, flowId: flowId},
	onSuccess: function(transport) {
		// pass
	},
	onFailure: function(transport) {
		alert("Something has gone wrong with launching Wireshark.")
	}}
    );
}

// Get new JavaScript defining the graph (returns JavaScript/HTML)
function updateGraph(container) {
    
    new Ajax.Request('/ajax_server', {
	method: 'get',
	parameters: {command: 'updateGraph'},
	onSuccess: function(transport) {
	    var responseContainer = $(container);
		
		responseContainer.update(transport.responseText);
	},
	onFailure: function(transport) {
		alert("Something has gone wrong with updating the graph.")
	}}
    );
}

// Get new JavaScript defining the graph legend (returns JavaScript/HTML) 
function updateLegend(container) {
    
    new Ajax.Request('/ajax_server', {
	method: 'get',
	parameters: {command: 'updateLegend' },
	onSuccess: function(transport) {
	    var responseContainer = $(container);
		
	    responseContainer.update(transport.responseText);
	},
	onFailure: function(transport) {
		alert("Something has gone wrong with updating the graph.")
	}}
    );
}

// Start/stop/restart Switzerland client
function clientServiceControl(commandString, container) {
    
    new Ajax.Request('/ajax_server', {
	method: 'get',
	parameters: {command: 'clientServiceControl', commandString: commandString },
	onSuccess: function(transport) {
	    //var responseContainer = $(container);
	    //responseContainer.update(transport.responseText);
		// do nothing for now.
	},
	onFailure: function(transport) {
		alert("Something has gone wrong controlling the client service.")
	}}
    );
}
