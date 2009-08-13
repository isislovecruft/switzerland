
// The functions in this file depend on the prototype library
// http://www.prototypejs.org/

// Get detailed packet information (returns HTML)
function getPacketInfo(flowId, histBinId, container) {
    
    new Ajax.Request('/ajax_server', {
	method: 'get',
	parameters: {command: 'packetInfo', histBinId: histBinId, flowId: flowId},
	onSuccess: function(transport) {
	    var responseContainer = $(container);
		
		responseContainer.update(transport.responseText);
	},
	onFailure: function(transport) {
		alert("Something has gone wrong with getting packet details.")
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

