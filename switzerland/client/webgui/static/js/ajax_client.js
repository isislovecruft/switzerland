
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

// randomKey is used to verify that the request is coming from
// Firefox.
function launchWireshark(flowId, histBinId, packetType, randomKey) {
    
    new Ajax.Request('/ajax_server', {
	method: 'get',
	parameters: {command: 'launchWireshark', packetType: packetType, histBinId: histBinId, flowId: flowId, randomKey: randomKey},
	onSuccess: function(transport) {
		// pass
	},
	onFailure: function(transport) {
		alert("Something has gone wrong with launching Wireshark.")
	}}
    );
    
    // For debugging
	//var responseContainer = $('debug_ws');
	//responseContainer.update("Sending " + randomKey);
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

//Get a random key which allows the user to do 
//insecure things like run Wireshark
function getRandomKey(container, randomKey) {
    var rKey = '';
    new Ajax.Request('/ajax_server', {
	method: 'get',
	parameters: {command: 'getRandomKey'},
	onSuccess: function(transport) {
		rKey = transport.responseText;
		rKey = rKey.replace("<key>","");
		rKey = rKey.replace("</key>", "");
		randomKey.setKey(rKey);
		//For debugging
		//var responseContainer = $(container);
		//responseContainer.update("Updating key to " + rKey);
	},
	onFailure: function(transport) {
		alert("Something has gone wrong with updating the random key.")
	}}
    );
}
