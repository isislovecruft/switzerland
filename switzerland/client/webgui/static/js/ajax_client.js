function getPacketInfo(flowId, histBinId, container) {

    // Use the prototype library to get a cross-browser AJAX request
    
    new Ajax.Request('/ajax_server', {
	method: 'get',
	parameters: {command: 'packetInfo', histBinId: histBinId, flowId: flowId},
	onSuccess: function(transport) {
	    var responseContainer = $(container);
		
		responseContainer.update(transport.responseText);
	},
	onFailure: function(transport) {
		alert("Something has gone wrong.")
	}}
    );
}
