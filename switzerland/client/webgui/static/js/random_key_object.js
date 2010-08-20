function RandomKey(initVal) {
    this.key = initVal;
    

}

RandomKey.prototype.setKey = function(newKey) {
	this.key = newKey;
}

RandomKey.prototype.getKey = function() {
	return this.key;
}