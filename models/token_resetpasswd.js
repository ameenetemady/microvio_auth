var randomstring = require("randomstring");
var mongoose = require('mongoose')
var Schema = mongoose.Schema;

var tokenSchema = new Schema({
	uid: { type: String, require: true, unique: false },
	accessToken: { type: String, require: true, unique: true },
	expires_at: { type: Date, require: true, expires:0  }
});

tokenSchema.statics.issueToken = function issueToken(req, callback, expires_at){
	uri = req.body.srcuri
	uid = req.body.email
	if (typeof expires_at === 'undefined') {
		expires_at = new Date();
		expires_at.setSeconds(expires_at.getSeconds() + 3600)
	}

	var newToken = new this();
	newToken.uid = uid;
	newToken.accessToken = randomstring.generate(16);
	newToken.expires_at = expires_at;

	newToken.save(function(err){
		if (err) {
			console.log("newToken Err");
		}
		callback(newToken);
	});
}

tokenSchema.statics.isValid = function(uidGiven, accessTokenGiven, callback) {
	console.log('%s:%s', uidGiven, accessTokenGiven);
	this.count({ uid: uidGiven, accessToken: accessTokenGiven }, function(err, count) {
		if (err){
			console.log("**** err:" + err);
		}

		var isTokenValid = count > 0;
		callback(isTokenValid);
	});

};

tokenSchema.statics.removeToken = function(uidGiven, accessTokenGiven, callback) {
	console.log("removing: %s:%s", uidGiven, accessTokenGiven);
	this.findOneAndRemove({uid: uidGiven, accessToken: accessTokenGiven}, function(err){
		if (err){
			console.log("**** err:" + err);
		} else {
			console.log("removed: %s:%s", uidGiven, accessTokenGiven);
			return callback();
		}
	});
};

var Token = mongoose.model('Token_ResetPasswd', tokenSchema);

module.exports = Token;
