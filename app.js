var express = require('express');
var path = require('path')
var app = express();
var http = require('http');
var url = require("url")
var mongoose = require('mongoose');
var Token = require('./models/token');

var Token_ResetPasswd = require('./models/token_resetpasswd');
var User = require('./models/account');
var bcrypt = require('bcrypt-nodejs');

var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var flash = require('connect-flash');
var session = require('express-session');
var configDB = require('./config/database.js');
var appendQuery = require('append-query')
var nodemailer = require('nodemailer');

var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');

mongoose.connect(configDB.url); // connect to our database

require('./config/passport')(passport);
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(cookieParser()); // read cookies (needed for auth)

app.use( bodyParser.json() );       // to support JSON-encoded bodies
app.use(bodyParser.urlencoded({     // to support URL-encoded bodies
  extended: true
})); 

app.use(express.static(path.join(__dirname, 'public')));
app.use(session({ secret: 'I_will_tell_Ilias_if_you_reveal_this_secret',
		  resave: true,
		  saveUninitialized: true }));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

/*
app.get('/', function (req, res) {
	res.render('index', {user: req.session.uid });
}); 
*/

/* Description: '/getuid', is to be called from individual app to retrive uid 
                  and token from active user session in the microvio app. 
*/
app.get('/getuid', function (req, res) {

	Token.isValid(req.session.uid, req.session.token, function(isValid){
		var uid = '';
		var token = '';
		if (isValid) {
			uid = req.session.uid;
			token = req.session.token;
		} 

		var uriRedirect = appendQuery(req.query.srcuri, {uid: uid, token: token })
		res.redirect(uriRedirect);
	});
});

/* Description: '/isValidToken' is to be called from individual app using REST 
                   client to verify a given token is still valid.
*/
app.get('/isValidToken', function (req, res) {
	Token.isValid(req.query.uid, req.query.token, function(isValid){
		var data = { isValid: isValid };
		res.end(JSON.stringify(data));
	});
});

/* Description: '/removeToken' is to be called from individual app through REST
                    client and remove a given token. It's useful for logout.
*/
app.get('/removeToken', function(req, res) {
	Token.removeToken(req.query.uid, req.query.token, function(){
		res.end();
	});
});

/* Description: '/login' to redirect user from individual app to login. Upon
                   successful authentication, the user will go back, otherwise
                   login form will be shown.
*/
app.get('/login',  function (req, res) {

  Token.isValid(req.session.uid, req.session.token, function(isValid){
		if( isValid ) {
			var uriRedirect = '/'
			if ( typeof req.query.srcuri !== 'undefined') {
      				uriRedirect = appendQuery(req.query.srcuri, { token: req.session.token, uid: req.session.uid })
			}
			console.log("REDIRECT!!!!!!!!!!!");
      			
			//res.render('counting', { srcuri: uriRedirect });
			var uriRedirect2 = appendQuery('/counting',{srcuri: uriRedirect});
			res.redirect(uriRedirect2);
		} else {
			req.logout();
			var srcuri = req.query.srcuri;
			var passwdreset = req.query.passwdreset;
			var success_message = '';
			if ( typeof srcuri === 'undefined' || srcuri === null ){
				srcuri = req.flash('srcuri');
			}
			if ( typeof passwdreset !== 'undefined'){
				success_message = 'Password Changed Successfully!';
			}
			res.render('login', { message: req.flash('loginMessage'),
					      success_message: success_message,
					      srcuri: srcuri});
		}
	});
});

/* Description: '/login' (post) is to verify the submission of the 
                  authentication form in the case that user enters empty 
                  email/password.
*/
app.post('/login', function(req, res, next) {
	if ( typeof req.body.email === 'undefined' ||
	     typeof req.body.password === 'undefined' ||
	     !req.body.email ||
	     !req.body.password )	{
		res.render('login', { message: 'Empty email/password!',
				      success_message: '', 
				      srcuri: req.body.srcuri });
	} else {
		next();
	}
});

/* Description: '/login' (post) is to verify username/password upon submission
                   if authentication form.
*/
app.post('/login', passport.authenticate('local-login', {
	successReturnToOrRedirect: true,
        failureRedirect : '/login', // redirect back to the signup page if there is an error
        failureFlash : true // allow flash messages
}));


/* Description: '/register' is to show the user the register form.
*/
app.get('/register', function(req, res) {
	// render the page and pass in any flash data if it exists
	var flash_srcuri = req.flash('srcuri');
	var srcuri = req.query.srcuri || req.body.srcuri || flash_srcuri;
	res.render('register', { message: req.flash('signupMessage'), 
				 srcuri: srcuri });
});

/* Description: '/register' (post) to handle submission of registration form.
*/
app.post('/register', passport.authenticate('local-signup', {
	successReturnToOrRedirect: true,
	failureRedirect : '/register', // redirect back to the signup page if there is an error
	failureFlash : true // allow flash messages
}));

/* Description: '/resetpasswdrequest' is to make user sent the reset request.
*/
app.get('/resetpasswdrequest', function(req, res) {
	// render the page and pass in any flash data if it exists
	var flash_srcuri = req.flash('srcuri');
	var srcuri = req.query.srcuri || req.body.srcuri || flash_srcuri;
	res.render('resetpasswdrequest', { message: req.flash('reset password'), 
				 		srcuri: srcuri });
});

/* Description: '/resetpasswdrequest' (post) is to verify the submission of the 
                  authentication form in the case that user enters email.
*/
app.post('/resetpasswdrequest', function(req, res, next) {
	console.log("XD")
	console.log(req.body)
	if ( typeof req.body.email === 'undefined' ||
	     !req.body.email )	{
		res.render('resetpasswdrequest', { message: 'Empty email!', 
				      		srcuri: req.body.srcuri });
	} else {
		// Check User Existence
		User.findOne({ 'local.email' :  req.body.email }, function(err, user) {
		// if there are any errors, return the error
		// check to see if theres already a user with that email
			if (!user) {
				//req.flash('srcuri'); // remove prev src flash if any
				//req.flash('srcuri', req.body.srcuri);
                		//return done(null, false, req.flash('reset password', 'Account not found. Please sign up new account.'));
            			return res.render('resetpasswdrequest', { message: 'Account not found!', 
				      		srcuri: req.body.srcuri });
	
			}else{
						//Issue token_resetpassswd
				Token_ResetPasswd.issueToken(req, function(newToken){
					req.session.token = newToken.accessToken;
					req.session.uid = newToken.uid;
					console.log(req.body)
					console.log('srcuri: %s', req.body.srcuri);
					var uriRedirect = appendQuery(req.body.srcuri, { token: newToken.accessToken, uid: newToken.uid})
					console.log('Issue new token: %s', newToken.accessToken);
					req.session.returnTo = uriRedirect;
					var passwdResetLink = appendQuery("https://t1_taglabrouter.genomecenter.ucdavis.edu/resetpasswd", { srcuri: req.body.srcuri, token: newToken.accessToken, uid: newToken.uid});
				
					// send mail
					var generator = require('xoauth2').createXOAuth2Generator({
						user: 'microvioweb@gmail.com', // Your gmail address.
						clientId: '507358027096-ea6mq24c0mr9h2kkp87eg2eu72d92ffc.apps.googleusercontent.com',
						clientSecret: 'KDe-bL7XdQcMBVDeJyGPQ5gQ',
						refreshToken: '1/mAZhgPIJJG-DxybDePPK5JL0QWzTSD4VFuTPkv6O-Zs'
					});

					// listen for token updates
					// you probably want to store these to a db
					generator.on('token', function(token){
						console.log('New token for %s: %s', token.user, token.accessToken);
					});

					// login
					var transporter = nodemailer.createTransport(({
						service: 'gmail',
						auth: {
							xoauth2: generator
						}
					}));
				
					transporter.sendMail({
						from: 'microvioweb@gmail.com',
						to: req.body.email,
						subject: 'Reset Password for the Microvio.com resources',
						text: '',
						html:	'If you would like to reset the password at your microvio account, please follow this link: <br>' + 
							'<a href=' + passwdResetLink + '>Reset Password</a><br>' +
							'Microvio.com is the home of the Ecomics, PAMDB and MutationDB. If you have any questions please contact us at microvioweb@gmail.com.'
						}, function(error, response) {
						if (error) {
							console.log(error);
							return res.render('resetpasswdrequest', { message: '(ERROR)', 
								srcuri: req.body.srcuri });	

						} else {
							console.log('Message sent');
							return res.render('info', {message:'', success_message: 'Reset Password: Email Message Sent to ' + req.body.email + '!', 
								srcuri: req.body.srcuri });
			
		
						}
					});
			
				});
		
			}
		})

		

	}
});






/* Description: '/resetpasswd' is to reset the password.
*/
app.get('/resetpasswd', function(req, res) {
	// render the page and pass in any flash data if it exists
	// should check the token (FUTURE WORK)
	var flash_srcuri = req.flash('srcuri');
	var srcuri = req.query.srcuri || req.body.srcuri || flash_srcuri;
	console.log("Test: Reset Password:");
	console.log(req.session.uid);
	console.log(req.session.token);
	console.log(req.query.uid);
	console.log(req.query.token);
	console.log("EndTest: Reset Password");
	Token_ResetPasswd.isValid(req.query.uid, req.query.token, function(isValid){
		if( !isValid ) {
			return res.render('info', {  message: 'Reset Password: Invalid Token!', success_message: '', 
				 srcuri: srcuri });
		
		}else{	
			return res.render('resetpasswd', { email: req.session.uid, message: '', 
				 srcuri: srcuri });
		}
	});
		

});

app.post('/resetpasswd', function(req, res, next) {
	// render the page and pass in any flash data if it exists
	// should check the token (FUTURE WORK)	
	var flash_srcuri = req.flash('srcuri');
	var srcuri = req.query.srcuri || req.body.srcuri || flash_srcuri;
	
	console.log(req.body);
	if (req.body.passwd !== req.body.reppasswd){
		console.log('PASSWORDRESET: NOT REPEAT PASSWORD');
		res.render('resetpasswd', { email: req.session.uid, message: 'Repeat password does not match password!', 	 srcuri: srcuri });
	}else{
		
		Token_ResetPasswd.isValid(req.session.uid, req.session.token, function(isValid){
			if( isValid ) {
				var encrypted_password = bcrypt.hashSync(req.body.passwd, bcrypt.genSaltSync(8),null);
				console.log("encrypted passwd=" + encrypted_password)
				User.findOneAndUpdate(
					{'local.email': req.session.uid},
					{ 'local':{'email':req.session.uid,'password':encrypted_password}},
					function(err, data){
						if (err){
							//For Debug Only
							return res.render('resetpasswd', { email:req.session.uid,message: '(ERROR)', 				 					srcuri: req.body.srcuri });
						}
					}
				)				
				Token_ResetPasswd.removeToken(req.session.uid, req.session.token, function(){
				});
				var uriRedirect = '/';
				if ( typeof srcuri !== 'undefined') {
      					uriRedirect = appendQuery('/login', {srcuri: srcuri, passwdreset: 'OK' });
				}else{
					uriRedirect = appendQuery('/login', {srcuri: '/', passwdreset: 'OK'});
				}
				console.log(uriRedirect);
      				return res.redirect(uriRedirect);

			}else{
				return res.render('info', { message: 'Invalid Tokens', success_message:'', 
					 		srcuri: req.body.srcuri });		
			}
		});
		
	}
})

/* Description: '/counting' to count number of valid login sessions.
*/
app.get('/counting',  function (req, res) {

  Token.isValid(req.session.uid, req.session.token, function(isValid){
		if( isValid ) {
			var uriRedirect = '/'
			if ( typeof req.query.srcuri !== 'undefined') {
      				uriRedirect = appendQuery(req.query.srcuri, { token: req.session.token, uid: req.session.uid })
			}
			console.log("REDIRECT!!!!!!!!!!!");
      			
			res.render('counting', { srcuri: uriRedirect });

			//res.redirect(uriRedirect);
		} else {
			//impossible to reach here in normal operation unless users try to access /counting
			req.logout();
			res.redirect('/');
		}
	});
});




app.get('/logout', function(req, res) {
		var uid = req.session.uid;
		var token = req.session.token;

		Token.removeToken(uid, token, function() {
			req.logout();
			res.redirect('/');
		});
	});


  var server = app.listen(4100, function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('app listening at http://%s:%s', host, port);
  });
