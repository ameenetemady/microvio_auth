var express = require('express');
var path = require('path')
var app = express();
var http = require('http');
var url = require("url")
var mongoose = require('mongoose');
var Token = require('./models/token');

var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var flash = require('connect-flash');
var session = require('express-session');
var configDB = require('./config/database.js');
var appendQuery = require('append-query')

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

      			res.redirect(uriRedirect);
		} else {
			req.logout();
			var srcuri = req.query.srcuri;
			if ( typeof srcuri === 'undefined' || srcuri === null ){
				srcuri = req.flash('srcuri');
			}
			
			res.render('login', { message: req.flash('loginMessage'),
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


app.get('/logout', function(req, res) {
		var uid = req.session.uid;
		var token = req.session.token;

		Token.removeToken(uid, token, function() {
			req.logout();
			res.redirect('/');
		});
	});


  var server = app.listen(4000, function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('app listening at http://%s:%s', host, port);
  });
