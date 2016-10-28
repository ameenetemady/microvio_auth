var appendQuery = require('append-query')

/// config/passport.js

// load all the things we need
var LocalStrategy   = require('passport-local').Strategy;

// load up the user model
var User       		= require('../models/account');

var Token = require('../models/token')
var Token_ResetPasswd = require('../models/token_resetpasswd');

// expose this function to our app using module.exports
module.exports = function(passport) {

	// =========================================================================
    // passport session setup ==================================================
    // =========================================================================
    // required for persistent login sessions
    // passport needs ability to serialize and unserialize users out of session

    // used to serialize the user for the session
    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });

    // used to deserialize the user
    passport.deserializeUser(function(id, done) {
        User.findById(id, function(err, user) {
            done(err, user);
        });
    });

 	// =========================================================================
    // LOCAL SIGNUP ============================================================
    // =========================================================================
    // we are using named strategies since we have one for login and one for signup
	// by default, if there was no name, it would just be called 'local'

    passport.use('local-signup', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with email
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true // allows us to pass back the entire request to the callback
    },
    function(req, email, password, done) {
		console.log(email);
		// find a user whose email is the same as the forms email
		// we are checking to see if the user trying to login already exists
        User.findOne({ 'local.email' :  email }, function(err, user) {
            // if there are any errors, return the error
            if (err)
                return done(err);

            // check to see if theres already a user with that email
            if (user) {
		req.flash('srcuri'); // remove prev src flash if any
		req.flash('srcuri', req.body.srcuri);
                return done(null, false, req.flash('signupMessage', 'That email is already taken.'));
            } else {

		// if there is no user with that email
                // create the user
                var newUser            = new User();

                // set the user's local credentials
                newUser.local.email    = email;
                newUser.local.password = newUser.generateHash(password); // use the generateHash function in our user model

				// save the user
                newUser.save(function(err) {
                    if (err)
                        throw err;

			Token.issueToken(email, function(newToken){
				req.session.token = newToken.accessToken;
				req.session.uid = newToken.uid;

				var uriRedirect = appendQuery(req.body.srcuri, { token: newToken.accessToken, uid: newToken.uid})
				console.log('Redirecting to: %s', uriRedirect);
				req.session.returnTo = uriRedirect;
				return done(null, newUser);
			});



                });
            }

        });

    }));

    // =========================================================================
    // LOCAL LOGIN =============================================================
    // =========================================================================
    // we are using named strategies since we have one for login and one for signup
    // by default, if there was no name, it would just be called 'local'

    passport.use('local-login', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with email
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true // allows us to pass back the entire request to the callback
    },
    function(req, email, password, done) { // callback with email and password from our form

        // find a user whose email is the same as the forms email
        // we are checking to see if the user trying to login already exists
	console.log('running in local-login');
	req.flash('srcuri'); // remove prev flash for srcuri
	req.flash('srcuri', req.body.srcuri);
        User.findOne({ 'local.email' :  email }, function(err, user) {
            // if there are any errors, return the error before anything else
            if (err) {
		console.log("local-login Error: %s", err);
                return done(err);
		}

            // if no user is found, return the message
            if (!user)
                return done(null, false, req.flash('loginMessage', 'User not found!')); // req.flash is the way to set flashdata using connect-flash

            // if the user is found but the password is wrong
            if (!user.validPassword(password))
                return done(null, false, req.flash('loginMessage', 'Wrong password!')); // create the loginMessage and save it to session as flashdata

            // all is well, return successful user
		Token.issueToken(email, function(newToken){
			req.session.token = newToken.accessToken;
			req.session.uid = newToken.uid;

			var uriRedirect = appendQuery(req.body.srcuri, { token: newToken.accessToken, uid: newToken.uid})
			var uriRedirect2 = appendQuery('/counting', { srcuri: uriRedirect})
	
			console.log('Redirecting to: %s', uriRedirect2);
			req.session.returnTo = uriRedirect2;
            		return done(null, user);
		});
        });

    }));

};

