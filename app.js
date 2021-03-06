'use strict';

const express = require('express');
const path = require('path');
const favicon = require('serve-favicon');
const logger = require('morgan');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const debug = require('debug')('auth-saml:app');
const qs = require('querystring');
const URL = require('url');
const async = require('async');
const wicked = require('wicked-sdk');
const wickedSaml = require('wicked-saml');
const fs = require('fs');
const session = require('express-session');
const FileStore = require('session-file-store')(session);

const mustache = require('mustache');

const utils = require('./utils');
const authorization = require('./authorization');

// Use default options, see https://www.npmjs.com/package/session-file-store
const sessionStoreOptions = {};

const SECRET = 'ThisIsASecret';

let sessionMinutes = 60;
if (process.env.AUTH_SERVER_SESSION_MINUTES) {
    console.log('Using session duration specified in env var AUTH_SERVER_SESSION_MINUTES.');
    sessionMinutes = Number(process.env.AUTH_SERVER_SESSION_MINUTES);
}
debug('Session duration: ' + sessionMinutes + ' minutes.');
let BASE_URL = '/auth-saml';
if (process.env.AUTH_SERVER_BASE) {
    BASE_URL = process.env.AUTH_SERVER_BASE;
    console.log('Using overridden base path: ' + BASE_URL);
} else {
    console.log('Using base path: ' + BASE_URL + ' (override with env var AUTH_SERVER_BASE)');
}

// Specify the session arguments. Used for configuring the session component.
const sessionArgs = {
    store: new FileStore(sessionStoreOptions),
    secret: SECRET,
    saveUninitialized: true,
    resave: false,
    cookie: {
        maxAge: sessionMinutes * 60 * 1000
    }
};

const app = express();

app.initApp = function (callback) {

    if (!wicked.isDevelopmentMode()) {
        app.set('trust proxy', 1);
        //sessionArgs.cookie.secure = true;
        console.log("Running in PRODUCTION MODE.");
    } else {
        console.log("=============================");
        console.log(" Running in DEVELOPMENT MODE");
        console.log("=============================");
    }

    app.use(wicked.correlationIdHandler());

    // view engine setup
    app.set('views', path.join(__dirname, 'views'));
    app.set('view engine', 'jade');

    logger.token('correlation-id', function (req, res) {
        return req.correlationId;
    });
    app.use(logger('{"date":":date[clf]","method":":method","url":":url","remote-addr":":remote-addr","version":":http-version","status":":status","content-length":":res[content-length]","referrer":":referrer","response-time":":response-time","correlation-id":":correlation-id"}'));

    // Set up the body parser to get JSON
    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({ extended: false }));

    // Set up the cookie parser
    app.use(cookieParser(SECRET));
    // And session management
    app.use(session(sessionArgs));

    // Delegate the metadata end point to the wicked SAML library
    app.get(BASE_URL + '/metadata.xml', wickedSaml.metadata());

    // End point for authorization of web applications; looks like this:
    //   https://api.yourserver.com/auth-saml/some-api?client_id=id-from-api-portal
    // If the client ID checks out with wicked, it will go bother the SAML
    // IdP to get an identity back. If that succeeds, the /auth-saml/assert
    // end point will be called. 
    app.get(BASE_URL + '/api/:apiId', function (req, res, next) {
        const apiId = req.params.apiId;
        const clientId = req.query.client_id;
        const responseType = req.query.response_type;
        const givenRedirectUri = req.query.redirect_uri;
        const givenState = req.query.state;
        debug(BASE_URL + '/' + apiId + '?client_id=' + clientId + '&response_type=' + responseType);
        if (givenState)
            debug('given state: ' + givenState);
        if (!clientId)
            return next(makeError('The query parameter client_id is missing.', 400));
        if (responseType !== 'token' && responseType !== 'code')
            return next(utils.makeError('Bad request. Parameter response_type is missing or faulty. Only "token" and "code" are supported.', 400));

        // Check whether we need to bother the SAML IdP or not.
        wicked.getSubscriptionByClientId(clientId, apiId, function (err, subsInfo) {
            if (err)
                return next(err);
            // Yes, we have a valid combination of API and Client ID
            // Store data in the session.
            req.session.apiId = apiId;
            req.session.clientId = clientId;
            req.session.responseType = responseType;
            if (givenState)
                req.session.state = givenState;
            else if (req.session.state)
                delete req.session.state;

            // Get a login URL for the SSO provider:
            wickedSaml.login(function (err, loginInfo) {
                if (err)
                    return next(err);
                // loginInfo looks like this:
                // loginInfo = {
                //   loginUrl: 'https://url.of.your.idp/...',
                //   requestId: 'some-request-identifier-you-get-back-at-assert'
                // }

                // Store requestId in session for checking at assert
                req.session.requestId = loginInfo.requestId;

                // Redirect to IdP
                res.redirect(loginInfo.loginUrl);
            });
        });
    });

    app.post(BASE_URL + '/assert', function (req, res, next) {
        debug(BASE_URL + '/assert');

        // Sanity check session state before we do more things
        if (!req.session)
            return next(makeError('Invalid session state: No session data available.', 500));
        if (!req.session.requestId)
            return next(makeError('Unrelated assertion received (no pending request).', 400));
        if (!req.session.apiId)
            return next(makeError('Invalid session state: Unknown destination API.', 500));
        if (!req.session.clientId)
            return next(makeError('Invalid session state: Unknown destination client ID.', 500));
        if (!req.session.responseType)
            return next(makeError('Invalid session state: Unknown response type.', 500));

        // Now we can pick this data from the session.
        const requestId = req.session.requestId;
        const apiId = req.session.apiId;
        const clientId = req.session.clientId;
        const responseType = req.session.responseType;
        const givenState = req.session.state;

        // Now what does we haves here.
        wickedSaml.assert(req, requestId, function (err, userInfo, samlResponse) {
            if (err) {
                // Make sure we delete the userInfo if it's present
                if (req.session.userInfo)
                    delete req.session.userInfo;
                if (req.session.profile)
                    delete req.session.profile;
                return next(err);
            }
            // Looks like we made sense of it.
            debug('SAML Response:');
            debug(JSON.stringify(samlResponse, null, 2));

            // Build profile
            const profile = buildProfile(samlResponse);

            // Build up userInfo structure for registering the OAuth2 user.
            // authenticated_userid is forced to be a part of the profile.
            userInfo.authenticated_userid = qs.escape(profile.authenticated_userid);
            userInfo.api_id = apiId; // from session
            userInfo.client_id = clientId; // from session
            userInfo.auth_server = app.get('auth_server'); // global setting

            // Store this in the session.
            req.session.samlResponse = samlResponse;
            req.session.userInfo = userInfo;
            req.session.profile = profile;

            debug('User info for implicit token creation:');
            debug(userInfo);

            // If we have an authorization step, it's implemented in the
            // authorization module. This would add any scopes, if needed.
            authorization.applyUserScopes(userInfo, profile, samlResponse, req.session, function (err, userInfo) {
                if (err) {
                    // Propagate authorization errors to error handler.
                    return next(err);
                }

                if (responseType === 'token') {
                    // And redirect back to web application
                    return redirectWithAccessToken(userInfo, givenState, res, next);
                } else if (responseType === 'code') {
                    return redirectWithAuthorizationCode(userInfo, givenState, res, next);
                }
                return res.status(500).json({ message: 'Invalid response type: ' + responseType });
            });
        });
    });

    // These things make me love JavaScript and its infrastructure. Effortless
    // templating with Mustache.
    function buildProfile(samlResponse) {
        debug('buildProfile()');

        const samlConfig = app.authConfig;
        const profileConfig = samlConfig.profile;

        if (!profileConfig) {
            debug('There is no profile property in the saml configuration.');
            return { message: 'Profile configuration missing' };
        }

        const propNames = wickedSaml.getAttributeNames(samlResponse);
        debug('Profile property names:');
        debug(propNames);

        const profileModel = {};
        for (let i = 0; i < propNames.length; ++i) {
            const prop = propNames[i];
            profileModel[prop] = wickedSaml.getAttributeValue(samlResponse, prop);
        }

        const profile = {};
        for (let propName in profileConfig) {
            const propConfig = profileConfig[propName];
            profile[propName] = mustache.render(propConfig, profileModel);
        }
        debug('Built profile:');
        debug(profile);

        return profile;
    }

    app.get(BASE_URL + '/profile', utils.cors(), function (req, res, next) {
        debug(BASE_URL + '/profile');
        const validState = (req.session && req.session.userInfo && req.session.profile);
        if (!validState)
            return jsonError(res, 'No session available. Cannot retrieve profile.');
        return res.json(req.session.profile);
    });

    app.get(BASE_URL + '/heartbeat', utils.cors(), function (req, res, next) {
        debug(BASE_URL + '/heartbeart');
        const validState = (req.session && req.session.userInfo);
        if (!validState)
            return jsonError(res, 'No session available. Cannot renew access token.', 403);
        const userInfo = req.session.userInfo;
        // Try to renew the token.
        getRedirectUriWithAccessToken(userInfo, null, function (err, redirectUri) {
            if (err)
                return jsonError(res, 'Failed to renew access token: ' + err.message, 500);
            // Parse the redirect URI, looks like this:
            // https://sdfmlksd.com#access_token=4793ihfkdi4i37498374&expires_in=3600&token_type=bearer[&state=...]
            let tokenData = null;
            try {
                const parsedUri = URL.parse(redirectUri);
                if (!parsedUri.hash)
                    throw new Error('The redirectUri did not contain a hash ("#").');
                if (!parsedUri.hash.startsWith('#'))
                    throw new Error('The redirectUri hash did not start with "#".');
                // From the example: parsedUri.hash == "#access_token=4793ihfkdi4i37498374&expires_in=3600&token_type=bearer"
                const queryString = parsedUri.hash.substring(1); // Strip #
                // From the example: queryString == "access_token=4793ihfkdi4i37498374&expires_in=3600&token_type=bearer" 
                tokenData = qs.parse(queryString);
                // From the example: tokenData == { access_token: '4793ihfkdi4i37498374', expires_in: '3600', token_type: 'bearer' }
                if (!tokenData || !tokenData.access_token)
                    throw new Error('The access_token fragment in the redirectUri could not be located.');
                // Now we should be fine.
            } catch (ex) {
                return jsonError(res, 'Could not parse redirect URI: ' + ex.message, 500);
            }
            // Return the tokenData from the redirectUri
            return res.json(tokenData);
        });
    });

    function redirectWithAccessToken(userInfo, givenState, res, next) {
        debug('redirectWithAccessToken()');

        getRedirectUriWithAccessToken(userInfo, givenState, function (err, redirectUri) {
            if (err) {
                return next(err);
            }

            // Redirect back, please
            res.redirect(redirectUri);
        });
    }

    function getRedirectUriWithAccessToken(userInfo, givenState, callback) {
        wicked.oauth2AuthorizeImplicit(userInfo, function (err, result) {
            if (err) {
                debug('getRedirectUriWithAccessToken failed.');
                debug(err);
                return callback(err);
            }

            console.log(result);

            if (!result.redirect_uri)
                return callback(makeError('Did not receive redirect_uri from oauth2AuthorizeImplicit.', 500));

            let clientRedirectUri = result.redirect_uri;
            if (givenState)
                clientRedirectUri += '&state=' + givenState;

            // Remember this redirect URI, as we allow that for CORS calls
            utils.storeRedirectUriForCors(clientRedirectUri);

            // Just return the string, not the object
            callback(null, clientRedirectUri);
        });
    }

    function redirectWithAuthorizationCode(userInfo, givenState, res, next) {
        debug('redirectWithAuthorizationCode()');

        wicked.oauth2GetAuthorizationCode(userInfo, function (err, result) {
            if (err) {
                debug('oauth2GetAuthorizationCode failed.');
                debug(err);
                return next(err);
            }

            debug('Result of oauth2GetAuthorizationCode:');
            debug(result);

            if (!result.redirect_uri)
                return callback(makeError('Did not receive redirect_uri from oauth2GetAuthorizationCode.', 500));

            let clientRedirectUri = result.redirect_uri;
            if (givenState)
                clientRedirectUri += '&state=' + givenState;

            // Remember this redirect URI, as we allow that for CORS calls
            utils.storeRedirectUriForCors(clientRedirectUri);

            res.redirect(clientRedirectUri);
        });
    }

    // catch 404 and forward to error handler
    app.use(function (req, res, next) {
        const err = new Error('Not Found');
        err.status = 404;
        next(err);
    });

    // error handlers

    function makeError(message, status) {
        const err = new Error(message);
        if (status)
            err.status = status;
        else
            err.status = 500;
        return err;
    }

    function jsonError(res, message, status) {
        debug('Error ' + status + ': ' + message);
        res.status(status).json({ message: message });
    }

    // production error handler
    // no stacktraces leaked to user
    app.use(function (err, req, res, next) {
        if (err.status !== 404) {
            console.error(err);
            console.error(err.stack);
        }
        res.status(err.status || 500);
        res.render('error', {
            title: 'Error',
            correlationId: req.correlationId,
            message: err.message,
            status: err.status
        });
    });

    callback(null);
};


module.exports = app;
