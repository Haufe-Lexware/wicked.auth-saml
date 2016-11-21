'use strict';

const debug = require('debug')('auth-saml:authorization');

const authorization = function () { };

authorization.applyUserScopes = function (userInfo, profile, samlResponse, sessionData, callback) {
    debug('applyUserScopes()');

    // ====================================
    // ====================================
    // This is an excellent place to put in
    // some actual authorization and amend
    // a "scope" property to the userInfo
    // object, if you want to.
    // ====================================
    // ====================================

    // Default implementation does nothing.
    callback(null, userInfo);
}

module.exports = authorization;
