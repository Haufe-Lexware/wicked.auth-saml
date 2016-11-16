'use strict';

const cors = require('cors');
const debug = require('debug')('auth-saml:utils');
const url = require('url');

const utils = function () {};

const _validCorsHosts = {};
utils.storeRedirectUriForCors = function (uri) {
    debug('storeRedirectUriForCors() ' + uri);
    try {
        const parsedUri = url.parse(uri);
        const host = parsedUri.protocol + '//' + parsedUri.host;
        _validCorsHosts[host] = true;
        debug(_validCorsHosts);
    } catch (ex) {
        console.error(ex);
        console.error(ex.stack);
        console.error('storeRedirectUriForCors() - Invalid URI: ' + uri);
    }
}

function isCorsHostValid(host) {
    debug('isCorsHostValid(): ' + host);
    if (_validCorsHosts[host]) {
        debug('Yes, ' + host + ' is valid.');
        return true;
    }
    debug('*** ' + host + ' is not a valid CORS origin.');
    return false;
}

const _allowOptions = {
    origin: true,
    credentials: true,
    allowedHeaders: [
        'Accept',
        'Accept-Encoding',
        'Connection',
        'User-Agent',
        'Content-Type',
        'Cookie',
        'Host',
        'Origin',
        'Referer'
    ]
};

const _denyOptions = {
    origin: false
};

utils.cors = function () {
    const optionsDelegate = (req, callback) => {
        const origin = req.header('Origin');
        debug('in CORS options delegate. req.headers = ');
        debug(req.headers);
        if (isCorsHostValid(origin))
            callback(null, _allowOptions); // Mirror origin, it's okay
        else
            callback(null, _denyOptions);
    };
    return cors(optionsDelegate);
};

module.exports = utils;