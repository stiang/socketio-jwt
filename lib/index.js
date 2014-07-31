var xtend = require('xtend');
var jwt = require('jsonwebtoken');
var UnauthorizedError = require('./UnauthorizedError');

function authorize(options) {

  return function (socket) {
    var server = this;

    if (!server.$emit) {
      // then this is socket.io 1.0
      var Namespace = Object.getPrototypeOf(server.server.sockets).constructor;
      if (!~Namespace.events.indexOf('authenticated')) {
        Namespace.events.push('authenticated');
      }
    }

    var auth_timeout = setTimeout(function () {
      socket.disconnect('unauthorized');
    }, options.timeout || 5000);

    socket.on('authenticate', function (data) {
      clearTimeout(auth_timeout);
      // XXX: Need to use a copy of verify (added in index.js) to work around the
      // fact that koa-jwt thunkifies the version of verify that we use here
      jwt._verify(data.token, options.secret, options, function(err, decoded) {
        if (!err) {
          socket.decoded_token = decoded;
        }

        socket.emit('authenticated');
        if (server.$emit) {
          server.$emit('authenticated', socket);
        } else {
          server.server.sockets.emit('authenticated', socket);
        }
      });
    });

  };

}

exports.authorize = authorize;
