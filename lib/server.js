//
// ::::::::::..     .,-::::::::::::-.         ....:::::: .::::::.
// ;;;;;;;``;;;;  ,;;;'````' ;;,   `';,    ;;;;;;;;;````;;;`    `
// [[[ [[[,/[[['  [[[        `[[     [[    ''`  `[[.    '[==/[[[[,
// $$$ $$$$$$c    $$$         $$,    $$   ,,,    `$$      '''    $
// 888 888b "88bo,`88bo,__,o, 888_,o8P'd8b888boood88     88b    dP
// MMM MMMM   "W"   "YUMMMMMP"MMMMP"`  YMP"MMMMMMMM"      "YMmMY"
//
//                                            A Node.JS IRC Server
// ircd.js

// libs:
// http://github.com/pgte/carrier

// rfcs:
// http://www.networksorcery.com/enp/rfc/rfc2812.txt
// http://tools.ietf.org/html/rfc1459
//
// Spells out some stuff the RFC was light on:
// http://docs.dal.net/docs/misc.html#5

const net = require('net');
const tls = require('tls');
const carrier = require('carrier');
const fs = require('fs');
const irc = require('./protocol');
const path = require('path');
const assert = require('assert');
const Channel = require('./channel');
const User = require('./user');
const History = require('./storage').History;
const ChannelDatabase = require('./storage').ChannelDatabase;
const UserDatabase = require('./storage').UserDatabase;
const ServerCommands = require('./commands');
const winston = require('winston');
const commander = require('commander');

function AbstractConnection(stream) {
  this.stream = stream;
  this.object = null;

  this.__defineGetter__('id', () => {
    return this.object ? this.object.id : 'Unregistered';
  });
}


class Server {
  constructor() {
    this.history = new History(this);
    this.users = new UserDatabase(this);
    this.channels = new ChannelDatabase(this);
    this.config = null;
    this.commands = new ServerCommands(this);
    this.version = '0.0.17';
    this.created = '2012-09-21';
    this.debug = false;
  }

  get name() {
    return this.config.serverName;
  }

  get info() {
    return this.config.serverDescription;
  }

  get token() {
    return this.config.token;
  }

  get host() {
    return ':' + this.config.hostname;
  }

  cliParse() {
    let file = null;

    commander.option('-f --file [file]','Configuration file (Defaults: /etc/ircdjs/config.json or ../config/config.json)')
      .parse(process.argv);
    // When the -f switch is passwd without a parameter, commander.js evaluates it to true.
    if (commander.file && commander.file !== true) {
      file = commander.file;
    }

    return file;
  }

  loadConfig(fn) {
    let server = this;
    let paths = [
      path.join('/', 'etc', 'ircdjs', 'config.json'),
      path.join(__dirname, '..', 'config', 'config.json'),
    ];

    this.config = null;
    if (server.file) {
      paths.unshift(server.file);
    }

    paths.forEach(name => {
      fs.exists(name, exists => {
        if (!exists || server.config) return;
        try {
          server.config = JSON.parse(fs.readFileSync(name).toString());
          server.config.idleTimeout = server.config.idleTimeout || 60;
          winston.info('Using config file: ' + name);
          if (fn) {
            fn();
          }
        } catch (exception) {
          winston.error('Please ensure you have a valid config file.', exception);
        }
      });
    });
  }

  normalizeName(name) {
    return name &&
           name.toLowerCase()
           .replace(/{/g, '[')
           .replace(/}/g, ']')
           .replace(/\|/g, '\\')
           .trim();
  }

  isValidPositiveInteger(str) {
    let n = ~~Number(str);

    return String(n) === str && n >= 0;
  }

  valueExists(value, collection, field) {
    value = this.normalizeName(value);

    return collection.some(u => {
      return this.normalizeName(u[field]) === value;
    })
  }

  channelTarget(target) {
    let prefix = target[0];
    let channelPrefixes = ['#','&','!','+'];

    return (channelPrefixes.indexOf(prefix) !== -1);
  }

  parse(data) {
    let parts = data.trim().split(/ :/);
    let args = parts[0].split(' ');

    parts = [parts.shift(), parts.join(' :')];

    if (parts.length > 0) {
      args.push(parts[1]);
    }

    if (data.match(/^:/)) {
      args[1] = args.splice(0, 1, args[1]);
      args[1] = (args[1] + '').replace(/^:/, '');
    }

    return {
      command: args[0].toUpperCase(),
      args: args.slice(1),
    };
  }

  respondToMessage(user, message) {
    this.commands[message.command].apply(this.commands, [user].concat(message.args));
  }

  respond(data, client) {
    let message = this.parse(data);

    if (this.validCommand(message.command)) {
      if (this.config.serverPassword && !client.object.passwordAccepted) {
        this.queueResponse(client, message);
      } else {
        this.respondToMessage(client.object, message);
      }
    }
  }

  queueResponse(client, message) {
    if ('PASS' === message.command) {
      // Respond now
      client.object.pendingAuth = false;
      this.respondToMessage(client.object, message);
    } else {
      client.object.queue(message);
    }
  }

  validCommand(command) {
    return this.commands[command];
  }

  createDefaultChannels() {
    if (this.config.channels) {
      Object.keys(this.config.channels).forEach(channel => {
        let channelName = '';
        if (!this.channelTarget(channel)) {
          channelName = '#' + channel;
        } else {
          channelName = channel;
        }
        let newChannel = this.channels.registered[this.normalizeName(channelName)] = new Channel(channelName, this);
        newChannel.topic = this.config.channels[channel].topic;
      });
    }
  }

  motd(user) {
    user.send(this.host, irc.reply.motdStart, user.nick, ':- Message of the Day -');
    user.send(this.host, irc.reply.motd, user.nick, this.config.motd || 'No message set');
    user.send(this.host, irc.reply.motdEnd, user.nick, ':End of /MOTD command.');
  }

  startTimeoutHandler() {
    let timeout = this.config.pingTimeout || 10;

    this.timeoutHandler = setInterval(() => {
      this.users.forEach(user => {
        if (user.hasTimedOut()) {
          winston.info('User timed out:', user.mask);
          this.disconnect(user);
        } else {
          // TODO: If no other activity is detected
          user.send('PING', this.config.hostname, this.host);
        }
      });
    }, timeout * 1000);
  }

  stopTimeoutHandler() {
    clearInterval(this.timeoutHandler);
  }

  start(callback) {
    let _this = this;
    let key;
    let cert;
    let options;

    if (this.config.key && this.config.cert) {
      try {
        key = fs.readFileSync(this.config.key);
        cert = fs.readFileSync(this.config.cert);
      } catch (exception) {
        winston.error('Fatal error:', exception);
      }
      options = { key: key, cert: cert };
      this.server = tls.createServer(options, handleStream);
    } else {
      this.server = net.createServer(handleStream);
    }

    assert.ok(callback === undefined || typeof callback == 'function');
    this.server.listen(this.config.port, callback);
    winston.info('Server listening on port: ' + this.config.port);

    this.startTimeoutHandler();

    function handleStream(stream) {
      try {
        let carry = carrier.carry(stream);
        let client = new AbstractConnection(stream);

        client.object = new User(client, _this);
        if (_this.config.serverPassword) {
          client.object.pendingAuth = true;
        }

        stream.on('end', () => { _this.end(client); });
        stream.on('error', winston.error);
        carry.on('line',  line => { _this.data(client, line); });
      } catch (exception) {
        winston.error('Fatal error:', exception);
      }
    }
  }

  close(callback) {
    if (callback !== undefined) {
      assert.ok(typeof callback === 'function');
      this.server.once('close', callback);
    }
    this.stopTimeoutHandler();
    this.server.close();
  }

  end(client) {
    let user = client.object;

    if (user) {
      this.disconnect(user);
    }
  }

  disconnect(user) {
    user.channels.forEach(channel => {
      channel.users.forEach(channelUser => {
        if (channelUser !== user) {
          channelUser.send(user.mask, 'QUIT', user.quitMessage);
        }
      });

      channel.users.splice(channel.users.indexOf(user), 1);
    });

    user.closeStream();
    this.users.remove(user);
    user = null;
  }

  data(client, line) {
    line = line.slice(0, 512);
    winston.info('[' + this.name + ', C: ' + client.id + '] ' + line);
    this.respond(line, client);
  }
}

Server.boot = () => {
  let server = new Server();

  server.file = server.cliParse();

  server.loadConfig(() => {
    server.start();
    server.createDefaultChannels();
  });

  process.on('SIGHUP', () => {
    winston.info('Reloading config...');
    server.loadConfig();
  });

  process.on('SIGTERM', () => {
    winston.info('Exiting...');
    server.close();
  });
};

exports.Server = Server;
exports.winston = winston;

if (!module.parent) {
  Server.boot();
}
