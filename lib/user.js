const dns = require('dns');
const winston = require('winston');
const irc = require('./protocol');

class User {
  constructor(client, ircServer) {
    this.server = ircServer;
    this.config = ircServer.config;
    this.nick = null;
    this.username = null;
    this.realname = null;
    this.channels = [];
    this.quitMessage = 'Connection lost';
    this.disconnected = false;
    this.pendingAuth = false;
    this.passwordAccepted = false;
    this.lastPing = null;
    this.postAuthQueue = [];

    if (client) {
      this.client = client;
    }

    if (client && client.stream) {
      this.stream = client.stream;
      this.remoteAddress = client.stream.remoteAddress;
      this.hostname = client.stream.remoteAddress;
    }

    this.registered = false;
    this._modes = [];
    this.channelModes = {};
    this.serverName = '';
    this.created = new Date() / 1000;
    this.updated = new Date();
    this.isAway = false;
    this.awayMessage = null;
    this.serverOper = false;
    this.localOper = false;
    this.hopCount = 0;
    this.servertoken = null;

    this.hostLookup();
    this.addMode = {
      i: (user, arg) => {
        if (this.isOper || this === user) {
          if (!user.modes.match(/i/)) {
            user._modes.push('i');
            user.send(user.mask, 'MODE', this.nick, '+i', user.nick);
            if (this !== user) {
              this.send(this.mask, 'MODE', this.nick, '+i', user.nick);
            }
          }
        } else {
          this.send(this.server.host, irc.errors.usersDoNotMatch, this.nick, user.nick, ':Cannot change mode for other users');
        }
      },

      o: () => {
        // Can only be issued by OPER
      },

      w: () => {
        if (!this.modes.match(/w/)) {
          this._modes.push('w');
          this.send(this.mask, 'MODE', this.nick, '+w', this.nick);
        }
      },
    };
    this.removeMode = {
      i: (user, arg) => {
        if (this.isOper || this === user) {
          if (user.modes.match(/i/)) {
            user._modes.splice(user._modes.indexOf('i'), 1);
            user.send(user.mask, 'MODE', this.nick, '-i', user.nick);
            if (this !== user) {
              this.send(this.mask, 'MODE', this.nick, '-i', user.nick);
            }
          }
        } else {
          this.send(this.server.host, irc.errors.usersDoNotMatch, this.nick, user.nick, ':Cannot change mode for other users');
        }
      },

      o: () => {
        if (this.modes.match(/o/)) {
          user._modes.splice(user._modes.indexOf('o'), 1);
          this.send(this.mask, 'MODE', this.nick, '-o', this.nick);
        }
      },

      w: () => {
        if (this.modes.match(/w/)) {
          user._modes.splice(user._modes.indexOf('w'), 1);
          this.send(this.mask, 'MODE', this.nick, '-w', this.nick);
        }
      },
    };
  }

  get id() {
    return this.nick;
  }

  get mask() {
    return ':' + this.nick + '!' + this.username + '@' + this.hostname;
  }

  get modes() {
    return '+' + this._modes.join('');
  }

  set modes(modes) {
    if (modes) {
      modes = modes.replace(/^\+/, '');
      this._modes = modes.split('');
    }
  }

  get idle() {
    return parseInt(((new Date()) - this.updated) / 1000, 10);
  }

  get isOper() {
    return this.modes.indexOf('o') !== -1;
  }

  get isInvisible() {
    return this.modes.indexOf('i') !== -1;
  }

  send() {
    if (!this.stream) {
      return;
    }

    let self = this;
    let message = arguments.length === 1 ?
        arguments[0]
        : Array.prototype.slice.call(arguments).join(' ');

    winston.log('S: [' + this.nick + '] ' + message);

    try {
      this.stream.write(message + '\r\n');
    } catch (exception) {
      winston.error('[' + this.nick + '] error writing to stream:', exception);

      // This setTimeout helps prevent against race conditions when multiple clients disconnect at the same time
      setTimeout(() => {
        if (!self.disconnected) {
          self.disconnected = true;
          self.server.disconnect(self);
        }
      }, 1);
    }
  }

  expandMask(mask) {
    return mask.replace(/\./g, '\\.').
                replace(/\*/g, '.*');
  }

  matchesMask(mask) {
    let parts = mask.match(/([^!]*)!([^@]*)@(.*)/) || [];
    let matched = true;
    let lastPart = parts.length < 4 ? parts.length : 4;
    parts = parts.slice(1, lastPart).map(this.expandMask);

    if (!this.nick.match(parts[0])) {
      return false;
    } else if (!this.username.match(parts[1])) {
      return false;
    } else if (!this.hostname.match(parts[2])) {
      return false;
    } else {
      return true;
    }
  }

  sharedChannelWith(targetUser) {
    let user = this;
    let channels = targetUser.channels;
    let matchedChannel;

    channels.some(channel => {
      if (user.channels.indexOf(channel) !== -1) {
        matchedChannel = channel;
        return true;
      }
    });

    return matchedChannel;
  }

  channelNick(channel) {
    return this.isOp(channel) ? '@' + this.nick : this.nick;
  }

  isOp(channel) {
    if (this.channelModes[channel])
      return this.channelModes[channel].match(/o/);
  }

  op(channel) {
    this.channelModes[channel] += 'o';
  }

  deop(channel) {
    if (this.channelModes[channel])
      this.channelModes[channel] = this.channelModes[channel].replace(/o/, '');
  }

  oper() {
    if (!this.modes.match(/o/)) {
      this._modes.push('o');
      this.send(this.mask, 'MODE', this.nick, '+o', this.nick);
      this.localOper = true;
    }
  }

  deoper() {
    this.removeMode.o.apply(this);
    this.localOper = false;
  }

  isHop(channel) {
    if (this.channelModes[channel])
      return this.channelModes[channel].match(/h/) || this.isOp(channel);
  }

  hop(channel) {
    this.channelModes[channel] += 'h';
  }

  dehop(channel) {
    if (this.channelModes[channel])
      this.channelModes[channel] = this.channelModes[channel].replace(/h/, '');
  }

  isVoiced(channel) {
    if (this.channelModes[channel])
      return this.channelModes[channel].match(/v/) || this.isHop(channel) || this.isOp(channel);
  }

  voice(channel) {
    this.channelModes[channel] += 'v';
  }

  devoice(channel) {
    if (this.channelModes[channel])
      this.channelModes[channel] = this.channelModes[channel].replace(/v/, '');
  }

  hostLookup() {
    if (!this.remoteAddress) {
      return;
    }

    dns.reverse(this.remoteAddress, (err, addresses) => {
      this.hostname = addresses && addresses.length > 0 ? addresses[0] : this.remoteAddress;
    });
  }

  register() {
    if (
        this.registered === false &&
        this.nick &&
        this.username
    ) {
      this.serverName = this.config.name;
      this.send(this.server.host, irc.reply.welcome, this.nick, 'Welcome to the ' + this.config.network + ' IRC network', this.mask);
      this.send(this.server.host, irc.reply.yourHost, this.nick, 'Your host is', this.config.hostname, 'running version', this.server.version);
      this.send(this.server.host, irc.reply.created, this.nick, 'This server was created on', this.server.created);
      this.send(this.server.host, irc.reply.myInfo, this.nick, this.config.name, this.server.version);
      this.server.motd(this);
      this.registered = true;
      this.addMode.w.apply(this);
    }
  }

  message(nick, message) {
    let user = this.server.users.find(nick);
    this.updated = new Date();

    if (user) {
      if (user.isAway) {
        this.send(this.server.host, irc.reply.away, this.nick, user.nick, ':' + user.awayMessage);
      }
      user.send(this.mask, 'PRIVMSG', user.nick, ':' + message);
    } else {
      this.send(this.server.host, irc.errors.noSuchNick, this.nick, nick, ':No such nick/channel');
    }
  }

  addModes(user, modes, arg) {
    let thisUser = this;

    modes.slice(1).split('').forEach(mode => {
      if (thisUser.addMode[mode])
        thisUser.addMode[mode].apply(thisUser, [user, arg]);
    });
  }

  removeModes(user, modes, arg) {
    let thisUser = this;

    modes.slice(1).split('').forEach(mode => {
      if (thisUser.removeMode[mode])
        thisUser.removeMode[mode].apply(thisUser, [user, arg]);
    });
  }

  queue(message) {
    this.postAuthQueue.push(message);
  }

  runPostAuthQueue() {
    if (!this.passwordAccepted) {
      return;
    }

    this.postAuthQueue.forEach(message => {
      self.server.respondToMessage(this, message);
    });
  }

  hasTimedOut() {
    return this.lastPing && (Math.floor((Date.now() - this.lastPing) / 1000) > (this.config.pingTimeout || this.config.idleTimeout));
  }

  closeStream() {
    if (this.stream && this.stream.end) {
      this.stream.end();
    }
  }

  quit(message) {
    this.quitMessage = message;
    this.closeStream();
  }
}

module.exports = User;
