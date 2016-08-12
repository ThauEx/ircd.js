const irc = require('./protocol');
const ircd = require('./ircd');

class Commands {
  constructor(server) {
    this.server = server;
  }

  PONG(user, hostname) {
    user.lastPing = Date.now();
  }

  PING(user, hostname) {
    user.lastPing = Date.now();
    user.send(this.server.host, 'PONG', this.server.config.hostname, this.server.host);
  }

  PASS(user, password) {
    ircd.compareHash(password, this.server.config.serverPassword, (err, res) => {
      if (res) {
        user.passwordAccepted = true;
        user.server = this.server;
        user.runPostAuthQueue();
      } else {
        user.send(this.server.host, irc.errors.passwordWrong, user.nick || 'user', ':Password incorrect');
        user.quit();
      }
    });
  }

  AWAY(user, message) {
    if (user.isAway && (!message || message.length === 0)) {
      user.isAway = false;
      user.awayMessage = null;
      user.send(this.server.host, irc.reply.unaway, user.nick, ':You are no longer marked as being away');
    } else if (message && message.length > 0) {
      user.isAway = true;
      user.awayMessage = message;
      user.send(this.server.host, irc.reply.nowAway, user.nick, ':You have been marked as being away');
    } else {
      user.send(this.server.host, irc.errors.needMoreParams, user.nick, ':Need more parameters');
    }
  }

  VERSION(user, server) {
    // TODO: server
    user.send(
      this.server.host,
      irc.reply.version,
      user.nick,
      this.server.version + '.' + (this.server.debug ? 'debug' : ''),
      this.server.config.hostname, ':' + this.server.config.name
    );
  }

  TIME(user, server) {
    // TODO: server
    user.send(this.server.host, irc.reply.time, user.nick, this.server.config.hostname, ':' + (new Date()));
  }

  NICK(user, nick) {
    if (!nick || nick.length === 0) {
      return user.send(this.server.host, irc.errors.noNickGiven, ':No nickname given');
    } else if (nick === user.nick) {
      return;
    } else if (nick.length > (this.server.config.maxNickLength || 9) || nick.match(irc.validations.invalidNick)) {
      return user.send(this.server.host, irc.errors.badNick, (user.nick || ''), nick, ':Erroneus nickname');
    } else if (this.server.valueExists(nick, this.server.users.registered, 'nick')) {
      return user.send(this.server.host, irc.errors.nameInUse, '*', nick, ':is already in use');
    }

    nick = nick.trim();
    user.send(user.mask, 'NICK', ':' + nick);

    user.channels.forEach(channel => {
      let users = channel.users.splice(channel.users.indexOf(user), 1);
      channel.sendToGroup(users, user.mask + ' NICK : ' + nick);
    });

    user.nick = nick.trim();
    user.register();
  }

  USER(user, username, hostname, servername, realname) {
    this.server.users.register(user, username, hostname, servername, realname);
  }

  JOIN(user, channelNames, key) {
    if (!channelNames || !channelNames.length) {
      return user.send(this.server.host, irc.errors.needMoreParams, user.nick, ':Need more parameters');
    }

    channelNames.split(',').forEach(args => {
      let nameParts = args.split(' ');
      let channelName = nameParts[0];

      if (
          !this.server.channelTarget(channelName) ||
          channelName.match(irc.validations.invalidChannel)
      ) {
        user.send(this.server.host, irc.errors.noSuchChannel, ':No such channel');
      } else {
        this.server.channels.join(user, channelName, key);
      }
    });
  }

  PART(user, channelName, partMessage) {
    let channel = this.server.channels.find(channelName);

    if (channel && user.channels.indexOf(channel) !== -1) {
      partMessage = partMessage ? ' :' + partMessage : '';
      channel.send(user.mask, 'PART', channelName + partMessage);
      channel.part(user);

      if (channel.users.length === 0) {
        this.server.channels.remove(channel);
      }
    }
  }

  KICK(user, channels, users, kickMessage) {
    let channelMasks = channels.split(',');
    let userNames = users.split(',');
    let server = this.server;

    kickMessage = kickMessage ? ':' + kickMessage : ':' + user.nick;

    // ERR_BADCHANMASK

    if (userNames.length !== channelMasks.length) {
      user.send(this.server.host, irc.errors.needMoreParams, user.nick, ':Need more parameters');
    } else {
      channelMasks.forEach((channelMask, i) => {
        let channel = server.channels.findWithMask(channelMask);
        let userName = userNames[i];
        let targetUser;

        if (!channel) {
          user.send(server.host, irc.errors.noSuchChannel, ':No such channel');
          return;
        }

        targetUser = channel.findUserNamed(userName);

        if (!channel.findUserNamed(user.nick)) {
          user.send(server.host, irc.errors.notOnChannel, user.nick, channel.name, ':Not on channel');
        } else if (!targetUser) {
          user.send(server.host, irc.errors.userNotInChannel, userName, channel.name, ':User not in channel');
        } else if (!user.isOp(channel)) {
          user.send(server.host, irc.errors.channelOpsReq, user.nick, channel.name, ":You're not channel operator");
        } else {
          channel.send(user.mask, 'KICK', channel.name, targetUser.nick, kickMessage);
          channel.part(targetUser);
        }
      });
    }
  }

  TOPIC(user, channelName, topic) {
    let channel = this.server.channels.find(channelName);

    if (!channel) {
      user.send(this.server.host, irc.errors.noSuchNick, user.nick, channelName, ':No such nick/channel');
    } else {
      if (channel.modes.indexOf('t') === -1 || user.isHop(channel)) {
        channel.topic = topic;
        channel.send(user.mask, 'TOPIC', channel.name, ':' + topic);
      } else {
        user.send(this.server.host, irc.errors.channelOpsReq, user.nick, channel.name, ":You must be at least half-op to do that!");
      }
    }
  }

  PRIVMSG(user, target, message) {
    // ERR_NOTOPLEVEL
    // ERR_WILDTOPLEVEL
    // ERR_TOOMANYTARGETS
    // ERR_NOSUCHNICK
    // RPL_AWAY
    if (!target || target.length === 0) {
      user.send(this.server.host, irc.errors.noRecipient, ':No recipient given');
    } else if (!message || message.length === 0) {
      user.send(this.server.host, irc.errors.noTextToSend, ':No text to send');
    } else if (this.server.channelTarget(target)) {
      let channel = this.server.channels.find(target);

      if (!channel) {
        user.send(this.server.host, irc.errors.noSuchNick, user.nick, target, ':No such nick/channel');
      } else if (channel.isModerated && !user.isVoiced(channel)) {
        user.send(this.server.host, irc.errors.cannotSend, channel.name, ':Cannot send to channel');
      } else if (user.channels.indexOf(channel) === -1) {
        if (channel.modes.indexOf('n') !== -1) {
          user.send(this.server.host, irc.errors.cannotSend, channel.name, ':Cannot send to channel');
        }
      } else {
        this.server.channels.message(user, channel, message);
      }
    } else {
      user.message(target, message);
    }
  }

  INVITE(user, nick, channelName) {
    let channel = this.server.channels.find(channelName);
    let targetUser = this.server.users.find(nick);

    // TODO: Can this.server accept multiple channel names?
    // TODO: ERR_NOTONCHANNEL
    if (!targetUser) {
      user.send(this.server.host, irc.errors.noSuchNick, user.nick, nick, ':No such nick/channel');
      return;
    } else if (channel) {
      if (channel.isInviteOnly && !user.isOp(channel)) {
        user.send(this.server.host, irc.errors.channelOpsReq, user.nick, channel.name, ":You're not channel operator");
        return;
      } else if (channel.onInviteList(targetUser)) {
        user.send(this.server.host, irc.errors.userOnChannel, user.nick, targetUser.nick, ':User is already on that channel');
        return;
      }
    } else if (!this.server.channelTarget(channelName)) {
      // Invalid channel
      return;
    } else {
      // TODO: Make this.server a register function
      // Create the channel
      channel = this.server.channels.registered[this.server.normalizeName(channelName)] = new Channel(channelName, this.server);
    }

    user.send(this.server.host, irc.reply.inviting, user.nick, targetUser.nick, channelName);
    targetUser.send(user.mask, 'INVITE', targetUser.nick, ':' + channelName);

    // TODO: How does an invite list get cleared?
    channel.inviteList.push(targetUser.nick);
  }

  MODE(user, target, modes, arg) {
    // TODO: This should work with multiple parameters, like the definition:
    // <channel> {[+|-]|o|p|s|i|t|n|b|v} [<limit>] [<user>] [<ban mask>]
    // o - give/take channel operator privileges                   [done]
    // p - private channel flag                                    [done]
    // s - secret channel flag;                                    [done] - what's the difference?
    // i - invite-only channel flag;                               [done]
    // t - topic settable by channel operator only flag;           [done]
    // n - no messages to channel from clients on the outside;     [done]
    // m - moderated channel;                                      [done]
    // l - set the user limit to channel;                          [done]
    // b - set a ban mask to keep users out;                       [done]
    // v - give/take the ability to speak on a moderated channel;  [done]
    // k - set a channel key (password).                           [done]

    // User modes
    // a - user is flagged as away;                                [done]
    // i - marks a users as invisible;                             [done]
    // w - user receives wallops;                                  [done]
    // r - restricted user connection;
    // o - operator flag;
    // O - local operator flag;
    // s - marks a user for receipt of server notices.

    if (this.server.channelTarget(target)) {
      let channel = this.server.channels.find(target);

      if (!channel) {
        // TODO: Error
      } else if (modes) {
        if (modes[0] === '+') {
          channel.addModes(user, modes, arg);
        } else if (modes[0] === '-') {
          channel.removeModes(user, modes, arg);
        } else if (modes === 'b') {
          channel.banned.forEach(ban => {
            user.send(this.server.host, irc.reply.banList, user.nick, channel.name, ban.mask, ban.user.nick, ban.timestamp);
          });
          user.send(this.server.host, irc.reply.endBan, user.nick, channel.name, ':End of Channel Ban List');
        }
      } else {
        user.send(this.server.host, irc.reply.channelModes, user.nick, channel.name, channel.modes);
      }
    } else {
      // TODO: Server user modes
      let targetUser = this.server.users.find(target);

      if (targetUser) {
        if (modes[0] === '+') {
          targetUser.addModes(user, modes, arg);
        } else if (modes[0] === '-') {
          targetUser.removeModes(user, modes, arg);
        }
      }
    }
  }

  LIST(user, targets) {
    // TODO: ERR_TOOMANYMATCHES
    // TODO: ERR_NOSUCHSERVER
    let channels = this.server.channels.registered;

    user.send(this.server.host, irc.reply.listStart, user.nick, 'Channel', ':Users  Name');
    if (targets) {
      targets = targets.split(',');
      targets.forEach(target => {
        let channel = this.server.channels.find(target);

        if (channel) {
          channels = {};
          channels[channel.name] = channel;
        }
      });
    }

    for (let i in channels) {
      let channel = channels[i];
      // if channel is secret or private, ignore
      if (channel.isPublic || channel.isMember(user)) {
        user.send(this.server.host, irc.reply.list, user.nick, channel.name, channel.memberCount, ':[' + channel.modes + '] ' + channel.topic);
      }
    }

    user.send(this.server.host, irc.reply.listEnd, user.nick, ':End of /LIST');
  }

  NAMES(user, targets) {
    if (targets) {
      targets = targets.split(',');
      targets.forEach(target => {
        // if channel is secret or private, ignore
        let channel = this.server.channels.find(target);

        if (channel && (channel.isPublic || channel.isMember(user))) {
          user.send(this.server.host, irc.reply.nameReply, user.nick, channel.type, channel.name, ':' + channel.names);
        }
      });
    }
    user.send(this.server.host, irc.reply.endNames, user.nick, '*', ':End of /NAMES list.');
  }

  WHO(user, target) {
      if (this.server.channelTarget(target)) {
        // TODO: Channel wildcards
        let channel = this.server.channels.find(target);

        if (!channel) {
          user.send(this.server.host, irc.errors.noSuchChannel, user.nick, ':No such channel');
        } else {
          channel.users.forEach(channelUser => {
            if (channelUser.isInvisible
                && !user.isOper
                && channel.users.indexOf(user) === -1) {
            } else {
              user.send(
                this.server.host,
                irc.reply.who,
                user.nick,
                channel.name,
                channelUser.username,
                channelUser.hostname,
                this.server.config.hostname, // The IRC server rather than the network
                channelUser.channelNick(channel),
                'H', // TODO: H is here, G is gone, * is IRC operator, + is voice, @ is chanop
                ':0',
                channelUser.realname
              );
            }
          });
          user.send(this.server.host, irc.reply.endWho, user.nick, channel.name, ':End of /WHO list.');
        }
      } else {
        let matcher = this.server.normalizeName(target).replace(/\?/g, '.');
        this.server.users.registered.forEach(targetUser => {
          try {
            if (!targetUser.nick.match('^' + matcher + '$')) return;
          } catch (e) {
            return;
          }

          let sharedChannel = targetUser.sharedChannelWith(user);
          if (targetUser.isInvisible
              && !user.isOper
              && !sharedChannel) {
          } else {
            user.send(
              this.server.host,
              irc.reply.who,
              user.nick,
              sharedChannel ? sharedChannel.name : '',
              targetUser.username,
              targetUser.hostname,
              this.server.config.hostname,
              targetUser.channelNick(channel),
              'H', // TODO
              ':0',
              targetUser.realname
            );
          }
        });
        user.send(this.server.host, irc.reply.endWho, user.nick, target, ':End of /WHO list.');
      }
    }

  WHOIS(user, nickmask) {
    // TODO: nick masks
    let target = this.server.users.find(nickmask);

    if (target) {
      let channels = target.channels.map(channel => {
        if (channel.isSecret && !channel.isMember(user)) return;

        if (target.isOp(channel)) {
          return '@' + channel.name;
        } else {
          return channel.name;
        }
      });

      user.send(this.server.host, irc.reply.whoIsUser, user.nick, target.nick,
                target.username, target.hostname, '*', ':' + target.realname);
      user.send(this.server.host, irc.reply.whoIsChannels, user.nick, target.nick, ':' + channels);
      user.send(this.server.host, irc.reply.whoIsServer, user.nick, target.nick, this.server.config.hostname, ':' + this.server.config.serverDescription);
      if (target.isAway) {
        user.send(this.server.host, irc.reply.away, user.nick, target.nick, ':' + target.awayMessage);
      }
      user.send(this.server.host, irc.reply.whoIsIdle, user.nick, target.nick, target.idle, user.created, ':seconds idle, sign on time');
      user.send(this.server.host, irc.reply.endOfWhoIs, user.nick, target.nick, ':End of /WHOIS list.');
    } else if (!nickmask || nickmask.length === 0) {
      user.send(this.server.host, irc.errors.noNickGiven, user.nick, ':No nick given');
    } else {
      user.send(this.server.host, irc.errors.noSuchNick, user.nick, nickmask, ':No such nick/channel');
    }
  }

  WHOWAS(user, nicknames, count, serverName) {
    // TODO: Server
    let server = this.server;
    let found = false;

    nicknames.split(',').forEach(nick => {
      let matches = server.history.find(nick);

      if (count) {
        matches = matches.slice(0, count);
      }

      matches.forEach(item => {
        found = true;
        user.send(server.host, irc.reply.whoWasUser, user.nick, item.nick, item.username, item.host, '*', ':' + item.realname);
        user.send(server.host, irc.reply.whoIsServer, user.nick, item.nick, item.server, ':' + item.time);
      });
    });

    if (found) {
      user.send(this.server.host, irc.reply.endWhoWas, user.nick, nicknames, ':End of WHOWAS');
    } else {
      user.send(this.server.host, irc.errors.wasNoSuchNick, user.nick, nicknames, ':There was no such nickname');
    }
  }

  WALLOPS(user, text) {
    if (!text || text.length === 0) {
      user.send(this.server.host, irc.errors.needMoreParams, user.nick, ':Need more parameters');
      return;
    }

    this.server.users.registered.forEach(user => {
      if (user.modes.indexOf('w') !== -1) {
        user.send(this.server.host, 'WALLOPS', ':OPERWALL - ' + text);
      }
    });
  }

  OPER(user, name, password) {
    if (!name || !password) {
      user.send(this.server.host, irc.errors.wasNoSuchNick, user.nick, ':OPER requires a nick and password');
    } else {
      let self = this.server;
      let targetUser = self.config.opers[name];

      if (targetUser === undefined) {
        user.send(self.host, irc.errors.noSuchNick, user.nick, ':No such nick.');
      } else {
        ircd.compareHash(password, targetUser.password, (err, res) => {
          if (res) {
            user.send(self.host, irc.reply.youAreOper, user.nick, ':You are now an IRC operator');
            user.oper();
          } else {
            user.send(self.host, irc.errors.passwordWrong, user.nick || 'user', ':Password incorrect');
          }
        });
      }
    }
  }

  QUIT(user, message) {
    user.quit(message);
    this.server.history.add(user);
    //delete user;
    user = null;
  }

  MOTD(user) {
    this.server.motd(user);
  }
}

module.exports = Commands;
