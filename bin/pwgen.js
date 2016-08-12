#!/usr/bin/env node

const ircd = require(__dirname + '/../lib/ircd');

ircd.hash(process.argv[2], (err, hash) => {
  if (err) {
    throw(err);
  }

  console.log(hash);
});
