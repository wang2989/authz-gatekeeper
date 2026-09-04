#!/usr/bin/env node

import { runCli } from '../src/index.js';

runCli(process.argv.slice(2))
  .then((exitCode) => {
    process.exit(exitCode);
  })
  .catch((err) => {
    process.stderr.write(`\nUnexpected Fatal Error: ${err.stack || err.message}\n`);
    process.exit(2);
  });

