const core = require('@actions/core');
const exec = require('@actions/exec');
const path = require('path');

async function run() {
  const actionPath = path.resolve(__dirname, '..', '..');

  core.info('Stopping proxy...');
  await exec.exec('sudo', [path.join(actionPath, 'scripts', 'setup-proxy.sh'), 'stop'], {
    ignoreReturnCode: true
  });

  core.info('Cleaning up iptables...');
  await exec.exec('sudo', [path.join(actionPath, 'scripts', 'iptables.sh'), 'cleanup'], {
    ignoreReturnCode: true
  });

  core.info('Egress filter cleanup complete');
}

run();
