const core = require('@actions/core');
const exec = require('@actions/exec');
const path = require('path');

// Compute action root at runtime (2 levels up from dist/post/)
// Use array join to prevent ncc from transforming the path
const getActionPath = () => [__dirname, '..', '..'].reduce((a, b) => path.resolve(a, b));

async function run() {
  const actionPath = getActionPath();
  const scriptsDir = actionPath + path.sep + 'scripts';
  const env = { ...process.env, EGRESS_FILTER_ROOT: actionPath };

  core.info('Stopping proxy...');
  await exec.exec('sudo', ['-E', scriptsDir + path.sep + 'setup-proxy.sh', 'stop'], {
    ignoreReturnCode: true,
    env
  });

  core.info('Cleaning up iptables...');
  await exec.exec('sudo', ['-E', scriptsDir + path.sep + 'iptables.sh', 'cleanup'], {
    ignoreReturnCode: true,
    env
  });

  core.info('Egress filter cleanup complete');
}

run();
