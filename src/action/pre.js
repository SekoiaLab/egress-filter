const core = require('@actions/core');
const exec = require('@actions/exec');
const path = require('path');

async function run() {
  try {
    const actionPath = path.resolve(__dirname, '..', '..');
    const setupScript = path.join(actionPath, 'scripts', 'setup-proxy.sh');

    core.info('Installing dependencies...');
    await exec.exec('sudo', [setupScript, 'install-deps']);

    core.info('Starting proxy...');
    await exec.exec('sudo', [setupScript, 'start']);

    core.info('Egress filter proxy is running');
  } catch (error) {
    core.setFailed(error.message);
  }
}

run();
