const core = require('@actions/core');
const exec = require('@actions/exec');
const path = require('path');

// Compute action root at runtime (2 levels up from dist/pre/)
// Use array join to prevent ncc from transforming the path
const getActionPath = () => [__dirname, '..', '..'].reduce((a, b) => path.resolve(a, b));

async function run() {
  try {
    const actionPath = getActionPath();
    const setupScript = [actionPath, 'scripts', 'setup-proxy.sh'].join(path.sep);

    // Pass action path so script doesn't need to calculate it
    const env = { ...process.env, EGRESS_FILTER_ROOT: actionPath };

    core.info('Installing dependencies...');
    await exec.exec('sudo', ['-E', setupScript, 'install-deps'], { env });

    core.info('Starting proxy...');
    await exec.exec('sudo', ['-E', setupScript, 'start'], { env });

    core.info('Egress filter proxy is running');
  } catch (error) {
    core.setFailed(error.message);
  }
}

run();
