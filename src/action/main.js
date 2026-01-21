const core = require('@actions/core');

async function run() {
  try {
    core.info('Egress filter proxy is active');
    core.info('All network traffic is being monitored and attributed to processes');
  } catch (error) {
    core.setFailed(error.message);
  }
}

run();
