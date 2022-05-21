const execSync = require('child_process').execSync;

const preVersionGeneration = semver => "0." + semver

module.exports = {
  preVersionGeneration
}
