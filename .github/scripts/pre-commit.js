const execSync = require('child_process').execSync;

const preCommit = (props) => {
  console.log('Setting version to ' + props.version);
  execSync('yq -i e ".version |= \\"' + props.version + '\\"" package.yaml && stack build --dry-run');
};

module.exports = {
  preCommit
}
