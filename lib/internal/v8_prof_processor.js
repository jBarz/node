'use strict';
var cp = require('child_process');
var fs = require('fs');
var path = require('path');

const v8_parent_path = path.basename(process.config.variables.v8_parent_path);
var scriptFiles = [
  'internal/v8_prof_polyfill',
  v8_parent_path + '/tools/splaytree',
  v8_parent_path + '/tools/codemap',
  v8_parent_path + '/tools/csvparser',
  v8_parent_path + '/tools/consarray',
  v8_parent_path + '/tools/profile',
  v8_parent_path + '/tools/profile_view',
  v8_parent_path + '/tools/logreader',
  v8_parent_path + '/tools/tickprocessor',
  v8_parent_path + '/tools/SourceMap',
  v8_parent_path + '/tools/tickprocessor-driver'
];
var tempScript = 'tick-processor-tmp-' + process.pid;
var tempNm = 'mac-nm-' + process.pid;

process.on('exit', function() {
  try { fs.unlinkSync(tempScript); } catch (e) {}
  try { fs.unlinkSync(tempNm); } catch (e) {}
});
process.on('uncaughtException', function(err) {
  try { fs.unlinkSync(tempScript); } catch (e) {}
  try { fs.unlinkSync(tempNm); } catch (e) {}
  throw err;
});

scriptFiles.forEach(function(script) {
  fs.appendFileSync(tempScript, process.binding('natives')[script]);
});
var tickArguments = [tempScript];
if (process.platform === 'darwin') {
  fs.writeFileSync(tempNm, process.binding('natives')['v8/tools/mac-nm'],
    { mode: 0o555 });
  tickArguments.push('--mac', '--nm=' + path.join(process.cwd(), tempNm));
} else if (process.platform === 'win32') {
  tickArguments.push('--windows');
}
tickArguments.push.apply(tickArguments, process.argv.slice(1));
cp.spawn(process.execPath, tickArguments, { stdio: 'inherit' });
