'use strict';
require('../common');
const fixtures = require('../common/fixtures');
const assert = require('assert');
const fs = require('fs');
const fn = fixtures.path('non-existent');
const existingFile = fixtures.path('exit.js');
const existingFile2 = fixtures.path('create-file.js');
const existingDir = fixtures.path('empty');
const existingDir2 = fixtures.path('keys');

// ASYNC_CALL

fs.stat(fn, function(err) {
  assert.strictEqual(fn, err.path);
  assert.ok(err.message.includes(fn));
});

fs.lstat(fn, function(err) {
  assert.ok(err.message.includes(fn));
});

fs.readlink(fn, function(err) {
  assert.ok(err.message.includes(fn));
});

fs.link(fn, 'foo', function(err) {
  assert.ok(err.message.includes(fn));
});

fs.link(existingFile, existingFile2, function(err) {
  assert.ok(err.message.includes(existingFile));
  assert.ok(err.message.includes(existingFile2));
});

fs.symlink(existingFile, existingFile2, function(err) {
  assert.ok(err.message.includes(existingFile));
  assert.ok(err.message.includes(existingFile2));
});

fs.unlink(fn, function(err) {
  assert.ok(err.message.includes(fn));
});

fs.rename(fn, 'foo', function(err) {
  assert.ok(err.message.includes(fn));
});

fs.rename(existingDir, existingDir2, function(err) {
  assert.ok(err.message.includes(existingDir));
  assert.ok(err.message.includes(existingDir2));
});

fs.rmdir(fn, function(err) {
  assert.ok(err.message.includes(fn));
});

fs.mkdir(existingFile, 0o666, function(err) {
  assert.ok(err.message.includes(existingFile));
});

fs.rmdir(existingFile, function(err) {
  assert.ok(err.message.includes(existingFile));
});

fs.chmod(fn, 0o666, function(err) {
  assert.ok(err.message.includes(fn));
});

fs.open(fn, 'r', 0o666, function(err) {
  assert.ok(err.message.includes(fn));
});

fs.readFile(fn, function(err) {
  assert.ok(err.message.includes(fn));
});

// Sync

const errors = [];
let expected = 0;

try {
  ++expected;
  fs.statSync(fn);
} catch (err) {
  errors.push('stat');
  assert.ok(err.message.includes(fn));
}

try {
  ++expected;
  fs.mkdirSync(existingFile, 0o666);
} catch (err) {
  errors.push('mkdir');
  assert.ok(err.message.includes(existingFile));
}

try {
  ++expected;
  fs.chmodSync(fn, 0o666);
} catch (err) {
  errors.push('chmod');
  assert.ok(err.message.includes(fn));
}

try {
  ++expected;
  fs.lstatSync(fn);
} catch (err) {
  errors.push('lstat');
  assert.ok(err.message.includes(fn));
}

try {
  ++expected;
  fs.readlinkSync(fn);
} catch (err) {
  errors.push('readlink');
  assert.ok(err.message.includes(fn));
}

try {
  ++expected;
  fs.linkSync(fn, 'foo');
} catch (err) {
  errors.push('link');
  assert.ok(err.message.includes(fn));
}

try {
  ++expected;
  fs.linkSync(existingFile, existingFile2);
} catch (err) {
  errors.push('link');
  assert.ok(err.message.includes(existingFile));
  assert.ok(err.message.includes(existingFile2));
}

try {
  ++expected;
  fs.symlinkSync(existingFile, existingFile2);
} catch (err) {
  errors.push('symlink');
  assert.ok(err.message.includes(existingFile));
  assert.ok(err.message.includes(existingFile2));
}

try {
  ++expected;
  fs.unlinkSync(fn);
} catch (err) {
  errors.push('unlink');
  assert.ok(err.message.includes(fn));
}

try {
  ++expected;
  fs.rmdirSync(fn);
} catch (err) {
  errors.push('rmdir');
  assert.ok(err.message.includes(fn));
}

try {
  ++expected;
  fs.rmdirSync(existingFile);
} catch (err) {
  errors.push('rmdir');
  assert.ok(err.message.includes(existingFile));
}

try {
  ++expected;
  fs.openSync(fn, 'r');
} catch (err) {
  errors.push('opens');
  assert.ok(err.message.includes(fn));
}

try {
  ++expected;
  fs.renameSync(fn, 'foo');
} catch (err) {
  errors.push('rename');
  assert.ok(err.message.includes(fn));
}

try {
  ++expected;
  fs.renameSync(existingDir, existingDir2);
} catch (err) {
  errors.push('rename');
  assert.ok(err.message.includes(existingDir));
  assert.ok(err.message.includes(existingDir2));
}

try {
  ++expected;
  fs.readdirSync(fn);
} catch (err) {
  errors.push('readdir');
  assert.ok(err.message.includes(fn));
}

process.on('exit', function() {
  assert.strictEqual(
    expected, errors.length,
    `Test fs sync exceptions raised, got ${errors.length} expected ${expected}`
  );
});
