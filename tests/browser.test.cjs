const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const source = fs.readFileSync(require('node:path').join(__dirname, '../browser/cleanup.js'), 'utf8');

function fixture() {
  const removed = [], cleared = [];
  const registrations = ['legitimate', 'suspect'].map(name => ({
    scope: `https://example.test/${name}/`,
    active: {scriptURL: `https://example.test/${name}.js`},
    unregister: async () => { removed.push(name); return true; }
  }));
  const context = vm.createContext({
    URL, console: {info() {}}, isSecureContext: true,
    location: {origin: 'https://example.test'},
    navigator: {serviceWorker: {getRegistrations: async () => registrations}},
    caches: {keys: async () => ['app-cache', 'suspect-cache'],
      delete: async name => {cleared.push(name); return true;}}
  });
  vm.runInContext(source, context);
  return {api: context.scHealerBrowser, removed, cleared, registrations};
}

test('inspection has no side effects', async () => {
  const f = fixture();
  const report = await f.api.inspect();
  assert.equal(report.workers.length, 2);
  assert.deepEqual(f.removed, []);
  assert.deepEqual(f.cleared, []);
});

test('only exact selected registration and caches are removed', async () => {
  const f = fixture();
  const report = await f.api.inspect();
  await f.api.removeWorkers([report.workers[1]]);
  await f.api.removeCaches(['suspect-cache']);
  assert.deepEqual(f.removed, ['suspect']);
  assert.deepEqual(f.cleared, ['suspect-cache']);
});

test('changed worker causes refusal before any removal', async () => {
  const f = fixture();
  const report = await f.api.inspect();
  f.registrations[1].active.scriptURL = 'https://example.test/replaced.js';
  await assert.rejects(f.api.removeWorkers(report.workers), /changed/);
  assert.deepEqual(f.removed, []);
});

test('cross-origin and empty selections are rejected', async () => {
  const f = fixture();
  await assert.rejects(f.api.removeWorkers([]), /Select/);
  await assert.rejects(f.api.removeWorkers([{scope:'https://other.test/', scriptURLs:['https://other.test/a.js']}]), /origin/);
  await assert.rejects(f.api.removeCaches(['not-present']), /changed/);
  assert.deepEqual(f.removed, []);
  assert.deepEqual(f.cleared, []);
});

test('a worker that changes while earlier removals await is not removed', async () => {
  const f = fixture();
  const report = await f.api.inspect();
  f.registrations[0].unregister = async () => {
    f.registrations[1].active.scriptURL = 'https://example.test/new-version.js';
    return true;
  };
  await assert.rejects(f.api.removeWorkers(report.workers), /changed during removal/);
  assert.deepEqual(f.removed, []);
});
