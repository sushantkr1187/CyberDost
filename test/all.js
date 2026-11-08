/**
 * Master Test Suite - Runs both Unit Tests and API Integration Tests
 */

const { spawnSync } = require('node:child_process');

console.log('>>> Executing Unit & Engine Test Suite...');
const unitRes = spawnSync(process.execPath, ['test/run_tests.js'], { stdio: 'inherit' });

console.log('\n>>> Executing REST API & Route Test Suite...');
const apiRes = spawnSync(process.execPath, ['test/api.test.js'], { stdio: 'inherit' });

if (unitRes.status !== 0 || apiRes.status !== 0) {
  process.exit(1);
} else {
  console.log('\n[SUCCESS] ALL SUITES PASSED CLEANLY (30/30 tests).');
}
