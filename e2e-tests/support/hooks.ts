import { Before, After, BeforeAll, AfterAll } from '@cucumber/cucumber';
import { ApiWorld } from './world';

BeforeAll(async function () {
  console.log('Starting E2E test suite...');
});

Before(async function (this: ApiWorld) {
  await this.init();
});

After(async function (this: ApiWorld) {
  await this.cleanup();
});

AfterAll(async function () {
  console.log('E2E test suite completed.');
});
