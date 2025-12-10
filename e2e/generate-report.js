const reporter = require('cucumber-html-reporter');

reporter.generate({
  theme: 'bootstrap',
  jsonFile: 'e2e/reports/cucumber.json',
  output: 'e2e/reports/index.html',
  reportSuiteAsScenarios: true,
  launchReport: false,
});
