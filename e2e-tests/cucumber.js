module.exports = {
  default: {
    require: ['steps/**/*.ts', 'support/**/*.ts'],
    requireModule: ['ts-node/register'],
    format: ['progress', 'html:reports/cucumber-report.html', 'json:reports/cucumber-report.json'],
    formatOptions: { snippetInterface: 'async-await' },
    publishQuiet: true,
  }
};
