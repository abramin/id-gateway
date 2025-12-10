import { Given, When, Then, DataTable } from '@cucumber/cucumber';
import { expect } from '@playwright/test';
import { ApiWorld } from '../support/world';
import { randomUUID } from 'crypto';

Given('the API base URL is configured', async function (this: ApiWorld) {
  expect(this.baseUrl).toBeTruthy();
});

Given('OAuth2 client credentials are available', function (this: ApiWorld) {
  expect(this.oauth.clientId).toBeTruthy();
  expect(this.oauth.redirectUri).toBeTruthy();
});

Given('test user credentials are available', function (this: ApiWorld) {
  expect(this.testUser.email).toBeTruthy();
});

Given('I generate a random state value', function (this: ApiWorld) {
  this.state = randomUUID();
});

When('I POST to {string} with:', async function (this: ApiWorld, path: string, dataTable: DataTable) {
  const data: Record<string, any> = {};
  const rows = dataTable.raw();
  
  for (const [key, value] of rows) {
    let finalValue: any = value;
    
    // Replace placeholders
    if (value === '<state>') {
      finalValue = this.state;
    } else if (value === '<authorization_code>') {
      finalValue = this.authCode;
    } else if (value.includes(',')) {
      // Handle comma-separated values as arrays
      finalValue = value.split(',').map(v => v.trim()).filter(v => v);
    } else if (value === '') {
      finalValue = [];
    }
    
    data[key] = finalValue;
  }

  const response = await this.apiContext.post(path, {
    data,
  });

  this.response = {
    status: response.status(),
    body: await response.json().catch(() => ({})),
    headers: response.headers(),
  };
});

When('I GET {string} with bearer token', async function (this: ApiWorld, path: string) {
  const response = await this.apiContext.get(path, {
    headers: {
      Authorization: `Bearer ${this.accessToken}`,
    },
  });

  this.response = {
    status: response.status(),
    body: await response.json().catch(() => ({})),
    headers: response.headers(),
  };
});

When('I GET {string} without authorization', async function (this: ApiWorld, path: string) {
  const response = await this.apiContext.get(path);

  this.response = {
    status: response.status(),
    body: await response.json().catch(() => ({})),
    headers: response.headers(),
  };
});

When('I GET {string} with invalid bearer token {string}', async function (this: ApiWorld, path: string, token: string) {
  const response = await this.apiContext.get(path, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  this.response = {
    status: response.status(),
    body: await response.json().catch(() => ({})),
    headers: response.headers(),
  };
});

Then('the response status should be {int}', function (this: ApiWorld, expectedStatus: number) {
  expect(this.response?.status).toBe(expectedStatus);
});

Then('the response should contain {string}', function (this: ApiWorld, field: string) {
  expect(this.response?.body).toHaveProperty(field);
  expect(this.response?.body[field]).toBeTruthy();
});

Then('the response field {string} should equal {string}', function (this: ApiWorld, field: string, expectedValue: string) {
  expect(this.response?.body[field]).toBe(expectedValue);
});

Then('the redirect URI should contain the state parameter', function (this: ApiWorld) {
  const redirectUri = this.response?.body.redirect_uri;
  expect(redirectUri).toContain(`state=${this.state}`);
});

Then('I save the authorization code', function (this: ApiWorld) {
  this.authCode = this.response?.body.code;
  expect(this.authCode).toBeTruthy();
});

Then('I save the access token and id token', function (this: ApiWorld) {
  this.accessToken = this.response?.body.access_token;
  this.idToken = this.response?.body.id_token;
  expect(this.accessToken).toBeTruthy();
  expect(this.idToken).toBeTruthy();
});

Then('the ID token should be a valid JWT', function (this: ApiWorld) {
  expect(this.idToken).toMatch(/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/);
});

Then('the ID token should contain {string}', function (this: ApiWorld, field: string) {
  // Decode JWT (simple base64 decode of payload)
  const parts = this.idToken?.split('.');
  expect(parts).toHaveLength(3);
  
  const payload = JSON.parse(Buffer.from(parts![1], 'base64').toString());
  expect(payload).toHaveProperty(field);
});
