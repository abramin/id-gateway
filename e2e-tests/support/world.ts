import { World, IWorldOptions, setWorldConstructor } from '@cucumber/cucumber';
import { APIRequestContext, request } from '@playwright/test';

export interface ApiResponse {
  status: number;
  body: any;
  headers: Record<string, string>;
}

export class ApiWorld extends World {
  public apiContext!: APIRequestContext;
  public baseUrl: string;
  public response?: ApiResponse;
  public authCode?: string;
  public accessToken?: string;
  public idToken?: string;
  public state?: string;
  
  public oauth = {
    clientId: 'test-client',
    redirectUri: 'http://localhost:3000/callback',
  };
  
  public testUser = {
    username: 'test@example.com',
    email: 'test@example.com',
  };

  constructor(options: IWorldOptions) {
    super(options);
    this.baseUrl = process.env.BASE_URL || 'http://localhost:8080';
  }

  async init() {
    if (!this.apiContext) {
      this.apiContext = await request.newContext({
        baseURL: this.baseUrl,
        extraHTTPHeaders: {
          'Accept': 'application/json',
        },
      });
    }
  }

  async cleanup() {
    if (this.apiContext) {
      await this.apiContext.dispose();
    }
  }
}

setWorldConstructor(ApiWorld);
