const http = require("http");
const fs = require("fs");
const path = require("path");

const port = process.env.PORT || 4170;
const credoBase = process.env.CREDO_BASE_URL || "http://credo:8080";
const resourceBase = process.env.RESOURCE_SERVER_URL || "http://resource-server:9000";

const mimeTypes = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
};

const scenarios = {
  no_pkce_code_interception: {
    id: "no_pkce_code_interception",
    title: "Code Interception (PKCE disabled)",
    description:
      "Captures an authorization code from a public client that does not require PKCE and replays it to get tokens.",
  },
  wildcard_redirects: {
    id: "wildcard_redirects",
    title: "Redirect URI Manipulation",
    description:
      "Shows how wildcard redirect rules let an attacker bounce the flow to a malicious domain.",
  },
  missing_audience: {
    id: "missing_audience",
    title: "Token Reuse Across Audiences",
    description:
      "Replays a bearer token against the toy resource server which forgets to check the audience.",
  },
  overbroad_scopes: {
    id: "overbroad_scopes",
    title: "Scope Escalation",
    description: "Requests dangerous scopes that the naive resource server accepts at face value.",
  },
};

function sendJSON(res, statusCode, payload) {
  res.writeHead(statusCode, { "Content-Type": "application/json" });
  res.end(JSON.stringify(payload, null, 2));
}

const STATIC_ROOT = __dirname;

function serveStatic(req, res) {
  const requestPath = req.url === "/" ? "/index.html" : req.url;
  // Build the absolute normalized path (no .. segments, etc.)
  let unsafePath = path.join(STATIC_ROOT, requestPath);
  let filePath;
  try {
    filePath = fs.realpathSync(unsafePath);
  } catch (err) {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Not Found");
    return;
  }
  // Ensure filePath is within STATIC_ROOT
  if (!filePath.startsWith(STATIC_ROOT)) {
    res.writeHead(403, { "Content-Type": "text/plain" });
    res.end("Forbidden");
    return;
  }
  const ext = path.extname(filePath);
  const contentType = mimeTypes[ext] || "text/plain";

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(err.code === "ENOENT" ? 404 : 500, { "Content-Type": "text/plain" });
      res.end("Not Found");
      return;
    }
    res.writeHead(200, { "Content-Type": contentType });
    res.end(data);
  });
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString();
    });
    req.on("end", () => {
      if (!body) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(body));
      } catch (err) {
        reject(err);
      }
    });
  });
}

async function runMissingAudienceScenario() {
  const steps = [];
  const victimEmail = "victim@example.com";
  const redirectURI = "https://toy-client.example.com/callback";

  const authorizeBody = {
    email: victimEmail,
    client_id: "toy-client",
    scopes: ["openid", "profile", "admin:all"],
    redirect_uri: redirectURI,
    state: "lab-state",
  };

  const authorizeResp = await fetch(`${credoBase}/auth/authorize`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(authorizeBody),
  });
  const authorizeJSON = await authorizeResp.json();
  steps.push({
    title: "Authorization request",
    request: authorizeBody,
    response: authorizeJSON,
    status: authorizeResp.status,
    note: "Victim authenticates in a deployment where PKCE and audience enforcement are turned off.",
  });

  const tokenBody = {
    grant_type: "authorization_code",
    code: authorizeJSON.code,
    redirect_uri: redirectURI,
    client_id: "toy-client",
  };
  const tokenResp = await fetch(`${credoBase}/auth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(tokenBody),
  });
  let tokenJSON;
  if (tokenResp.ok) {
    tokenJSON = await tokenResp.json();
  } else {
    // Try to parse error response, or fallback to status text
    try {
      tokenJSON = await tokenResp.json();
    } catch (e) {
      tokenJSON = { error: tokenResp.statusText || "Unknown error", status: tokenResp.status };
    }
  }
  steps.push({
    title: "Token exchange",
    request: tokenBody,
    response: tokenJSON,
    status: tokenResp.status,
    note: "The intercepted code is exchanged without PKCE, yielding a bearer token.",
  });

  const rsResp = await fetch(`${resourceBase}/api/data`, {
    headers: { Authorization: `Bearer ${tokenJSON.access_token || ""}` },
  });
  let rsJSON;
  if (rsResp.ok) {
    rsJSON = await rsResp.json();
  } else {
    rsJSON = { error: `HTTP error ${rsResp.status}`, body: await rsResp.text() };
  }
  steps.push({
    title: "Replay token against naive resource server",
    request: { resource: `${resourceBase}/api/data` },
    response: rsJSON,
    status: rsResp.status,
    note: "Resource server accepts the token because it never inspects the audience claim.",
  });

  return { steps, scenario: scenarios.missing_audience };
}

async function runScenario(id) {
  switch (id) {
    case scenarios.missing_audience.id:
      return runMissingAudienceScenario();
    case scenarios.no_pkce_code_interception.id:
      return {
        scenario: scenarios.no_pkce_code_interception,
        steps: [
          {
            title: "Placeholder",
            status: 501,
            note: "Implement a PKCE-free interception flow using the mounted no_pkce_public_client profile.",
          },
        ],
      };
    case scenarios.wildcard_redirects.id:
      return {
        scenario: scenarios.wildcard_redirects,
        steps: [
          {
            title: "Placeholder",
            status: 501,
            note: "Demonstrates swapping redirect URIs when wildcards are permitted.",
          },
        ],
      };
    case scenarios.overbroad_scopes.id:
      return {
        scenario: scenarios.overbroad_scopes,
        steps: [
          {
            title: "Placeholder",
            status: 501,
            note: "Requests admin scopes and relies on the toy resource server to accept them without verification.",
          },
        ],
      };
    default:
      return { scenario: { id }, steps: [] };
  }
}

async function handleScenario(req, res) {
  try {
    const body = await parseBody(req);
    const scenarioId = body.scenarioId;
    if (!scenarioId || !scenarios[scenarioId]) {
      sendJSON(res, 400, { error: "Unknown scenario" });
      return;
    }
    const result = await runScenario(scenarioId);
    sendJSON(res, 200, result);
  } catch (err) {
    console.error("scenario handler failed", err);
    sendJSON(res, 500, { error: "Failed to run scenario", detail: err.message });
  }
}

const server = http.createServer((req, res) => {
  if (req.url === "/api/scenarios" && req.method === "POST") {
    handleScenario(req, res);
    return;
  }
  if (req.url === "/api/scenarios" && req.method === "GET") {
    sendJSON(res, 200, { scenarios: Object.values(scenarios) });
    return;
  }

  serveStatic(req, res);
});

server.listen(port, () => {
  console.log(`Attacker UI listening on ${port}`);
  console.log(`Using Credo at ${credoBase} and resource server at ${resourceBase}`);
});
