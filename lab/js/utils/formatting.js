/**
 * Formatting Utilities
 * JSON pretty printing, time formatting, and other display helpers
 */

const FormatUtils = {
  /**
   * Pretty print JSON with syntax highlighting classes
   * @param {any} obj - Object to format
   * @param {number} indent - Indentation level (default 2)
   * @returns {string} Formatted JSON string
   */
  prettyJson(obj, indent = 2) {
    if (obj === null) return 'null';
    if (obj === undefined) return 'undefined';

    try {
      return JSON.stringify(obj, null, indent);
    } catch (e) {
      return String(obj);
    }
  },

  /**
   * Format JSON with HTML syntax highlighting
   * @param {any} obj - Object to format
   * @returns {string} HTML string with syntax highlighting
   */
  highlightJson(obj) {
    const json = this.prettyJson(obj);

    // Simple syntax highlighting
    return json
      .replace(/"([^"]+)":/g, '<span class="json-key">"$1"</span>:')
      .replace(/: "([^"]*)"([,\n])/g, ': <span class="json-string">"$1"</span>$2')
      .replace(/: (\d+)([,\n])/g, ': <span class="json-number">$1</span>$2')
      .replace(/: (true|false)([,\n])/g, ': <span class="json-boolean">$1</span>$2')
      .replace(/: (null)([,\n])/g, ': <span class="json-null">$1</span>$2');
  },

  /**
   * Format bytes as human-readable size
   * @param {number} bytes - Number of bytes
   * @returns {string} Formatted size string
   */
  formatBytes(bytes) {
    if (bytes === 0) return '0 B';

    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const k = 1024;
    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + units[i];
  },

  /**
   * Format duration in milliseconds as human-readable string
   * @param {number} ms - Duration in milliseconds
   * @returns {string} Formatted duration string
   */
  formatDuration(ms) {
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    if (ms < 3600000) return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`;

    const hours = Math.floor(ms / 3600000);
    const minutes = Math.floor((ms % 3600000) / 60000);
    return `${hours}h ${minutes}m`;
  },

  /**
   * Format a Date object as relative time (e.g., "2 minutes ago")
   * @param {Date|number} date - Date object or timestamp
   * @returns {string} Relative time string
   */
  formatRelativeTime(date) {
    const now = Date.now();
    const timestamp = date instanceof Date ? date.getTime() : date;
    const diff = now - timestamp;

    if (diff < 0) {
      // Future time
      const absDiff = Math.abs(diff);
      if (absDiff < 60000) return 'in a few seconds';
      if (absDiff < 3600000) return `in ${Math.floor(absDiff / 60000)} minutes`;
      if (absDiff < 86400000) return `in ${Math.floor(absDiff / 3600000)} hours`;
      return `in ${Math.floor(absDiff / 86400000)} days`;
    }

    if (diff < 5000) return 'just now';
    if (diff < 60000) return `${Math.floor(diff / 1000)} seconds ago`;
    if (diff < 3600000) return `${Math.floor(diff / 60000)} minutes ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)} hours ago`;
    return `${Math.floor(diff / 86400000)} days ago`;
  },

  /**
   * Format a Date object as ISO-like string for display
   * @param {Date|number} date - Date object or timestamp
   * @returns {string} Formatted date string
   */
  formatDateTime(date) {
    const d = date instanceof Date ? date : new Date(date);
    return d.toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  },

  /**
   * Format a Date object as time only
   * @param {Date|number} date - Date object or timestamp
   * @returns {string} Formatted time string
   */
  formatTime(date) {
    const d = date instanceof Date ? date : new Date(date);
    return d.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  },

  /**
   * Truncate a string to a maximum length with ellipsis
   * @param {string} str - String to truncate
   * @param {number} maxLength - Maximum length
   * @returns {string} Truncated string
   */
  truncate(str, maxLength = 50) {
    if (!str || str.length <= maxLength) return str;
    return str.substring(0, maxLength - 3) + '...';
  },

  /**
   * Format HTTP method with appropriate styling class
   * @param {string} method - HTTP method
   * @returns {object} Object with method and class
   */
  formatHttpMethod(method) {
    const upper = (method || 'GET').toUpperCase();
    const classes = {
      GET: 'http-get',
      POST: 'http-post',
      PUT: 'http-put',
      PATCH: 'http-patch',
      DELETE: 'http-delete'
    };
    return {
      method: upper,
      class: classes[upper] || 'http-other'
    };
  },

  /**
   * Format HTTP status code with appropriate styling class
   * @param {number} status - HTTP status code
   * @returns {object} Object with status, text, and class
   */
  formatHttpStatus(status) {
    const texts = {
      200: 'OK',
      201: 'Created',
      204: 'No Content',
      301: 'Moved Permanently',
      302: 'Found',
      304: 'Not Modified',
      400: 'Bad Request',
      401: 'Unauthorized',
      403: 'Forbidden',
      404: 'Not Found',
      405: 'Method Not Allowed',
      409: 'Conflict',
      422: 'Unprocessable Entity',
      429: 'Too Many Requests',
      500: 'Internal Server Error',
      502: 'Bad Gateway',
      503: 'Service Unavailable'
    };

    let statusClass = 'status-info';
    if (status >= 200 && status < 300) statusClass = 'status-success';
    else if (status >= 300 && status < 400) statusClass = 'status-redirect';
    else if (status >= 400 && status < 500) statusClass = 'status-client-error';
    else if (status >= 500) statusClass = 'status-server-error';

    return {
      status,
      text: texts[status] || 'Unknown',
      class: statusClass
    };
  },

  /**
   * Format a URL for display (truncate long paths)
   * @param {string} url - URL string
   * @param {number} maxLength - Maximum length
   * @returns {string} Formatted URL
   */
  formatUrl(url, maxLength = 60) {
    if (!url || url.length <= maxLength) return url;

    try {
      const parsed = new URL(url);
      const host = parsed.host;
      const path = parsed.pathname + parsed.search;

      if (host.length + path.length <= maxLength) {
        return url;
      }

      // Truncate path
      const availableForPath = maxLength - host.length - 10;
      if (availableForPath > 0) {
        return `${parsed.protocol}//${host}${this.truncate(path, availableForPath)}`;
      }

      return this.truncate(url, maxLength);
    } catch (e) {
      return this.truncate(url, maxLength);
    }
  },

  /**
   * Generate a random string for state/nonce parameters
   * @param {number} length - Length of string
   * @returns {string} Random string
   */
  generateRandomString(length = 32) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    for (let i = 0; i < length; i++) {
      result += chars[array[i] % chars.length];
    }
    return result;
  },

  /**
   * Generate PKCE code verifier
   * @returns {string} Code verifier (43-128 characters)
   */
  generateCodeVerifier() {
    return this.generateRandomString(64);
  },

  /**
   * Generate PKCE code challenge from verifier (S256 method)
   * @param {string} verifier - Code verifier
   * @returns {Promise<string>} Code challenge
   */
  async generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const hash = await crypto.subtle.digest('SHA-256', data);

    // Base64 URL encode
    const base64 = btoa(String.fromCharCode(...new Uint8Array(hash)));
    return base64
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  },

  /**
   * Copy text to clipboard
   * @param {string} text - Text to copy
   * @returns {Promise<boolean>} Success status
   */
  async copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (e) {
      console.error('Failed to copy to clipboard:', e);
      return false;
    }
  },

  /**
   * Parse query string to object
   * @param {string} queryString - Query string (with or without ?)
   * @returns {object} Parsed parameters
   */
  parseQueryString(queryString) {
    const params = {};
    const search = queryString.startsWith('?') ? queryString.slice(1) : queryString;

    if (!search) return params;

    search.split('&').forEach(pair => {
      const [key, value] = pair.split('=').map(decodeURIComponent);
      if (key) {
        params[key] = value || '';
      }
    });

    return params;
  },

  /**
   * Build query string from object
   * @param {object} params - Parameters object
   * @returns {string} Query string (without ?)
   */
  buildQueryString(params) {
    return Object.entries(params)
      .filter(([_, value]) => value !== undefined && value !== null && value !== '')
      .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
      .join('&');
  }
};

// Export for use in modules
if (typeof window !== 'undefined') {
  window.FormatUtils = FormatUtils;
}
