/**
 * Request Viewer Component
 * Displays HTTP requests and responses with syntax highlighting
 */

document.addEventListener('alpine:init', () => {
  Alpine.data('requestViewer', (initialData = {}) => ({
    // Request data
    request: initialData.request || null,
    response: initialData.response || null,

    // UI state
    activeTab: 'response', // 'request' | 'response'
    showHeaders: true,
    showBody: true,
    expandedSections: {
      headers: true,
      body: true
    },

    // Copy state
    copied: false,
    copyTimeout: null,

    // Set request data
    setRequest(request) {
      this.request = request;
    },

    // Set response data
    setResponse(response) {
      this.response = response;
    },

    // Set both
    setData(request, response) {
      this.request = request;
      this.response = response;
    },

    // Clear data
    clear() {
      this.request = null;
      this.response = null;
    },

    // Format method with class
    formatMethod(method) {
      return FormatUtils.formatHttpMethod(method);
    },

    // Format status with class
    formatStatus(status) {
      return FormatUtils.formatHttpStatus(status);
    },

    // Pretty print JSON
    formatJson(obj) {
      return FormatUtils.prettyJson(obj);
    },

    // Copy content to clipboard
    async copy(content) {
      const text = typeof content === 'object' ? JSON.stringify(content, null, 2) : content;
      const success = await FormatUtils.copyToClipboard(text);

      if (success) {
        this.copied = true;
        if (this.copyTimeout) clearTimeout(this.copyTimeout);
        this.copyTimeout = setTimeout(() => {
          this.copied = false;
        }, 2000);
      }
    },

    // Get request as cURL command
    getCurlCommand() {
      if (!this.request) return '';

      const { method, url, headers, body } = this.request;
      let cmd = `curl -X ${method || 'GET'}`;

      if (headers) {
        Object.entries(headers).forEach(([key, value]) => {
          cmd += ` \\\n  -H '${key}: ${value}'`;
        });
      }

      if (body) {
        const bodyStr = typeof body === 'object' ? JSON.stringify(body) : body;
        cmd += ` \\\n  -d '${bodyStr}'`;
      }

      cmd += ` \\\n  '${url}'`;

      return cmd;
    },

    // Toggle section
    toggleSection(section) {
      this.expandedSections[section] = !this.expandedSections[section];
    },

    // Check if response indicates success
    get isSuccess() {
      if (!this.response) return null;
      const status = this.response.status || this.response.statusCode;
      return status >= 200 && status < 300;
    },

    // Check if response indicates error
    get isError() {
      if (!this.response) return null;
      const status = this.response.status || this.response.statusCode;
      return status >= 400;
    },

    // Get response body for display
    get responseBody() {
      if (!this.response) return null;
      return this.response.body || this.response.data || this.response;
    },

    // Get request body for display
    get requestBody() {
      if (!this.request) return null;
      return this.request.body || this.request.data;
    }
  }));
});
