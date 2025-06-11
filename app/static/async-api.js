class AsyncAPI {
    constructor() {
        this.baseURL = '';
        this.loadingStates = new Map();
    }

    // Show loading state for an element
    showLoading(elementId, originalContent = null) {
        const element = document.getElementById(elementId);
        if (element) {
            if (originalContent) {
                this.loadingStates.set(elementId, originalContent);
            } else {
                this.loadingStates.set(elementId, element.innerHTML);
            }
            element.innerHTML = '<i class="bi bi-hourglass-split"></i> Loading...';
            element.disabled = true;
        }
    }

    // Hide loading state for an element
    hideLoading(elementId) {
        const element = document.getElementById(elementId);
        if (element && this.loadingStates.has(elementId)) {
            element.innerHTML = this.loadingStates.get(elementId);
            element.disabled = false;
            this.loadingStates.delete(elementId);
        }
    }

    // Show success message
    showSuccess(message, duration = 3000) {
        this.showNotification(message, 'success', duration);
    }

    // Show error message
    showError(message, duration = 5000) {
        this.showNotification(message, 'danger', duration);
    }

    // Show notification
    showNotification(message, type = 'info', duration = 3000) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        alertDiv.style.cssText = `
            top: 20px; 
            right: 20px; 
            z-index: 9999; 
            min-width: 300px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        `;
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        document.body.appendChild(alertDiv);

        // Auto-remove after duration
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, duration);
    }

    // Get CSRF token from meta tag or form
    getCSRFToken() {
        const metaTag = document.querySelector('meta[name="csrf-token"]');
        if (metaTag) {
            return metaTag.getAttribute('content');
        }

        const hiddenInput = document.querySelector('input[name="csrf_token"]');
        if (hiddenInput) {
            return hiddenInput.value;
        }

        return null;
    }

    // Make async HTTP request
    async makeRequest(url, options = {}) {
        const defaultOptions = {
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        };

        // Only set Content-Type for JSON requests, not FormData
        if (!(options.body instanceof FormData)) {
            defaultOptions.headers['Content-Type'] = 'application/json';
        }

        // Add CSRF token for non-GET requests
        if (options.method && options.method !== 'GET') {
            const csrfToken = this.getCSRFToken();
            if (csrfToken) {
                defaultOptions.headers['X-CSRFToken'] = csrfToken;
            }
        }

        const finalOptions = {
            ...defaultOptions,
            ...options,
            headers: {
                ...defaultOptions.headers,
                ...options.headers
            }
        };

        try {
            const response = await fetch(url, finalOptions);

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.detail || `HTTP ${response.status}: ${response.statusText}`);
            }

            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                return await response.json();
            }

            return await response.text();
        } catch (error) {
            console.error('Request failed:', error);
            throw error;
        }
    }

    // Create collection asynchronously
    async createCollection(formData) {
        try {
            const data = new FormData();
            data.append('name', formData.name);
            data.append('instance_id', formData.instance_id);
            data.append('metadata', formData.metadata || '{}');
            data.append('csrf_token', formData.csrf_token || this.getCSRFToken());

            // Debug: Log what's being sent
            console.log('Creating FormData with:');
            console.log('- name:', formData.name);
            console.log('- instance_id:', formData.instance_id);
            console.log('- metadata:', formData.metadata || '{}');
            console.log('- csrf_token:', formData.csrf_token || this.getCSRFToken());

            // Log FormData contents
            for (let [key, value] of data.entries()) {
                console.log(`FormData ${key}:`, value);
            }

            const result = await this.makeRequest('/api/collections/create', {
                method: 'POST',
                body: data,
                headers: {} // Let browser set Content-Type for FormData
            });

            this.showSuccess('Collection created successfully!');
            return result;
        } catch (error) {
            this.showError(`Failed to create collection: ${error.message}`);
            throw error;
        }
    }

    // Delete collection asynchronously
    async deleteCollection(collectionName, instanceId) {
        try {
            const data = new FormData();
            data.append('instance_id', instanceId);
            data.append('csrf_token', this.getCSRFToken());

            await this.makeRequest(`/api/collections/${collectionName}/delete`, {
                method: 'POST',
                body: data,
                headers: {}
            });

            this.showSuccess('Collection deleted successfully!');
            return true;
        } catch (error) {
            this.showError(`Failed to delete collection: ${error.message}`);
            throw error;
        }
    }

    // Execute query asynchronously
    async executeQuery(queryData) {
        try {
            const data = new FormData();
            data.append('collection_name', queryData.collection_name);
            data.append('instance_id', queryData.instance_id);
            data.append('query_text', queryData.query_text);
            data.append('n_results', queryData.n_results || 10);
            data.append('csrf_token', this.getCSRFToken());

            const result = await this.makeRequest('/api/query/execute', {
                method: 'POST',
                body: data,
                headers: {}
            });

            return result;
        } catch (error) {
            this.showError(`Query failed: ${error.message}`);
            throw error;
        }
    }

    // Add documents asynchronously
    async addDocuments(collectionName, documentsData) {
        try {
            const data = new FormData();
            data.append('instance_id', documentsData.instance_id);
            data.append('documents', documentsData.documents);
            data.append('ids', documentsData.ids || '');
            data.append('metadatas', documentsData.metadatas || '');
            data.append('processing_mode', documentsData.processing_mode || 'lines');
            data.append('splitter_type', documentsData.splitter_type || 'recursive');
            data.append('chunk_size', documentsData.chunk_size || 1000);
            data.append('chunk_overlap', documentsData.chunk_overlap || 200);
            data.append('csrf_token', this.getCSRFToken());

            const result = await this.makeRequest(`/add-documents/${collectionName}`, {
                method: 'POST',
                body: data,
                headers: {}
            });

            this.showSuccess('Documents added successfully!');
            return result;
        } catch (error) {
            this.showError(`Failed to add documents: ${error.message}`);
            throw error;
        }
    }

    // Create instance asynchronously
    async createInstance(instanceData) {
        try {
            const data = new FormData();
            data.append('name', instanceData.name);
            data.append('url', instanceData.url);
            data.append('description', instanceData.description || '');
            data.append('token', instanceData.token || '');
            if (instanceData.is_default) {
                data.append('is_default', 'true');
            }
            data.append('csrf_token', this.getCSRFToken());

            const result = await this.makeRequest('/instances/create', {
                method: 'POST',
                body: data,
                headers: {}
            });

            this.showSuccess('Instance created successfully!');
            return result;
        } catch (error) {
            this.showError(`Failed to create instance: ${error.message}`);
            throw error;
        }
    }

    // Test instance connection asynchronously
    async testInstanceConnection(instanceId) {
        try {
            const result = await this.makeRequest(`/api/instances/${instanceId}/test`, {
                method: 'POST'
            });

            if (result.success) {
                this.showSuccess('Connection test successful!');
            } else {
                this.showError(`Connection test failed: ${result.error || 'Unknown error'}`);
            }

            return result;
        } catch (error) {
            this.showError(`Connection test failed: ${error.message}`);
            throw error;
        }
    }

    // Update instance asynchronously
    async updateInstance(instanceData) {
        try {
            const data = new FormData();
            data.append('instance_id', instanceData.instance_id);
            data.append('name', instanceData.name);
            data.append('url', instanceData.url);
            data.append('description', instanceData.description || '');
            data.append('token', instanceData.token || '');
            if (instanceData.is_default) {
                data.append('is_default', 'true');
            }
            if (instanceData.is_active) {
                data.append('is_active', 'true');
            }
            data.append('csrf_token', this.getCSRFToken());

            const result = await this.makeRequest('/instances/update', {
                method: 'POST',
                body: data,
                headers: {}
            });

            this.showSuccess('Instance updated successfully!');
            return result;
        } catch (error) {
            this.showError(`Failed to update instance: ${error.message}`);
            throw error;
        }
    }

    // Delete instance asynchronously
    async deleteInstance(instanceId) {
        try {
            const data = new FormData();
            data.append('instance_id', instanceId);
            data.append('csrf_token', this.getCSRFToken());

            const result = await this.makeRequest('/instances/delete', {
                method: 'POST',
                body: data,
                headers: {}
            });

            this.showSuccess('Instance deleted successfully!');
            return result;
        } catch (error) {
            this.showError(`Failed to delete instance: ${error.message}`);
            throw error;
        }
    }

    // Load content asynchronously
    async loadContent(url, targetElementId) {
        try {
            this.showLoading(targetElementId);
            const content = await this.makeRequest(url);

            const targetElement = document.getElementById(targetElementId);
            if (targetElement) {
                targetElement.innerHTML = content;
            }

            return content;
        } catch (error) {
            this.showError(`Failed to load content: ${error.message}`);
            throw error;
        } finally {
            this.hideLoading(targetElementId);
        }
    }

    // Handle form submission asynchronously
    async handleFormSubmit(form, successCallback = null, errorCallback = null) {
        const formData = new FormData(form);
        const action = form.action || form.getAttribute('action');
        const method = form.method || 'POST';

        try {
            const result = await this.makeRequest(action, {
                method: method.toUpperCase(),
                body: formData,
                headers: {}
            });

            if (successCallback) {
                successCallback(result);
            } else {
                this.showSuccess('Operation completed successfully!');
            }

            return result;
        } catch (error) {
            if (errorCallback) {
                errorCallback(error);
            } else {
                this.showError(`Operation failed: ${error.message}`);
            }
            throw error;
        }
    }

    // Refresh page content without full reload
    async refreshContent(targetSelector = 'main') {
        try {
            const currentUrl = window.location.pathname + window.location.search;
            const content = await this.makeRequest(currentUrl);

            // Parse the response and update only the main content
            const parser = new DOMParser();
            const doc = parser.parseFromString(content, 'text/html');
            const newContent = doc.querySelector(targetSelector);
            const currentContent = document.querySelector(targetSelector);

            if (newContent && currentContent) {
                currentContent.innerHTML = newContent.innerHTML;
                // Re-initialize any JavaScript components if needed
                this.initializeComponents();
            }
        } catch (error) {
            console.error('Failed to refresh content:', error);
            // Fallback to full page reload if async refresh fails
            window.location.reload();
        }
    }

    // Initialize components after content update
    initializeComponents() {
        // Re-initialize any Bootstrap components or other JS libraries
        if (typeof bootstrap !== 'undefined') {
            // Re-initialize tooltips, modals, etc.
            const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
            tooltipTriggerList.map(function (tooltipTriggerEl) {
                return new bootstrap.Tooltip(tooltipTriggerEl);
            });
        }
    }
}

// Create global instance
window.asyncAPI = new AsyncAPI();

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function () {
    window.asyncAPI.initializeComponents();
}); 