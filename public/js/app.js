/**
 * Privacy-First Data Vault - Main JavaScript
 * Client-side utilities and API interactions
 */

class VaultAPI {
  constructor() {
    this.baseURL = '/api';
    this.token = localStorage.getItem('accessToken');
    this.setupAxiosInterceptors();
  }

  // Setup axios interceptors for token refresh
  setupAxiosInterceptors() {
    axios.defaults.baseURL = this.baseURL;
    
    // Request interceptor
    axios.interceptors.request.use((config) => {
      const token = localStorage.getItem('accessToken');
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });

    // Response interceptor for token refresh
    axios.interceptors.response.use(
      (response) => response,
      async (error) => {
        const originalRequest = error.config;
        
        if (error.response?.status === 401 && !originalRequest._retry) {
          originalRequest._retry = true;
          
          try {
            await this.refreshToken();
            const newToken = localStorage.getItem('accessToken');
            originalRequest.headers.Authorization = `Bearer ${newToken}`;
            return axios(originalRequest);
          } catch (refreshError) {
            this.handleAuthError();
            return Promise.reject(refreshError);
          }
        }
        
        return Promise.reject(error);
      }
    );
  }

  // Refresh access token
  async refreshToken() {
    const refreshToken = localStorage.getItem('refreshToken');
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    try {
      const response = await axios.post('/auth/refresh', {
        refreshToken
      });
      
      const { accessToken, refreshToken: newRefreshToken } = response.data.data;
      localStorage.setItem('accessToken', accessToken);
      
      if (newRefreshToken) {
        localStorage.setItem('refreshToken', newRefreshToken);
      }
      
      return accessToken;
    } catch (error) {
      localStorage.removeItem('accessToken');
      localStorage.removeItem('refreshToken');
      throw error;
    }
  }

  // Handle authentication errors
  handleAuthError() {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    window.location.href = '/login';
  }

  // Authentication methods
  async login(email, password) {
    const response = await axios.post('/auth/login', { email, password });
    return response.data;
  }

  async signup(userData) {
    const response = await axios.post('/auth/signup', userData);
    return response.data;
  }

  async verifyOTP(email, otp) {
    const response = await axios.post('/auth/verify-otp', { email, otp });
    return response.data;
  }

  async logout() {
    try {
      await axios.post('/auth/logout');
    } catch (error) {
      console.warn('Logout request failed:', error);
    }
    
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    window.location.href = '/login';
  }

  // User profile methods
  async getProfile() {
    const response = await axios.get('/auth/me');
    return response.data;
  }

  async updateProfile(profileData) {
    const response = await axios.put('/auth/profile', { profile: profileData });
    return response.data;
  }

  async changePassword(currentPassword, newPassword) {
    const response = await axios.post('/auth/change-password', {
      currentPassword,
      newPassword,
      confirmNewPassword: newPassword
    });
    return response.data;
  }

  // Vault methods
  async getVaultStats() {
    const response = await axios.get('/vault/stats');
    return response.data;
  }

  async viewVault(password) {
    const response = await axios.get('/vault/view', {
      params: { password }
    });
    return response.data;
  }

  async addAttributes(password, attributes) {
    const response = await axios.post('/vault/add', {
      password,
      attributes
    });
    return response.data;
  }

  async createDisclosure(password, selectedFields, purpose, requestedBy, expiresIn) {
    const response = await axios.post('/vault/share', {
      password,
      selectedFields,
      purpose,
      requestedBy,
      expiresIn
    });
    return response.data;
  }

  async verifyDisclosure(disclosureData) {
    const response = await axios.post('/vault/verify', {
      disclosureData
    });
    return response.data;
  }

  async getDisclosureHistory(page = 1, limit = 10, status = null) {
    const params = { page, limit };
    if (status) params.status = status;
    
    const response = await axios.get('/vault/disclosures', { params });
    return response.data;
  }

  async revokeDisclosure(disclosureId, reason = null) {
    const response = await axios.post(`/vault/revoke/${disclosureId}`, {
      reason
    });
    return response.data;
  }

  // Admin methods (if user is admin)
  async getAdminStats() {
    const response = await axios.get('/admin/stats');
    return response.data;
  }

  async getUsers(filters = {}) {
    const response = await axios.get('/admin/users', { params: filters });
    return response.data;
  }

  async getVaults(page = 1, limit = 20) {
    const response = await axios.get('/admin/vaults', {
      params: { page, limit }
    });
    return response.data;
  }
}

// Utility Functions
class VaultUtils {
  // Show alert messages
  static showAlert(message, type = 'info', duration = 5000) {
    const alertContainer = document.getElementById('alertContainer');
    if (!alertContainer) return;

    const alertId = `alert-${Date.now()}`;
    const alertHTML = `
      <div id="${alertId}" class="alert alert-${type} alert-dismissible fade show" role="alert">
        <i class="bi bi-${this.getAlertIcon(type)}"></i>
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
      </div>
    `;

    alertContainer.insertAdjacentHTML('beforeend', alertHTML);

    // Auto-remove after duration
    setTimeout(() => {
      const alert = document.getElementById(alertId);
      if (alert) {
        const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
        bsAlert.close();
      }
    }, duration);
  }

  static getAlertIcon(type) {
    const icons = {
      success: 'check-circle',
      danger: 'exclamation-triangle',
      warning: 'exclamation-triangle',
      info: 'info-circle',
      primary: 'info-circle'
    };
    return icons[type] || 'info-circle';
  }

  // Format field names for display
  static formatFieldName(field) {
    return field.replace(/([A-Z])/g, ' $1')
                .replace(/^./, str => str.toUpperCase())
                .trim();
  }

  // Format category names for display
  static formatCategoryName(category) {
    const categoryNames = {
      personalInfo: 'Personal Information',
      contactInfo: 'Contact Information',
      identificationInfo: 'Identification',
      financialInfo: 'Financial Information',
      healthInfo: 'Health Information',
      educationInfo: 'Education Information'
    };
    return categoryNames[category] || this.formatFieldName(category);
  }

  // Get status badge color
  static getStatusBadgeColor(status) {
    const colors = {
      pending: 'warning',
      verified: 'success',
      expired: 'secondary',
      revoked: 'danger',
      active: 'success',
      inactive: 'secondary'
    };
    return colors[status] || 'secondary';
  }

  // Format date for display
  static formatDate(dateString, options = {}) {
    const defaultOptions = {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    };
    
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', { ...defaultOptions, ...options });
  }

  // Format relative time
  static formatRelativeTime(dateString) {
    const now = new Date();
    const date = new Date(dateString);
    const diffInSeconds = Math.floor((now - date) / 1000);

    if (diffInSeconds < 60) return 'Just now';
    if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} minutes ago`;
    if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} hours ago`;
    if (diffInSeconds < 604800) return `${Math.floor(diffInSeconds / 86400)} days ago`;
    
    return this.formatDate(dateString, { year: 'numeric', month: 'short', day: 'numeric' });
  }

  // Validate email
  static isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  // Validate password strength
  static validatePassword(password) {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    const issues = [];
    
    if (password.length < minLength) {
      issues.push(`At least ${minLength} characters`);
    }
    if (!hasUpperCase) issues.push('One uppercase letter');
    if (!hasLowerCase) issues.push('One lowercase letter');
    if (!hasNumbers) issues.push('One number');
    if (!hasSpecialChar) issues.push('One special character');

    return {
      isValid: issues.length === 0,
      issues,
      strength: this.getPasswordStrength(password)
    };
  }

  static getPasswordStrength(password) {
    let strength = 0;
    
    if (password.length >= 8) strength++;
    if (password.length >= 12) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/\d/.test(password)) strength++;
    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) strength++;

    if (strength <= 2) return { level: 'weak', color: 'danger' };
    if (strength <= 4) return { level: 'medium', color: 'warning' };
    return { level: 'strong', color: 'success' };
  }

  // Copy to clipboard
  static async copyToClipboard(text, successMessage = 'Copied to clipboard!') {
    try {
      await navigator.clipboard.writeText(text);
      this.showAlert(successMessage, 'success', 2000);
      return true;
    } catch (error) {
      console.error('Failed to copy:', error);
      this.showAlert('Failed to copy to clipboard', 'danger');
      return false;
    }
  }

  // Download JSON file
  static downloadJSON(data, filename = 'vault-data.json') {
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: 'application/json'
    });
    
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    this.showAlert(`Downloaded ${filename}`, 'success');
  }

  // Generate secure random string
  static generateRandomString(length = 32) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    
    for (let i = 0; i < length; i++) {
      result += chars[array[i] % chars.length];
    }
    
    return result;
  }

  // Debounce function
  static debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  }

  // Throttle function
  static throttle(func, limit) {
    let inThrottle;
    return function() {
      const args = arguments;
      const context = this;
      if (!inThrottle) {
        func.apply(context, args);
        inThrottle = true;
        setTimeout(() => inThrottle = false, limit);
      }
    };
  }

  // Check if user is authenticated
  static isAuthenticated() {
    return !!localStorage.getItem('accessToken');
  }

  // Redirect to login if not authenticated
  static requireAuth() {
    if (!this.isAuthenticated()) {
      window.location.href = '/login';
      return false;
    }
    return true;
  }

  // Format file size
  static formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  // Sanitize HTML
  static sanitizeHTML(html) {
    const temp = document.createElement('div');
    temp.textContent = html;
    return temp.innerHTML;
  }

  // Loading state manager
  static setLoading(element, isLoading = true) {
    if (isLoading) {
      element.classList.add('loading');
      element.disabled = true;
      
      // Store original content
      if (!element.dataset.originalContent) {
        element.dataset.originalContent = element.innerHTML;
      }
      
      element.innerHTML = '<i class="bi bi-hourglass-split"></i> Loading...';
    } else {
      element.classList.remove('loading');
      element.disabled = false;
      
      if (element.dataset.originalContent) {
        element.innerHTML = element.dataset.originalContent;
        delete element.dataset.originalContent;
      }
    }
  }

  // Progressive enhancement for forms
  static enhanceForm(formElement) {
    const inputs = formElement.querySelectorAll('input, textarea, select');
    
    inputs.forEach(input => {
      // Add floating labels effect
      input.addEventListener('focus', () => {
        input.parentElement.classList.add('focused');
      });
      
      input.addEventListener('blur', () => {
        if (!input.value) {
          input.parentElement.classList.remove('focused');
        }
      });
      
      // Real-time validation
      if (input.type === 'email') {
        input.addEventListener('input', VaultUtils.debounce(() => {
          const isValid = VaultUtils.isValidEmail(input.value);
          input.classList.toggle('is-valid', isValid && input.value);
          input.classList.toggle('is-invalid', !isValid && input.value);
        }, 300));
      }
      
      if (input.type === 'password') {
        input.addEventListener('input', VaultUtils.debounce(() => {
          const validation = VaultUtils.validatePassword(input.value);
          input.classList.toggle('is-valid', validation.isValid);
          input.classList.toggle('is-invalid', !validation.isValid && input.value);
        }, 300));
      }
    });
  }
}

// Initialize API client
const vaultAPI = new VaultAPI();

// Global event handlers
document.addEventListener('DOMContentLoaded', function() {
  // Enhance all forms
  document.querySelectorAll('form').forEach(form => {
    VaultUtils.enhanceForm(form);
  });
  
  // Add global keyboard shortcuts
  document.addEventListener('keydown', function(e) {
    // Ctrl/Cmd + K for search
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      const searchInput = document.querySelector('input[type="search"], input[placeholder*="search" i]');
      if (searchInput) {
        searchInput.focus();
      }
    }
    
    // Escape to close modals
    if (e.key === 'Escape') {
      const openModal = document.querySelector('.modal.show');
      if (openModal) {
        const modal = bootstrap.Modal.getInstance(openModal);
        if (modal) modal.hide();
      }
    }
  });
  
  // Add global error handler
  window.addEventListener('unhandledrejection', function(event) {
    console.error('Unhandled promise rejection:', event.reason);
    VaultUtils.showAlert('An unexpected error occurred. Please try again.', 'danger');
  });
  
  // Add offline/online handlers
  window.addEventListener('offline', function() {
    VaultUtils.showAlert('You are now offline. Some features may not work.', 'warning');
  });
  
  window.addEventListener('online', function() {
    VaultUtils.showAlert('You are back online!', 'success', 2000);
  });
});

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { VaultAPI, VaultUtils };
}

// Make available globally
window.VaultAPI = VaultAPI;
window.VaultUtils = VaultUtils;
window.vaultAPI = vaultAPI;