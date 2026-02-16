// Main JavaScript for DarkNet Defend

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    initializeAlerts();
    initializeCharts();
    initializeNotifications();
});

// Initialize main app functionality
function initializeApp() {
    // Add fade-in animation to cards
    const cards = document.querySelectorAll('.card');
    cards.forEach((card, index) => {
        card.style.opacity = '0';
        card.style.animation = `fadeIn 0.6s ease ${index * 0.1}s forwards`;
    });

    // Form validation
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            if (!form.checkValidity()) {
                e.preventDefault();
                e.stopPropagation();
            }
            form.classList.add('was-validated');
        });
    });

    // Add loading state to buttons
    const submitButtons = document.querySelectorAll('button[type="submit"]');
    submitButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            if (this.form && this.form.checkValidity()) {
                addLoadingState(this);
            }
        });
    });
}

// Add loading state to button
function addLoadingState(button) {
    const originalText = button.innerHTML;
    button.disabled = true;
    button.innerHTML = '<span class="loading"></span> Processing...';
    
    // Reset after form submission (in case of validation errors)
    setTimeout(() => {
        button.disabled = false;
        button.innerHTML = originalText;
    }, 3000);
}

// Initialize alert functionality
function initializeAlerts() {
    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.animation = 'slideOut 0.5s ease forwards';
            setTimeout(() => {
                alert.remove();
            }, 500);
        }, 5000);
    });

    // Mark alerts as read
    const markReadButtons = document.querySelectorAll('.mark-read');
    markReadButtons.forEach(button => {
        button.addEventListener('click', function() {
            const alertId = this.getAttribute('data-alert-id');
            markAlertAsRead(alertId, this);
        });
    });
}

// Mark alert as read via API
function markAlertAsRead(alertId, button) {
    button.disabled = true;
    button.innerHTML = '<span class="loading"></span>';
    
    fetch(`/alerts/${alertId}/read`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Alert marked as read', 'success');
            setTimeout(() => {
                location.reload();
            }, 1000);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('Failed to mark alert as read', 'error');
        button.disabled = false;
        button.innerHTML = '<i class="bi bi-check"></i> Mark as Read';
    });
}

// Initialize charts if Chart.js is loaded
function initializeCharts() {
    if (typeof Chart === 'undefined') {
        return;
    }

    // Check if we're on the dashboard
    const statsEndpoint = document.querySelector('[data-stats-endpoint]');
    if (!statsEndpoint) {
        return;
    }

    // Fetch statistics data
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            createAlertChart(data.alerts_by_severity);
            createLogsChart(data.logs_by_type);
        })
        .catch(error => console.error('Error fetching stats:', error));
}

// Create alert severity chart
function createAlertChart(data) {
    const canvas = document.getElementById('alertChart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(data),
            datasets: [{
                data: Object.values(data),
                backgroundColor: [
                    'rgba(220, 53, 69, 0.8)',
                    'rgba(255, 193, 7, 0.8)',
                    'rgba(13, 202, 240, 0.8)',
                    'rgba(108, 117, 125, 0.8)'
                ],
                borderColor: [
                    'rgb(220, 53, 69)',
                    'rgb(255, 193, 7)',
                    'rgb(13, 202, 240)',
                    'rgb(108, 117, 125)'
                ],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#e8eaf6'
                    }
                }
            }
        }
    });
}

// Create security logs chart
function createLogsChart(data) {
    const canvas = document.getElementById('logsChart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: Object.keys(data).map(key => key.replace(/_/g, ' ').toUpperCase()),
            datasets: [{
                label: 'Security Events',
                data: Object.values(data),
                backgroundColor: 'rgba(13, 110, 253, 0.8)',
                borderColor: 'rgb(13, 110, 253)',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: '#e8eaf6'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                },
                x: {
                    ticks: {
                        color: '#e8eaf6'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                }
            },
            plugins: {
                legend: {
                    labels: {
                        color: '#e8eaf6'
                    }
                }
            }
        }
    });
}

// Notification system
function initializeNotifications() {
    // Check for browser notification support
    if ('Notification' in window && Notification.permission === 'default') {
        // You can request permission here if needed
        // Notification.requestPermission();
    }
}

// Show in-page notification
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} alert-dismissible fade show notification-toast`;
    notification.style.position = 'fixed';
    notification.style.top = '20px';
    notification.style.right = '20px';
    notification.style.zIndex = '9999';
    notification.style.minWidth = '300px';
    notification.style.animation = 'slideIn 0.5s ease';
    
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(notification);
    
    // Auto remove after 4 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.5s ease forwards';
        setTimeout(() => {
            notification.remove();
        }, 500);
    }, 4000);
}

// Real-time monitoring simulation
function startMonitoring() {
    // Simulate real-time updates every 30 seconds
    setInterval(() => {
        updateDashboardStats();
    }, 30000);
}

// Update dashboard statistics
function updateDashboardStats() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            // Update UI with new data
            console.log('Dashboard updated:', data);
        })
        .catch(error => console.error('Error updating stats:', error));
}

// SQL Injection detection demo
function testSQLInjection(input) {
    const patterns = [
        /(\bunion\b.*\bselect\b)/i,
        /(\bor\b.*=.*)/i,
        /(\band\b.*=.*)/i,
        /(';.*--)/i,
        /(\bdrop\b.*\btable\b)/i,
        /(\bexec\b.*\()/i,
        /(\binsert\b.*\binto\b)/i,
        /(\bdelete\b.*\bfrom\b)/i,
        /(\bupdate\b.*\bset\b)/i
    ];
    
    for (let pattern of patterns) {
        if (pattern.test(input)) {
            return {
                detected: true,
                pattern: pattern.toString(),
                message: 'Potential SQL injection detected!'
            };
        }
    }
    
    return { detected: false };
}

// Add real-time input validation
const credentialInput = document.getElementById('credential_value');
if (credentialInput) {
    credentialInput.addEventListener('input', function(e) {
        const result = testSQLInjection(e.target.value);
        
        if (result.detected) {
            e.target.classList.add('is-invalid');
            showNotification('Suspicious input detected!', 'warning');
        } else {
            e.target.classList.remove('is-invalid');
        }
    });
}

// Password strength checker
const passwordInput = document.getElementById('password');
if (passwordInput) {
    const strengthIndicator = document.createElement('div');
    strengthIndicator.className = 'password-strength mt-2';
    passwordInput.parentElement.appendChild(strengthIndicator);
    
    passwordInput.addEventListener('input', function(e) {
        const strength = checkPasswordStrength(e.target.value);
        updateStrengthIndicator(strengthIndicator, strength);
    });
}

function checkPasswordStrength(password) {
    let strength = 0;
    
    if (password.length >= 8) strength++;
    if (password.length >= 12) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^a-zA-Z0-9]/.test(password)) strength++;
    
    return strength;
}

function updateStrengthIndicator(element, strength) {
    let text = '';
    let className = '';
    
    if (strength <= 2) {
        text = 'Weak';
        className = 'text-danger';
    } else if (strength <= 4) {
        text = 'Medium';
        className = 'text-warning';
    } else {
        text = 'Strong';
        className = 'text-success';
    }
    
    element.innerHTML = `<small class="${className}">Password strength: ${text}</small>`;
}

// Credential type validation
const credentialTypeSelect = document.getElementById('credential_type');
const credentialValueInput = document.getElementById('credential_value');

if (credentialTypeSelect && credentialValueInput) {
    credentialTypeSelect.addEventListener('change', function() {
        updateInputValidation(this.value, credentialValueInput);
    });
}

function updateInputValidation(type, input) {
    switch(type) {
        case 'email':
            input.type = 'email';
            input.placeholder = 'example@domain.com';
            input.pattern = '[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}$';
            break;
        case 'phone':
            input.type = 'tel';
            input.placeholder = '+1234567890';
            input.pattern = '\\+?[0-9]{10,15}';
            break;
        case 'credit_card':
            input.type = 'text';
            input.placeholder = '1234-5678-9012-3456';
            input.pattern = '[0-9]{4}-?[0-9]{4}-?[0-9]{4}-?[0-9]{4}';
            break;
        case 'username':
            input.type = 'text';
            input.placeholder = 'username123';
            input.pattern = '[a-zA-Z0-9_]{3,20}';
            break;
        default:
            input.type = 'text';
            input.placeholder = 'Enter credential value';
            input.removeAttribute('pattern');
    }
}

// Export functions for use in HTML
window.DarknetDefend = {
    markAlertAsRead,
    showNotification,
    testSQLInjection,
    checkPasswordStrength
};

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideOut {
        from {
            opacity: 1;
            transform: translateY(0);
        }
        to {
            opacity: 0;
            transform: translateY(-20px);
        }
    }
    
    @keyframes fadeIn {
        from {
            opacity: 0;
            transform: translateY(20px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    .notification-toast {
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
    }
    
    .is-invalid {
        border-color: #dc3545 !important;
        box-shadow: 0 0 0 0.25rem rgba(220, 53, 69, 0.25) !important;
    }
    
    .password-strength {
        height: 20px;
    }
`;
document.head.appendChild(style);

console.log('DarkNet Defend initialized successfully!');