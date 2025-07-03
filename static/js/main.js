// Ana JavaScript dosyası - Malware Analysis Platform

document.addEventListener('DOMContentLoaded', function() {
    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Bootstrap tooltip initialization
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Loading states for buttons
    function setButtonLoading(button, loading = true) {
        if (loading) {
            button.disabled = true;
            const originalText = button.innerHTML;
            button.setAttribute('data-original-text', originalText);
            button.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status"></span>Yükleniyor...';
        } else {
            button.disabled = false;
            const originalText = button.getAttribute('data-original-text');
            if (originalText) {
                button.innerHTML = originalText;
            }
        }
    }

    // Global error handler
    window.showError = function(message, title = 'Hata') {
        // Simple alert for now, can be replaced with a modal
        alert(title + ': ' + message);
    };

    // Global success handler
    window.showSuccess = function(message, title = 'Başarılı') {
        // Simple alert for now, can be replaced with a modal
        alert(title + ': ' + message);
    };

    // Format file size
    window.formatFileSize = function(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    // Format date
    window.formatDate = function(dateString) {
        const date = new Date(dateString);
        return date.toLocaleDateString('tr-TR') + ' ' + date.toLocaleTimeString('tr-TR');
    };

    // Copy to clipboard function
    window.copyToClipboard = function(text) {
        if (navigator.clipboard) {
            navigator.clipboard.writeText(text).then(function() {
                showSuccess('Panoya kopyalandı');
            });
        } else {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            try {
                document.execCommand('copy');
                showSuccess('Panoya kopyalandı');
            } catch (err) {
                showError('Panoya kopyalanamadı');
            }
            document.body.removeChild(textArea);
        }
    };

    // Animation helpers
    window.animateElement = function(element, animationClass, duration = 1000) {
        element.classList.add(animationClass);
        setTimeout(() => {
            element.classList.remove(animationClass);
        }, duration);
    };

    // Progress bar animation
    window.animateProgressBar = function(progressBar, targetPercent, duration = 1000) {
        let currentPercent = 0;
        const increment = targetPercent / (duration / 16); // 60fps
        
        const timer = setInterval(() => {
            currentPercent += increment;
            if (currentPercent >= targetPercent) {
                currentPercent = targetPercent;
                clearInterval(timer);
            }
            
            progressBar.style.width = currentPercent + '%';
            progressBar.setAttribute('aria-valuenow', currentPercent);
            progressBar.textContent = Math.round(currentPercent) + '%';
        }, 16);
    };

    // Page loading overlay
    window.showLoadingOverlay = function(show = true) {
        let overlay = document.getElementById('loadingOverlay');
        
        if (show && !overlay) {
            overlay = document.createElement('div');
            overlay.id = 'loadingOverlay';
            overlay.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0,0,0,0.7);
                display: flex;
                justify-content: center;
                align-items: center;
                z-index: 9999;
            `;
            overlay.innerHTML = `
                <div class="text-center text-white">
                    <div class="spinner-border mb-3" role="status" style="width: 3rem; height: 3rem;">
                        <span class="visually-hidden">Yükleniyor...</span>
                    </div>
                    <h5>İşlem devam ediyor...</h5>
                </div>
            `;
            document.body.appendChild(overlay);
        } else if (!show && overlay) {
            overlay.remove();
        }
    };

    // Input validation helpers
    window.validateFile = function(file, maxSize = 100 * 1024 * 1024) {
        const allowedTypes = [
            'exe', 'dll', 'bin', 'com', 'scr', 'pif', 'bat', 'cmd',
            'msi', 'jar', 'apk', 'dex', 'elf', 'so', 'dmg', 'pkg',
            'zip', 'rar', '7z', 'tar', 'gz'
        ];
        
        // File size check
        if (file.size > maxSize) {
            return {
                valid: false,
                error: `Dosya boyutu çok büyük. Maksimum ${formatFileSize(maxSize)} olabilir.`
            };
        }
        
        // File type check
        const extension = file.name.split('.').pop().toLowerCase();
        if (!allowedTypes.includes(extension)) {
            return {
                valid: false,
                error: `Desteklenmeyen dosya türü: .${extension}`
            };
        }
        
        return { valid: true };
    };

    // Hash detection
    window.detectHashType = function(hash) {
        if (!hash) return 'Unknown';
        
        const length = hash.length;
        if (length === 32) return 'MD5';
        if (length === 40) return 'SHA1';
        if (length === 64) return 'SHA256';
        if (length === 128) return 'SHA512';
        
        return 'Unknown';
    };

    // Risk level styling
    window.getRiskLevelClass = function(riskLevel) {
        switch(riskLevel.toUpperCase()) {
            case 'KRİTİK':
                return 'bg-danger';
            case 'YÜKSEK':
                return 'bg-warning';
            case 'ORTA':
                return 'bg-info';
            case 'DÜŞÜK':
                return 'bg-success';
            default:
                return 'bg-secondary';
        }
    };

    // Local storage helpers
    window.saveToStorage = function(key, data) {
        try {
            localStorage.setItem(key, JSON.stringify(data));
            return true;
        } catch (e) {
            console.error('Storage save error:', e);
            return false;
        }
    };

    window.getFromStorage = function(key) {
        try {
            const data = localStorage.getItem(key);
            return data ? JSON.parse(data) : null;
        } catch (e) {
            console.error('Storage get error:', e);
            return null;
        }
    };

    // Analytics helper
    window.trackEvent = function(eventName, properties = {}) {
        // Log to console for now
        console.log('Event:', eventName, properties);
        
        // Here you could integrate with analytics services
        // like Google Analytics, Mixpanel, etc.
    };

    // Console welcome message
    console.log(`
    ███╗   ███╗ █████╗ ██╗    ██╗ █████╗ ██████╗ ███████╗
    ████╗ ████║██╔══██╗██║    ██║██╔══██╗██╔══██╗██╔════╝
    ██╔████╔██║███████║██║ █╗ ██║███████║██████╔╝█████╗  
    ██║╚██╔╝██║██╔══██║██║███╗██║██╔══██║██╔══██╗██╔══╝  
    ██║ ╚═╝ ██║██║  ██║╚███╔███╔╝██║  ██║██║  ██║███████╗
    ╚═╝     ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
    
    🔍 Malware Analysis Platform
    🛠️ Qu1cksc0pe + AI Powered
    🔒 Secure & Isolated Analysis
    
    Welcome to the console! This platform is designed for security research.
    `);

    // Track page load
    trackEvent('page_load', {
        page: window.location.pathname,
        timestamp: new Date().toISOString()
    });
});
