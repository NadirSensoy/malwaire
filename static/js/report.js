// Report sayfası JavaScript - Rapor görüntüleme ve etkileşim

document.addEventListener('DOMContentLoaded', function() {
    // DOM elementleri
    const reportContent = document.querySelector('.container');
    const progressBars = document.querySelectorAll('.progress-bar');
    const codeBlocks = document.querySelectorAll('.code-block code');
    const hashValues = document.querySelectorAll('.font-monospace');
    const collapsibleSections = document.querySelectorAll('[data-bs-toggle="collapse"]');
    const cards = document.querySelectorAll('.card');

    // Sayfa yüklendiğinde animasyonları başlat
    initializeReportAnimations();
    
    // Progress bar'ları animate et
    animateProgressBars();
    
    // Hash değerlerine click-to-copy özelliği ekle
    addCopyToClipboard();
    
    // Code block'lara syntax highlighting ekle
    enhanceCodeBlocks();
    
    // Rapor metrikleri
    trackReportMetrics();

    // Mavi tema animasyonları
    initializeBlueThemeAnimations();

    function initializeReportAnimations() {
        // Fade-in animasyonu için kartları hazırla
        cards.forEach((card, index) => {
            card.style.opacity = '0';
            card.style.transform = 'translateY(20px)';
            
            setTimeout(() => {
                card.style.transition = 'all 0.6s ease';
                card.style.opacity = '1';
                card.style.transform = 'translateY(0)';
            }, index * 100);
        });

        // Fade-in animasyonu için observer
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('fade-in');
                    observer.unobserve(entry.target);
                }
            });
        }, {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        });

        // Tüm kartları observe et
        document.querySelectorAll('.card, .key-findings-item, .ioc-item').forEach(el => {
            observer.observe(el);
        });
    }

    function initializeBlueThemeAnimations() {
        // Hover efektleri
        document.querySelectorAll('.card-hover').forEach(card => {
            card.addEventListener('mouseenter', function() {
                this.style.transform = 'translateY(-3px)';
                this.style.boxShadow = '0 8px 25px rgba(116, 185, 255, 0.2)';
            });

            card.addEventListener('mouseleave', function() {
                this.style.transform = 'translateY(0)';
                this.style.boxShadow = '0 4px 15px rgba(116, 185, 255, 0.1)';
            });
        });

        // IOC item hover efektleri
        document.querySelectorAll('.ioc-item').forEach(item => {
            item.addEventListener('mouseenter', function() {
                this.style.background = 'linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%)';
                this.style.transform = 'scale(1.02)';
            });

            item.addEventListener('mouseleave', function() {
                this.style.background = 'linear-gradient(135deg, #f8fbff 0%, #e3f2fd 100%)';
                this.style.transform = 'scale(1)';
            });
        });

        // Progress bar animasyonu
        setTimeout(() => {
            document.querySelectorAll('.progress-bar').forEach(bar => {
                const width = bar.style.width;
                bar.style.width = '0%';
                setTimeout(() => {
                    bar.style.width = width;
                }, 100);
            });
        }, 500);
    }

    function animateProgressBars() {
        progressBars.forEach(bar => {
            const targetWidth = bar.style.width || bar.getAttribute('aria-valuenow') + '%';
            const targetPercent = parseInt(targetWidth);
            
            // Başlangıçta sıfırla
            bar.style.width = '0%';
            
            // Animate et
            setTimeout(() => {
                animateProgressBar(bar, targetPercent, 1500);
            }, 500);
        });
    }

    function addCopyToClipboard() {
        hashValues.forEach(element => {
            // Hash değerlerini tespit et (32, 40, 64 karakter)
            const text = element.textContent.trim();
            const hashPattern = /^[a-fA-F0-9]{32,64}$/;
            
            if (hashPattern.test(text)) {
                element.style.cursor = 'pointer';
                element.title = 'Kopyalamak için tıklayın';
                element.classList.add('text-primary');
                
                element.addEventListener('click', function() {
                    copyToClipboard(text);
                    
                    // Visual feedback
                    const originalText = element.textContent;
                    element.textContent = '✓ Kopyalandı';
                    element.classList.remove('text-primary');
                    element.classList.add('text-success');
                    
                    setTimeout(() => {
                        element.textContent = originalText;
                        element.classList.remove('text-success');
                        element.classList.add('text-primary');
                    }, 2000);
                    
                    trackEvent('hash_copied', { 
                        hash_type: detectHashType(text),
                        hash_length: text.length 
                    });
                });
            }
        });
    }

    function enhanceCodeBlocks() {
        codeBlocks.forEach(block => {
            // Line numbers ekle
            addLineNumbers(block);
            
            // Copy button ekle
            addCopyButton(block);
            
            // Syntax highlighting
            if (window.Prism) {
                Prism.highlightElement(block);
            }
        });
    }

    function addLineNumbers(codeBlock) {
        const lines = codeBlock.textContent.split('\n');
        if (lines.length > 5) { // Sadece uzun kod blokları için
            const numberedContent = lines.map((line, index) => {
                return `<span class="line-number">${index + 1}</span>${line}`;
            }).join('\n');
            
            codeBlock.innerHTML = numberedContent;
            codeBlock.parentElement.classList.add('has-line-numbers');
        }
    }

    function addCopyButton(codeBlock) {
        const container = codeBlock.parentElement;
        if (!container.querySelector('.copy-btn')) {
            const copyBtn = document.createElement('button');
            copyBtn.className = 'btn btn-sm btn-outline-secondary copy-btn';
            copyBtn.innerHTML = '<i class="fas fa-copy"></i>';
            copyBtn.title = 'Kodu kopyala';
            copyBtn.style.cssText = `
                position: absolute;
                top: 10px;
                right: 10px;
                z-index: 10;
            `;
            
            container.style.position = 'relative';
            container.appendChild(copyBtn);
            
            copyBtn.addEventListener('click', function() {
                const text = codeBlock.textContent;
                copyToClipboard(text);
                
                copyBtn.innerHTML = '<i class="fas fa-check"></i>';
                copyBtn.classList.remove('btn-outline-secondary');
                copyBtn.classList.add('btn-success');
                
                setTimeout(() => {
                    copyBtn.innerHTML = '<i class="fas fa-copy"></i>';
                    copyBtn.classList.remove('btn-success');
                    copyBtn.classList.add('btn-outline-secondary');
                }, 2000);
                
                trackEvent('code_copied', { 
                    code_length: text.length 
                });
            });
        }
    }

    function trackReportMetrics() {
        // Rapor görüntüleme süresi
        const startTime = Date.now();
        
        // Risk seviyesini tespit et
        const riskBadge = document.querySelector('.badge');
        const riskLevel = riskBadge ? riskBadge.textContent.trim() : 'Unknown';
        
        trackEvent('report_viewed', {
            risk_level: riskLevel,
            timestamp: new Date().toISOString()
        });
        
        // Sayfa kapatılırken süreyi kaydet
        window.addEventListener('beforeunload', function() {
            const viewDuration = Date.now() - startTime;
            trackEvent('report_view_duration', {
                duration: viewDuration,
                risk_level: riskLevel
            });
        });
        
        // Scroll tracking
        let maxScroll = 0;
        window.addEventListener('scroll', function() {
            const scrollPercent = (window.scrollY / (document.body.scrollHeight - window.innerHeight)) * 100;
            maxScroll = Math.max(maxScroll, scrollPercent);
        });
        
        window.addEventListener('beforeunload', function() {
            trackEvent('report_scroll_depth', {
                max_scroll_percent: Math.round(maxScroll)
            });
        });
    }

    // Print functionality
    function printReport() {
        // Hide interactive elements before printing
        const hideElements = document.querySelectorAll('.btn, .collapse');
        hideElements.forEach(el => el.style.display = 'none');
        
        window.print();
        
        // Restore after printing
        setTimeout(() => {
            hideElements.forEach(el => el.style.display = '');
        }, 1000);
        
        trackEvent('report_printed');
    }

    // Export functionality
    function exportReport(format) {
        const reportData = extractReportData();
        
        switch(format) {
            case 'json':
                exportAsJSON(reportData);
                break;
            case 'csv':
                exportAsCSV(reportData);
                break;
            case 'pdf':
                exportAsPDF();
                break;
            default:
                console.error('Unsupported export format:', format);
        }
        
        trackEvent('report_exported', { format: format });
    }

    function extractReportData() {
        // Extract structured data from the report
        const data = {
            analysis_date: document.querySelector('.text-muted')?.textContent,
            risk_level: document.querySelector('.badge')?.textContent.trim(),
            file_info: {},
            hash_values: {},
            key_findings: [],
            recommendations: []
        };
        
        // Extract hash values
        document.querySelectorAll('table tr').forEach(row => {
            const cells = row.querySelectorAll('td');
            if (cells.length === 2) {
                const key = cells[0].textContent.trim().replace(':', '');
                const value = cells[1].textContent.trim();
                
                if (['MD5', 'SHA1', 'SHA256', 'IMPHASH'].includes(key)) {
                    data.hash_values[key] = value;
                } else {
                    data.file_info[key] = value;
                }
            }
        });
        
        // Extract findings and recommendations
        document.querySelectorAll('.list-group-item').forEach(item => {
            const text = item.textContent.trim();
            if (item.querySelector('.fa-check-circle')) {
                data.key_findings.push(text);
            } else if (item.querySelector('.fa-exclamation-triangle')) {
                data.recommendations.push(text);
            }
        });
        
        return data;
    }

    function exportAsJSON(data) {
        const jsonString = JSON.stringify(data, null, 2);
        downloadFile(jsonString, 'malware_analysis_report.json', 'application/json');
    }

    function exportAsCSV(data) {
        let csv = 'Kategori,Anahtar,Değer\n';
        
        // File info
        Object.entries(data.file_info).forEach(([key, value]) => {
            csv += `Dosya Bilgisi,"${key}","${value}"\n`;
        });
        
        // Hash values
        Object.entries(data.hash_values).forEach(([key, value]) => {
            csv += `Hash Değeri,"${key}","${value}"\n`;
        });
        
        // Findings
        data.key_findings.forEach(finding => {
            csv += `Önemli Bulgular,"Bulgu","${finding}"\n`;
        });
        
        // Recommendations
        data.recommendations.forEach(rec => {
            csv += `Öneriler,"Öneri","${rec}"\n`;
        });
        
        downloadFile(csv, 'malware_analysis_report.csv', 'text/csv');
    }

    function exportAsPDF() {
        // Simple PDF export using browser's print dialog
        printReport();
    }

    function downloadFile(content, filename, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        
        URL.revokeObjectURL(url);
    }

    // Search functionality within report
    function searchInReport(query) {
        if (!query) return;
        
        const walker = document.createTreeWalker(
            document.body,
            NodeFilter.SHOW_TEXT,
            null,
            false
        );
        
        const textNodes = [];
        let node;
        
        while (node = walker.nextNode()) {
            if (node.textContent.toLowerCase().includes(query.toLowerCase())) {
                textNodes.push(node);
            }
        }
        
        // Highlight found text
        textNodes.forEach(textNode => {
            const parent = textNode.parentElement;
            if (parent && !parent.classList.contains('highlighted')) {
                parent.classList.add('highlighted');
                parent.style.backgroundColor = '#ffeb3b';
                parent.style.padding = '2px';
                parent.style.borderRadius = '3px';
            }
        });
        
        trackEvent('report_searched', { 
            query: query, 
            results_count: textNodes.length 
        });
        
        return textNodes.length;
    }

    // Risk level animations
    function animateRiskLevel() {
        const riskBadge = document.querySelector('.badge');
        if (riskBadge) {
            const riskText = riskBadge.textContent.trim();
            
            if (riskText.includes('KRİTİK') || riskText.includes('YÜKSEK')) {
                riskBadge.classList.add('animated-pulse');
            }
        }
    }

    // Add keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        // Ctrl+P for print
        if (e.ctrlKey && e.key === 'p') {
            e.preventDefault();
            printReport();
        }
        
        // Ctrl+F for search (custom implementation)
        if (e.ctrlKey && e.key === 'f') {
            e.preventDefault();
            const query = prompt('Rapor içinde ara:');
            if (query) {
                const results = searchInReport(query);
                alert(`${results} sonuç bulundu`);
            }
        }
        
        // Ctrl+S for save/export
        if (e.ctrlKey && e.key === 's') {
            e.preventDefault();
            exportReport('json');
        }
    });

    // Initialize risk level animation
    animateRiskLevel();

    // Global functions
    window.printReport = printReport;
    window.exportReport = exportReport;
    window.searchInReport = searchInReport;

    console.log('📊 Report sayfası hazır - Analiz raporunu inceleyebilirsiniz');
});
