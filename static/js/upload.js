// Upload sayfası JavaScript - Dosya yükleme ve analiz işlemleri

let selectedFile = null;
let socket = null;
let currentFileId = null;

document.addEventListener('DOMContentLoaded', function() {
    // DOM elementleri
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const fileInfo = document.getElementById('fileInfo');
    const fileName = document.getElementById('fileName');
    const fileSize = document.getElementById('fileSize');
    const uploadForm = document.getElementById('uploadForm');
    const uploadBtn = document.getElementById('uploadBtn');
    const progressSection = document.getElementById('progressSection');
    const progressBar = document.getElementById('progressBar');
    const currentStage = document.getElementById('currentStage');
    const resultsSection = document.getElementById('resultsSection');
    const successResult = document.getElementById('successResult');
    const errorResult = document.getElementById('errorResult');
    const errorMessage = document.getElementById('errorMessage');
    const reportLink = document.getElementById('reportLink');

    // Socket.IO bağlantısı
    initializeSocket();

    // Drag and drop olayları
    dropZone.addEventListener('dragover', handleDragOver);
    dropZone.addEventListener('dragleave', handleDragLeave);
    dropZone.addEventListener('drop', handleDrop);
    dropZone.addEventListener('click', () => fileInput.click());

    // Dosya seçim olayı
    fileInput.addEventListener('change', handleFileSelect);

    // Form gönderimi
    uploadForm.addEventListener('submit', handleFormSubmit);

    function initializeSocket() {
        try {
            socket = io();
            
            socket.on('connect', function() {
                console.log('Socket.IO bağlantısı kuruldu');
                trackEvent('socket_connected');
            });

            socket.on('disconnect', function() {
                console.log('Socket.IO bağlantısı kesildi');
                trackEvent('socket_disconnected');
            });

            socket.on('analysis_progress', handleAnalysisProgress);
            socket.on('analysis_complete', handleAnalysisComplete);
            socket.on('analysis_error', handleAnalysisError);

        } catch (error) {
            console.error('Socket.IO başlatılamadı:', error);
        }
    }

    function handleDragOver(e) {
        e.preventDefault();
        e.stopPropagation();
        dropZone.classList.add('dragover');
        dropZone.style.borderColor = '#28a745';
        dropZone.style.backgroundColor = 'rgba(40, 167, 69, 0.1)';
    }

    function handleDragLeave(e) {
        e.preventDefault();
        e.stopPropagation();
        dropZone.classList.remove('dragover');
        dropZone.style.borderColor = '';
        dropZone.style.backgroundColor = '';
    }

    function handleDrop(e) {
        e.preventDefault();
        e.stopPropagation();
        handleDragLeave(e);

        const files = e.dataTransfer.files;
        if (files.length > 0) {
            processFile(files[0]);
            trackEvent('file_dropped', { filename: files[0].name });
        }
    }

    function handleFileSelect(e) {
        const files = e.target.files;
        if (files.length > 0) {
            processFile(files[0]);
            trackEvent('file_selected', { filename: files[0].name });
        }
    }

    function processFile(file) {
        // Dosya validasyonu
        const validation = validateFile(file);
        if (!validation.valid) {
            showError(validation.error);
            return;
        }

        selectedFile = file;
        
        // Dosya bilgilerini göster
        fileName.textContent = file.name;
        fileSize.textContent = formatFileSize(file.size);
        
        fileInfo.classList.remove('d-none');
        uploadBtn.disabled = false;

        // Drop zone'u güncelle
        dropZone.style.borderColor = '#28a745';
        dropZone.style.backgroundColor = 'rgba(40, 167, 69, 0.05)';
        
        animateElement(fileInfo, 'slide-up');
    }

    function clearFile() {
        selectedFile = null;
        currentFileId = null;
        fileInput.value = '';
        
        fileInfo.classList.add('d-none');
        uploadBtn.disabled = true;
        
        // Drop zone'u sıfırla
        dropZone.style.borderColor = '';
        dropZone.style.backgroundColor = '';
        
        // Sonuç bölümlerini gizle
        progressSection.classList.add('d-none');
        resultsSection.classList.add('d-none');
    }

    function handleFormSubmit(e) {
        e.preventDefault();
        
        if (!selectedFile) {
            showError('Lütfen bir dosya seçin');
            return;
        }

        uploadFile();
    }

    function uploadFile() {
        const formData = new FormData();
        formData.append('file', selectedFile);
        
        // VirusTotal seçeneğini ekle
        const enableVirusTotal = document.getElementById('enableVirusTotal').checked;
        formData.append('enable_virustotal', enableVirusTotal.toString());

        // Upload butonunu devre dışı bırak
        setButtonLoading(uploadBtn, true);
        
        trackEvent('file_upload_started', { 
            filename: selectedFile.name, 
            size: selectedFile.size,
            virustotal_enabled: enableVirusTotal
        });

        fetch('/upload', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            setButtonLoading(uploadBtn, false);
            
            if (data.success) {
                currentFileId = data.file_id;
                showSuccess('Dosya başarıyla yüklendi!');
                
                // Socket odasına katıl
                if (socket) {
                    socket.emit('join_analysis', { file_id: currentFileId });
                }
                
                // Analizi başlat
                startAnalysis(currentFileId);
                trackEvent('file_upload_success', { file_id: currentFileId });
            } else {
                showError(data.error || 'Dosya yüklenirken hata oluştu');
                trackEvent('file_upload_error', { error: data.error });
            }
        })
        .catch(error => {
            setButtonLoading(uploadBtn, false);
            showError('Dosya yüklenirken hata oluştu: ' + error.message);
            trackEvent('file_upload_error', { error: error.message });
        });
    }

    function startAnalysis(fileId) {
        // Progress bölümünü göster
        progressSection.classList.remove('d-none');
        animateElement(progressSection, 'slide-up');
        
        // Upload formunu gizle
        uploadForm.style.display = 'none';

        // VirusTotal seçeneğini al
        const enableVirusTotal = document.getElementById('enableVirusTotal').checked;
        const analyzeUrl = `/analyze/${fileId}?enable_virustotal=${enableVirusTotal}`;

        fetch(analyzeUrl)
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                updateProgress('Analiz başlatıldı...', 5);
                trackEvent('analysis_started', { 
                    file_id: fileId,
                    virustotal_enabled: enableVirusTotal
                });
            } else {
                showAnalysisError(data.error || 'Analiz başlatılamadı');
                trackEvent('analysis_start_error', { error: data.error });
            }
        })
        .catch(error => {
            showAnalysisError('Analiz başlatılamadı: ' + error.message);
            trackEvent('analysis_start_error', { error: error.message });
        });
    }

    function handleAnalysisProgress(data) {
        if (data.file_id === currentFileId) {
            updateProgress(data.stage, data.progress);
        }
    }

    function handleAnalysisComplete(data) {
        if (data.file_id === currentFileId) {
            updateProgress('Analiz tamamlandı!', 100);
            
            setTimeout(() => {
                showAnalysisSuccess(data.report_url);
                trackEvent('analysis_completed', { file_id: data.file_id });
            }, 1000);
        }
    }

    function handleAnalysisError(data) {
        if (data.file_id === currentFileId) {
            showAnalysisError(data.error);
            trackEvent('analysis_error', { error: data.error });
        }
    }

    function updateProgress(stage, percent) {
        currentStage.textContent = stage;
        
        // Progress bar animasyonu
        progressBar.style.width = percent + '%';
        progressBar.setAttribute('aria-valuenow', percent);
        progressBar.textContent = Math.round(percent) + '%';
        
        // Renk değişimi
        if (percent >= 90) {
            progressBar.className = 'progress-bar progress-bar-striped bg-success';
        } else if (percent >= 70) {
            progressBar.className = 'progress-bar progress-bar-striped bg-info';
        } else {
            progressBar.className = 'progress-bar progress-bar-striped progress-bar-animated bg-primary';
        }
    }

    function showAnalysisSuccess(reportUrl) {
        progressSection.classList.add('d-none');
        resultsSection.classList.remove('d-none');
        successResult.classList.remove('d-none');
        errorResult.classList.add('d-none');
        
        reportLink.href = reportUrl;
        
        animateElement(resultsSection, 'success-state');
    }

    function showAnalysisError(error) {
        progressSection.classList.add('d-none');
        resultsSection.classList.remove('d-none');
        successResult.classList.add('d-none');
        errorResult.classList.remove('d-none');
        
        errorMessage.textContent = error;
        
        animateElement(resultsSection, 'error-state');
    }

    function cancelAnalysis() {
        if (currentFileId && socket) {
            // İptal isteği gönder (backend'de implement edilebilir)
            console.log('Analiz iptal edildi:', currentFileId);
            trackEvent('analysis_cancelled', { file_id: currentFileId });
        }
        
        resetForm();
    }

    function resetForm() {
        clearFile();
        uploadForm.style.display = 'block';
        setButtonLoading(uploadBtn, false);
    }

    // Global fonksiyonlar
    window.clearFile = clearFile;
    window.cancelAnalysis = cancelAnalysis;
    window.resetForm = resetForm;

    // Sayfa kapatılırken uyarı
    window.addEventListener('beforeunload', function(e) {
        if (currentFileId && progressSection && !progressSection.classList.contains('d-none')) {
            e.preventDefault();
            e.returnValue = 'Analiz devam ediyor. Sayfayı kapatmak istediğinizden emin misiniz?';
        }
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        // Escape tuşu ile iptal
        if (e.key === 'Escape' && currentFileId) {
            cancelAnalysis();
        }
        
        // Ctrl+V ile dosya yapıştırma (clipboard API desteklenirse)
        if (e.ctrlKey && e.key === 'v') {
            handlePasteFile(e);
        }
    });

    function handlePasteFile(e) {
        if (navigator.clipboard && navigator.clipboard.read) {
            navigator.clipboard.read().then(items => {
                for (let item of items) {
                    if (item.types.includes('Files')) {
                        item.getType('Files').then(blob => {
                            if (blob instanceof File) {
                                processFile(blob);
                                trackEvent('file_pasted', { filename: blob.name });
                            }
                        });
                    }
                }
            }).catch(err => {
                console.log('Clipboard okuma hatası:', err);
            });
        }
    }

    // Progress tracking
    let progressStartTime = null;
    
    function trackProgressTime(stage, percent) {
        if (percent === 0) {
            progressStartTime = Date.now();
        } else if (percent === 100 && progressStartTime) {
            const duration = Date.now() - progressStartTime;
            trackEvent('analysis_duration', { 
                file_id: currentFileId,
                duration: duration,
                stage: stage
            });
        }
    }

    // Eksik yardımcı fonksiyonlar
    function validateFile(file) {
        const maxSize = 100 * 1024 * 1024; // 100MB
        const allowedTypes = [
            'application/x-executable',
            'application/x-msdownload',
            'application/x-dosexec',
            'application/octet-stream',
            'application/x-pe',
            'application/x-elf',
            'application/x-mach-o',
            'application/java-archive',
            'application/zip',
            'application/x-rar-compressed',
            'application/x-7z-compressed',
            'application/pdf',
            'text/plain',
            'application/x-msdos-program'
        ];

        // Dosya boyutu kontrolü
        if (file.size > maxSize) {
            return {
                valid: false,
                error: 'Dosya boyutu çok büyük (maksimum 100MB)'
            };
        }

        // Dosya boyutu minimum kontrolü
        if (file.size < 1) {
            return {
                valid: false,
                error: 'Dosya boş olamaz'
            };
        }

        // Dosya uzantısı kontrolü (isteğe bağlı)
        const fileName = file.name.toLowerCase();
        const dangerousExtensions = ['.bat', '.cmd', '.scr', '.pif'];
        const executableExtensions = ['.exe', '.dll', '.sys', '.bin', '.apk', '.dex', '.so', '.dylib'];
        
        // İzin verilen dosya türleri
        if (!allowedTypes.includes(file.type) && file.type !== '') {
            // MIME type belirsizse uzantıya bak
            const hasAllowedExtension = executableExtensions.some(ext => fileName.endsWith(ext));
            if (!hasAllowedExtension) {
                console.log('Dosya tipi uyarısı:', file.type, 'Dosya adı:', fileName);
            }
        }

        return { valid: true };
    }

    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function showError(message) {
        errorMessage.textContent = message;
        errorResult.classList.remove('d-none');
        resultsSection.classList.remove('d-none');
        successResult.classList.add('d-none');
        
        animateElement(errorResult, 'shake');
    }

    function showSuccess(message) {
        // Success mesajı gösterimi (gerekirse element eklenebilir)
        console.log('Success:', message);
    }

    function showAnalysisSuccess(reportUrl) {
        reportLink.href = reportUrl;
        successResult.classList.remove('d-none');
        resultsSection.classList.remove('d-none');
        errorResult.classList.add('d-none');
        
        animateElement(successResult, 'bounce');
    }

    function showAnalysisError(message) {
        showError('Analiz hatası: ' + message);
        
        // Upload formunu tekrar göster
        uploadForm.style.display = 'block';
        setButtonLoading(uploadBtn, false);
    }

    function setButtonLoading(button, loading) {
        if (loading) {
            button.disabled = true;
            button.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Yükleniyor...';
        } else {
            button.disabled = false;
            button.innerHTML = '<i class="fas fa-upload me-2"></i>Analizi Başlat';
        }
    }

    function animateElement(element, animationType) {
        element.classList.add('animate__animated', 'animate__' + animationType);
        
        // Animasyon bitince class'ları temizle
        setTimeout(() => {
            element.classList.remove('animate__animated', 'animate__' + animationType);
        }, 1000);
    }

    function trackEvent(eventName, data = {}) {
        console.log('Event:', eventName, data);
        // Google Analytics veya diğer tracking servisleri için
    }

    function cancelAnalysis() {
        if (currentFileId && socket) {
            socket.emit('cancel_analysis', { file_id: currentFileId });
            resetForm();
        }
    }

    function resetForm() {
        clearFile();
        uploadForm.style.display = 'block';
        setButtonLoading(uploadBtn, false);
    }

    console.log('📁 Upload sayfası hazır - Malware dosyalarınızı güvenle yükleyebilirsiniz');
});
