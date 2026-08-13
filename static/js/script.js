// static/js/script.js
// ============================================
// AI Cyber Threat Detection System - Frontend JavaScript
// ============================================

// ============================================
// DOM Ready - Initialize all functionality
// ============================================
document.addEventListener('DOMContentLoaded', function() {
    // Initialize all modules
    initNavigation();
    initScrollToTop();
    initActiveNavLink();
    initSmoothScroll();
    initWebsiteDetection();
    initEXEDetection();
});

// ============================================
// Navigation Module
// ============================================
function initNavigation() {
    const navToggle = document.getElementById('navToggle');
    const navLinks = document.getElementById('navLinks');
    
    if (navToggle && navLinks) {
        navToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            navLinks.classList.toggle('active');
            
            // Toggle icon
            const icon = this.querySelector('i');
            if (icon) {
                icon.classList.toggle('fa-bars');
                icon.classList.toggle('fa-times');
            }
        });
        
        // Close menu when clicking outside
        document.addEventListener('click', function(e) {
            if (!navLinks.contains(e.target) && !navToggle.contains(e.target)) {
                navLinks.classList.remove('active');
                const icon = navToggle.querySelector('i');
                if (icon) {
                    icon.classList.remove('fa-times');
                    icon.classList.add('fa-bars');
                }
            }
        });
        
        // Close menu when clicking a link (mobile)
        navLinks.querySelectorAll('a').forEach(function(link) {
            link.addEventListener('click', function() {
                navLinks.classList.remove('active');
                const icon = navToggle.querySelector('i');
                if (icon) {
                    icon.classList.remove('fa-times');
                    icon.classList.add('fa-bars');
                }
            });
        });
    }
}

// ============================================
// Scroll to Top Module
// ============================================
function initScrollToTop() {
    const scrollBtn = document.getElementById('scrollTopBtn');
    
    if (scrollBtn) {
        // Show/hide button based on scroll position
        window.addEventListener('scroll', function() {
            if (window.pageYOffset > 300) {
                scrollBtn.classList.add('visible');
            } else {
                scrollBtn.classList.remove('visible');
            }
        });
        
        // Scroll to top on click
        scrollBtn.addEventListener('click', function() {
            window.scrollTo({
                top: 0,
                behavior: 'smooth'
            });
        });
    }
}

// ============================================
// Active Navigation Link Module
// ============================================
function initActiveNavLink() {
    const currentPage = window.location.pathname.split('/').pop() || 'index.html';
    const navLinks = document.querySelectorAll('.nav-links a');
    
    navLinks.forEach(function(link) {
        const href = link.getAttribute('href');
        if (href === currentPage) {
            link.classList.add('active');
        } else {
            link.classList.remove('active');
        }
    });
}

// ============================================
// Smooth Scroll Module
// ============================================
function initSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(function(anchor) {
        anchor.addEventListener('click', function(e) {
            const targetId = this.getAttribute('href');
            if (targetId === '#') return;
            
            const target = document.querySelector(targetId);
            if (target) {
                e.preventDefault();
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
}

// ============================================
// Website Detection Module
// ============================================
function initWebsiteDetection() {
    const detectBtn = document.getElementById('detectBtn');
    const urlInput = document.getElementById('websiteUrl');
    const loadingSection = document.getElementById('loadingSection');
    const resultsSection = document.getElementById('resultsSection');
    const scanAgainBtn = document.getElementById('scanAgainBtn');
    
    if (detectBtn && urlInput) {
        // Detect button click
        detectBtn.addEventListener('click', function() {
            const url = urlInput.value.trim();
            
            // Validate URL
            if (!isValidURL(url)) {
                showValidationError(urlInput, 'Please enter a valid URL (e.g., https://example.com)');
                return;
            }
            
            // Clear any previous validation error
            clearValidationError(urlInput);
            
            // Perform detection
            performWebsiteDetection(url);
        });
        
        // Enter key support
        urlInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                detectBtn.click();
            }
        });
        
        // Real-time validation on input
        urlInput.addEventListener('input', function() {
            if (this.value.trim() && isValidURL(this.value.trim())) {
                clearValidationError(this);
            }
        });
    }
    
    // Scan again button
    if (scanAgainBtn) {
        scanAgainBtn.addEventListener('click', function() {
            resetWebsiteDetection();
        });
    }
}

// ============================================
// URL Validation
// ============================================
function isValidURL(url) {
    try {
        const urlObj = new URL(url);
        return urlObj.protocol === 'http:' || urlObj.protocol === 'https:';
    } catch (e) {
        return false;
    }
}

function showValidationError(inputElement, message) {
    inputElement.style.borderColor = '#EF4444';
    inputElement.style.boxShadow = '0 0 0 3px rgba(239, 68, 68, 0.1)';
    
    // Remove existing error message
    const existingError = inputElement.parentElement.querySelector('.validation-error');
    if (existingError) {
        existingError.remove();
    }
    
    // Add error message
    const error = document.createElement('div');
    error.className = 'validation-error';
    error.style.cssText = 'color: #EF4444; font-size: 0.85rem; margin-top: 0.25rem; display: flex; align-items: center; gap: 0.25rem;';
    error.innerHTML = '<i class="fas fa-exclamation-circle"></i> ' + message;
    inputElement.parentElement.appendChild(error);
}

function clearValidationError(inputElement) {
    inputElement.style.borderColor = '#E2E8F0';
    inputElement.style.boxShadow = 'none';
    
    const error = inputElement.parentElement.querySelector('.validation-error');
    if (error) {
        error.remove();
    }
}

// ============================================
// Perform Website Detection (Placeholder)
// ============================================
function performWebsiteDetection(url) {
    const detectBtn = document.getElementById('detectBtn');
    const loadingSection = document.getElementById('loadingSection');
    const resultsSection = document.getElementById('resultsSection');
    
    // Show loading, hide results
    if (loadingSection) loadingSection.style.display = 'block';
    if (resultsSection) resultsSection.style.display = 'none';
    if (detectBtn) detectBtn.disabled = true;
    
    // Animate progress bar
    animateProgressBar('progressBar', 'progressText', 0, 100, 2000, function() {
        // Simulate API call with dummy data
        setTimeout(function() {
            // Generate dummy result
            const dummyResult = generateDummyWebsiteResult(url);
            
            // Display results
            displayWebsiteResults(dummyResult);
            
            // Hide loading, show results
            if (loadingSection) loadingSection.style.display = 'none';
            if (resultsSection) resultsSection.style.display = 'block';
            if (detectBtn) detectBtn.disabled = false;
            
            // Scroll to results
            resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 500);
    });
}

// ============================================
// Generate Dummy Website Result
// ============================================
function generateDummyWebsiteResult(url) {
    const threats = ['Phishing', 'Malware', 'Suspicious', 'Safe'];
    const predictions = ['Threat Detected', 'Safe', 'Suspicious Activity'];
    const riskLevels = ['Low', 'Medium', 'High'];
    const recommendations = {
        'Low': [
            'The website appears safe. Continue with normal usage.',
            'Regular monitoring is recommended.',
            'Keep your browser and security software updated.'
        ],
        'Medium': [
            'Exercise caution when interacting with this website.',
            'Avoid entering sensitive information.',
            'Consider using a VPN for added security.'
        ],
        'High': [
            'This website is potentially dangerous. Avoid visiting it.',
            'Do not download any files from this site.',
            'Report this website to security authorities.'
        ]
    };
    
    const randomIndex = Math.floor(Math.random() * 10);
    let prediction, riskLevel, confidence, recommendationList;
    
    if (randomIndex < 3) {
        // High risk
        prediction = 'Threat Detected';
        riskLevel = 'High';
        confidence = 85 + Math.floor(Math.random() * 15);
        recommendationList = recommendations['High'];
    } else if (randomIndex < 6) {
        // Medium risk
        prediction = 'Suspicious Activity';
        riskLevel = 'Medium';
        confidence = 60 + Math.floor(Math.random() * 20);
        recommendationList = recommendations['Medium'];
    } else {
        // Low risk
        prediction = 'Safe';
        riskLevel = 'Low';
        confidence = 90 + Math.floor(Math.random() * 10);
        recommendationList = recommendations['Low'];
    }
    
    return {
        url: url,
        prediction: prediction,
        confidence: confidence,
        riskLevel: riskLevel,
        recommendations: recommendationList
    };
}

// ============================================
// Display Website Results
// ============================================
function displayWebsiteResults(result) {
    // Update URL
    const scannedUrl = document.getElementById('scannedUrl');
    if (scannedUrl) scannedUrl.textContent = result.url;
    
    // Update prediction
    const predictionValue = document.getElementById('predictionValue');
    if (predictionValue) {
        predictionValue.textContent = result.prediction;
        predictionValue.className = 'result-value';
        if (result.prediction === 'Safe') {
            predictionValue.classList.add('text-success');
        } else if (result.prediction === 'Threat Detected') {
            predictionValue.classList.add('text-danger');
        } else {
            predictionValue.classList.add('text-warning');
        }
    }
    
    // Update confidence
    const confidenceValue = document.getElementById('confidenceValue');
    const confidenceBar = document.getElementById('confidenceBar');
    if (confidenceValue) confidenceValue.textContent = result.confidence;
    if (confidenceBar) {
        confidenceBar.style.width = result.confidence + '%';
        // Color based on confidence
        if (result.confidence >= 80) {
            confidenceBar.style.background = 'var(--gradient-success)';
        } else if (result.confidence >= 60) {
            confidenceBar.style.background = 'var(--gradient-warning)';
        } else {
            confidenceBar.style.background = 'var(--gradient-danger)';
        }
    }
    
    // Update risk level
    const riskLevel = document.getElementById('riskLevel');
    const riskBadge = document.getElementById('riskBadge');
    if (riskLevel) {
        riskLevel.textContent = result.riskLevel + ' Risk';
        riskLevel.className = 'result-value';
        if (result.riskLevel === 'Low') {
            riskLevel.classList.add('text-success');
        } else if (result.riskLevel === 'Medium') {
            riskLevel.classList.add('text-warning');
        } else {
            riskLevel.classList.add('text-danger');
        }
    }
    if (riskBadge) {
        riskBadge.textContent = result.riskLevel + ' Risk';
        riskBadge.className = 'result-badge';
        if (result.riskLevel === 'Low') {
            riskBadge.classList.add('risk-low');
        } else if (result.riskLevel === 'Medium') {
            riskBadge.classList.add('risk-medium');
        } else {
            riskBadge.classList.add('risk-high');
        }
    }
    
    // Update recommendations
    const recommendationText = document.getElementById('recommendationText');
    const recommendationList = document.getElementById('recommendationList');
    if (recommendationText) {
        recommendationText.textContent = result.recommendations[0];
    }
    if (recommendationList) {
        recommendationList.innerHTML = '';
        result.recommendations.slice(1).forEach(function(rec) {
            const li = document.createElement('li');
            li.textContent = rec;
            recommendationList.appendChild(li);
        });
    }
}

// ============================================
// Reset Website Detection
// ============================================
function resetWebsiteDetection() {
    const urlInput = document.getElementById('websiteUrl');
    const loadingSection = document.getElementById('loadingSection');
    const resultsSection = document.getElementById('resultsSection');
    
    if (urlInput) {
        urlInput.value = '';
        clearValidationError(urlInput);
        urlInput.focus();
    }
    if (loadingSection) loadingSection.style.display = 'none';
    if (resultsSection) resultsSection.style.display = 'none';
    
    // Reset progress bar
    const progressBar = document.getElementById('progressBar');
    const progressText = document.getElementById('progressText');
    if (progressBar) progressBar.style.width = '0%';
    if (progressText) progressText.textContent = '0%';
    
    // Scroll to top of detection section
    document.querySelector('.detection-section')?.scrollIntoView({ behavior: 'smooth' });
}

// ============================================
// EXE Detection Module
// ============================================
function initEXEDetection() {
    const uploadArea = document.getElementById('uploadArea');
    const fileInput = document.getElementById('fileInput');
    const browseBtn = document.getElementById('browseBtn');
    const fileCard = document.getElementById('fileCard');
    const fileName = document.getElementById('fileName');
    const fileSize = document.getElementById('fileSize');
    const removeFileBtn = document.getElementById('removeFileBtn');
    const scanBtn = document.getElementById('scanBtn');
    const loadingSection = document.getElementById('loadingSection');
    const resultsSection = document.getElementById('resultsSection');
    const scanAgainBtn = document.getElementById('scanAgainBtn');
    
    let selectedFile = null;
    
    // Browse button click
    if (browseBtn && fileInput) {
        browseBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            fileInput.click();
        });
    }
    
    // Upload area click
    if (uploadArea && fileInput) {
        uploadArea.addEventListener('click', function() {
            fileInput.click();
        });
    }
    
    // File input change
    if (fileInput) {
        fileInput.addEventListener('change', function() {
            if (this.files && this.files.length > 0) {
                handleFileSelect(this.files[0]);
            }
        });
    }
    
    // Drag and drop events
    if (uploadArea) {
        uploadArea.addEventListener('dragover', function(e) {
            e.preventDefault();
            this.classList.add('drag-over');
        });
        
        uploadArea.addEventListener('dragleave', function(e) {
            e.preventDefault();
            this.classList.remove('drag-over');
        });
        
        uploadArea.addEventListener('drop', function(e) {
            e.preventDefault();
            this.classList.remove('drag-over');
            
            const files = e.dataTransfer.files;
            if (files && files.length > 0) {
                handleFileSelect(files[0]);
            }
        });
    }
    
    // Remove file
    if (removeFileBtn) {
        removeFileBtn.addEventListener('click', function() {
            selectedFile = null;
            if (fileInput) fileInput.value = '';
            if (fileCard) fileCard.style.display = 'none';
            if (scanBtn) scanBtn.disabled = true;
        });
    }
    
    // Scan button
    if (scanBtn) {
        scanBtn.addEventListener('click', function() {
            if (selectedFile) {
                performEXEScan(selectedFile);
            }
        });
    }
    
    // Scan again button
    if (scanAgainBtn) {
        scanAgainBtn.addEventListener('click', function() {
            resetEXEDetection();
        });
    }
}

// ============================================
// Handle File Selection
// ============================================
function handleFileSelect(file) {
    const fileCard = document.getElementById('fileCard');
    const fileName = document.getElementById('fileName');
    const fileSize = document.getElementById('fileSize');
    const scanBtn = document.getElementById('scanBtn');
    const fileInput = document.getElementById('fileInput');
    
    // Validate file type (.exe)
    const fileExtension = file.name.split('.').pop().toLowerCase();
    if (fileExtension !== 'exe') {
        alert('Only .exe files are allowed. Please select a valid Windows executable file.');
        if (fileInput) fileInput.value = '';
        return;
    }
    
    // Validate file size (max 100MB)
    const maxSize = 100 * 1024 * 1024; // 100MB in bytes
    if (file.size > maxSize) {
        alert('File size exceeds the maximum limit of 100MB. Please select a smaller file.');
        if (fileInput) fileInput.value = '';
        return;
    }
    
    // Store selected file
    selectedFile = file;
    
    // Display file card
    if (fileCard) fileCard.style.display = 'block';
    if (fileName) fileName.textContent = file.name;
    if (fileSize) {
        const sizeInMB = (file.size / (1024 * 1024)).toFixed(2);
        fileSize.textContent = sizeInMB + ' MB';
    }
    
    // Enable scan button
    if (scanBtn) scanBtn.disabled = false;
}

// ============================================
// Perform EXE Scan (Placeholder)
// ============================================
function performEXEScan(file) {
    const scanBtn = document.getElementById('scanBtn');
    const loadingSection = document.getElementById('loadingSection');
    const resultsSection = document.getElementById('resultsSection');
    
    // Show loading, hide results
    if (loadingSection) loadingSection.style.display = 'block';
    if (resultsSection) resultsSection.style.display = 'none';
    if (scanBtn) scanBtn.disabled = true;
    
    // Animate progress bar
    animateProgressBar('progressBar', 'progressText', 0, 100, 3000, function() {
        // Simulate API call with dummy data
        setTimeout(function() {
            // Generate dummy result
            const dummyResult = generateDummyEXEResult(file);
            
            // Display results
            displayEXEResults(dummyResult);
            
            // Hide loading, show results
            if (loadingSection) loadingSection.style.display = 'none';
            if (resultsSection) resultsSection.style.display = 'block';
            if (scanBtn) scanBtn.disabled = false;
            
            // Scroll to results
            resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 500);
    });
}

// ============================================
// Generate Dummy EXE Result
// ============================================
function generateDummyEXEResult(file) {
    const predictions = ['Safe', 'Malware Detected', 'Suspicious'];
    const riskLevels = ['Low', 'Medium', 'High'];
    const recommendations = {
        'Low': [
            'The file appears safe. No malicious code detected.',
            'Regular file scanning is recommended.',
            'Keep your antivirus software updated.'
        ],
        'Medium': [
            'The file shows suspicious characteristics. Exercise caution.',
            'Run in a sandbox environment before execution.',
            'Review the file\'s digital signature and source.'
        ],
        'High': [
            'This file is potentially malicious. Do not execute it.',
            'Delete the file immediately.',
            'Report this file to security authorities.'
        ]
    };
    
    const randomIndex = Math.floor(Math.random() * 10);
    let prediction, riskLevel, confidence, recommendationList;
    
    if (randomIndex < 3) {
        prediction = 'Malware Detected';
        riskLevel = 'High';
        confidence = 85 + Math.floor(Math.random() * 15);
        recommendationList = recommendations['High'];
    } else if (randomIndex < 6) {
        prediction = 'Suspicious';
        riskLevel = 'Medium';
        confidence = 60 + Math.floor(Math.random() * 20);
        recommendationList = recommendations['Medium'];
    } else {
        prediction = 'Safe';
        riskLevel = 'Low';
        confidence = 90 + Math.floor(Math.random() * 10);
        recommendationList = recommendations['Low'];
    }
    
    // Generate dummy SHA-256 hash
    const sha256 = generateDummySHA256();
    
    return {
        fileName: file.name,
        fileSize: (file.size / (1024 * 1024)).toFixed(2) + ' MB',
        sha256: sha256,
        prediction: prediction,
        confidence: confidence,
        riskLevel: riskLevel,
        recommendations: recommendationList
    };
}

// ============================================
// Generate Dummy SHA-256
// ============================================
function generateDummySHA256() {
    const chars = '0123456789abcdef';
    let hash = '';
    for (let i = 0; i < 64; i++) {
        hash += chars[Math.floor(Math.random() * chars.length)];
    }
    return hash;
}

// ============================================
// Display EXE Results
// ============================================
function displayEXEResults(result) {
    // Update file summary
    const resultFileName = document.getElementById('resultFileName');
    const resultFileSize = document.getElementById('resultFileSize');
    const resultSha256 = document.getElementById('resultSha256');
    
    if (resultFileName) resultFileName.textContent = result.fileName;
    if (resultFileSize) resultFileSize.textContent = result.fileSize;
    if (resultSha256) resultSha256.textContent = result.sha256;
    
    // Update prediction
    const predictionValue = document.getElementById('predictionValue');
    if (predictionValue) {
        predictionValue.textContent = result.prediction;
        predictionValue.className = 'result-value';
        if (result.prediction === 'Safe') {
            predictionValue.classList.add('text-success');
        } else if (result.prediction === 'Malware Detected') {
            predictionValue.classList.add('text-danger');
        } else {
            predictionValue.classList.add('text-warning');
        }
    }
    
    // Update confidence
    const confidenceValue = document.getElementById('confidenceValue');
    const confidenceBar = document.getElementById('confidenceBar');
    if (confidenceValue) confidenceValue.textContent = result.confidence;
    if (confidenceBar) {
        confidenceBar.style.width = result.confidence + '%';
        if (result.confidence >= 80) {
            confidenceBar.style.background = 'var(--gradient-success)';
        } else if (result.confidence >= 60) {
            confidenceBar.style.background = 'var(--gradient-warning)';
        } else {
            confidenceBar.style.background = 'var(--gradient-danger)';
        }
    }
    
    // Update risk level
    const riskLevel = document.getElementById('riskLevel');
    const riskBadge = document.getElementById('riskBadge');
    if (riskLevel) {
        riskLevel.textContent = result.riskLevel + ' Risk';
        riskLevel.className = 'result-value';
        if (result.riskLevel === 'Low') {
            riskLevel.classList.add('text-success');
        } else if (result.riskLevel === 'Medium') {
            riskLevel.classList.add('text-warning');
        } else {
            riskLevel.classList.add('text-danger');
        }
    }
    if (riskBadge) {
        riskBadge.textContent = result.riskLevel + ' Risk';
        riskBadge.className = 'result-badge';
        if (result.riskLevel === 'Low') {
            riskBadge.classList.add('risk-low');
        } else if (result.riskLevel === 'Medium') {
            riskBadge.classList.add('risk-medium');
        } else {
            riskBadge.classList.add('risk-high');
        }
    }
    
    // Update recommendations
    const recommendationText = document.getElementById('recommendationText');
    const recommendationList = document.getElementById('recommendationList');
    if (recommendationText) {
        recommendationText.textContent = result.recommendations[0];
    }
    if (recommendationList) {
        recommendationList.innerHTML = '';
        result.recommendations.slice(1).forEach(function(rec) {
            const li = document.createElement('li');
            li.textContent = rec;
            recommendationList.appendChild(li);
        });
    }
}

// ============================================
// Reset EXE Detection
// ============================================
function resetEXEDetection() {
    const fileInput = document.getElementById('fileInput');
    const fileCard = document.getElementById('fileCard');
    const scanBtn = document.getElementById('scanBtn');
    const loadingSection = document.getElementById('loadingSection');
    const resultsSection = document.getElementById('resultsSection');
    const uploadArea = document.getElementById('uploadArea');
    
    if (fileInput) fileInput.value = '';
    if (fileCard) fileCard.style.display = 'none';
    if (scanBtn) scanBtn.disabled = true;
    if (loadingSection) loadingSection.style.display = 'none';
    if (resultsSection) resultsSection.style.display = 'none';
    
    // Reset progress bar
    const progressBar = document.getElementById('progressBar');
    const progressText = document.getElementById('progressText');
    if (progressBar) progressBar.style.width = '0%';
    if (progressText) progressText.textContent = '0%';
    
    // Remove drag-over class if any
    if (uploadArea) uploadArea.classList.remove('drag-over');
    
    selectedFile = null;
    
    // Scroll to top of upload section
    document.querySelector('.detection-section')?.scrollIntoView({ behavior: 'smooth' });
}

// ============================================
// Progress Bar Animation
// ============================================
function animateProgressBar(barId, textId, start, end, duration, callback) {
    const progressBar = document.getElementById(barId);
    const progressText = document.getElementById(textId);
    
    if (!progressBar) return;
    
    const startTime = Date.now();
    const increment = 10; // Update every 10ms
    let current = start;
    
    function updateProgress() {
        const elapsed = Date.now() - startTime;
        const progress = Math.min(elapsed / duration, 1);
        current = start + (end - start) * progress;
        
        const rounded = Math.round(current);
        if (progressBar) progressBar.style.width = rounded + '%';
        if (progressText) progressText.textContent = rounded + '%';
        
        if (progress < 1) {
            setTimeout(updateProgress, increment);
        } else if (callback) {
            callback();
        }
    }
    
    updateProgress();
}

// ============================================
// Utility Functions
// ============================================

// Format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Debounce function for performance
function debounce(func, wait) {
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

// ============================================
// Note: All placeholder data and dummy results
// will be replaced with actual Flask API calls
// when the backend is integrated.
// ============================================