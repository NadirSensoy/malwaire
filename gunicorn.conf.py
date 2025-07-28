#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Gunicorn yapılandırma dosyası - Malware Analysis Platform
Uzun süren DLL analizleri için optimize edilmiş ayarlar
"""

import multiprocessing

# Server socket
bind = "0.0.0.0:5003"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "eventlet"  # SocketIO için gerekli
worker_connections = 1000

# Timeout ayarları - DLL analizleri için uzun timeout'lar
timeout = 3600  # 60 dakika - worker timeout
keepalive = 120  # Keep-alive bağlantıları

# Request timeout'ları
graceful_timeout = 3600  # 60 dakika - graceful shutdown
preload_app = True  # Uygulamayı önceden yükle

# Logging
accesslog = "-"  # stdout'a log
errorlog = "-"   # stderr'e log
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = "malware_analysis_platform"

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Performance
max_requests = 1000  # Worker yeniden başlatma sayısı
max_requests_jitter = 50  # Jitter ekle

# Memory management
preload_app = True
worker_tmp_dir = "/dev/shm"  # Geçici dosyalar için RAM disk kullan
