#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Malware Analysis Platform
Ana Flask uygulaması - Kullanıcıların malware yükleyip Qu1cksc0pe ile analiz edip AI destekli rapor alacağı platform
"""

import os
import uuid
import hashlib
import json
import threading
from datetime import datetime
from pathlib import Path
from flask import Flask, request, render_template, jsonify, send_file, redirect, url_for
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
import magic

# Yardımcı modüller
from utils.quickscope_runner import QuickScopeRunner
from utils.ai_analyzer import AIAnalyzer
from utils.file_handler import FileHandler

# Flask uygulaması yapılandırması
app = Flask(__name__)
app.config['SECRET_KEY'] = 'malware_analysis_secret_key_2025'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# CORS ve SocketIO yapılandırması
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Dizin yapılandırması
UPLOAD_FOLDER = Path('./uploads')
REPORTS_FOLDER = Path('./reports')
UPLOAD_FOLDER.mkdir(exist_ok=True)
REPORTS_FOLDER.mkdir(exist_ok=True)

# Qu1cksc0pe yapılandırması
QUICKSCOPE_PATH = "./Qu1cksc0pe"

# İzin verilen dosya türleri (malware analizi için)
ALLOWED_EXTENSIONS = {
    # Windows Executables
    'exe', 'dll', 'bin', 'msi',
    # Java/Android
    'jar', 'apk',
    
    # Linux/Unix
    'elf',
    
    # macOS
    'macho',
    
    # Scripts
    'ps1', 'psm1', 'psd1', 
    
    # Archives
    'zip', 'rar', 'ace',
    
    # Documents (potential macro malware)
    'doc', 'docx', 'docm', 'dot', 'dotx', 'dotm',
    'xls', 'xlsx', 'xlsm', 'xlsb', 'xlt', 'xltx', 'xltm',
    'ppt', 'pptx', 'pptm', 'pot', 'potx', 'potm',
    'pdf', 'rtf', 'odt', 'ods', 'odp',
    
    # Email
    'eml'

}

# Global objeler
file_handler = FileHandler(UPLOAD_FOLDER)
quickscope_runner = QuickScopeRunner(QUICKSCOPE_PATH)
# OpenAI API anahtarını environment variable'dan al
openai_api_key = os.getenv('OPENAI_API_KEY', None)
ai_analyzer = AIAnalyzer(api_key=openai_api_key)

# Aktif analiz işlemleri takibi
active_analyses = {}

def allowed_file(filename):
    """
    Dosya tipinin analiz için uygun olup olmadığını kontrol eder.
    Uzantısız dosyalar da kabul edilir (malware'ler genelde uzantısız olabilir).
    """
    if not filename:
        return False
    
    # Uzantısız dosyalar kabul edilir
    if '.' not in filename:
        return True
    
    # Uzantılı dosyalar için kontrol
    extension = filename.rsplit('.', 1)[1].lower()
    
    # Bilinen zararsız uzantıları reddet
    dangerous_extensions = {
        'txt', 'md', 'readme', 'license', 'changelog',
        'gitignore', 'gitkeep', 'dockerignore'
    }
    
    if extension in dangerous_extensions:
        return False
    
    # İzin verilen uzantılar veya bilinmeyen uzantılar kabul edilir
    return extension in ALLOWED_EXTENSIONS or len(extension) <= 4

def get_file_info(filepath):
    """Dosya hakkında temel bilgileri toplar"""
    try:
        stat = os.stat(filepath)
        file_magic = magic.from_file(filepath)
        
        # Dosya hash'leri
        with open(filepath, 'rb') as f:
            content = f.read()
            md5_hash = hashlib.md5(content).hexdigest()
            sha256_hash = hashlib.sha256(content).hexdigest()
        
        return {
            'filename': os.path.basename(filepath),
            'size': stat.st_size,
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'mime_type': file_magic,
            'md5': md5_hash,
            'sha256': sha256_hash
        }
    except Exception as e:
        return {'error': str(e)}

@app.route('/')
def index():
    """Ana sayfa"""
    return render_template('index.html')

@app.route('/upload')
def upload_page():
    """Dosya yükleme sayfası"""
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Dosya yükleme işleyicisi"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'Dosya seçilmedi'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Dosya seçilmedi'}), 400
        
        if not allowed_file(file.filename):
            # Daha detaylı hata mesajı
            extension = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'uzantısız'
            return jsonify({
                'error': f'Desteklenmeyen dosya türü: .{extension}', 
                'details': 'Malware analizi için executable, archive, script veya şüpheli dosya türleri desteklenmektedir.',
                'supported_types': 'exe, dll, apk, zip, jar, elf, py, js, pdf, doc, vb...'
            }), 400
        
        # Analiz seçeneklerini al
        enable_virustotal = request.form.get('enable_virustotal', 'false').lower() == 'true'
        
        # Güvenli dosya adı oluştur
        filename = secure_filename(file.filename)
        file_id = str(uuid.uuid4())
        file_extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
        safe_filename = f"{file_id}.{file_extension}"
        
        # Dosyayı kaydet
        filepath = UPLOAD_FOLDER / safe_filename
        file.save(str(filepath))
        
        # Dosya bilgilerini al
        file_info = get_file_info(str(filepath))
        file_info['file_id'] = file_id
        file_info['original_name'] = filename
        file_info['analysis_options'] = {
            'enable_virustotal': enable_virustotal
        }
        
        return jsonify({
            'success': True,
            'file_id': file_id,
            'file_info': file_info,
            'message': 'Dosya başarıyla yüklendi. Analiz başlatılıyor...'
        })
    
    except Exception as e:
        return jsonify({'error': f'Yükleme hatası: {str(e)}'}), 500

@app.route('/analyze/<file_id>')
def start_analysis(file_id):
    """Analiz işlemini başlatır"""
    try:
        # Dosya var mı kontrol et
        file_path = None
        for file in UPLOAD_FOLDER.glob(f"{file_id}.*"):
            file_path = file
            break
        
        if not file_path:
            return jsonify({'error': 'Dosya bulunamadı'}), 404
        
        if file_id in active_analyses:
            return jsonify({
                'status': 'running',
                'message': 'Analiz zaten devam ediyor',
                'progress': active_analyses[file_id]['progress']
            })
        
        # Analiz işlemini başlat
        active_analyses[file_id] = {
            'status': 'starting',
            'progress': 0,
            'start_time': datetime.now(),
            'file_path': str(file_path),
            'analysis_options': {
                'enable_virustotal': request.args.get('enable_virustotal', 'false').lower() == 'true'
            }
        }
        
        # Arka planda analiz başlat
        analysis_options = active_analyses[file_id].get('analysis_options', {})
        thread = threading.Thread(target=run_analysis, args=(file_id, str(file_path), analysis_options))
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'file_id': file_id,
            'status': 'started',
            'message': 'Analiz başlatıldı'
        })
    
    except Exception as e:
        return jsonify({'error': f'Analiz başlatma hatası: {str(e)}'}), 500

def run_analysis(file_id, file_path, analysis_options=None):
    """Arka planda analiz işlemini çalıştırır"""
    try:
        if analysis_options is None:
            analysis_options = {}
            
        enable_virustotal = analysis_options.get('enable_virustotal', False)
        # Progress güncelleme fonksiyonu
        def update_progress(stage, progress):
            if file_id in active_analyses:
                active_analyses[file_id]['progress'] = progress
                active_analyses[file_id]['current_stage'] = stage
                socketio.emit('analysis_progress', {
                    'file_id': file_id,
                    'stage': stage,
                    'progress': progress
                }, room=file_id)
        
        update_progress('Qu1cksc0pe analizi başlatılıyor...', 10)
        
        # Debug: Dosya yolunu kontrol et
        print(f"🔍 Analiz edilecek dosya: {file_path}")
        print(f"📂 Dosya var mı? {os.path.exists(file_path)}")
        
        # Qu1cksc0pe analizi çalıştır
        quickscope_result = quickscope_runner.run_analysis(file_path, update_progress, enable_virustotal)
        
        if not quickscope_result['success']:
            raise Exception(f"Qu1cksc0pe analizi başarısız: {quickscope_result['error']}")
        
        update_progress('AI analizi başlatılıyor...', 70)
        
        # AI ile analiz et - yeni format
        file_name = quickscope_result.get('file_info', {}).get('name', 'bilinmiyor')
        md5_hash = quickscope_result.get('file_info', {}).get('md5')
        sha256_hash = quickscope_result.get('file_info', {}).get('sha256')
        raw_output = quickscope_result.get('raw_output', '')
        
        # VirusTotal verilerini al
        virustotal_data = None
        if enable_virustotal and 'output' in quickscope_result and quickscope_result['output']:
            virustotal_data = quickscope_result['output'].get('virustotal_results')
        
        ai_result = ai_analyzer.analyze_quickscope_output(
            raw_output, 
            file_name,
            md5_hash,
            sha256_hash,
            virustotal_data
        )
        
        update_progress('Rapor oluşturuluyor...', 90)
        
        # Rapor oluştur ve kaydet
        report_data = {
            'file_id': file_id,
            'analysis_date': datetime.now().isoformat(),
            'file_info': quickscope_result['file_info'],
            'quickscope_output': quickscope_result['output'],
            'raw_output': raw_output,  # Ham Qu1cksc0pe çıktısı
            'ai_analysis': ai_result,
            'analysis_options': analysis_options,
            'status': 'completed'
        }
        
        # Raporu kaydet
        report_path = REPORTS_FOLDER / f"{file_id}_report.json"
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
        
        # Analiz tamamlandı
        active_analyses[file_id].update({
            'status': 'completed',
            'progress': 100,
            'end_time': datetime.now(),
            'report_path': str(report_path)
        })
        
        update_progress('Analiz tamamlandı!', 100)
        
        # Tamamlanma bildirimi gönder
        socketio.emit('analysis_complete', {
            'file_id': file_id,
            'report_url': f'/report/{file_id}'
        }, room=file_id)
        
    except Exception as e:
        # Hata durumu
        if file_id in active_analyses:
            active_analyses[file_id].update({
                'status': 'error',
                'error': str(e),
                'end_time': datetime.now()
            })
        
        socketio.emit('analysis_error', {
            'file_id': file_id,
            'error': str(e)
        }, room=file_id)

@app.route('/analysis_status/<file_id>')
def get_analysis_status(file_id):
    """Analiz durumunu kontrol eder"""
    if file_id not in active_analyses:
        return jsonify({'error': 'Analiz bulunamadı'}), 404
    
    status = active_analyses[file_id].copy()
    
    # Datetime objelerini string'e çevir
    if 'start_time' in status:
        status['start_time'] = status['start_time'].isoformat()
    if 'end_time' in status:
        status['end_time'] = status['end_time'].isoformat()
    
    return jsonify(status)

@app.route('/report/<file_id>')
def view_report(file_id):
    """Analiz raporunu görüntüler"""
    report_path = REPORTS_FOLDER / f"{file_id}_report.json"
    
    if not report_path.exists():
        return render_template('error.html', 
                             error='Rapor bulunamadı'), 404
    
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
        
        return render_template('report_new.html', report=report_data)
    
    except Exception as e:
        return render_template('error.html', 
                             error=f'Rapor okuma hatası: {str(e)}'), 500

@app.route('/download_report/<file_id>')
def download_report(file_id):
    """Raporu JSON olarak indir"""
    report_path = REPORTS_FOLDER / f"{file_id}_report.json"
    
    if not report_path.exists():
        return jsonify({'error': 'Rapor bulunamadı'}), 404
    
    return send_file(report_path, as_attachment=True, 
                    download_name=f"malware_analysis_report_{file_id}.json")

# SocketIO event handlers
@socketio.on('connect')
def handle_connect():
    """Kullanıcı bağlandığında"""
    print(f'Kullanıcı bağlandı: {request.sid}')

@socketio.on('disconnect')
def handle_disconnect():
    """Kullanıcı bağlantısı kesildiğinde"""
    print(f'Kullanıcı bağlantısı kesildi: {request.sid}')

@socketio.on('join_analysis')
def handle_join_analysis(data):
    """Analiz odasına katıl"""
    file_id = data.get('file_id')
    if file_id:
        join_room(file_id)
        emit('joined', {'file_id': file_id})

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error='Sayfa bulunamadı'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error='Sunucu hatası'), 500

@app.errorhandler(413)
def too_large(error):
    return jsonify({'error': 'Dosya boyutu çok büyük (max 100MB)'}), 413

if __name__ == '__main__':
    print("🔍 Malware Analysis Platform başlatılıyor...")
    print(f"📁 Upload klasörü: {UPLOAD_FOLDER}")
    print(f"📊 Reports klasörü: {REPORTS_FOLDER}")
    print(f"🛠️ Qu1cksc0pe yolu: {QUICKSCOPE_PATH}")
    print("🌐 Server: http://localhost:5003")
    
    # Development modunda çalıştır
    socketio.run(app, debug=True, host='0.0.0.0', port=5003)
