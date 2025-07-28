#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
File Handler - Dosya işlemleri ve güvenlik kontrollerini yapan modül
"""

import os
import hashlib
import math
import magic
from pathlib import Path
from datetime import datetime

class FileHandler:
    """Dosya işlemleri ve güvenlik kontrollerini yapan sınıf"""
    
    def __init__(self, upload_folder):
        """
        Args:
            upload_folder (str): Dosyaların yükleneceği klasör yolu
        """
        self.upload_folder = Path(upload_folder)
        self.upload_folder.mkdir(exist_ok=True)
        
        # İzin verilen dosya boyutu (100MB)
        self.max_file_size = 100 * 1024 * 1024
        
        # Güvenli dosya türleri (malware analizi için)
        self.allowed_extensions = {
            # Windows Executables
            'exe', 'dll', 'bin', 'msi',
            
            # Java/Android
            'jar', 'apk', 'dex',
            
            # Linux/Unix
            'elf',
            
            # macOS
            'macho',
            
            # Scripts
            'ps1', 'psm1', 'psd1', 
            
            # Archives
            'zip', 'rar', 'ace',
            
            # Documents
            'doc', 'docx', 'docm', 'dot', 'dotx', 'dotm',
            'xls', 'xlsx', 'xlsm', 'xlsb', 'xlt', 'xltx', 'xltm',
            'ppt', 'pptx', 'pptm', 'pot', 'potx', 'potm',
            'pdf', 'rtf', 'odt', 'ods', 'odp',
            'one', 'htm', 'html',
            
            # Email
            'eml',
            
            # PCAP Files
            'pcap'
        }
        
        # Tehlikeli MIME türleri
        self.dangerous_mimes = {
            'application/x-executable',
            'application/x-msdownload',
            'application/x-dosexec',
            'application/vnd.microsoft.portable-executable'
        }
    
    def validate_file(self, file_path):
        """
        Dosyayı güvenlik açısından doğrular
        
        Args:
            file_path (str): Doğrulanacak dosya yolu
            
        Returns:
            dict: Doğrulama sonuçları
        """
        try:
            file_path = Path(file_path)
            
            # Dosya var mı?
            if not file_path.exists():
                return {'valid': False, 'error': 'Dosya bulunamadı'}
            
            # Dosya boyutu kontrolü
            file_size = file_path.stat().st_size
            if file_size > self.max_file_size:
                return {'valid': False, 'error': f'Dosya boyutu çok büyük ({file_size} bytes > {self.max_file_size} bytes)'}
            
            if file_size == 0:
                return {'valid': False, 'error': 'Dosya boş'}
            
            # Dosya uzantısı kontrolü
            extension = file_path.suffix.lower().lstrip('.')
            
            # Uzantısız dosyalar da kabul edilir (malware'ler genelde uzantısız olabilir)
            if extension == '':
                extension = 'no_extension'
            else:
                # Bilinen zararsız uzantıları reddet
                dangerous_extensions = {
                    'txt', 'md', 'readme', 'license', 'changelog',
                    'gitignore', 'gitkeep', 'dockerignore'
                }
                
                if extension in dangerous_extensions:
                    return {'valid': False, 'error': f'Güvenlik nedeniyle reddedilen dosya türü: .{extension}'}
                
                # İzin verilen uzantılar veya bilinmeyen uzantılar kabul edilir
                if extension not in self.allowed_extensions and len(extension) > 4:
                    return {'valid': False, 'error': f'Desteklenmeyen dosya türü: .{extension}'}
            
            # MIME tip kontrolü
            try:
                mime_type = magic.from_file(str(file_path), mime=True)
                file_description = magic.from_file(str(file_path))
            except Exception as e:
                return {'valid': False, 'error': f'Dosya tipi tespit edilemedi: {str(e)}'}
            
            # Dosya hash'lerini hesapla
            hashes = self._calculate_hashes(file_path)
            
            return {
                'valid': True,
                'file_size': file_size,
                'mime_type': mime_type,
                'file_description': file_description,
                'extension': extension,
                'hashes': hashes,
                'is_potentially_dangerous': mime_type in self.dangerous_mimes
            }
            
        except Exception as e:
            return {'valid': False, 'error': f'Dosya doğrulama hatası: {str(e)}'}
    
    def _calculate_hashes(self, file_path):
        """Dosya hash'lerini hesaplar"""
        hashes = {}
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                
                # MD5
                hashes['md5'] = hashlib.md5(content).hexdigest()
                
                # SHA1
                hashes['sha1'] = hashlib.sha1(content).hexdigest()
                
                # SHA256
                hashes['sha256'] = hashlib.sha256(content).hexdigest()
                
        except Exception as e:
            hashes['error'] = str(e)
        
        return hashes
    
    def get_file_info(self, file_path):
        """Dosya hakkında detaylı bilgi döndürür"""
        try:
            file_path = Path(file_path)
            stat = file_path.stat()
            
            return {
                'filename': file_path.name,
                'path': str(file_path),
                'size': stat.st_size,
                'size_human': self._human_readable_size(stat.st_size),
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
                'extension': file_path.suffix.lower(),
                'validation': self.validate_file(file_path)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _human_readable_size(self, size_bytes):
        """Dosya boyutunu okunabilir formata çevirir"""
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        
        return f"{s} {size_names[i]}"
    
    def sanitize_filename(self, filename):
        """Dosya adını güvenli hale getirir"""
        # Tehlikeli karakterleri temizle
        dangerous_chars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*']
        for char in dangerous_chars:
            filename = filename.replace(char, '_')
        
        # Çok uzun dosya adlarını kısalt
        if len(filename) > 255:
            name, ext = os.path.splitext(filename)
            filename = name[:250] + ext
        
        return filename
    
    def cleanup_old_files(self, max_age_hours=24):
        """Eski dosyaları temizler"""
        try:
            current_time = datetime.now().timestamp()
            max_age_seconds = max_age_hours * 3600
            
            cleaned_count = 0
            
            for file_path in self.upload_folder.glob('*'):
                if file_path.is_file():
                    file_age = current_time - file_path.stat().st_mtime
                    
                    if file_age > max_age_seconds:
                        try:
                            file_path.unlink()
                            cleaned_count += 1
                        except Exception as e:
                            print(f"Dosya silinirken hata: {file_path} - {str(e)}")
            
            return {'success': True, 'cleaned_count': cleaned_count}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def create_safe_path(self, filename, file_id):
        """Güvenli dosya yolu oluşturur"""
        # Dosya adını güvenli hale getir
        safe_filename = self.sanitize_filename(filename)
        
        # Uzantıyı al
        if '.' in safe_filename:
            extension = safe_filename.rsplit('.', 1)[1].lower()
        else:
            extension = 'bin'  # Varsayılan uzantı
        
        # Benzersiz dosya adı oluştur
        safe_path = self.upload_folder / f"{file_id}.{extension}"
        
        return safe_path
    
    def scan_directory(self):
        """Upload klasöründeki dosyaları tarar"""
        try:
            files = []
            
            for file_path in self.upload_folder.glob('*'):
                if file_path.is_file():
                    file_info = self.get_file_info(file_path)
                    files.append(file_info)
            
            return {
                'success': True,
                'files': files,
                'total_count': len(files),
                'total_size': sum(f.get('size', 0) for f in files)
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
