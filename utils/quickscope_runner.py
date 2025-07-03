#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Qu1cksc0pe Runner - Qu1cksc0pe malware analiz aracını çalıştıran modül
"""

import os
import subprocess
import json
import re
from datetime import datetime
from pathlib import Path

class QuickScopeRunner:
    """Qu1cksc0pe malware analiz aracını çalıştıran sınıf"""
    
    def __init__(self, quickscope_path):
        """
        Args:
            quickscope_path (str): Qu1cksc0pe aracının kurulu olduğu dizin yolu
        """
        self.quickscope_path = Path(quickscope_path)
        self.venv_path = self.quickscope_path / "sc0pe_venv"
        self.script_path = self.quickscope_path / "qu1cksc0pe.py"
        
        # Qu1cksc0pe kurulumu kontrol et
        self._verify_installation()
    
    def _verify_installation(self):
        """Qu1cksc0pe kurulumunu ve gerekli dosyaları kontrol eder"""
        if not self.quickscope_path.exists():
            raise FileNotFoundError(f"Qu1cksc0pe dizini bulunamadı: {self.quickscope_path}")
        
        if not self.script_path.exists():
            raise FileNotFoundError(f"qu1cksc0pe.py dosyası bulunamadı: {self.script_path}")
        
        if not self.venv_path.exists():
            raise FileNotFoundError(f"Sanal ortam bulunamadı: {self.venv_path}")
    
    def _get_activation_command(self):
        """Sanal ortam aktivasyon komutunu döndürür"""
        activate_script = self.venv_path / "bin" / "activate"
        return f"source {activate_script}"
    
    def run_analysis(self, file_path, progress_callback=None, enable_virustotal=False):
        """
        Qu1cksc0pe ile malware analizi çalıştırır
        
        Args:
            file_path (str): Analiz edilecek dosya yolu
            progress_callback (callable): İlerleme durumunu bildiren callback fonksiyonu
            enable_virustotal (bool): VirusTotal analizi aktif edilsin mi
            
        Returns:
            dict: Analiz sonuçları
        """
        try:
            if progress_callback:
                progress_callback("Qu1cksc0pe hazırlanıyor...", 15)
            
            # Dosya yolunu mutlak yol olarak al
            abs_file_path = os.path.abspath(file_path)
            
            # Debug: Dosya yolu ve varlığını kontrol et
            print(f"🔍 QuickScope Runner - Orijinal dosya yolu: {file_path}")
            print(f"🔍 QuickScope Runner - Mutlak dosya yolu: {abs_file_path}")
            print(f"📂 Orijinal dosya var mı? {os.path.exists(file_path)}")
            print(f"📂 Mutlak dosya var mı? {os.path.exists(abs_file_path)}")
            print(f"📁 Qu1cksc0pe yolu: {self.quickscope_path}")
            
            if not os.path.exists(abs_file_path):
                return {
                    'success': False,
                    'error': f'Dosya bulunamadı: {abs_file_path}'
                }
            
            # Komut oluştur - tam parametre seti
            base_params = f"--file '{abs_file_path}' --analyze --domain --packer --resource --sigcheck --mitre --lang"
            
            # VirusTotal analizi ekle
            if enable_virustotal:
                base_params += " --vtFile"
            
            cmd = [
                "bash", "-c",
                f"{self._get_activation_command()} && "
                f"cd {self.quickscope_path} && "
                f"python qu1cksc0pe.py {base_params}"
            ]
            
            print(f"🔧 Çalıştırılacak komut: {' '.join(cmd)}")
            
            if progress_callback:
                progress_callback("Qu1cksc0pe analizi çalışıyor...", 25)
            
            # Qu1cksc0pe'u çalıştır
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 dakika timeout
                cwd=str(self.quickscope_path)
            )
            
            if progress_callback:
                progress_callback("Qu1cksc0pe çıktısı işleniyor...", 60)
            
            # Sonuçları parse et
            # Qu1cksc0pe bazen çıktı olsa bile 0 dışında exit code döndürebilir
            # Bu durumda çıktı varsa başarılı sayıyoruz
            has_meaningful_output = (result.stdout and 
                                   (len(result.stdout.strip()) > 100 or 
                                    'File Type:' in result.stdout or 
                                    'MD5:' in result.stdout or
                                    'SHA256:' in result.stdout))
            
            if result.returncode == 0 or has_meaningful_output:
                try:
                    output_data = self._parse_quickscope_output(result.stdout)
                    file_info = self._extract_file_info(result.stdout)
                    
                    return {
                        'success': True,
                        'output': output_data,
                        'file_info': file_info,
                        'raw_output': result.stdout,
                        'command': ' '.join(cmd),
                        'returncode': result.returncode,
                        'stderr': result.stderr
                    }
                except Exception as parse_error:
                    print(f"⚠️ Parse hatası ama çıktı var, devam ediyoruz: {parse_error}")
                    return {
                        'success': True,
                        'output': {'raw_analysis': result.stdout},
                        'file_info': self._extract_file_info(result.stdout),
                        'raw_output': result.stdout,
                        'command': ' '.join(cmd),
                        'parse_error': str(parse_error)
                    }
            else:
                # Gerçek hata durumu
                error_msg = result.stderr or result.stdout or "Bilinmeyen analiz hatası"
                
                # Progress bar çıktıları hataya dahil etme
                if "extracting" in error_msg.lower() and "%" in error_msg:
                    # Bu normal progress çıktısı, analiz devam etmiş olabilir
                    if result.stdout and len(result.stdout.strip()) > 50:
                        return {
                            'success': True,
                            'output': {'raw_analysis': result.stdout},
                            'file_info': self._extract_file_info(result.stdout),
                            'raw_output': result.stdout,
                            'command': ' '.join(cmd),
                            'warning': 'Analiz tamamlandı ama bazı kısımlar atlandı'
                        }
                
                return {
                    'success': False,
                    'error': error_msg,
                    'returncode': result.returncode,
                    'command': ' '.join(cmd)
                }
        
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Qu1cksc0pe analizi zaman aşımına uğradı (10 dakika)',
                'timeout': True
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Qu1cksc0pe çalıştırma hatası: {str(e)}',
                'exception': str(e)
            }
    
    def _parse_quickscope_output(self, output):
        """Qu1cksc0pe çıktısını yapılandırılmış formata çevirir"""
        parsed_data = {
            'file_type': None,
            'target_os': None,
            'functions_analysis': [],
            'classes_analysis': [],
            'sections_info': [],
            'dll_files': [],
            'yara_matches': [],
            'interesting_strings': [],
            'statistics': {},
            'magic_numbers': [],
            'language_detection': [],
            'compiler_detection': [],
            'warnings': [],
            'ip_addresses': [],
            'domains': [],
            'virustotal_results': {
                'scan_results': [],
                'total_scans': 0,
                'positive_detections': 0,
                'scan_date': None,
                'permalink': None,
                'sha256': None,
                'md5': None
            }
        }
        
        try:
            lines = output.split('\n')
            current_section = None
            
            for line in lines:
                line = line.strip()
                
                # Dosya tipi tespiti
                if 'File Type:' in line:
                    parsed_data['file_type'] = line.split('File Type:')[1].strip()
                
                # Hedef OS tespiti
                if 'Target OS:' in line:
                    parsed_data['target_os'] = line.split('Target OS:')[1].strip()
                
                # Fonksiyon ve string analizi tabloları
                if 'Functions or Strings about' in line:
                    current_section = 'functions'
                    category = line.split('about')[1].strip().replace('┃', '')
                    parsed_data['functions_analysis'].append({
                        'category': category,
                        'items': []
                    })
                
                # Class metodları
                if 'Methods in Class:' in line:
                    current_section = 'classes'
                    class_name = line.split('Methods in Class:')[1].strip().replace('┃', '')
                    parsed_data['classes_analysis'].append({
                        'class_name': class_name,
                        'methods': []
                    })
                
                # Section bilgileri
                if 'Informations About Sections' in line:
                    current_section = 'sections'
                
                # DLL dosyaları
                if 'Linked DLL Files' in line:
                    current_section = 'dlls'
                
                # YARA kuralları
                if 'Rule name:' in line:
                    rule_name = line.split('Rule name:')[1].strip()
                    parsed_data['yara_matches'].append({
                        'rule_name': rule_name,
                        'matches': []
                    })
                
                # İlginç string'ler
                if 'Interesting Patterns' in line:
                    current_section = 'strings'
                
                # IP adresleri
                if '[IP_Address]>' in line:
                    ip = line.split('[IP_Address]>')[1].strip()
                    parsed_data['ip_addresses'].append(ip)
                
                # İstatistikler
                if 'MD5:' in line:
                    parsed_data['statistics']['md5'] = line.split('MD5:')[1].strip()
                if 'SHA1:' in line:
                    parsed_data['statistics']['sha1'] = line.split('SHA1:')[1].strip()
                if 'SHA256:' in line:
                    parsed_data['statistics']['sha256'] = line.split('SHA256:')[1].strip()
                if 'IMPHASH:' in line:
                    parsed_data['statistics']['imphash'] = line.split('IMPHASH:')[1].strip()
                
                # Uyarılar
                if '* WARNING *' in line:
                    parsed_data['warnings'].append(line)
                
                # Magic number analizi
                if 'File Type' in line and 'Pattern' in line and 'Offset' in line:
                    current_section = 'magic'
                
                # Dil tespiti
                if 'Programming Language' in line and 'Probability' in line:
                    current_section = 'language'
                
                # VirusTotal sonuçları - çeşitli formatları kontrol et
                if any(keyword in line.lower() for keyword in ['virustotal', 'virus total', 'vt analysis', 'vt scan']):
                    current_section = 'virustotal'
                    print(f"🔍 VT section başlatıldı: {line.strip()}")
                
                if current_section == 'virustotal':
                    print(f"🔍 VT line processing: {line.strip()}")
                    
                    # Tarama sonuçları - farklı formatlar
                    if any(keyword in line.lower() for keyword in ['detected', 'clean', 'undetected', 'malware', 'trojan']):
                        # Format 1: "EngineAdı detected/clean"
                        if ':' in line:
                            parts = line.split(':')
                            if len(parts) >= 2:
                                engine_name = parts[0].strip()
                                detection = parts[1].strip()
                                parsed_data['virustotal_results']['scan_results'].append({
                                    'engine': engine_name,
                                    'result': detection
                                })
                                if 'detected' in detection.lower() or detection.lower() not in ['clean', 'undetected']:
                                    parsed_data['virustotal_results']['positive_detections'] += 1
                                print(f"✅ VT Engine kaydedildi: {engine_name} -> {detection}")
                        
                        # Format 2: "EngineAdı detected"
                        elif ' ' in line and not line.startswith(' '):
                            parts = line.strip().split()
                            if len(parts) >= 2:
                                engine_name = parts[0]
                                detection = ' '.join(parts[1:])
                                parsed_data['virustotal_results']['scan_results'].append({
                                    'engine': engine_name,
                                    'result': detection
                                })
                                if 'detected' in detection.lower() or detection.lower() not in ['clean', 'undetected']:
                                    parsed_data['virustotal_results']['positive_detections'] += 1
                                print(f"✅ VT Engine kaydedildi (v2): {engine_name} -> {detection}")
                    
                    # Toplam tarama sayısı
                    if any(keyword in line.lower() for keyword in ['total scans', 'total engines', 'scanned by']):
                        try:
                            numbers = re.findall(r'\d+', line)
                            if numbers:
                                total = int(numbers[0])
                                parsed_data['virustotal_results']['total_scans'] = total
                                print(f"✅ VT Total scans: {total}")
                        except:
                            pass
                    
                    # Tarama tarihi
                    if any(keyword in line.lower() for keyword in ['scan date', 'analysis date', 'first submission']):
                        scan_date = line.split(':')[1].strip() if ':' in line else line.strip()
                        parsed_data['virustotal_results']['scan_date'] = scan_date
                        print(f"✅ VT Scan date: {scan_date}")
                    
                    # Permalink
                    if any(keyword in line.lower() for keyword in ['permalink', 'url', 'virustotal.com']):
                        if 'http' in line:
                            url = line.split('http')[1]
                            url = 'http' + url.strip()
                            parsed_data['virustotal_results']['permalink'] = url
                            print(f"✅ VT Permalink: {url}")
                
                # Eğer başka bir section başlarsa VT section'ını kapat
                if current_section == 'virustotal' and line.startswith('===') and 'virustotal' not in line.lower():
                    current_section = None
                    print("🔚 VT section sonlandırıldı")
            
            return parsed_data
            
        except Exception as e:
            print(f"❌ Parse hatası: {str(e)}")
            return {
                'parse_error': str(e),
                'raw_output': output
            }
        
        finally:
            # VirusTotal debug bilgisi
            vt_results = parsed_data.get('virustotal_results', {})
            print(f"🔍 VT Parse sonuçları:")
            print(f"   - Total scans: {vt_results.get('total_scans', 0)}")
            print(f"   - Positive detections: {vt_results.get('positive_detections', 0)}")
            print(f"   - Scan results count: {len(vt_results.get('scan_results', []))}")
            print(f"   - Scan date: {vt_results.get('scan_date', 'None')}")
            print(f"   - Permalink: {vt_results.get('permalink', 'None')}")
    
    def _extract_file_info(self, output):
        """Çıktıdan dosya bilgilerini çıkarır"""
        file_info = {}
        
        try:
            # Dosya hash'leri
            if 'MD5:' in output:
                md5_match = re.search(r'MD5:\s*([a-fA-F0-9]{32})', output)
                if md5_match:
                    file_info['md5'] = md5_match.group(1)
            
            if 'SHA256:' in output:
                sha256_match = re.search(r'SHA256:\s*([a-fA-F0-9]{64})', output)
                if sha256_match:
                    file_info['sha256'] = sha256_match.group(1)
            
            # Dosya tipi
            if 'File Type:' in output:
                type_match = re.search(r'File Type:\s*(.+)', output)
                if type_match:
                    file_info['file_type'] = type_match.group(1).strip()
            
            # Hedef OS
            if 'Target OS:' in output:
                os_match = re.search(r'Target OS:\s*(.+)', output)
                if os_match:
                    file_info['target_os'] = os_match.group(1).strip()
            
            # Timestamp
            if 'Time Date Stamp:' in output:
                time_match = re.search(r'Time Date Stamp:\s*(.+)', output)
                if time_match:
                    file_info['timestamp'] = time_match.group(1).strip()
            
            return file_info
            
        except Exception as e:
            return {'extraction_error': str(e)}
    
    def get_quickscope_version(self):
        """Qu1cksc0pe versiyonunu alır"""
        try:
            cmd = [
                "bash", "-c",
                f"{self._get_activation_command()} && "
                f"cd {self.quickscope_path} && "
                f"python qu1cksc0pe.py --version"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.stdout.strip() if result.returncode == 0 else "Bilinmiyor"
            
        except Exception:
            return "Bilinmiyor"
