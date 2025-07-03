#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI Analyzer - Qu1cksc0pe çıktılarını Google Gemini API ile analiz eden modül
Geliştirilmiş prompt ve yapılandırılmış JSON çıktısı ile
"""

import os
import json
import google.generativeai as genai
from datetime import datetime

class AIAnalyzer:
    """Qu1cksc0pe çıktılarını Google Gemini AI ile analiz eden sınıf"""
    
    def __init__(self, api_key=None):
        """
        Args:
            api_key (str): Google Gemini API anahtarı
        """
        self.api_key = api_key or os.getenv('GEMINI_API_KEY')
        self.model = None
        
        if not self.api_key:
            print("⚠️  UYARI: Google Gemini API anahtarı bulunamadı. AI analizi çalışmayacak.")
        else:
            try:
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel('gemini-2.5-pro')
                print("✅ Google Gemini AI başarıyla yapılandırıldı!")
            except Exception as e:
                print(f"❌ Gemini AI yapılandırma hatası: {str(e)}")
                self.model = None

    def _get_analysis_prompt(self):
        """Tam ham çıktı analizi için geliştirilmiş AI prompt'u"""
        return """Sen, siber güvenlik alanında uzmanlaşmış bir Kıdemli Malware Analistisin. Görevin, 'Qu1cksc0pe' adlı statik analiz aracının TAMAMI ile terminal çıktılarını derinlemesine analiz ederek, kapsamlı ve detaylı bir malware analiz raporu oluşturmaktır.

**ÖNEMLİ: Yanıtın SADECE VE SADECE JSON formatında olmalı. Başka hiçbir metin, açıklama veya markdown yazma. Doğrudan JSON ile başla ve JSON ile bitir.**

**KAPSAMLI ANALİZ GÖREVİ:**
Sana `[QUICKSCOPE_CIKTISI]` etiketi altında Qu1cksc0pe aracının TAMAMI ham terminal çıktısı verilecek. Bu çıktının her satırını, her detayını dikkatlice analiz et:

**ANALİZ ALANLARI:**
1. **Dosya Kimlik Bilgileri:** Dosya tipi, boyut, hedef işletim sistemi, compiler bilgileri
2. **Hash Analizi:** MD5, SHA1, SHA256, Imphash değerleri
3. **Section Analizi:** Tüm section'lar, entropi değerleri, şüpheli section'lar
4. **Import/Export Analizi:** Tüm DLL'ler, fonksiyon isimleri, şüpheli API çağrıları
5. **String Analizi:** Şüpheli stringler, URL'ler, IP adresleri, domain'ler
6. **YARA Kuralları:** Eşleşen tüm kurallar ve açıklamaları
7. **VirusTotal Sonuçları:** Antivirus motorları tarafından tespit edilen malware isimleri, tespit oranları
8. **Packer/Obfuscation:** Paketleme teknikleri, anti-debug, anti-VM
9. **Davranış Analizi:** Potansiyel kötü amaçlı davranışlar
10. **Network İndikatörleri:** C&C sunucuları, DNS sorguları
11. **Dosya Sistemi Aktiviteleri:** Yaratılan/değiştirilen dosyalar
12. **Registry Aktiviteleri:** Registry anahtarları
13. **Mitre ATT&CK Teknikleri:** Eşleşen teknikler

**RİSK DEĞERLENDİRME KRİTERLERİ:**
- **Kritik (90-100):** Kesin malware, çoklu AV tespiti (>15), aktif C&C, veri hırsızlığı, sistem manipülasyonu
- **Yüksek (70-89):** Güçlü malware belirtileri, orta AV tespiti (5-15), şüpheli ağ aktivitesi, obfuscation
- **Orta (40-69):** Bazı şüpheli özellikler, düşük AV tespiti (1-5), potansiyel risk faktörleri
- **Düşük (0-39):** Minimal risk göstergeleri, AV tespiti yok, temiz veya belirsiz

**VirusTotal Analizi Dahil Et:** Eğer VirusTotal sonuçları varsa, bu sonuçları risk skoruna ve analiz raporuna dahil et. Tespit eden antivirus sayısı, malware türleri, ve güvenilir motorların değerlendirmelerini önemse.

**YANIT FORMATI: Sadece aşağıdaki JSON formatında yanıt ver:**

{{
  "rapor_ozeti": {{
    "dosya_adi": "ornek.exe",
    "md5": "...",
    "sha256": "...",
    "sha1": "...",
    "dosya_boyutu": "1024 KB",
    "tehlike_seviyesi": "YÜKSEK",
    "risk_skoru": 85,
    "analiz_tarihi": "YYYY-MM-DDTHH:MM:SS",
    "kisa_degerlendirme": "Kapsamlı analiz sonucu belirlenen risk değerlendirmesi ve önemli bulgular özeti."
  }},
  "kullanici_raporu": {{
    "bu_dosya_ne_yapiyor": "Kullanıcı dostu açıklama - dosyanın ne yaptığı, hangi sistem kaynaklarına eriştiği, arka planda hangi aktiviteleri gerçekleştirdiği.",
    "potansiyel_riskler": [
      "Risk 1: Açıklama",
      "Risk 2: Açıklama",
      "Risk 3: Açıklama"
    ],
    "oneriler": [
      "Öneri 1: Detaylı açıklama",
      "Öneri 2: Detaylı açıklama",
      "Öneri 3: Detaylı açıklama"
    ],
    "aciliyet_durumu": "Yüksek/Orta/Düşük - Ne kadar hızlı aksiyon alınmalı"
  }},
  "teknik_analiz": {{
    "dosya_kimligi": {{
      "tip": "PE32/ELF/.NET Executable",
      "hedef_isletim_sistemi": "Windows/Linux",
      "mimari": "x86/x64",
      "compiler": "Microsoft Visual C++",
      "imphash": "...",
      "pdb_adi": "debug.pdb",
      "timestamp": "2023-01-01",
      "entry_point": "0x1000"
    }},
    "section_analizi": [
      {{
        "section_adi": ".text",
        "boyut": "4096",
        "entropi": "7.95",
        "izinler": "rx",
        "supheli_durum": "Yüksek entropi - şifrelenmiş kod olabilir"
      }}
    ],
    "import_analizi": {{
      "dll_listesi": ["kernel32.dll", "user32.dll", "ws2_32.dll"],
      "supheli_api_cagirilari": [
        {{
          "api": "CreateRemoteThread",
          "dll": "kernel32.dll",
          "risk_seviyesi": "Yüksek",
          "aciklama": "Uzak thread oluşturma - kod enjeksiyonu için kullanılabilir"
        }}
      ],
      "ag_api_cagirilari": ["connect", "send", "recv", "WSAStartup"],
      "dosya_api_cagirilari": ["CreateFile", "WriteFile", "DeleteFile"]
    }},
    "string_analizi": {{
      "supheli_stringler": ["cmd.exe", "powershell.exe", "reg.exe"],
      "url_listesi": ["http://malicious.com", "https://c2server.net"],
      "ip_adresleri": ["192.168.1.1", "10.0.0.1"],
      "dosya_yollari": ["C:\\\\Windows\\\\System32", "C:\\\\temp"],
      "registry_anahtarlari": ["HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"]
    }},
    "yara_eslesmeleri": [
      {{
        "kural_adi": "malware_family_xyz",
        "aciklama": "Belirli bir malware ailesini tespit eden kural",
        "risk_seviyesi": "Yüksek",
        "etiketler": ["trojan", "stealer"]
      }}
    ],
    "packer_obfuscation": {{
      "packer_tespit": "UPX/Themida/Yok",
      "obfuscation_teknikleri": ["String encryption", "Control flow obfuscation"],
      "anti_debug": true,
      "anti_vm": false,
      "entropi_analizi": "Genel dosya entropi: 7.2 (şüpheli)"
    }},
    "mitre_attack": [
      {{
        "teknik_id": "T1055",
        "teknik_adi": "Process Injection",
        "aciklama": "Başka bir sürecin adres alanına kod enjekte etme",
        "kanit": ["CreateRemoteThread", "VirtualAllocEx"]
      }}
    ],
    "ag_indikatörleri": {{
      "c2_sunuculari": ["malicious-domain.com", "192.168.1.100"],
      "dns_sorguları": ["evil.com", "badguy.net"],
      "protokoller": ["HTTP", "HTTPS", "TCP"],
      "portlar": [80, 443, 8080]
    }},
    "davranis_analizi": {{
      "sistem_degisiklikleri": ["Registry modification", "Service installation"],
      "dosya_operasyonlari": ["File encryption", "File deletion"],
      "ag_aktiviteleri": ["Data exfiltration", "Command receiving"],
      "persistance_teknikleri": ["Registry startup", "Scheduled task"]
    }},
    "virustotal_analizi": {{
      "tespit_orani": "15/65",
      "risk_seviyesi": "Yüksek",
      "tespit_eden_motorlar": [
        {{
          "antivirus": "Microsoft Defender",
          "sonuc": "Trojan:Win32/Malware.gen",
          "guvenilirlik": "Yüksek"
        }},
        {{
          "antivirus": "Kaspersky",
          "sonuc": "HEUR:Trojan.Win32.Generic",
          "guvenilirlik": "Yüksek"
        }}
      ],
      "temiz_bulan_motorlar": ["Norton", "Avira"],
      "malware_aileleri": ["Trojan", "Generic"],
      "ilk_tespit_tarihi": "2024-01-01",
      "genel_degerlendirme": "VirusTotal sonuçlarına göre değerlendirme"
    }},
    "anahtar_bulgular": [
      {{
        "bulgu": "Ana Risk Faktörü",
        "aciklama": "Detaylı teknik açıklama",
        "kanit": ["kanıt1", "kanıt2"],
        "risk_seviyesi": "Yüksek/Orta/Düşük"
      }}
    ]
  }},
  "ioc_listesi": {{
    "dosya_hashleri": ["md5_hash", "sha256_hash"],
    "ip_adresleri": ["1.2.3.4", "5.6.7.8"],
    "domain_listesi": ["malicious.com", "evil.net"],
    "url_listesi": ["http://bad.com/payload", "https://evil.net/data"],
    "registry_anahtarlari": ["HKLM\\\\...", "HKCU\\\\..."],
    "dosya_yollari": ["C:\\\\malware.exe", "C:\\\\temp\\\\payload.dll"],
    "mutex_listesi": ["Global\\\\UniqueMutexName"],
    "servis_listesi": ["MaliciousService"]
  }}
}}

[QUICKSCOPE_CIKTISI]
{qu1cksc0pe_raw_output}
[QUICKSCOPE_CIKTISI_SONU]"""

    def analyze_quickscope_output(self, quickscope_raw_output, file_name, md5=None, sha256=None, virustotal_data=None):
        """
        Qu1cksc0pe'un ham çıktısını Gemini AI ile analiz eder.
        
        Args:
            quickscope_raw_output (str): Qu1cksc0pe'un ham terminal çıktısı.
            file_name (str): Analiz edilen dosyanın adı.
            md5 (str): Dosyanın MD5 hash'i.
            sha256 (str): Dosyanın SHA256 hash'i.
            virustotal_data (dict): VirusTotal analiz sonuçları (varsa).
            
        Returns:
            dict: AI tarafından oluşturulan yapılandırılmış analiz raporu.
        """
        if not self.model:
            print("AI modeli yapılandırılmadığı için fallback analizi kullanılıyor.")
            return self._create_fallback_analysis(error="AI modeli yüklenemedi.", raw_quickscope_output=quickscope_raw_output)

        try:
            print("🤖 Gemini AI ile kapsamlı analiz başlatılıyor...")
            print(f"📝 Ham çıktı uzunluğu: {len(quickscope_raw_output)} karakter")
            
            # Tam çıktıyı hiç özetlemeden direkt gönder
            full_output = quickscope_raw_output
            
            # Sistem prompt'unu ve Qu1cksc0pe çıktısını birleştir
            system_prompt = self._get_analysis_prompt()
            
            # VirusTotal verisini prompt'a ekle
            vt_section = ""
            if virustotal_data and virustotal_data.get('total_scans', 0) > 0:
                vt_section = f"""

**VirusTotal Analiz Sonuçları:**
- Toplam tarayıcı: {virustotal_data.get('total_scans', 0)}
- Tespit eden tarayıcı: {virustotal_data.get('positive_detections', 0)}
- Tarama tarihi: {virustotal_data.get('scan_date', 'Bilinmiyor')}
- Tespit oranı: {(virustotal_data.get('positive_detections', 0) / virustotal_data.get('total_scans', 1)) * 100:.1f}%

**Detaylı VirusTotal Sonuçları:**
{json.dumps(virustotal_data.get('scan_results', []), indent=2, ensure_ascii=False)}

Bu VirusTotal verilerini de analiz raporuna dahil et ve risk değerlendirmesinde kullan.
"""

            full_prompt = system_prompt.format(qu1cksc0pe_raw_output=full_output) + vt_section

            print(f"📝 Tam prompt uzunluğu: {len(full_prompt)} karakter")
            print("🔄 Gemini AI'ya tam ham çıktı gönderiliyor...")
            
            # Gemini API çağrısı
            response = self.model.generate_content(full_prompt)

            print("✅ Gemini AI'dan yanıt alındı, parse ediliyor...")
            
            # Ham yanıtı kontrol et
            raw_response = response.text.strip()
            print(f"📝 Ham yanıt uzunluğu: {len(raw_response)} karakter")
            print(f"🔍 AI Yanıt Preview (ilk 1000 karakter):\n{raw_response[:1000]}")
            print(f"🔍 AI Yanıt Preview (son 500 karakter):\n{raw_response[-500:]}")
            
            # JSON'ı parse etmek için gelişmiş stratejiler
            ai_analysis_data = self._robust_json_parser(raw_response)

            # AI'dan gelen veriyi kendi standartlarımıza göre zenginleştirelim
            if 'rapor_ozeti' not in ai_analysis_data:
                ai_analysis_data['rapor_ozeti'] = {}
                
            ai_analysis_data['rapor_ozeti']['dosya_adi'] = file_name
            if md5:
                ai_analysis_data['rapor_ozeti']['md5'] = md5
            if sha256:
                ai_analysis_data['rapor_ozeti']['sha256'] = sha256
            ai_analysis_data['rapor_ozeti']['analiz_tarihi'] = datetime.now().isoformat()
            ai_analysis_data['ai_model'] = 'gemini-2.5-pro'
            
            print("✅ AI analizi başarıyla tamamlandı!")
            return ai_analysis_data
                
        except json.JSONDecodeError as e:
            print(f"❌ Gemini AI'dan gelen yanıt JSON formatında değil: {str(e)}")
            print(f"📝 JSON Hata Pozisyonu: {e.pos}")
            print(f"📝 Ham Yanıt (ilk 500 karakter):\n{raw_response[:500]}")
            return self._create_fallback_analysis(error=f"AI yanıtı parse edilemedi: {e}", raw_quickscope_output=full_output)
        except ValueError as e:
            print(f"❌ JSON yapısı hatası: {str(e)}")
            print(f"📝 Ham Yanıt (ilk 500 karakter):\n{raw_response[:500]}")
            return self._create_fallback_analysis(error=f"JSON yapısı hatası: {e}", raw_quickscope_output=full_output)
        except Exception as e:
            print(f"❌ Gemini AI analizi sırasında beklenmedik bir hata oluştu: {str(e)}")
            print(f"📝 Hata Tipi: {type(e).__name__}")
            if 'raw_response' in locals():
                print(f"📝 Ham Yanıt (ilk 500 karakter):\n{raw_response[:500]}")
            return self._create_fallback_analysis(error=str(e), raw_quickscope_output=full_output)

    def _create_fallback_analysis(self, error=None, raw_quickscope_output=None):
        """AI analizi başarısız olduğunda temel bir hata raporu oluşturur."""
        
        # Ham Qu1cksc0pe çıktısından bazı bilgileri çıkarmaya çalış
        basic_info = self._extract_basic_info_from_quickscope(raw_quickscope_output) if raw_quickscope_output else {}
        
        fallback_data = {
            "rapor_ozeti": {
                "dosya_adi": basic_info.get('file_name', 'bilinmiyor'),
                "md5": basic_info.get('md5', 'N/A'),
                "sha256": basic_info.get('sha256', 'N/A'),
                "tehlike_seviyesi": "BELİRSİZ",
                "risk_skoru": -1,
                "analiz_tarihi": datetime.now().isoformat(),
                "kisa_degerlendirme": "AI analizi sırasında bir hata oluştuğu için otomatik rapor oluşturulamadı. Ham analiz çıktısını manuel olarak inceleyin."
            },
            "kullanici_raporu": {
                "bu_dosya_ne_yapiyor": "Teknik bir sorun nedeniyle bu dosyanın ne yaptığı AI tarafından belirlenemedi. Bu, dosyanın güvenli olduğu anlamına gelmez.",
                "potansiyel_riskler": [
                    "Bilinmeyen riskler - AI analizi tamamlanamadı",
                    "Manuel inceleme gerekli",
                    "Güvenlik taramaları önerilir"
                ],
                "oneriler": [
                    "Ham Qu1cksc0pe çıktısını manuel olarak inceleyin.",
                    "Dosyayı güvenilir antivirüs yazılımlarıyla taratın.",
                    "Şüpheli dosyaları izole ortamda çalıştırın.",
                    "Analizi farklı bir zamanda yeniden deneyin."
                ]
            },
            "teknik_analiz": {
                "dosya_kimligi": {
                    "tip": basic_info.get('file_type', 'Belirlenemedi'),
                    "hedef_isletim_sistemi": basic_info.get('target_os', 'Bilinmiyor'),
                    "imphash": basic_info.get('imphash', 'N/A'),
                    "pdb_adi": basic_info.get('pdb_name', 'N/A')
                },
                "anahtar_bulgular": [{
                    "bulgu": "AI Analiz Hatası",
                    "aciklama": f"Otomatik analiz tamamlanamadı: {error or 'Bilinmeyen hata'}",
                    "kanit": ["Fallback analiz kullanıldı"]
                }],
                "yara_eslesmeleri": basic_info.get('yara_rules', []),
                "string_analizi": {
                    "supheli_stringler": basic_info.get('suspicious_strings', []),
                    "ip_adresleri": basic_info.get('ip_addresses', []),
                    "url_listesi": [],
                    "dosya_yollari": [],
                    "registry_anahtarlari": []
                },
                "section_analizi": [],
                "import_analizi": {
                    "dll_listesi": [],
                    "supheli_api_cagirilari": [],
                    "ag_api_cagirilari": [],
                    "dosya_api_cagirilari": []
                },
                "packer_obfuscation": {
                    "packer_tespit": "Bilinmiyor",
                    "obfuscation_teknikleri": [],
                    "anti_debug": False,
                    "anti_vm": False,
                    "entropi_analizi": "Analiz edilemedi"
                },
                "mitre_attack": [],
                "ag_indikatörleri": {
                    "c2_sunuculari": [],
                    "dns_sorguları": [],
                    "protokoller": [],
                    "portlar": []
                },
                "davranis_analizi": {
                    "sistem_degisiklikleri": [],
                    "dosya_operasyonlari": [],
                    "ag_aktiviteleri": [],
                    "persistance_teknikleri": []
                }
            },
            "ioc_listesi": {
                "dosya_hashleri": [basic_info.get('md5', ''), basic_info.get('sha256', '')],
                "ip_adresleri": basic_info.get('ip_addresses', []),
                "domain_listesi": [],
                "url_listesi": [],
                "registry_anahtarlari": [],
                "dosya_yollari": [],
                "mutex_listesi": [],
                "servis_listesi": []
            },
            "error": f"Analiz başarısız oldu: {error}",
            "ai_model": "fallback_analysis",
            "ham_quickscope_ciktisi": raw_quickscope_output[:2000] if raw_quickscope_output else "Mevcut değil"
        }
        return fallback_data

    def _extract_basic_info_from_quickscope(self, raw_output):
        """Ham Qu1cksc0pe çıktısından temel bilgileri çıkarır."""
        if not raw_output:
            return {}
            
        basic_info = {}
        lines = raw_output.split('\n')
        
        try:
            for line in lines:
                line_lower = line.lower().strip()
                
                # Dosya tipi
                if 'file type:' in line_lower or 'filetype:' in line_lower:
                    basic_info['file_type'] = line.split(':')[-1].strip()
                    
                # Target OS
                elif 'target os:' in line_lower or 'target operating system:' in line_lower:
                    basic_info['target_os'] = line.split(':')[-1].strip()
                    
                # MD5
                elif 'md5:' in line_lower and 'md5' not in basic_info:
                    basic_info['md5'] = line.split(':')[-1].strip()
                    
                # SHA256
                elif 'sha256:' in line_lower and 'sha256' not in basic_info:
                    basic_info['sha256'] = line.split(':')[-1].strip()
                    
                # PDB Name
                elif '.pdb' in line_lower:
                    basic_info['pdb_name'] = line.strip()
                    
                # Imphash
                elif 'imphash:' in line_lower:
                    basic_info['imphash'] = line.split(':')[-1].strip()
                    
                # YARA rules (basit çıkarım)
                elif 'yara' in line_lower and 'rule' in line_lower:
                    if 'yara_rules' not in basic_info:
                        basic_info['yara_rules'] = []
                    basic_info['yara_rules'].append({
                        'kural_adi': line.strip(),
                        'aciklama': 'Ham çıktıdan çıkarıldı'
                    })
                    
        except Exception as e:
            print(f"⚠️ Ham çıktıdan bilgi çıkarma hatası: {e}")
            
        return basic_info

    def _summarize_quickscope_output(self, raw_output):
        """Qu1cksc0pe'un ham çıktısını AI için özetler"""
        
        # Çıktı çok uzunsa kısalt
        if len(raw_output) > 5000:
            lines = raw_output.split('\n')
            important_lines = []
            
            # Önemli bölümleri filtrele
            for line in lines:
                line_lower = line.lower()
                # Önemli keyword'leri içeren satırları al
                if any(keyword in line_lower for keyword in [
                    'file type', 'target os', 'packer', 'entropy', 
                    'yara', 'suspicious', 'warning', 'error',
                    'ip address', 'domain', 'url', 'http',
                    'function', 'class', 'import', 'dll',
                    'signature', 'hash', 'md5', 'sha'
                ]):
                    important_lines.append(line)
                    
                # İlk 50 ve son 20 satırı her zaman dahil et
                if len(important_lines) == 0:  # Başlangıçta
                    important_lines.append(line)
                    
            # Maksimum 200 satır al
            summarized = '\n'.join(important_lines[:200])
            print(f"📝 Qu1cksc0pe çıktısı özetlendi: {len(raw_output)} -> {len(summarized)} karakter")
            return summarized
        else:
            return raw_output

    def _robust_json_parser(self, raw_response):
        """
        AI'dan gelen yanıtı güvenilir şekilde JSON olarak parse eder.
        Birden fazla strategi kullanarak başarı şansını artırır.
        """
        import re
        
        print("🔍 JSON parse işlemi başlatılıyor...")
        
        # Strategi 1: Markdown kod bloklarını temizle
        strategies = [
            {
                'name': 'Markdown JSON Code Block',
                'pattern': r'```json\s*\n(.*?)\n```',
                'flags': re.DOTALL,
                'group': 1
            },
            {
                'name': 'Generic Code Block',
                'pattern': r'```\s*\n(.*?)\n```',
                'flags': re.DOTALL,
                'group': 1
            },
            {
                'name': 'JSON Object Pattern',
                'pattern': r'(\{.*\})',
                'flags': re.DOTALL,
                'group': 1
            },
            {
                'name': 'Multiline JSON Search',
                'pattern': None,  # Özel işleme
                'flags': None,
                'group': None
            }
        ]
        
        for strategy in strategies:
            try:
                print(f"🔄 Denenen strateji: {strategy['name']}")
                
                if strategy['pattern']:
                    # Regex tabanlı stratejiler
                    matches = re.findall(strategy['pattern'], raw_response, strategy['flags'])
                    print(f"  📋 Bulunan eşleşme sayısı: {len(matches)}")
                    if matches:
                        candidate_json = matches[0] if isinstance(matches[0], str) else matches[0][strategy['group']-1]
                        candidate_json = candidate_json.strip()
                        print(f"  🔍 JSON adayı uzunluğu: {len(candidate_json)} karakter")
                        print(f"  🔍 JSON adayı preview (ilk 200 karakter): {candidate_json[:200]}")
                        
                        # JSON'ı parse etmeye çalış
                        parsed_data = json.loads(candidate_json)
                        print(f"✅ JSON başarıyla parse edildi: {strategy['name']}")
                        print(f"  📊 Parse edilen JSON ana anahtarları: {list(parsed_data.keys())}")
                        return parsed_data
                        
                else:
                    # Özel strateji: Satır satır JSON arama
                    result = self._line_by_line_json_search(raw_response)
                    if result:
                        print(f"✅ JSON başarıyla parse edildi: {strategy['name']}")
                        return result
                        
            except json.JSONDecodeError as e:
                print(f"❌ {strategy['name']} başarısız: {e}")
                continue
            except Exception as e:
                print(f"❌ {strategy['name']} beklenmedik hata: {e}")
                continue
        
        # Son çare: Ham yanıtın kendisini JSON olarak parse etmeye çalış
        try:
            print("🔄 Son çare: Ham yanıtı doğrudan parse etme")
            cleaned_response = raw_response.strip()
            # Başında ve sonunda potansiyel gereksiz karakterleri temizle
            if cleaned_response.startswith('```'):
                cleaned_response = '\n'.join(cleaned_response.split('\n')[1:-1])
            
            parsed_data = json.loads(cleaned_response)
            print("✅ Ham yanıt doğrudan parse edildi!")
            return parsed_data
            
        except json.JSONDecodeError as e:
            print(f"❌ Ham yanıt parse edilemedi: {e}")
            
        # Hiçbir strateji çalışmadı
        print("❌ Tüm JSON parse stratejileri başarısız oldu")
        print(f"📝 Ham yanıt preview (ilk 1000 karakter):\n{raw_response[:1000]}")
        print(f"📝 Ham yanıt preview (son 500 karakter):\n{raw_response[-500:]}")
        
        # Exception fırlat
        raise ValueError(f"JSON parse edilemedi. Ham yanıt uzunluğu: {len(raw_response)} karakter")

    def _line_by_line_json_search(self, raw_response):
        """
        Satır satır JSON bloğu arar ve parse eder.
        """
        lines = raw_response.split('\n')
        json_start = -1
        json_end = -1
        brace_count = 0
        
        # JSON başlangıcını bul
        for i, line in enumerate(lines):
            stripped_line = line.strip()
            if stripped_line.startswith('{'):
                json_start = i
                brace_count = line.count('{') - line.count('}')
                break
        
        if json_start == -1:
            return None
            
        # JSON bitişini bul
        for i in range(json_start + 1, len(lines)):
            line = lines[i]
            brace_count += line.count('{') - line.count('}')
            if brace_count == 0:
                json_end = i
                break
        
        if json_end == -1:
            return None
            
        # JSON bloğunu çıkar ve parse et
        candidate_json = '\n'.join(lines[json_start:json_end+1])
        try:
            return json.loads(candidate_json)
        except json.JSONDecodeError:
            return None
            
    # Eski metodları backward compatibility için saklayalım
    def analyze_quickscope_data(self, quickscope_data, file_info):
        """
        Geriye dönük uyumluluk için eski method imzası.
        Yeni analyze_quickscope_output metodunu kullanır.
        """
        print("⚠️ UYARI: analyze_quickscope_data metodu deprecated. analyze_quickscope_output kullanın.")
        
        # Eski formatı yeni formata çevir
        raw_output = quickscope_data.get('raw_output', str(quickscope_data))
        file_name = file_info.get('original_name', file_info.get('name', 'bilinmiyor'))
        md5 = file_info.get('md5')
        sha256 = file_info.get('sha256')
        
        return self.analyze_quickscope_output(raw_output, file_name, md5, sha256)

