#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI Analyzer - Qu1cksc0pe çıktılarını OpenAI API ile analiz eden modül
Geliştirilmiş prompt ve yapılandırılmış JSON çıktısı ile
"""

import os
import json
import openai
from datetime import datetime

class AIAnalyzer:
    """Qu1cksc0pe çıktılarını OpenAI GPT ile analiz eden sınıf"""
    
    def __init__(self, api_key=None):
        """
        Args:
            api_key (str): OpenAI API anahtarı
        """
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        self.client = None
        
        if not self.api_key:
            print("⚠️  UYARI: OpenAI API anahtarı bulunamadı. AI analizi çalışmayacak.")
        else:
            try:
                import openai
                self.client = openai.OpenAI(api_key=self.api_key)
                print("✅ OpenAI GPT-4 başarıyla yapılandırıldı!")
            except Exception as e:
                print(f"❌ OpenAI yapılandırma hatası: {str(e)}")
                self.client = None

    def _get_analysis_prompt(self):
        """Structured Output için optimize edilmiş AI prompt'u - Qu1cksc0pe'nin tüm detaylarını kapsayacak"""
        return """Analyze the raw output of Qu1cksc0pe malware analysis tool and create a comprehensive security report.

**ANALYSIS TASK:**
Analyze all details of the provided Qu1cksc0pe output and report everything in structured JSON format without missing any details:

1. **File Identity Information:** File type, size, target operating system, timestamp
2. **Hash Analysis:** MD5, SHA1, SHA256, Imphash values (exactly as shown in output)
3. **Section Analysis:** All sections (.text, .rsrc, .reloc etc.) with details:
   - Section name, Virtual Size, Virtual Address, Raw Data Size, Entropy
   - Flag obfuscation risk if entropy > 7
4. **Function/String Categories:** Analyze each category in detail:
   - File operations (CreateDirectory, GetFolderPath, etc.)
   - Networking/Web (connect, send, bind, ping, etc.)
   - Process operations (STAThreadAttribute, etc.)
   - Dll/Resource Handling (get_ResourceManager, System.Resources, etc.)
   - Evasion/Bypassing (DebuggableAttribute, DebuggerNonUserCodeAttribute, etc.)
   - Cryptography (GetHashCode, etc.)
   - Information Gathering (get_CurrentDomain, etc.)
   - All functions in Other/Unknown categories
5. **.NET Class/Method Analysis:** List all classes and their methods:
   - ModernAdapter.Program, BusinessLogic, DataAccess, DataRecord, MainForm, Form2-7, Properties.Resources, Properties.Settings
   - Count all methods in each class and list important ones
6. **YARA Rules:** All matching rules with details:
   - dotnet_binary_file, Microsoft_Visual_Studio_NET, NET_executable etc.
   - Matching offset and string values for each rule
7. **Magic Number Analysis:** Detected file types with their patterns:
   - Windows Executable File (MZ signature)
   - PNG file patterns
   - Offset information
8. **Language Detection:** Programming language detection:
   - Ratios like C# 60%, C 40%
   - Pattern occurrence counts
9. **DLL Dependencies:** Linked DLL files (mscoree.dll etc.)
10. **Interesting Strings:** jIXC.pdb, jIXC.exe, mscoree.dll, System.Config etc.
11. **Debug Information:** PDB name and Debug Signature
12. **IP/Domain Analysis:** Detected IP addresses (1.0.0.0, 16.0.0.0 etc.)
13. **VirusTotal Results:** All detailed detection results if available
14. **Function Statistics:** Categories and counts table

**IMPORTANT NOTES:**
- Analyze ALL functions/strings listed in ALL categories in Qu1cksc0pe output
- Report empty categories as well
- WARNING markers are important security indicators
- Sections with entropy > 7 pose obfuscation risk
- Report all YARA rule matches with details
- Specify magic number patterns and offsets exactly
- Transfer language detection ratios correctly

**RISK ASSESSMENT:**
- **CRITICAL (90-100):** Confirmed malware, multiple AV detections (>30), active C&C, data theft, anti-debug
- **HIGH (70-89):** Strong malware indicators, moderate AV detections (15-30), suspicious network activity
- **MEDIUM (40-69):** Some suspicious features, low AV detections (5-15), obfuscation
- **LOW (0-39):** Minimal risk indicators, few AV detections (<5)

**Qu1cksc0pe Output:**
{qu1cksc0pe_raw_output}

Report all findings in structured JSON format with English language. Include user-friendly explanations and technical details."""

    def analyze_quickscope_output(self, quickscope_raw_output, file_name, md5=None, sha256=None, virustotal_data=None):
        """
        Qu1cksc0pe'un ham çıktısını OpenAI GPT ile analiz eder.
        
        Args:
            quickscope_raw_output (str): Qu1cksc0pe'un ham terminal çıktısı.
            file_name (str): Analiz edilen dosyanın adı.
            md5 (str): Dosyanın MD5 hash'i.
            sha256 (str): Dosyanın SHA256 hash'i.
            virustotal_data (dict): VirusTotal analiz sonuçları (varsa).
            
        Returns:
            dict: AI tarafından oluşturulan yapılandırılmış analiz raporu.
        """
        if not self.client:
            print("Using fallback analysis since AI model is not configured.")
            return self._create_fallback_analysis(error="AI model could not be loaded.", raw_quickscope_output=quickscope_raw_output)

        try:
            print("🤖 Starting comprehensive analysis with OpenAI GPT-4...")
            print(f"📝 Raw output length: {len(quickscope_raw_output)} characters")
            
            # Özel karakterleri temizle ve safe hale getir
            full_output = self._sanitize_quickscope_output(quickscope_raw_output)
            print(f"📝 Sanitized output length: {len(full_output)} characters")
            
            # Sistem prompt'unu ve Qu1cksc0pe çıktısını birleştir
            system_prompt = self._get_analysis_prompt()
            
            # VirusTotal verisini prompt'a ekle
            vt_section = ""
            if virustotal_data and virustotal_data.get('total_scans', 0) > 0:
                vt_section = f"""

**VirusTotal Analysis Results:**
- Total scanners: {virustotal_data.get('total_scans', 0)}
- Detecting scanners: {virustotal_data.get('positive_detections', 0)}
- Scan date: {virustotal_data.get('scan_date', 'Unknown')}
- Detection ratio: {(virustotal_data.get('positive_detections', 0) / virustotal_data.get('total_scans', 1)) * 100:.1f}%

**Detailed VirusTotal Results:**
{json.dumps(virustotal_data.get('scan_results', []), indent=2, ensure_ascii=False)}

Include this VirusTotal data in the analysis report and use it in risk assessment.
"""

            full_prompt = system_prompt.format(qu1cksc0pe_raw_output=full_output) + vt_section

            print(f"📝 Full prompt length: {len(full_prompt)} characters")
            print("🔄 Sending full raw output to OpenAI GPT...")
            
            # OpenAI API çağrısı - Structured Output ile
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {
                        "role": "system", 
                        "content": "You are a Senior Malware Analyst specialized in cybersecurity. You analyze Qu1cksc0pe malware analysis tool outputs and create comprehensive reports."
                    },
                    {
                        "role": "user", 
                        "content": full_prompt
                    }
                ],
                temperature=0.3,
                max_tokens=16384,  # Token limitini düşür
                response_format={
                    "type": "json_schema",
                    "json_schema": {
                        "name": "malware_analysis_report",
                        "strict": True,
                        "schema": self._get_json_schema()
                    }
                }
            )

            print("✅ Structured response received from OpenAI, parsing...")
            
            # Structured Output sayesinde yanıt garantili JSON formatında
            raw_response = response.choices[0].message.content.strip()
            print(f"📝 Structured response length: {len(raw_response)} characters")
            
            # Structured output ile gelen JSON doğrudan parse edilebilir
            try:
                ai_analysis_data = json.loads(raw_response)
                print("✅ Structured JSON parsed successfully!")
                print(f"📊 Main sections: {list(ai_analysis_data.keys())}")
            except json.JSONDecodeError as e:
                print(f"⚠️ Structured output parse error (using fallback): {e}")
                # Eski robust parser'ı fallback olarak kullan
                ai_analysis_data = self._robust_json_parser(raw_response)

            # AI'dan gelen veriyi kendi standartlarımıza göre zenginleştirelim
            if 'report_summary' not in ai_analysis_data:
                ai_analysis_data['report_summary'] = {}
                
            ai_analysis_data['report_summary']['file_name'] = file_name
            if md5:
                ai_analysis_data['report_summary']['md5'] = md5
            if sha256:
                ai_analysis_data['report_summary']['sha256'] = sha256
            ai_analysis_data['report_summary']['analysis_date'] = datetime.now().isoformat()
            ai_analysis_data['ai_model'] = 'gpt-4o-structured'
            
            print("✅ AI analysis completed successfully!")
            return ai_analysis_data
                
        except Exception as e:
            print(f"❌ OpenAI API error: {str(e)}")
            
            # Eğer JSON parse hatası ise, chunked analysis dene
            if "JSON could not be parsed" in str(e) or "Unterminated string" in str(e):
                print("🔄 Trying chunked analysis as fallback...")
                return self._try_chunked_analysis(full_output, file_name, md5, sha256, virustotal_data)
            
            return self._create_fallback_analysis(error=f"OpenAI API error: {e}", raw_quickscope_output=full_output)

    def _create_fallback_analysis(self, error=None, raw_quickscope_output=None):
        """Creates a basic error report when AI analysis fails."""
        
        # Ham Qu1cksc0pe çıktısından bazı bilgileri çıkarmaya çalış
        basic_info = self._extract_basic_info_from_quickscope(raw_quickscope_output) if raw_quickscope_output else {}
        
        fallback_data = {
            "report_summary": {
                "file_name": basic_info.get('file_name', 'unknown'),
                "md5": basic_info.get('md5', 'N/A'),
                "sha256": basic_info.get('sha256', 'N/A'),
                "imphash": basic_info.get('imphash', 'N/A'),
                "file_type": basic_info.get('file_type', 'Unknown'),
                "target_os": basic_info.get('target_os', 'Unknown'),
                "threat_level": "UNCLEAR",
                "risk_score": -1,
                "analysis_date": datetime.now().isoformat(),
                "brief_assessment": "Automatic report could not be generated due to an error during AI analysis. Please manually examine the raw analysis output."
            },
            "user_report": {
                "what_does_this_file_do": "Due to a technical issue, what this file does could not be determined by AI. This does not mean the file is safe.",
                "potential_risks": [
                    "Unknown risks - AI analysis could not be completed",
                    "Manual examination required",
                    "Security scans recommended"
                ],
                "recommendations": [
                    "Manually examine the raw Qu1cksc0pe output.",
                    "Scan the file with trusted antivirus software.",
                    "Run suspicious files in isolated environment.",
                    "Retry the analysis at a different time."
                ],
                "malware_type": "Unknown - Analysis failed"
            },
            "technical_analysis": {
                "file_identity": {
                    "details": f"Type: {basic_info.get('file_type', 'Unknown')}, Target OS: {basic_info.get('target_os', 'Unknown')}, Imphash: {basic_info.get('imphash', 'N/A')}, PDB: {basic_info.get('pdb_name', 'N/A')}",
                    "ai_analysis": "File identity could not be fully analyzed due to AI processing error."
                },
                "section_analysis": {
                    "summary": "Section analysis could not be completed",
                    "section_details": [],
                    "ai_analysis": "Section analysis was not possible due to AI processing limitations."
                },
                "function_categories": {
                    "categories": [],
                    "ai_analysis": "Function categorization could not be performed due to analysis failure."
                },
                "dotnet_classes": {
                    "classes": [],
                    "ai_analysis": ".NET class analysis was not completed due to processing error."
                },
                "dll_files": {
                    "dll_list": [],
                    "ai_analysis": "DLL dependency analysis could not be performed."
                },
                "yara_rules": {
                    "matches": basic_info.get('yara_rules', []),
                    "ai_analysis": "YARA rule analysis was limited due to processing constraints."
                },
                "magic_numbers": {
                    "detections": [],
                    "ai_analysis": "Magic number analysis could not be completed."
                },
                "programming_language": {
                    "detected_languages": [],
                    "primary_language": "Unknown",
                    "ai_analysis": "Programming language detection failed during analysis."
                },
                "interesting_strings": {
                    "strings": basic_info.get('suspicious_strings', []),
                    "ai_analysis": "String analysis was incomplete due to processing error."
                },
                "embedded_files": {
                    "description": "Could not analyze embedded files",
                    "ai_analysis": "Embedded file analysis was not possible."
                },
                "debug_information": {
                    "pdb_name": basic_info.get('pdb_name', 'N/A'),
                    "debug_signature": "N/A",
                    "ai_analysis": "Debug information analysis was limited."
                },
                "key_findings": {
                    "findings": [f"AI Analysis Error: Automatic analysis could not be completed: {error or 'Unknown error'}"],
                    "ai_analysis": "Key findings could not be determined due to analysis failure."
                }
            },
            "virustotal_analysis": {
                "detection_ratio": "N/A",
                "detection_count": 0,
                "total_scanners": 0,
                "threat_labels": [],
                "important_detections": [],
                "overall_assessment": "VirusTotal analysis not available due to processing error."
            },
            "mitre_attack": [],
            "ioc_list": {
                "file_hashes": [basic_info.get('md5', ''), basic_info.get('sha256', '')],
                "ip_addresses": basic_info.get('ip_addresses', []),
                "domain_list": [],
                "url_list": [],
                "pdb_information": [basic_info.get('pdb_name', '')] if basic_info.get('pdb_name') else []
            },
            "error": f"Analysis failed: {error}",
            "ai_model": "fallback_analysis",
            "raw_quickscope_output": raw_quickscope_output[:2000] if raw_quickscope_output else "Not available"
        }
        return fallback_data

    def _extract_basic_info_from_quickscope(self, raw_output):
        """Extracts basic information from raw Qu1cksc0pe output."""
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
                        'rule_name': line.strip(),
                        'description': 'Extracted from raw output'
                    })
                    
        except Exception as e:
            print(f"⚠️ Error extracting info from raw output: {e}")
            
        return basic_info

    def _summarize_quickscope_output(self, raw_output):
        """Summarizes Qu1cksc0pe's raw output for AI"""
        
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
            print(f"📝 Qu1cksc0pe output summarized: {len(raw_output)} -> {len(summarized)} characters")
            return summarized
        else:
            return raw_output

    def _robust_json_parser(self, raw_response):
        """
        Parses AI response as JSON safely.
        Uses multiple strategies to increase success rate.
        """
        import re
        
        print("🔍 Starting JSON parse process...")
        
        # Strategy 1: Clean markdown code blocks
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
                'pattern': None,  # Special processing
                'flags': None,
                'group': None
            }
        ]
        
        for strategy in strategies:
            try:
                print(f"🔄 Trying strategy: {strategy['name']}")
                
                if strategy['pattern']:
                    # Regex-based strategies
                    matches = re.findall(strategy['pattern'], raw_response, strategy['flags'])
                    print(f"  📋 Found matches: {len(matches)}")
                    if matches:
                        candidate_json = matches[0] if isinstance(matches[0], str) else matches[0][strategy['group']-1]
                        candidate_json = candidate_json.strip()
                        print(f"  🔍 JSON candidate length: {len(candidate_json)} characters")
                        print(f"  🔍 JSON candidate preview (first 200 chars): {candidate_json[:200]}")
                        
                        # Try to parse JSON
                        parsed_data = json.loads(candidate_json)
                        print(f"✅ JSON successfully parsed: {strategy['name']}")
                        print(f"  📊 Parsed JSON main keys: {list(parsed_data.keys())}")
                        return parsed_data
                        
                else:
                    # Special strategy: Line-by-line JSON search
                    result = self._line_by_line_json_search(raw_response)
                    if result:
                        print(f"✅ JSON successfully parsed: {strategy['name']}")
                        return result
                        
            except json.JSONDecodeError as e:
                print(f"❌ {strategy['name']} failed: {e}")
                continue
            except Exception as e:
                print(f"❌ {strategy['name']} unexpected error: {e}")
                continue
        
        # Last resort: Try to parse raw response as JSON
        try:
            print("🔄 Last resort: Direct raw response parsing")
            cleaned_response = raw_response.strip()
            # Clean potential unnecessary characters at beginning and end
            if cleaned_response.startswith('```'):
                cleaned_response = '\n'.join(cleaned_response.split('\n')[1:-1])
            
            parsed_data = json.loads(cleaned_response)
            print("✅ Raw response parsed directly!")
            return parsed_data
            
        except json.JSONDecodeError as e:
            print(f"❌ Raw response could not be parsed: {e}")
            
        # No strategy worked
        print("❌ All JSON parse strategies failed")
        print(f"📝 Raw response preview (first 1000 chars):\n{raw_response[:1000]}")
        print(f"📝 Raw response preview (last 500 chars):\n{raw_response[-500:]}")
        
        # Throw exception
        raise ValueError(f"JSON could not be parsed. Raw response length: {len(raw_response)} characters")

    def _line_by_line_json_search(self, raw_response):
        """
        Searches for JSON block line by line and parses it.
        """
        lines = raw_response.split('\n')
        json_start = -1
        json_end = -1
        brace_count = 0
        
        # Find JSON start
        for i, line in enumerate(lines):
            stripped_line = line.strip()
            if stripped_line.startswith('{'):
                json_start = i
                brace_count = line.count('{') - line.count('}')
                break
        
        if json_start == -1:
            return None
            
        # Find JSON end
        for i in range(json_start + 1, len(lines)):
            line = lines[i]
            brace_count += line.count('{') - line.count('}')
            if brace_count == 0:
                json_end = i
                break
        
        if json_end == -1:
            return None
            
        # Extract JSON block and parse
        candidate_json = '\n'.join(lines[json_start:json_end+1])
        try:
            return json.loads(candidate_json)
        except json.JSONDecodeError:
            return None
            
    def _get_json_schema(self):
        """OpenAI Structured Output için genişletilmiş JSON schema - Her teknik analiz bölümünde AI analizi ile"""
        return {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "report_summary": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "file_name": {"type": "string"},
                        "md5": {"type": "string"},
                        "sha256": {"type": "string"},
                        "imphash": {"type": "string"},
                        "file_type": {"type": "string"},
                        "target_os": {"type": "string"},
                        "threat_level": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNCLEAR"]},
                        "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
                        "brief_assessment": {"type": "string"}
                    },
                    "required": ["file_name", "md5", "sha256", "imphash", "file_type", "target_os", "threat_level", "risk_score", "brief_assessment"]
                },
                "user_report": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "what_does_this_file_do": {"type": "string"},
                        "potential_risks": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "recommendations": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "malware_type": {"type": "string"}
                    },
                    "required": ["what_does_this_file_do", "potential_risks", "recommendations", "malware_type"]
                },
                "technical_analysis": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "file_identity": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "details": {"type": "string"},
                                "ai_analysis": {"type": "string"}
                            },
                            "required": ["details", "ai_analysis"]
                        },
                        "section_analysis": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "summary": {"type": "string"},
                                "section_details": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "additionalProperties": False,
                                        "properties": {
                                            "section_name": {"type": "string"},
                                            "virtual_size": {"type": "string"},
                                            "virtual_address": {"type": "string"},
                                            "raw_data_size": {"type": "string"},
                                            "entropy": {"type": "string"},
                                            "risk_analysis": {"type": "string"}
                                        },
                                        "required": ["section_name", "virtual_size", "virtual_address", "raw_data_size", "entropy", "risk_analysis"]
                                    }
                                },
                                "ai_analysis": {"type": "string"}
                            },
                            "required": ["summary", "section_details", "ai_analysis"]
                        },
                        "function_categories": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "categories": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "additionalProperties": False,
                                        "properties": {
                                            "category": {"type": "string"},
                                            "count": {"type": "integer"},
                                            "functions": {
                                                "type": "array",
                                                "items": {"type": "string"}
                                            },
                                            "risk_level": {"type": "string"}
                                        },
                                        "required": ["category", "count", "functions", "risk_level"]
                                    }
                                },
                                "ai_analysis": {"type": "string"}
                            },
                            "required": ["categories", "ai_analysis"]
                        },
                        "dotnet_classes": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "classes": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "additionalProperties": False,
                                        "properties": {
                                            "class_name": {"type": "string"},
                                            "method_count": {"type": "integer"},
                                            "important_methods": {
                                                "type": "array",
                                                "items": {"type": "string"}
                                            }
                                        },
                                        "required": ["class_name", "method_count", "important_methods"]
                                    }
                                },
                                "ai_analysis": {"type": "string"}
                            },
                            "required": ["classes", "ai_analysis"]
                        },
                        "dll_files": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "dll_list": {
                                    "type": "array",
                                    "items": {"type": "string"}
                                },
                                "ai_analysis": {"type": "string"}
                            },
                            "required": ["dll_list", "ai_analysis"]
                        },
                        "yara_rules": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "matches": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "additionalProperties": False,
                                        "properties": {
                                            "rule_name": {"type": "string"},
                                            "rule_matches": {
                                                "type": "array",
                                                "items": {
                                                    "type": "object",
                                                    "additionalProperties": False,
                                                    "properties": {
                                                        "offset": {"type": "string"},
                                                        "value": {"type": "string"}
                                                    },
                                                    "required": ["offset", "value"]
                                                }
                                            }
                                        },
                                        "required": ["rule_name", "rule_matches"]
                                    }
                                },
                                "ai_analysis": {"type": "string"}
                            },
                            "required": ["matches", "ai_analysis"]
                        },
                        "magic_numbers": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "detections": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "additionalProperties": False,
                                        "properties": {
                                            "file_type": {"type": "string"},
                                            "pattern": {"type": "string"},
                                            "offset": {"type": "string"}
                                        },
                                        "required": ["file_type", "pattern", "offset"]
                                    }
                                },
                                "ai_analysis": {"type": "string"}
                            },
                            "required": ["detections", "ai_analysis"]
                        },
                        "programming_language": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "detected_languages": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "additionalProperties": False,
                                        "properties": {
                                            "language": {"type": "string"},
                                            "probability": {"type": "number"},
                                            "pattern_count": {"type": "integer"}
                                        },
                                        "required": ["language", "probability", "pattern_count"]
                                    }
                                },
                                "primary_language": {"type": "string"},
                                "ai_analysis": {"type": "string"}
                            },
                            "required": ["detected_languages", "primary_language", "ai_analysis"]
                        },
                        "interesting_strings": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "strings": {
                                    "type": "array",
                                    "items": {"type": "string"}
                                },
                                "ai_analysis": {"type": "string"}
                            },
                            "required": ["strings", "ai_analysis"]
                        },
                        "embedded_files": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "description": {"type": "string"},
                                "ai_analysis": {"type": "string"}
                            },
                            "required": ["description", "ai_analysis"]
                        },
                        "debug_information": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "pdb_name": {"type": "string"},
                                "debug_signature": {"type": "string"},
                                "ai_analysis": {"type": "string"}
                            },
                            "required": ["pdb_name", "debug_signature", "ai_analysis"]
                        },
                        "key_findings": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "findings": {
                                    "type": "array",
                                    "items": {"type": "string"}
                                },
                                "ai_analysis": {"type": "string"}
                            },
                            "required": ["findings", "ai_analysis"]
                        }
                    },
                    "required": ["file_identity", "section_analysis", "function_categories", "dotnet_classes", "dll_files", "yara_rules", "magic_numbers", "programming_language", "interesting_strings", "embedded_files", "debug_information", "key_findings"]
                },
                "virustotal_analysis": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "detection_ratio": {"type": "string"},
                        "detection_count": {"type": "integer"},
                        "total_scanners": {"type": "integer"},
                        "threat_labels": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "important_detections": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": False,
                                "properties": {
                                    "engine": {"type": "string"},
                                    "detection": {"type": "string"}
                                },
                                "required": ["engine", "detection"]
                            }
                        },
                        "overall_assessment": {"type": "string"}
                    },
                    "required": ["detection_ratio", "detection_count", "total_scanners", "threat_labels", "important_detections", "overall_assessment"]
                },
                "mitre_attack": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "ioc_list": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "file_hashes": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "ip_addresses": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "domain_list": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "url_list": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "pdb_information": {
                            "type": "array",
                            "items": {"type": "string"}
                        }
                    },
                    "required": ["file_hashes", "ip_addresses", "domain_list", "url_list", "pdb_information"]
                }
            },
            "required": ["report_summary", "user_report", "technical_analysis", "virustotal_analysis", "mitre_attack", "ioc_list"]
        }

    def _sanitize_quickscope_output(self, raw_output):
        """
        Sanitizes Qu1cksc0pe output to prevent JSON parsing issues.
        Removes problematic characters and limits size.
        """
        import re
        
        if not raw_output:
            return ""
            
        # 1. Binary/Hex data temizleme
        sanitized = raw_output
        
        # Null karakterleri temizle
        sanitized = sanitized.replace('\x00', '[NULL]')
        
        # Çok uzun hex stringleri kısalt
        hex_pattern = r'\\x[0-9a-fA-F]{2}'
        # Ardışık 20'den fazla hex karakteri kısalt
        def replace_long_hex(match):
            hex_sequence = match.group(0)
            if len(hex_sequence) > 100:  # 50 hex karakter = 100 char
                return hex_sequence[:50] + '...[HEX_TRUNCATED]...' + hex_sequence[-20:]
            return hex_sequence
        
        sanitized = re.sub(r'(' + hex_pattern + r'){20,}', replace_long_hex, sanitized)
        
        # 2. Özel karakterleri escape et
        sanitized = sanitized.replace('\\', '\\\\')
        sanitized = sanitized.replace('"', '\\"')
        
        # 3. Çok uzun satırları kısalt
        lines = sanitized.split('\n')
        processed_lines = []
        
        for line in lines:
            if len(line) > 1000:  # 1000 karakterden uzun satırları kısalt
                processed_lines.append(line[:500] + '...[LINE_TRUNCATED]...' + line[-200:])
            else:
                processed_lines.append(line)
        
        sanitized = '\n'.join(processed_lines)
        
        # 4. Toplam uzunluğu kontrol et
        if len(sanitized) > 25000:  # 25K karakterle sınırla
            print(f"⚠️  Large output detected ({len(sanitized)} chars), truncating...")
            # Baştan ve sondan al, ortayı kısalt
            sanitized = sanitized[:12000] + '\n\n...[MIDDLE_CONTENT_TRUNCATED]...\n\n' + sanitized[-10000:]
            print(f"📝 Truncated to {len(sanitized)} characters")
        
        return sanitized

    def _try_chunked_analysis(self, sanitized_output, file_name, md5, sha256, virustotal_data):
        """
        Fallback method: Analyze in smaller chunks if main analysis fails.
        """
        print("🔄 Trying chunked analysis fallback...")
        
        # Önemli bölümleri çıkar
        chunks = self._extract_important_chunks(sanitized_output)
        
        simplified_prompt = """Analyze this Qu1cksc0pe malware analysis output chunk and extract key information:

**Instructions:**
- Focus on the most critical findings
- Provide concise analysis
- Use shorter descriptions
- Avoid long lists

**Qu1cksc0pe Output Chunk:**
{chunk_content}

Provide a focused analysis in the required JSON format."""

        try:
            # Her chunk için ayrı analiz yap
            chunk_analyses = []
            
            for i, chunk in enumerate(chunks[:3]):  # Max 3 chunk
                print(f"📝 Analyzing chunk {i+1}/{len(chunks[:3])}...")
                
                chunk_prompt = simplified_prompt.format(chunk_content=chunk)
                
                response = self.client.chat.completions.create(
                    model="gpt-4o",
                    messages=[
                        {
                            "role": "system", 
                            "content": "You are a malware analyst. Provide concise analysis."
                        },
                        {
                            "role": "user", 
                            "content": chunk_prompt
                        }
                    ],
                    temperature=0.3,
                    max_tokens=4096,  # Daha kısa response
                    response_format={
                        "type": "json_schema",
                        "json_schema": {
                            "name": "chunk_analysis",
                            "strict": True,
                            "schema": self._get_simplified_json_schema()
                        }
                    }
                )
                
                chunk_data = json.loads(response.choices[0].message.content)
                chunk_analyses.append(chunk_data)
            
            # Chunk'ları birleştir
            merged_analysis = self._merge_chunk_analyses(chunk_analyses, file_name, md5, sha256, virustotal_data)
            print("✅ Chunked analysis completed successfully!")
            return merged_analysis
            
        except Exception as e:
            print(f"❌ Chunked analysis also failed: {e}")
            return self._create_fallback_analysis(error=f"All analysis methods failed: {e}", raw_quickscope_output=sanitized_output)

    def _extract_important_chunks(self, sanitized_output):
        """Extract important sections from sanitized output."""
        lines = sanitized_output.split('\n')
        chunks = []
        current_chunk = []
        chunk_size = 0
        max_chunk_size = 8000  # 8K per chunk
        
        for line in lines:
            if chunk_size + len(line) > max_chunk_size:
                if current_chunk:
                    chunks.append('\n'.join(current_chunk))
                    current_chunk = []
                    chunk_size = 0
            
            current_chunk.append(line)
            chunk_size += len(line)
        
        if current_chunk:
            chunks.append('\n'.join(current_chunk))
        
        return chunks

    def _get_simplified_json_schema(self):
        """Simplified schema for chunked analysis."""
        return {
            "type": "object",
            "properties": {
                "key_findings": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "risk_indicators": {
                    "type": "array", 
                    "items": {"type": "string"}
                },
                "technical_details": {"type": "string"}
            },
            "required": ["key_findings", "risk_indicators", "technical_details"],
            "additionalProperties": False
        }

    def _merge_chunk_analyses(self, chunk_analyses, file_name, md5, sha256, virustotal_data):
        """Merge multiple chunk analyses into final report."""
        
        # Tüm bulguları topla
        all_findings = []
        all_risks = []
        all_technical = []
        
        for chunk in chunk_analyses:
            all_findings.extend(chunk.get('key_findings', []))
            all_risks.extend(chunk.get('risk_indicators', []))
            all_technical.append(chunk.get('technical_details', ''))
        
        # Risk skorunu hesapla
        risk_score = min(85, len(all_risks) * 15)  # Risk sayısına göre
        
        # Simplified but complete report
        merged_report = {
            "report_summary": {
                "file_name": file_name,
                "md5": md5 or "N/A",
                "sha256": sha256 or "N/A", 
                "imphash": "N/A",
                "file_type": "Unknown",
                "target_os": "Unknown",
                "threat_level": "HIGH" if risk_score > 70 else "MEDIUM",
                "risk_score": risk_score,
                "brief_assessment": f"Chunked analysis detected {len(all_findings)} key findings and {len(all_risks)} risk indicators."
            },
            "user_report": {
                "what_does_this_file_do": "Analysis completed using chunked processing due to size constraints.",
                "potential_risks": all_risks[:10],  # Top 10 risks
                "recommendations": [
                    "Full analysis recommended with smaller input",
                    "Manual review of identified risks",
                    "Quarantine until further analysis"
                ],
                "malware_type": "Requires full analysis"
            },
            "technical_analysis": {
                "file_identity": {
                    "details": "Chunked analysis mode - limited details available",
                    "ai_analysis": "Analysis performed in chunks due to size constraints"
                },
                "section_analysis": {
                    "summary": "Section analysis limited in chunked mode",
                    "section_details": [],
                    "ai_analysis": "Full section analysis requires complete processing"
                },
                "function_categories": {
                    "categories": [],
                    "ai_analysis": "Function analysis limited in chunked mode"
                },
                "dotnet_classes": {
                    "classes": [],
                    "ai_analysis": "Class analysis limited in chunked mode"
                },
                "dll_files": {
                    "dll_list": [],
                    "ai_analysis": "DLL analysis limited in chunked mode"
                },
                "yara_rules": {
                    "matches": [],
                    "ai_analysis": "YARA analysis limited in chunked mode"
                },
                "magic_numbers": {
                    "detections": [],
                    "ai_analysis": "Magic number analysis limited in chunked mode"
                },
                "programming_language": {
                    "detected_languages": [],
                    "primary_language": "Unknown",
                    "ai_analysis": "Language detection limited in chunked mode"
                },
                "interesting_strings": {
                    "strings": [],
                    "ai_analysis": "String analysis limited in chunked mode"
                },
                "embedded_files": {
                    "description": "Analysis limited in chunked mode",
                    "ai_analysis": "Embedded file analysis requires full processing"
                },
                "debug_information": {
                    "pdb_name": "N/A",
                    "debug_signature": "N/A",
                    "ai_analysis": "Debug info analysis limited in chunked mode"
                },
                "key_findings": {
                    "findings": all_findings[:15],  # Top 15 findings
                    "ai_analysis": ' '.join(all_technical)[:1000]  # Combined technical analysis
                }
            },
            "virustotal_analysis": {
                "detection_ratio": "N/A",
                "detection_count": 0,
                "total_scanners": 0,
                "threat_labels": [],
                "important_detections": [],
                "overall_assessment": "VirusTotal analysis limited in chunked mode"
            },
            "mitre_attack": [],
            "ioc_list": {
                "file_hashes": [md5 or "", sha256 or ""],
                "ip_addresses": [],
                "domain_list": [],
                "url_list": [],
                "pdb_information": []
            },
            "ai_model": "gpt-4o-chunked"
        }
        
        return merged_report

