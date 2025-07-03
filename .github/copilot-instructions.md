<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# Malware Analysis Platform - Copilot Instructions

Bu proje, malware analizi için geliştirilmiş bir Flask web uygulamasıdır. Lütfen aşağıdaki kılavuzları takip edin:

## Proje Yapısı
- **Backend**: Flask ile RESTful API
- **Frontend**: Modern HTML/CSS/JavaScript
- **Analiz Motoru**: Qu1cksc0pe entegrasyonu
- **AI**: OpenAI API ile rapor analizi

## Kodlama Standartları
- Python için PEP 8 standartlarını kullanın
- Türkçe yorumlar ve değişken isimleri tercih edilir
- Güvenlik odaklı kod yazımına dikkat edin
- Error handling ve logging önemlidir

## Güvenlik Gereksinimleri
- Dosya upload validasyonları zorunlu
- Malware analizi sandbox ortamında yapılmalı
- Input sanitization her zaman uygulanmalı
- API endpoint'lerde rate limiting kullanın

## AI Entegrasyonu
- OpenAI API kullanarak Qu1cksc0pe çıktılarını analiz edin
- Raporlar Türkçe olarak oluşturulmalı
- Teknik detaylar ve risk seviyeleri belirtilmeli

## Qu1cksc0pe Entegrasyonu
- Sanal ortam aktivasyonu gerekli
- Komut satırı parametreleri: --analyze --domain --packer --resource --sigcheck --mitre --lang
- Çıktı parsing ve hata yönetimi kritik
