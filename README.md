# Malware Analysis Platform

Bu proje, kullanıcıların malware örneklerini yükleyip Qu1cksc0pe aracıyla analiz edip AI destekli detaylı raporlar alabilecekleri bir web platformudur.

## 🚀 Özellikler

- 📁 **Dosya Yükleme**: Güvenli malware örneği yükleme
- 🔍 **Qu1cksc0pe Entegrasyonu**: Otomatik malware analizi
- 🤖 **AI Destekli Raporlama**: Analiz sonuçlarının AI ile yorumlanması
- 📊 **Detaylı Raporlar**: Kapsamlı ve anlaşılır analiz raporları
- 🔒 **Güvenlik**: İzole ortamda analiz

## 🛠️ Kurulum

1. **Gereksinimler**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Qu1cksc0pe Kurulumu**:
   ```bash
   # Qu1cksc0pe'u klonlayın
   git clone --depth 1 https://github.com/CYB3RMX/Qu1cksc0pe /home/kali/Desktop/Qu1cksc0pe
   
   # Sanal ortam oluşturun
   cd /home/kali/Desktop/Qu1cksc0pe
   virtualenv -p python3 sc0pe_venv
   source sc0pe_venv/bin/activate
   ```

3. **Ortam Değişkenleri**:
   `.env` dosyası oluşturun:
   ```
   OPENAI_API_KEY=your_openai_api_key_here
   QUICKSCOPE_PATH=/home/kali/Desktop/Qu1cksc0pe
   UPLOAD_FOLDER=./uploads
   MAX_FILE_SIZE=100MB
   ```

## 🔧 Kullanım

1. **Sunucuyu Başlatın**:
   ```bash
   python app.py
   ```

2. **Web Arayüzü**: `http://localhost:5000` adresini ziyaret edin

3. **Malware Analizi**:
   - Dosyayı upload sayfasında yükleyin
   - Analiz işleminin tamamlanmasını bekleyin
   - Detaylı AI destekli raporu görüntüleyin

## 📁 Proje Yapısı

```
malwaire/
├── app.py                 # Ana Flask uygulaması
├── templates/             # HTML şablonları
│   ├── index.html        # Ana sayfa
│   ├── upload.html       # Upload sayfası
│   └── report.html       # Rapor sayfası
├── static/               # CSS, JS, resimler
│   ├── css/
│   ├── js/
│   └── images/
├── uploads/              # Yüklenen dosyalar
├── reports/              # Oluşturulan raporlar
├── utils/                # Yardımcı modüller
│   ├── quickscope_runner.py
│   ├── ai_analyzer.py
│   └── file_handler.py
└── requirements.txt      # Python bağımlılıkları
```

## ⚠️ Güvenlik Uyarıları

- Bu platform sadece güvenli, izole edilmiş ortamlarda kullanılmalıdır
- Malware örnekleri gerçek tehditler içerebilir
- Analiz işlemleri sandbox ortamında gerçekleştirilir

## 🤝 Katkı

1. Projeyi fork edin
2. Feature branch oluşturun (`git checkout -b feature/AmazingFeature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add some AmazingFeature'`)
4. Branch'inizi push edin (`git push origin feature/AmazingFeature`)
5. Pull Request oluşturun

## 📄 Lisans

Bu proje MIT Lisansı altında lisanslanmıştır.
