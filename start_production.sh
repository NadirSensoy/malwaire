#!/bin/bash

# Malware Analysis Platform - Production Başlatma Script'i
# DLL ve büyük dosya analizi için optimize edilmiş ayarlar

echo "🔍 Malware Analysis Platform Production Mod - Başlatılıyor..."

# Ortam kontrolü
if [ ! -d "Qu1cksc0pe" ]; then
    echo "❌ Qu1cksc0pe dizini bulunamadı!"
    exit 1
fi

if [ ! -f "Qu1cksc0pe/sc0pe_venv/bin/activate" ]; then
    echo "❌ Qu1cksc0pe virtual environment bulunamadı!"
    echo "💡 Önce setup.sh script'ini çalıştırın"
    exit 1
fi

# Virtual environment kontrolü
if [ ! -d "venv" ]; then
    echo "📦 Python virtual environment oluşturuluyor..."
    python3 -m venv venv
fi

# Virtual environment aktivasyonu
echo "🐍 Virtual environment aktifleştiriliyor..."
source venv/bin/activate

# Bağımlılıkları yükle
echo "📦 Bağımlılıklar kontrol ediliyor..."
pip install -r requirements.txt

# Gerekli dizinleri oluştur
mkdir -p uploads
mkdir -p reports
mkdir -p logs

# Dizin izinlerini ayarla
chmod 755 uploads reports logs

# Sistem kaynaklarını kontrol et
echo "💾 Sistem kaynakları kontrol ediliyor..."
AVAILABLE_RAM=$(free -m | awk 'NR==2{printf "%.0f", $7}')
AVAILABLE_DISK=$(df -m . | awk 'NR==2{printf "%.0f", ($4)}')

echo "📊 Mevcut RAM: ${AVAILABLE_RAM}MB"
echo "💿 Mevcut Disk: ${AVAILABLE_DISK}MB"

if [ "$AVAILABLE_RAM" -lt 2048 ]; then
    echo "⚠️  Uyarı: Düşük RAM (${AVAILABLE_RAM}MB). DLL analizleri yavaş olabilir."
fi

if [ "$AVAILABLE_DISK" -lt 5120 ]; then
    echo "⚠️  Uyarı: Düşük disk alanı (${AVAILABLE_DISK}MB). Büyük dosya analizleri başarısız olabilir."
fi

# Timeout ayarlarını göster
echo ""
echo "⏱️  Timeout Ayarları:"
echo "   🔹 Standart dosyalar: 10 dakika"
echo "   🔹 Döküman dosyalar: 15 dakika"
echo "   🔹 APK dosyalar: 30 dakika"
echo "   🔹 DLL/büyük dosyalar: 60 dakika"
echo ""

# Port kontrolü
if lsof -i:5003 > /dev/null 2>&1; then
    echo "⚠️  Port 5003 kullanımda! Mevcut process kapatılıyor..."
    pkill -f "gunicorn.*app:app"
    sleep 2
fi

# Gunicorn ile başlat
echo "🚀 Gunicorn ile production modda başlatılıyor..."
echo "🌐 Server: http://localhost:5003"
echo "📝 Loglar: Terminal'de görüntüleniyor"
echo ""
echo "🛑 Kapatmak için: Ctrl+C"
echo ""

# Environment değişkenlerini ayarla
export FLASK_ENV=production
export FLASK_DEBUG=0

# Gunicorn başlat
exec gunicorn --config gunicorn.conf.py "app:app"
