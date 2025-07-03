#!/bin/bash

# Malware Analysis Platform - Setup Script

echo "🔍 Malware Analysis Platform Setup Başlatılıyor..."

# Renk kodları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Python kontrolü
echo -e "${BLUE}Python versiyonu kontrol ediliyor...${NC}"
python3 --version
if [ $? -ne 0 ]; then
    echo -e "${RED}Python3 bulunamadı. Lütfen Python3'ü yükleyin.${NC}"
    exit 1
fi

# pip kontrolü
echo -e "${BLUE}pip kontrol ediliyor...${NC}"
pip3 --version
if [ $? -ne 0 ]; then
    echo -e "${RED}pip3 bulunamadı. Lütfen pip3'ü yükleyin.${NC}"
    exit 1
fi

# Virtual environment oluştur
echo -e "${BLUE}Python sanal ortamı oluşturuluyor...${NC}"
python3 -m venv venv
if [ $? -ne 0 ]; then
    echo -e "${RED}Sanal ortam oluşturulamadı.${NC}"
    exit 1
fi

# Virtual environment'i aktifleştir
echo -e "${BLUE}Sanal ortam aktifleştiriliyor...${NC}"
source venv/bin/activate

# Requirements yükle
echo -e "${BLUE}Python bağımlılıkları yükleniyor...${NC}"
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}Bazı bağımlılıklar yüklenemedi. Devam ediliyor...${NC}"
fi

# magic library yükle
echo -e "${BLUE}python-magic kütüphanesi yükleniyor...${NC}"
pip install python-magic

# OpenAI kütüphanesi yükle
echo -e "${BLUE}OpenAI kütüphanesi yükleniyor...${NC}"
pip install openai

# Flask ve bağımlılıkları yükle
echo -e "${BLUE}Flask ve bağımlılıkları yükleniyor...${NC}"
pip install Flask Flask-CORS Flask-SocketIO python-socketio

# Sistem bağımlılıkları kontrolü
echo -e "${BLUE}Sistem bağımlılıkları kontrol ediliyor...${NC}"

# libmagic kontrolü
if ! dpkg -l | grep -q libmagic; then
    echo -e "${YELLOW}libmagic bulunamadı. Yükleniyor...${NC}"
    sudo apt-get update
    sudo apt-get install -y libmagic1 libmagic-dev
fi

# Qu1cksc0pe kontrolü
echo -e "${BLUE}Qu1cksc0pe kurulumu kontrol ediliyor...${NC}"
if [ ! -d "/home/kali/Desktop/Qu1cksc0pe" ]; then
    echo -e "${YELLOW}Qu1cksc0pe bulunamadı. Klonlanıyor...${NC}"
    cd /home/kali/Desktop/
    git clone --depth 1 https://github.com/CYB3RMX/Qu1cksc0pe
    cd Qu1cksc0pe
    
    echo -e "${BLUE}Qu1cksc0pe sanal ortamı oluşturuluyor...${NC}"
    virtualenv -p python3 sc0pe_venv
    source sc0pe_venv/bin/activate
    
    echo -e "${BLUE}Qu1cksc0pe bağımlılıkları yükleniyor...${NC}"
    pip install -r requirements.txt
    
    deactivate
    cd -
fi

# Klasör izinleri ayarla
echo -e "${BLUE}Klasör izinleri ayarlanıyor...${NC}"
chmod 755 uploads/
chmod 755 reports/
chmod +x setup.sh

# .env dosyası kontrolü
echo -e "${BLUE}.env dosyası kontrol ediliyor...${NC}"
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}.env dosyası bulunamadı. Örnek dosya oluşturuluyor...${NC}"
    cp .env.example .env 2>/dev/null || echo "OPENAI_API_KEY=your_api_key_here" > .env
fi

echo -e "${GREEN}✅ Setup tamamlandı!${NC}"
echo ""
echo -e "${BLUE}🚀 Başlatmak için:${NC}"
echo "1. Sanal ortamı aktifleştirin: source venv/bin/activate"
echo "2. .env dosyasını düzenleyin ve OpenAI API anahtarınızı ekleyin"
echo "3. Uygulamayı başlatın: python app.py"
echo ""
echo -e "${BLUE}📝 Notlar:${NC}"
echo "- Qu1cksc0pe /home/kali/Desktop/Qu1cksc0pe dizininde kurulu olmalı"
echo "- OpenAI API anahtarı olmadan AI analizi çalışmaz (fallback kullanılır)"
echo "- Maximum dosya boyutu: 100MB"
echo "- Desteklenen formatlar: .exe, .dll, .bin, .jar, .apk vb."
echo ""
echo -e "${GREEN}🔒 Güvenlik: Bu platform sadece güvenilir, izole edilmiş ortamlarda kullanılmalıdır!${NC}"
