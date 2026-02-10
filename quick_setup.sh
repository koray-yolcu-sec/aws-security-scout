#!/bin/bash

# AWS Security Scout - Hızlı Kurulum ve Test Script'i
# Bu script'i çalıştırarak projeyi hızlıca kurabilir ve test edebilirsiniz

set -e  # Hata durumunda dur

echo "🚀 AWS Security Scout - Hızlı Kurulum Script'i"
echo "=================================================="
echo ""

# Renk tanımlamaları
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 1. Python kontrolü
echo -e "${YELLOW}1. Python versiyonu kontrol ediliyor...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo -e "${GREEN}✓ Python bulundu: $PYTHON_VERSION${NC}"
else
    echo -e "${RED}✗ Python3 bulunamadı! Python 3.8+ yükleyin.${NC}"
    exit 1
fi

# 2. Virtual environment oluşturma
echo ""
echo -e "${YELLOW}2. Virtual environment oluşturuluyor...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual environment oluşturuldu${NC}"
else
    echo -e "${GREEN}✓ Virtual environment zaten var${NC}"
fi

# 3. Virtual environment'ı aktif et
echo ""
echo -e "${YELLOW}3. Virtual environment aktif ediliyor...${NC}"
source venv/bin/activate
echo -e "${GREEN}✓ Virtual environment aktif${NC}"

# 4. Bağımlılıkları yükle
echo ""
echo -e "${YELLOW}4. Python bağımlılıkları yükleniyor...${NC}"
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
echo -e "${GREEN}✓ Bağımlılıklar yüklendi${NC}"

# 5. Python syntax kontrolü
echo ""
echo -e "${YELLOW}5. Python syntax kontrolü yapılıyor...${NC}"
python -m py_compile aws_scout/core/*.py
python -m py_compile aws_scout/checks/*.py
python -m py_compile aws_scout/cli.py
python -m py_compile main.py
echo -e "${GREEN}✓ Syntax kontrolü başarılı${NC}"

# 6. Import kontrolü
echo ""
echo -e "${YELLOW}6. Modül import kontrolü yapılıyor...${NC}"
python3 << 'EOF'
try:
    from aws_scout.core.aws_auth import AWSAuth
    from aws_scout.core.scorer import ScoringEngine, Severity, Finding
    from aws_scout.core.reporter import Reporter
    from aws_scout.checks.s3_checks import S3Check
    from aws_scout.checks.iam_checks import IAMCheck
    from aws_scout.core.scanner import SecurityScanner
    print("✅ Tüm modüller başarıyla import edildi!")
except ImportError as e:
    print(f"❌ Import hatası: {e}")
    exit(1)
EOF

# 7. CLI help kontrolü
echo ""
echo -e "${YELLOW}7. CLI help kontrolü yapılıyor...${NC}"
python main.py --help > /dev/null
python main.py scan --help > /dev/null
python main.py fix-plan --help > /dev/null
echo -e "${GREEN}✓ CLI help çalışıyor${NC}"

# 8. .gitignore oluşturma
echo ""
echo -e "${YELLOW}8. .gitignore dosyası oluşturuluyor...${NC}"
if [ ! -f ".gitignore" ]; then
    cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
ENV/
build/
dist/
*.egg-info/

# IDE
.vscode/
.idea/
*.swp

# Outputs
outputs/
workspace_output_*.txt

# Agent hooks
.agent_hooks/

# OS
.DS_Store
Thumbs.db

# Temporary
todo.md
*.tmp
EOF
    echo -e "${GREEN}✓ .gitignore oluşturuldu${NC}"
else
    echo -e "${GREEN}✓ .gitignore zaten var${NC}"
fi

# 9. Git başlatma
echo ""
echo -e "${YELLOW}9. Git başlatılıyor...${NC}"
if [ ! -d ".git" ]; then
    git init
    git add .
    git commit -m "Initial commit: AWS Security Scout v1.0"
    echo -e "${GREEN}✓ Git başlatıldı ve initial commit yapıldı${NC}"
else
    echo -e "${GREEN}✓ Git zaten başlatılmış${NC}"
fi

# 10. AWS kontrolü
echo ""
echo -e "${YELLOW}10. AWS credentials kontrol ediliyor...${NC}"
if command -v aws &> /dev/null; then
    if aws configure list &> /dev/null; then
        echo -e "${GREEN}✓ AWS CLI yapılandırılmış${NC}"
        
        # Test isteği (optional)
        echo ""
        read -p "AWS ile test taraması yapmak istiyor musunuz? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo ""
            echo -e "${YELLOW}AWS test taraması yapılıyor (Sadece S3)...${NC}"
            python main.py scan --services s3 || echo -e "${RED}✗ Test başarısız - AWS credentials kontrol edin${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ AWS CLI kurulu ama credentials yapılandırılmamış${NC}"
        echo -e "${YELLOW}  'aws configure' komutu ile credentials'ları ayarlayın${NC}"
    fi
else
    echo -e "${YELLOW}⚠ AWS CLI bulunamadı${NC}"
    echo -e "${YELLOW}  'pip install awscli' ile yükleyebilirsiniz${NC}"
fi

# Sonuç
echo ""
echo "=================================================="
echo -e "${GREEN}✅ Kurulum tamamlandı!${NC}"
echo ""
echo "Sonraki adımlar:"
echo "1. GitHub repository oluşturun"
echo "2. Git remote ekleyin: git remote add origin <url>"
echo "3. GitHub'a push edin: git push -u origin main"
echo "4. AWS ile test etmek isterseniz: python main.py scan --services s3"
echo ""
echo -e "${YELLOW}Daha fazla bilgi için DEPLOYMENT_GUIDE.md dosyasını okuyun${NC}"
echo ""