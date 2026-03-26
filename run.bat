@echo off
chcp 65001 > nul
title Mortex Çekiliş Yönetim Sistemi
color 0A

echo.
echo  =====================================================
echo   MORTEX CEKİLİS YÖNETİM SİSTEMİ - Baslatiliyor...
echo  =====================================================
echo.

:: Check if pip is available
where pip >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [HATA] Python/pip bulunamadi. Python 3.x yükleyiniz.
    pause
    exit /b 1
)

:: Install requirements
echo [1/2] Bagimliliklar yukleniyor...
pip install -r requirements.txt -q

:: Run the app
echo [2/2] Uygulama baslatiliyor...
echo.
echo  [+] Adres : http://127.0.0.1:5000
echo  [+] Admin : admin  /  Sifre: mortex2024
echo  [+] Durdurmak icin: Ctrl+C
echo.
python app.py
pause
