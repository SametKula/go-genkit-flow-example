# Project Brief: Go Genkit Network Security Analyzer

## Proje Adı
`go-genkit-flow-example-1` — AI Destekli Ağ Güvenlik Analiz Sistemi

## Genel Amaç
Go programlama dili ile Firebase Genkit framework'ü kullanarak gerçek zamanlı ağ trafiğini izleyen, yakalanan IP adreslerini yapay zeka aracılığıyla tehdit analizi yapan ve sonuçlara göre otomatik aksiyonlar alan bir güvenlik sistemi geliştirmek.

## Temel Gereksinimler

### 1. Ağ Yakalama (gopacket)
- `google/gopacket` kütüphanesi ile ağ paketlerini yakala
- Kaynak ve hedef IP adreslerini ayıkla
- Tekrarlanan IP'leri filtrele, her IP'yi bir kez analiz et
- Belirlenen ağ arayüzünden (interface) dinleme yap

### 2. IP Analizi (Genkit Flow)
Her yakalanan IP için şu bilgileri topla:
- **Tehdit İstihbaratı**: IP'nin bilinen zararlı listelerde olup olmadığı
- **Coğrafi Bilgiler**: Ülke, şehir, ISP bilgileri (ip-api.com)
- **WHOIS Benzeri Bilgiler**: IP sahibi, ASN (Autonomous System Number)
- **3. Parti Güvenlik Kontrolü**: AbuseIPDB veya benzeri servisler

### 3. Yapay Zeka Analizi (Ollama - Yerel Model)
- Toplanan tüm IP bilgilerini Genkit flow üzerinden yerel Ollama modeline gönder
- Model çıktısına göre karar ver:
  - `CLEAN` → Serbest bırak, log yaz
  - `SUSPICIOUS` → Karantinaya al (`quarantine_ips.json`)
  - `DANGEROUS` → Blokla + Telegram bildirimi gönder

### 4. Aksiyon Sistemi
| Durum | Aksiyon |
|-------|---------|
| CLEAN | Log yaz, işlem yok |
| SUSPICIOUS | `quarantine_ips.json` dosyasına ekle |
| DANGEROUS | `blocked_ips.json` + Telegram API bildirimi |

## Kısıtlamalar & Notlar
- Karantina ve blok işlemleri şu an dosya bazlı (gelecekte gerçek firewall entegrasyonu planlanıyor)
- Telegram bildirimi sadece DANGEROUS durumda tetiklenir
- Yerel Ollama modeli kullanılacak (internet bağlantısı gerektirmez AI için)
- macOS geliştirme ortamı, libpcap gerekli

## Gelecek Planlar
- Gerçek firewall kuralları (iptables/pf) entegrasyonu
- Web dashboard (gerçek zamanlı IP izleme)
- Çoklu ağ arayüzü desteği
- Whitelist/Blacklist yönetimi
