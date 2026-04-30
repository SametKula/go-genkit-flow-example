# Teknik Bağlam

## Teknoloji Yığını

### Dil & Framework
- **Go** 1.22+
- **Firebase Genkit for Go** (`github.com/firebase/genkit/go`)
  - Flow tanımlaması ve yönetimi
  - Ollama plugin entegrasyonu
  
### Ana Kütüphaneler
| Kütüphane | Versiyon | Kullanım |
|-----------|----------|---------|
| `google/gopacket` | v1.1.19 | Ağ paketi yakalama |
| `firebase/genkit/go` | latest | AI flow orchestration |
| `genkit-go-plugins/ollama` | latest | Yerel Ollama modeli |
| `google/gopacket/pcap` | - | libpcap binding |

### Harici Servisler
| Servis | URL | Amaç |
|--------|-----|-------|
| ip-api.com | http://ip-api.com/json/{ip} | Coğrafi IP bilgisi |
| AbuseIPDB | https://api.abuseipdb.com/api/v2/check | Tehdit istihbaratı |
| Telegram Bot API | https://api.telegram.org | Kritik bildirimler |
| Ollama | http://localhost:11434 | Yerel AI modeli |

### Sistem Gereksinimleri
- **libpcap**: `brew install libpcap` (macOS)
- **Ollama**: Yerel kurulum, model çalışıyor olmalı
- **Root/Admin yetkisi**: pcap için gerekli

## Proje Yapısı
```
go-genkit-flow-example-1/
├── memory-bank/          # Proje dokümantasyonu
│   ├── projectbrief.md
│   ├── techContext.md
│   ├── systemPatterns.md
│   ├── activeContext.md
│   └── progress.md
├── cmd/
│   └── main.go           # Entry point, config, başlatma
├── internal/
│   ├── capture/
│   │   └── capture.go    # gopacket ile IP yakalama
│   ├── enrichment/
│   │   └── enrichment.go # IP bilgi toplama (geo, abuse)
│   ├── flow/
│   │   └── flow.go       # Genkit flow tanımı
│   ├── actions/
│   │   └── actions.go    # CLEAN/SUSPICIOUS/DANGEROUS aksiyonları
│   └── telegram/
│       └── telegram.go   # Telegram bildirimleri
├── data/
│   ├── blocked_ips.json
│   └── quarantine_ips.json
├── .env.example          # Ortam değişkenleri şablonu
├── go.mod
├── go.sum
└── README.md
```

## Ortam Değişkenleri
```env
# Ağ Arayüzü (eth0, en0, etc.)
NETWORK_INTERFACE=en0

# Ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2

# Telegram
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id

# AbuseIPDB (opsiyonel)
ABUSEIPDB_API_KEY=your_api_key
```

## Genkit Flow Mimarisi
```
IP Yakalama (gopacket)
      │
      ▼
[Enrichment Step]
  - Geo bilgi (ip-api.com)
  - Abuse check (AbuseIPDB)
  - ASN/WHOIS bilgisi
      │
      ▼
[Genkit Flow - analyzeIPFlow]
  - Tüm bilgileri prompt olarak hazırla
  - Ollama modeline gönder
  - Yapılandırılmış yanıt parse et
      │
      ▼
[Aksiyon Motoru]
  CLEAN → log
  SUSPICIOUS → quarantine_ips.json
  DANGEROUS → blocked_ips.json + Telegram
```
