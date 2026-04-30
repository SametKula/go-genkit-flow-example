# Sentinel AI - Intelligent Network Traffic Analyzer 🛡️

Sentinel AI, ağınızdaki trafiği pasif olarak dinleyen ve şüpheli aktiviteleri yerel bir yapay zeka modeli (Ollama/Llama 3.2) kullanarak analiz eden otonom bir ağ güvenlik sistemidir.

## 🚀 Öne Çıkan Özellikler

*   **Gerçek Zamanlı Paket İzleme:** `gopacket` kullanarak ağ arayüzünden (NIC) canlı trafik yakalama.
*   **Zenginleştirilmiş Veri (Enrichment):** Yakalanan IP'ler için coğrafi konum (Geo-IP) ve AbuseIPDB üzerinden tehdit skoru sorgulama.
*   **AI Analiz Akışı (Genkit Flow):** Firebase Genkit v1.7 Go SDK ile yapılandırılmış, yerel Ollama modeline bağlı akıllı karar mekanizması.
*   **Otonom Aksiyon Motoru:**
    *   ✅ **Clean:** Güvenli IP'ler geçici ve kalıcı olarak beyaz listeye (Whitelist) alınır.
    *   🟡 **Suspicious:** Şüpheli IP'ler karantina listesine eklenir.
    *   🔴 **Dangerous:** Yüksek riskli IP'ler blok listesine alınır ve anında uyarı tetiklenir.
*   **Telegram Bildirimleri:** Kritik tehditler için anlık bot bildirimleri.
*   **Kalıcı Depolama:** Tüm listeler (Whitelist, Quarantine, Block) JSON formatında diskte tutulur ve IP erişim sayıları (`access_count`) takip edilir.
*   **Yüksek Performans:** Worker Pool mimarisi ile aynı anda birden fazla IP'nin asenkron analizi.

## 🛠️ Teknoloji Yığını

*   **Dil:** Go (Golang)
*   **AI Framework:** [Firebase Genkit Go SDK](https://github.com/firebase/genkit/tree/main/go)
*   **LLM:** Ollama (Llama 3.2:3b)
*   **Paket Analizi:** Google gopacket (libpcap)
*   **İstihbarat:** AbuseIPDB API & IP-API

## 📋 Gereksinimler

1.  **Go 1.22+**
2.  **Ollama:** Bilgisayarınızda yüklü ve çalışır durumda olmalıdır.
    *   `ollama pull llama3.2` komutu ile modeli indirin.
3.  **libpcap:** Paket yakalama için sisteminizde yüklü olmalıdır (macOS: varsayılan, Linux: `sudo apt install libpcap-dev`).
4.  **Telegram Bot:** (Opsiyonel) Bildirimler için bir bot token'ı ve Chat ID.
5.  **AbuseIPDB API Key:** (Opsiyonel) Daha derin tehdit analizi için.

## ⚙️ Kurulum

1.  **Projeyi Klonlayın:**
    ```bash
    git clone [repo-url]
    cd go-genkit-flow-example-1
    ```

2.  **Bağımlılıkları Yükleyin:**
    ```bash
    go mod tidy
    ```

3.  **Yapılandırma:**
    `.env.example` dosyasını `.env` olarak kopyalayın ve bilgilerinizi girin:
    ```bash
    cp .env.example .env
    # .env dosyasını bir editör ile düzenleyin
    ```

## 🚀 Çalıştırma

Ağ arayüzünü dinlemek için uygulamanın yönetici yetkileriyle (sudo) çalıştırılması gerekebilir:

```bash
sudo go run cmd/main.go
```

## 📂 Proje Yapısı

*   `cmd/main.go`: Uygulama giriş noktası ve worker pool yönetimi.
*   `internal/capture/`: Ağ paketlerini yakalama mantığı.
*   `internal/flow/`: Genkit Flow ve AI prompt tanımları.
*   `internal/enrichment/`: IP veri zenginleştirme (Geo & Abuse).
*   `internal/actions/`: Güvenlik kararlarını uygulama ve kayıt tutma.
*   `internal/telegram/`: Telegram bot entegrasyonu.
*   `data/`: Whitelist, Quarantine ve Block JSON dosyaları.

## 📊 İstatistikler ve Kayıtlar

Uygulama çalışırken her 10 saniyede bir terminalde canlı istatistikleri gösterir:
`[MAIN] 📊 Stats | Quarantined: 141 | Blocked: 0 | Whitelisted: 178 | Queue: 77/100`

Tüm detaylı analiz sonuçları `data/` klasöründeki dosyalarda saklanır. Her kayıtta IP'nin neden bu kategoriye alındığına dair AI açıklaması ve erişim sayısı yer alır.

## 🛣️ Gelecek Yol Haritası

- [ ] Web Dashboard: Canlı trafiği izlemek için bir arayüz.
- [ ] Gerçek Firewall Entegrasyonu: `iptables` veya `pf` üzerinden otomatik IP engelleme.
- [ ] Manuel Müdahale: Whitelist'e manuel IP ekleme/çıkarma arayüzü.

---
*Bu proje eğitim ve ağ güvenliği izleme amaçlı geliştirilmiştir.*
