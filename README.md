# Sentinel AI - Intelligent Network Security Analyzer 🛡️

Sentinel AI, ağınızdaki trafiği pasif olarak dinleyen, derin paket detaylarını çıkaran ve şüpheli aktiviteleri yerel bir yapay zeka modeli (Ollama/Llama 3.2) kullanarak analiz eden otonom bir **Saldırı Tespit Sistemi (IDS)**'dir.

## 🚀 Öne Çıkan Özellikler

*   **Gerçek Zamanlı Paket İzleme:** `gopacket` kullanarak ağ arayüzünden (NIC) canlı trafik yakalama.
*   **Fast-Path Hız Sınırlayıcı (Rate Limiter):** TCP SYN Flood veya port taraması yapan (saniyede >50 bağlantı isteği) saldırganları, Yapay Zekayı (LLM) hiç yormadan **doğrudan engelleme (DANGEROUS)** listesine alır.
*   **Derin Ağ Bağlamı (Local Network Context):** Yapay zekaya yalnızca IP'yi değil; IP'nin **hangi portlara** erişmeye çalıştığı, **hangi protokolleri** (TCP/UDP) kullandığı ve **ne kadar veri aktardığı** bilgisini sunarak isabetli (False-Positive'i düşük) analizler yapar.
*   **Zenginleştirilmiş Veri (Enrichment):** Yakalanan IP'ler için coğrafi konum (Geo-IP) ve AbuseIPDB üzerinden tehdit skoru sorgulama.
*   **AI Analiz Akışı (Genkit Flow):** Firebase Genkit v1.7 Go SDK ile yapılandırılmış, yerel Ollama modeline bağlı akıllı karar mekanizması.
*   **Otonom Aksiyon Motoru & Merkezi SQLite:** Tüm kayıtlar JSON yerine, performanslı ve tutarlı bir **SQLite (`data/security.db`)** veritabanında tutulur:
    *   ✅ **Clean:** Güvenli IP'ler beyaz listeye (Whitelist) alınır ve bellek içi (In-Memory) olarak süreli muaf tutulur.
    *   🟡 **Suspicious:** Şüpheli IP'ler karantina listesine eklenir.
    *   🔴 **Dangerous:** Yüksek riskli ve Flood yapan IP'ler blok listesine alınır.
*   **Yüksek Performans:** Worker Pool mimarisi ile aynı anda birden fazla IP'nin asenkron analizi.

## 🏛️ Çalışma Mantığı ve Mimari

Sistem **"Fast-Path" (Hızlı Yol)** ve **"Slow-Path" (Yapay Zeka Yolu)** olmak üzere çift katmanlı bir mimariyle çalışır:

1. **Paket Yakalama (Capture):** Sistem ağ kartını dinler. Sadece **yeni** bağlantı isteklerini (TCP SYN) takip eder.
2. **Hız Sınırı (Fast-Path):** Eğer bir IP saniyede çok fazla kapı çalıyorsa (Port Scan / Flood), anında "DANGEROUS" olarak veritabanına yazılır.
3. **Bağlam Toplama (Context):** Normal bir hızdaysa, sistem bu IP'nin son 30 dakikada hangi portlara eriştiğini toparlar.
4. **Zenginleştirme (Enrichment):** Bu IP'nin lokasyonu (hangi ülke, şehir, şirket) ve AbuseIPDB'deki sabıka kaydı API'ler aracılığıyla çekilir.
5. **Yapay Zeka Analizi (Slow-Path):** Toplanan tüm *Bağlam* (portlar, byte'lar) ve *Zenginleştirilmiş Veri* (ülke, sabıka skoru), yapılandırılmış bir "Prompt" ile **Llama 3.2**'ye verilir. LLM bu IP'nin niyetini analiz eder ve JSON formatında karar bildirir.
6. **Aksiyon (Action):** Yapay Zekadan dönen karara göre (CLEAN, SUSPICIOUS, DANGEROUS) IP veritabanına kaydedilir ve istatistiklere (Access Count) yansıtılır.

## 📂 Dosya Hiyerarşisi

*   `cmd/main.go`: Uygulama giriş noktası. Fast-Path / Slow-Path kanallarını (channel) kurar ve Worker Pool'ları (İşçiler) yönetir.
*   `internal/capture/`: Ağ paketlerini yakalar (gopacket). Rate Limiting hesaplamasını yapar ve "ConnectionContext" oluşturur.
*   `internal/flow/`: Firebase Genkit Flow tanımının yapıldığı yerdir. Yapay zeka sistem komutlarını (Prompt) ve Llama model bağlantısını içerir.
*   `internal/enrichment/`: IP adresi için dış dünya verilerini (Geo-IP ve AbuseIPDB) toplayarak IP'yi zenginleştirir.
*   `internal/actions/`: Güvenlik kararlarını veritabanına (SQLite) kaydeder. Bellek içi (In-Memory) Whitelist mekanizmasını çalıştırır.

## 🛠️ Teknoloji Yığını

*   **Dil:** Go (Golang)
*   **Veritabanı:** SQLite3
*   **AI Framework:** [Firebase Genkit Go SDK](https://github.com/firebase/genkit/tree/main/go)
*   **LLM:** Ollama (Llama 3.2:3b)
*   **Paket Analizi:** Google gopacket (libpcap)

## 📋 Gereksinimler

1.  **Go 1.22+**
2.  **Ollama:** Bilgisayarınızda yüklü ve çalışır durumda olmalıdır.
    *   `ollama pull llama3.2` komutu ile modeli indirin.
3.  **libpcap & CGO:** Paket yakalama için sisteminizde yüklü olmalıdır (macOS: varsayılan, Linux: `sudo apt install libpcap-dev gcc`). (SQLite entegrasyonu için GCC gereklidir).
4.  **AbuseIPDB API Key:** (Opsiyonel) Daha derin tehdit analizi için `.env` dosyasında bulunmalıdır.

## ⚙️ Kurulum

1.  **Projeyi Klonlayın:**
    ```bash
    git clone https://github.com/SametKula/go-genkit-flow-example.git
    cd go-genkit-flow-example
    ```

2.  **Bağımlılıkları Yükleyin:**
    ```bash
    go mod tidy
    ```

3.  **Yapılandırma:**
    `.env.example` dosyasını `.env` olarak kopyalayın ve bilgilerinizi girin:
    ```bash
    cp .env.example .env
    ```

## 🚀 Çalıştırma

Ağ arayüzünü dinlemek için uygulamanın yönetici yetkileriyle (sudo) çalıştırılması gerekebilir:

```bash
sudo go run cmd/main.go
```

## 📊 İstatistikler

Uygulama çalışırken her 60 saniyede bir terminalde canlı istatistikleri gösterir:
`[MAIN] [STATS] Quarantined: 14 | Blocked: 2 | Whitelisted: 178 | Queue: 0/100`

Analiz sonuçlarını incelemek için doğrudan `data/security.db` SQLite dosyasını DB Browser veya VS Code eklentileriyle açabilirsiniz.

## 🛣️ Gelecek Yol Haritası

- [ ] Web Dashboard: Canlı trafiği ve veritabanı kayıtlarını izlemek için bir arayüz.
- [ ] Gerçek Firewall Entegrasyonu: İşletim sistemi (`pf` veya `iptables`) seviyesinde otomatik bağlantı koparma.
- [ ] Local Threat Intelligence: Düzenli Spamhaus/Firehol karaliste senkronizasyonu.

---
*Bu proje eğitim ve otonom ağ güvenliği izleme amaçlı geliştirilmiştir.*
