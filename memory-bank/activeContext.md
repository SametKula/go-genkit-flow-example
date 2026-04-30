# Aktif Bağlam

## Mevcut Durum
**Tarih**: 2026-04-30
**Faz**: Başlangıç - Temel altyapı kurulumu

## Tamamlanan İşler
- [x] Git init
- [x] Go mod init
- [x] Memory Bank oluşturuldu
- [x] Proje dizin yapısı planlandı

## Yapılacaklar (Bu Oturum)
- [ ] `go.mod` bağımlılıklarını ekle
- [ ] `internal/capture/capture.go` - gopacket IP yakalama
- [ ] `internal/enrichment/enrichment.go` - IP zenginleştirme
- [ ] `internal/flow/flow.go` - Genkit flow
- [ ] `internal/actions/actions.go` - Aksiyon motoru
- [ ] `internal/telegram/telegram.go` - Telegram bildirimi
- [ ] `cmd/main.go` - Ana giriş noktası
- [ ] `.env.example` - Ortam değişkenleri şablonu
- [ ] `README.md` - Proje dokümantasyonu
- [ ] İlk git commit

## Aktif Kararlar
1. **Ollama Model**: `llama3.2` varsayılan (config ile değiştirilebilir)
2. **Ağ Interface**: `.env` ile yapılandırılabilir
3. **Worker Count**: 5 paralel IP analizi
4. **Dedup TTL**: 30 dakika (aynı IP 30 dk sonra tekrar analiz edilir)

## Dikkat Edilecekler
- gopacket için `libpcap` kurulu olmalı
- Paket yakalama için root yetkisi gerekli
- Ollama'nın çalışıyor olması şart
