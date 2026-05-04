# Aktif Bağlam

## Mevcut Durum
**Tarih**: 2026-04-30
**Faz**: Başlangıç - Temel altyapı kurulumu

## Tamamlanan İşler
- [x] Git init
- [x] Go mod init
- [x] Memory Bank oluşturuldu
- [x] Proje dizin yapısı planlandı
- [x] `internal/capture/capture.go` - gopacket IP yakalama
- [x] `internal/enrichment/enrichment.go` - IP zenginleştirme
- [x] `internal/flow/flow.go` - Genkit flow (v1.x API fixed)
- [x] `internal/actions/actions.go` - Aksiyon motoru & SQLite veritabanı entegrasyonu
- [x] `cmd/main.go` - Ana giriş noktası
- [x] Whitelist özelliği (CLEAN ipler için bellek içi muafiyet ve SQLite persistence)
- [x] IP Erişim Sayacı (SQLite veritabanı üzerinde access_count takibi)
- [x] Terminal çıktılarındaki emojiler kaldırılarak log formatı daha kurumsal ve okunabilir hale getirildi
- [x] Saniyede 50'den fazla paket gönderen IP'leri algılayan ve LLM'i atlayarak (Fast-Path) doğrudan veritabanına kaydeden Rate Limiter eklendi
- [x] Telegram entegrasyonu ve JSON dosya depolaması projeden tamamen kaldırıldı

## Aktif Kararlar
1. **Ollama Model**: `llama3.2` varsayılan (config ile değiştirilebilir)
2. **Ağ Interface**: `.env` ile yapılandırılabilir
3. **Worker Count**: 5 paralel IP analizi
4. **Dedup TTL**: 30 dakika (aynı IP 30 dk sonra tekrar analiz edilir)

## Dikkat Edilecekler
- gopacket için `libpcap` kurulu olmalı
- Paket yakalama için root yetkisi gerekli
- Ollama'nın çalışıyor olması şart
