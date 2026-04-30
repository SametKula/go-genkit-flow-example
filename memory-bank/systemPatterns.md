# Sistem Desenleri & Mimari Kararlar

## Temel Desenler

### 1. Pipeline Deseni (Capture → Enrich → Analyze → Act)
Her IP adresi şu pipeline'dan geçer:
```
Capture → Deduplicate → Enrich → Flow(AI) → Action
```
- Her adım bağımsız ve test edilebilir
- Hata herhangi bir aşamada olursa log yaz, devam et

### 2. Worker Pool Deseni
- Goroutine havuzu ile paralel IP analizi
- Buffered channel ile IP kuyruğu
- Context ile graceful shutdown

```go
// IP kanalı - capture'dan flow'a
ipChan := make(chan string, 100)

// Worker pool - paralel analiz
for i := 0; i < workerCount; i++ {
    go analyzeWorker(ctx, ipChan, genkitClient)
}
```

### 3. Deduplication Deseni
- `sync.Map` ile görülen IP'lerin takibi
- TTL bazlı temizlik (30 dakika sonra tekrar analiz)
- Özel IP adreslerini filtrele (192.168.x.x, 10.x.x.x, 127.x.x.x)

### 4. Yapılandırılmış AI Yanıtı
Ollama'dan JSON formatında yapılandırılmış yanıt al:
```json
{
  "status": "CLEAN|SUSPICIOUS|DANGEROUS",
  "confidence": 0.95,
  "reason": "Açıklama",
  "indicators": ["indicator1", "indicator2"],
  "recommended_action": "Önerilen aksiyon"
}
```

### 5. Dosya Bazlı Depolama
Tüm IP kayıtları JSON formatında:
```json
{
  "ip": "1.2.3.4",
  "added_at": "2024-01-01T00:00:00Z",
  "reason": "AI analiz nedeni",
  "confidence": 0.95,
  "geo": {
    "country": "CN",
    "city": "Beijing"
  }
}
```

## Hata Yönetimi
- API hataları → log yaz, IP'yi varsayılan olarak SUSPICIOUS say
- Ollama bağlantı hatası → kritik log, sistem durur
- gopacket hatası → retry mekanizması

## Güvenlik Notları
- API anahtarları `.env` dosyasında saklanır, git'e eklenmez
- `private_ips` listesi her zaman CLEAN sayılır
- Kendi sunucu IP'si whitelist'e eklenir
