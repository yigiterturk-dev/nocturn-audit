# İkinci canary — SQLite / Python hedefli

Ana canary (`test/canary/`) bir Next + Supabase projesidir. Bazı kurallar o
bağlamda **temsil edilemez**: SQLite lehçe artığı kuralı SQLite hedefli bir
proje ister, ama RLS kuralı Supabase ister — ikisi aynı projede olmaz.

Bu ikinci canary o boşluğu kapatır. Aynı sözleşme geçerli: her dosya bir
kuralın yakalaması **gereken** açığı taşır, ve fikstürler sahaya benzer —
yorum satırına anahtar kelime yazmak yasak (motor yorumları temizler, kendini
kandırmış olursun).
