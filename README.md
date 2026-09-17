# ACA-AOL Inventory Adjustment

Importer Inventory Adjustment Accurate Online berbasis Flask, diturunkan dari modul ACA-AOL Sales Invoice.

## Flow
1. Login ACA-AOL
2. Connect Accurate via OAuth
3. Pilih database Accurate
4. Upload Excel
5. Cek/validasi file
6. Import Inventory Adjustment via bulk API
7. Lihat ringkasan sukses/gagal

## Accurate API
- POST `/api/item-adjustment/bulk-save.do`
- Scope: `item_adjustment_save`
- Maksimum 100 transaksi per request; aplikasi otomatis membagi batch jika lebih dari 100 transaksi.

## Kolom wajib Excel
- `NUMBER`
- `TRANSDATE`
- `ADJUSTMENTTYPE`
- `ITEMNO`
- `QUANTITY`
- `UNITCOST` diwajibkan oleh importer untuk `ADJUSTMENT_IN`

Nilai `ADJUSTMENTTYPE`:
- `ADJUSTMENT_IN`
- `ADJUSTMENT_OUT`
- `ADJUSTMENT_STOCK`

Baris dengan `NUMBER` yang sama digabung menjadi satu Inventory Adjustment dengan banyak detail item.

## Menjalankan
1. Buat virtual environment Python.
2. Install: `pip install -r requirements.txt`
3. Copy `.env.example` menjadi `.env` dan isi OAuth Accurate.
4. Jalankan: `python app.py`

Template Excel siap pakai tersedia di `template-inventory-adjustment.xlsx` atau melalui tombol **Download Template** di aplikasi.

## Deployment entrypoint

For platforms that default to `gunicorn main:app`, this package includes `main.py` as a compatibility entrypoint.
Recommended start command:

```bash
gunicorn main:app --bind 0.0.0.0:$PORT
```

Equivalent direct entrypoint:

```bash
gunicorn app:app --bind 0.0.0.0:$PORT
```
