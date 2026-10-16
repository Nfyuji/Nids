# NIDS — نظام كشف التسلل للشبكات

لوحة تحكم عربية (RTL) لمراقبة الشبكة، وتحليل الحزم، وعرض التنبيهات الأمنية مع فصل صارم بين البيانات الحقيقية والتجريبية.

## المتطلبات

- Windows 11 (أو Linux/macOS)
- Python 3.11+
- (اختياري) [Npcap](https://npcap.com/) لالتقاط الحزم على Windows
- (اختياري) [Suricata](https://suricata.io/) مع تفعيل EVE JSON

## التثبيت السريع (Windows)

```powershell
cd nids
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
# عدّل ADMIN_PASSWORD في .env
python app.py
```

افتح: http://127.0.0.1:5000

الحساب الافتراضي من `.env`: `admin` / القيمة التي عيّنتها في `ADMIN_PASSWORD`.

## السمات

- **Dark Mode**: مطابق لهوية SOC في الصورة المرجعية.
- **Light Mode**: من زر الشمس/القمر في الشريط العلوي أو من الإعدادات.

## الصفحات

| الصفحة | المسار |
|--------|--------|
| لوحة التحكم | `/` |
| التنبيهات | `/alerts` |
| الحركة الحية | `/live-traffic` |
| تحليل الهجمات | `/attack-analysis` |
| تحقيق IP | `/ip-investigation` |
| أنواع الهجمات | `/attack-types` |
| المستشعرات | `/sensors` |
| التقارير | `/reports` |
| الإعدادات | `/settings` |

## الالتقاط (Scapy)

1. ثبّت Npcap مع خيار WinPcap API compatibility.
2. `pip install scapy`
3. حدّد واجهة الشبكة من الإعدادات.
4. من صفحة المستشعرات → **بدء المراقبة** (للمسؤول فقط).
5. إن فشلت الصلاحيات ستظهر رسالة واضحة ولن يُعرض المستشعر كـ «يعمل».

تحقق من الواجهات في Python:

```python
from scapy.all import get_if_list
print(get_if_list())
```

## Suricata

1. ثبّت Suricata وفعّل `eve-log` في `suricata.yaml`.
2. ضع مسار `eve.json` في الإعدادات (`suricata_eve_path`).
3. من المستشعرات → **بدء قراءة EVE**.
4. يقرأ النظام السجلات الجديدة فقط ويمنع التكرار.

وضع Scapy ووضع Suricata منفصلان ويمكن تشغيلهما معاً دون خلط مصادر البيانات في الواجهة.

## الاختبارات

```powershell
cd nids
pytest -q
```

## ملاحظات أمنية

- لا تشغّل Flask Debug على شبكة عامة.
- الافتراضي يستمع على `127.0.0.1` فقط.
- كلمات المرور مُجزّأة عبر Werkzeug.
- لا يُنفَّذ حظر تلقائي للاتصالات في هذا الإصدار.
- البيانات التجريبية تحمل `is_simulated=True` وشارة «تجريبي» ولا تدخل إحصائيات الاكتشاف الحقيقي.
