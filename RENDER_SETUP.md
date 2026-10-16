# نشر NIDS على Render

## القيم في واجهة New Web Service

| الحقل | القيمة |
|--------|--------|
| Language | Python 3 |
| Branch | `main` |
| Root Directory | **اتركه فارغاً** (المستودع أصلاً من مجلد المشروع) |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `gunicorn wsgi:app --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 120` |

**لا تستخدم:** `gunicorn app:app` أو `gunicorn your_application.wsgi`  
السبب: مجلد `app/` يتعارض مع الملف؛ استخدم `wsgi:app`.

أضف أيضاً Environment: `PYTHON_VERSION` = `3.11.9`

## Environment Variables (مهم)

أضف في Render → Environment:

```
SECRET_KEY=<سلسلة عشوائية طويلة>
FLASK_DEBUG=0
ADMIN_USERNAME=admin
ADMIN_PASSWORD=<كلمة مرور قوية للمناقشة>
THEME_DEFAULT=light
```

Render يضبط `PORT` و`RENDER` تلقائياً.

## ملاحظات لمشروع التخرج

- **التقاط الحزم / Scapy / شبكة الراوتر** لا تعمل على سيرفر سحابي — استخدم **وضع العرض التجريبي** من المستشعرات.
- SQLite على Render مجاني لكن البيانات قد تُمسح عند إعادة النشر. للثبات أضف PostgreSQL من Render وضَع `DATABASE_URL` تلقائياً.
- بعد أول دخول غيّر كلمة المرور من الإعدادات.

## بعد النجاح

1. افتح رابط الخدمة.
2. سجّل الدخول.
3. المستشعرات → **تشغيل سيناريو الهجوم التجريبي**.
4. شاهد لوحة التحكم والتنبيهات.
