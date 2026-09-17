# TikZoom — منصة استضافة بوتات تيليجرام

تشغيل مجاني 24/7 عبر GitHub Actions (وضع polling).

- الأدمن فقط أو مشتركو VIP يستطيعون رفع الملفات — باقي المستخدمين يتواصلون مع الأدمن لتفعيل خطة VIP.
- إعادة تشغيل تلقائية كل ~6 ساعات مع حفظ الحالة (قاعدة البيانات + بوتات المستخدمين) في فرع `state`.
- القوالب (208 بوت GitHub) في `templates_data.tar.gz` وتُفك عند الإقلاع.

الإعدادات (Repo Secrets): `BOT_TOKEN`, `ADMIN_IDS`, `ADMIN_USERNAME`, `FERNET_KEY`, `GEMINI_API_KEY`.
