# 1. استخدم صورة Node.js رسمية كنقطة بداية
FROM node:18-alpine

# 2. أنشئ مجلد العمل داخل الحاوية
WORKDIR /app

# ✨ الخطوة الجديدة: حدد أن كل العمليات القادمة يجب أن تتم داخل مجلد backend
WORKDIR /app/backend

# 3. انسخ ملفات package.json و package-lock.json من مجلد backend المحلي
COPY backend/package*.json ./

# 4. ثبّت الاعتماديات
RUN npm install

# 5. انسخ بقية ملفات المشروع من مجلد backend المحلي إلى مجلد العمل الحالي
COPY backend/ .

# 6. عرّف المنفذ الذي سيعمل عليه الخادم
EXPOSE 3000

# 7. الأمر الذي سيتم تشغيله عند بدء الحاوية
CMD [ "node", "index.js" ]
