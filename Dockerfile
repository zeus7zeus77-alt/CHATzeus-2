FROM node:18-alpine

# مجلد العمل داخل الحاوية
WORKDIR /usr/src/app

# نسخ ملفات التعريف من مجلد Backend
COPY Backend/package*.json ./

RUN npm install --production

# نسخ باقي الملفات
COPY Backend/. .

# المنصة تضبط PORT تلقائياً
EXPOSE 3000

CMD ["node", "index.js"]
