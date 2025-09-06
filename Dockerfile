# Dockerfile بسيط وموثوق لتطبيق Express
FROM node:18-alpine

# مجلد العمل
WORKDIR /usr/src/app

# نسخ ملفات التعريف وتثبيت الاعتمادات
COPY package*.json ./
RUN npm install --production

# نسخ باقي المشروع
COPY . .

# تأكد أن الخادم يستمع لـ process.env.PORT (كودك يفعل ذلك)
EXPOSE 3000

# أمر التشغيل
CMD ["node", "index.js"]
