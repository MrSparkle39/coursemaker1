Write-Host "Installing Node.js dependencies..." -ForegroundColor Green
npm install

Write-Host "`nInitializing database..." -ForegroundColor Green
node init-db.js

Write-Host "`nStarting CourseMaker server..." -ForegroundColor Green
node server.js
