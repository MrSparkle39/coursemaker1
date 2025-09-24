@echo off
echo Installing Node.js dependencies...
npm install
echo.
echo Initializing database...
node init-db.js
echo.
echo Starting CourseMaker server...
node server.js
pause
