const puppeteer = require('puppeteer');
(async () => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  page.on('console', msg => console.log('PAGE LOG:', msg.text()));
  page.on('pageerror', error => console.log('PAGE ERROR:', error.message));
  await page.goto('http://localhost:8069/web/login');
  await page.type('input[name="login"]', 'admin');
  await page.type('input[name="password"]', 'admin');
  await page.click('button[type="submit"]');
  await page.waitForNavigation();
  console.log("Logged in!");
  await page.goto('http://localhost:8069/web#action=securec_odoo.action_securec_dashboard');
  await new Promise(r => setTimeout(r, 3000));
  await browser.close();
})();
