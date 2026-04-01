const puppeteer = require('puppeteer');

(async () => {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    // Log all messages
    page.on('console', msg => console.log('PAGE LOG:', msg.type(), msg.text()));
    page.on('pageerror', error => console.log('PAGE ERROR:', error.message));
    page.on('requestfailed', request => console.log('FAILED:', request.url(), request.failure()?.errorText));

    await page.goto('http://localhost:8069/web/login');
    await page.type('input[name="login"]', 'admin');
    await page.type('input[name="password"]', 'admin');
    await page.click('button[type="submit"]');
    await page.waitForNavigation({ waitUntil: 'networkidle0' });
    console.log("Logged in!");
    
    await page.goto('http://localhost:8069/web#action=securec_odoo.action_securec_dashboard', { waitUntil: 'networkidle0' });
    await new Promise(r => setTimeout(r, 4000));
    
    await browser.close();
})();
