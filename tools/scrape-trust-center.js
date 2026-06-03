const { chromium } = require('playwright');
const fs = require('fs');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();

  await page.goto('https://trust.phala.com/', { waitUntil: 'networkidle' });

  // Scroll to load all apps via infinite scroll
  let prevCount = 0;
  let stableRounds = 0;
  for (let i = 0; i < 30; i++) {
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    await page.waitForTimeout(1500);

    const count = await page.locator('[class*="app"]').count();
    // Count actual app cards by looking for contract addresses
    const addrs = await page.evaluate(() => {
      const els = document.querySelectorAll('a[href*="/app/"]');
      return els.length;
    });

    console.error(`Scroll ${i+1}: ${addrs} app links found`);

    if (addrs === prevCount) {
      stableRounds++;
      if (stableRounds >= 3) break;
    } else {
      stableRounds = 0;
    }
    prevCount = addrs;
  }

  // Extract all app data
  const apps = await page.evaluate(() => {
    const results = [];
    // Find all app card links
    const links = document.querySelectorAll('a[href*="/app/"]');
    for (const link of links) {
      const href = link.getAttribute('href') || '';
      const idMatch = href.match(/\/app\/([a-f0-9]{40})/);
      if (!idMatch) continue;

      const id = idMatch[1];
      const text = link.textContent || '';

      // Try to extract the app name from the card
      const nameEl = link.querySelector('h3, [class*="name"], [class*="title"], span');
      const name = nameEl ? nameEl.textContent.trim() : text.trim().split('\n')[0].trim();

      results.push({ id, name, href });
    }

    // Dedupe by id
    const seen = new Set();
    return results.filter(a => {
      if (seen.has(a.id)) return false;
      seen.add(a.id);
      return true;
    });
  });

  console.error(`\nTotal unique apps: ${apps.length}`);

  // Also try to get more structured data from the page
  const structured = await page.evaluate(() => {
    const cards = document.querySelectorAll('[class*="card"], [class*="Card"]');
    const results = [];
    for (const card of cards) {
      const addrEl = card.querySelector('[class*="mono"]');
      const addr = addrEl ? addrEl.textContent.trim() : null;
      if (!addr || !addr.startsWith('0x')) continue;

      // Get all text content to find name and domain
      const allText = card.textContent;
      results.push({
        address: addr,
        fullText: allText.substring(0, 300)
      });
    }
    return results;
  });

  // Merge data
  const output = {
    scraped_at: new Date().toISOString(),
    total_found: apps.length,
    apps: apps,
    cards: structured
  };

  fs.writeFileSync('/tmp/trust-center-apps.json', JSON.stringify(output, null, 2));
  console.log(JSON.stringify(output, null, 2));

  await browser.close();
})();
