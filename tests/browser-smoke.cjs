const assert = require('assert');
const fs = require('fs');
const http = require('http');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const root = path.resolve(__dirname, '..');
let appPort = 0;
let cdpPort = 0;
let baseUrl = '';

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function stopProcess(child) {
  if (!child || child.exitCode !== null) return;
  child.kill();
  await new Promise((resolve) => {
    child.once('exit', resolve);
    setTimeout(resolve, 1500);
  });
}

async function removeDirWithRetry(dir) {
  for (let i = 0; i < 6; i += 1) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
      return;
    } catch (err) {
      if (i === 5) throw err;
      await delay(250);
    }
  }
}

function getFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
  });
}

function isSafePort(port) {
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

async function resolveSmokePort(envName) {
  const explicit = process.env[envName];
  if (explicit) {
    const port = Number(explicit);
    assert.ok(isSafePort(port), `${envName} must be an integer from 1 to 65535`);
    return port;
  }
  return getFreePort();
}

function findChrome() {
  const candidates = [
    process.env.CHROME_PATH,
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser'
  ].filter(Boolean);
  return candidates.find((candidate) => fs.existsSync(candidate));
}

function startStaticServer() {
  const types = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.svg': 'image/svg+xml'
  };
  const server = http.createServer((req, res) => {
    try {
      const url = new URL(req.url, baseUrl);
      let name = decodeURIComponent(url.pathname);
      if (name === '/') name = '/index.html';
      const file = path.resolve(root, `.${name}`);
      const relative = path.relative(root, file);
      if (relative.startsWith('..') || path.isAbsolute(relative)) {
        res.writeHead(403);
        res.end('Forbidden');
        return;
      }
      fs.readFile(file, (err, data) => {
        if (err) {
          res.writeHead(404);
          res.end('Not found');
          return;
        }
        res.writeHead(200, {
          'Content-Type': types[path.extname(file)] || 'application/octet-stream',
          'Cache-Control': 'no-store'
        });
        res.end(data);
      });
    } catch (err) {
      res.writeHead(500);
      res.end(String(err));
    }
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(appPort, '127.0.0.1', () => resolve(server));
  });
}

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) throw new Error(`${response.status} ${url}`);
  return response.json();
}

class CdpClient {
  constructor(wsUrl) {
    this.wsUrl = wsUrl;
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = new Map();
  }

  async connect() {
    this.ws = new WebSocket(this.wsUrl);
    this.ws.addEventListener('message', (event) => this._onMessage(event));
    await new Promise((resolve, reject) => {
      this.ws.addEventListener('open', resolve, { once: true });
      this.ws.addEventListener('error', reject, { once: true });
    });
  }

  _onMessage(event) {
    const message = JSON.parse(event.data);
    if (message.id && this.pending.has(message.id)) {
      const { resolve, reject } = this.pending.get(message.id);
      this.pending.delete(message.id);
      if (message.error) reject(new Error(message.error.message));
      else resolve(message.result || {});
      return;
    }
    const bucket = this.listeners.get(message.method);
    if (bucket) bucket.forEach((listener) => listener(message.params || {}));
  }

  send(method, params = {}) {
    const id = this.nextId++;
    this.ws.send(JSON.stringify({ id, method, params }));
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error(`CDP timeout: ${method}`));
        }
      }, 8000);
    });
  }

  waitForEvent(method, predicate = () => true, timeout = 8000) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error(`CDP event timeout: ${method}`));
      }, timeout);
      const listener = (params) => {
        if (!predicate(params)) return;
        cleanup();
        resolve(params);
      };
      const cleanup = () => {
        clearTimeout(timer);
        const bucket = this.listeners.get(method);
        if (bucket) bucket.delete(listener);
      };
      if (!this.listeners.has(method)) this.listeners.set(method, new Set());
      this.listeners.get(method).add(listener);
    });
  }

  on(method, listener) {
    if (!this.listeners.has(method)) this.listeners.set(method, new Set());
    this.listeners.get(method).add(listener);
  }

  async evaluate(expression) {
    const result = await this.send('Runtime.evaluate', {
      expression,
      awaitPromise: true,
      returnByValue: true,
      userGesture: true
    });
    if (result.exceptionDetails) {
      const text = result.exceptionDetails.text || 'Runtime evaluation failed';
      throw new Error(text);
    }
    return result.result ? result.result.value : undefined;
  }

  close() {
    if (this.ws) this.ws.close();
  }
}

async function waitFor(client, expression, message) {
  const deadline = Date.now() + 8000;
  while (Date.now() < deadline) {
    if (await client.evaluate(expression)) return;
    await delay(80);
  }
  throw new Error(message);
}

async function click(client, selector) {
  const ok = await client.evaluate(`
    (() => {
      const el = document.querySelector(${JSON.stringify(selector)});
      if (!el) return false;
      el.click();
      return true;
    })()
  `);
  assert.ok(ok, `missing clickable selector: ${selector}`);
}

function tapPlaceScript(cardSelector, dataKey, slotPrefix) {
  return `
    (() => {
      const card = document.querySelector(${JSON.stringify(cardSelector)});
      const id = card?.dataset?.[${JSON.stringify(dataKey)}];
      const slot = id ? document.getElementById(${JSON.stringify(slotPrefix)} + id) : null;
      if (!card || !slot) return false;
      card.click();
      slot.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
      return card.classList.contains('placed') && slot.classList.contains('filled');
    })()
  `;
}

function qAdventureSpec(gameId) {
  return {
    gameId,
    screen: `screen-${gameId}`,
    open: `#btn-open-${gameId}`,
    back: `#btn-${gameId}-back`,
    transientRef: '_qadventure',
    assistCheck: `document.querySelectorAll('.ap-option-btn.eliminated').length > 0`,
    tapReady: `window._qadventure && window._qadventure.gameId === ${JSON.stringify(gameId)} && document.querySelectorAll('.ap-option-btn').length >= 4`,
    runtimeCheck: `
      (() => {
        const gameId = ${JSON.stringify(gameId)};
        const btn = document.getElementById(gameId + '-pu-hint');
        const count = document.getElementById(gameId + '-hint-count');
        const beforeEliminated = document.querySelectorAll('.ap-option-btn.eliminated').length;
        const beforeCount = Number(count?.textContent || -1);
        if (!btn || btn.disabled || beforeCount <= 0) return false;
        btn.click();
        const afterEliminated = document.querySelectorAll('.ap-option-btn.eliminated').length;
        const afterCount = Number(count?.textContent || -1);
        const eliminatedOk = Array.from(document.querySelectorAll('.ap-option-btn.eliminated')).every((option) =>
          option.getAttribute('aria-disabled') === 'true' &&
          option.getAttribute('aria-label')?.includes('已排除')
        );
        return afterEliminated > beforeEliminated && afterCount === beforeCount - 1 && eliminatedOk;
      })()
    `,
    beforeBack: `
      (() => {
        const game = window._qadventure;
        const btn = document.querySelector('.ap-option-btn:not(.eliminated):not(:disabled)');
        if (!game || !btn) return false;
        btn.click();
        window.__qaLifecycleProbe = game;
        return (
          game.nextQuestionTimer != null &&
          (game.charJumpTimer != null || game.nodeErrorTimer != null || game.questionAnimTimer != null)
        );
      })()
    `,
    afterBack: `
      (() => {
        const game = window.__qaLifecycleProbe;
        const ok = !!game &&
          game.active === false &&
          game.timerId == null &&
          game.nextQuestionTimer == null &&
          game.questionAnimTimer == null &&
          game.nodeErrorTimer == null &&
          game.charJumpTimer == null;
        window.__qaLifecycleProbe = null;
        return ok;
      })()
    `
  };
}

async function smokeGame(client, spec) {
  const beforePlayed = await client.evaluate(`gameState.gameStats[${JSON.stringify(spec.gameId)}]?.played || 0`);
  await click(client, spec.open);
  await waitFor(client, `gameState.currentScreen === ${JSON.stringify(spec.screen)}`, `did not enter ${spec.screen}`);
  await assertInteractiveSemantics(client, spec.screen);
  await waitFor(client, `document.querySelector('.coach-tip-btn') && !document.getElementById('gameplay-coach').classList.contains('hidden')`, `coach missing on ${spec.screen}`);
  await click(client, '.coach-tip-btn');
  await waitFor(client, spec.assistCheck || `document.querySelectorAll('.coach-highlight, .coach-peek').length > 0`, `coach did not assist ${spec.screen}`);
  const played = await client.evaluate(`gameState.gameStats[${JSON.stringify(spec.gameId)}]?.played || 0`);
  assert.strictEqual(played, beforePlayed + 1, `${spec.gameId} should record exactly one play per open`);
  if (spec.tapReady) {
    await waitFor(client, spec.tapReady, `tap placement controls missing on ${spec.screen}`);
  }
  if (spec.tapPlacement) {
    const tapOk = await client.evaluate(spec.tapPlacement);
    assert.ok(tapOk, `tap placement failed on ${spec.screen}`);
  }
  if (spec.runtimeCheck) {
    const runtimeOk = await client.evaluate(spec.runtimeCheck);
    assert.ok(runtimeOk, `runtime check failed on ${spec.screen}`);
  }
  if (spec.keyboardCheck) {
    const keyboardOk = await client.evaluate(spec.keyboardCheck);
    assert.ok(keyboardOk, `keyboard activation failed on ${spec.screen}`);
  }
  if (spec.beforeBack) {
    const beforeBackOk = await client.evaluate(spec.beforeBack);
    assert.ok(beforeBackOk, `before-back setup failed on ${spec.screen}`);
  }
  await click(client, spec.back);
  await waitFor(client, `gameState.currentScreen === 'screen-hub'`, `did not return from ${spec.screen}`);
  await waitFor(client, `!document.querySelector('.coach-highlight,.coach-peek,.coach-generated-marker')`, `gameplay assist highlights leaked after ${spec.screen}`);
  await waitFor(client, `typeof cognitiveRuntimeTimerCount !== 'function' || cognitiveRuntimeTimerCount() === 0`, `cognitive runtime timers leaked after ${spec.screen}`);
  await waitFor(client, `
    !document.querySelector('.tap-place-selected') &&
    window._timelineTapCard == null &&
    (!window._ecoGame || window._ecoGame.tapSelectedItem == null)
  `, `tap-to-place state leaked after ${spec.screen}`);
  if (spec.transientRef) {
    await waitFor(client, `window[${JSON.stringify(spec.transientRef)}] == null`, `${spec.transientRef} was not cleared after ${spec.screen}`);
  }
  if (spec.afterBack) {
    const afterBackOk = await client.evaluate(spec.afterBack);
    assert.ok(afterBackOk, `after-back cleanup failed on ${spec.screen}`);
  }
  if (spec.skillRef) {
    await waitFor(client, `
      (typeof skillRuntimeTimerCount !== 'function' || skillRuntimeTimerCount() === 0) &&
      window._a11yStage == null &&
      window._tracePath == null &&
      window._traceNodes == null &&
      window._decodeCurrent == null &&
      window._decodePuzzles == null &&
      !document.getElementById('a11y-tunnel-overlay')
    `, `skill runtime state leaked after ${spec.screen}`);
  }
}

async function assertHubCardA11yLabels(client) {
  const result = await client.evaluate(`
    (() => Array.from(document.querySelectorAll('.game-card[id^="btn-open-"]')).map((card) => {
      const label = card.getAttribute('aria-label') || '';
      return {
        id: card.id,
        label,
        title: card.querySelector('.game-card-title')?.textContent?.trim() || '',
        playedMentions: (label.match(/已玩|新体验/g) || []).length,
        bestMentions: (label.match(/最佳|未挑战/g) || []).length
      };
    }))()
  `);
  const bad = result.filter((item) => !item.label.includes(item.title) || item.playedMentions !== 1 || item.bestMentions !== 1);
  assert.deepStrictEqual(bad, [], 'hub card aria-labels should include clean title/status/best exactly once');
  const nestedCapsuleControls = await client.evaluate(`
    (() => Array.from(document.querySelectorAll('.capsule-card')).flatMap((card) =>
      Array.from(card.querySelectorAll('button, a[href], input, select, textarea, [tabindex]:not(.capsule-card)')).map((el) => ({
        card: card.id,
        tag: el.tagName,
        id: el.id || '',
        className: String(el.className || '')
      }))
    ))()
  `);
  assert.deepStrictEqual(nestedCapsuleControls, [], 'capsule cards should not contain nested interactive controls');
}

async function assertThemeSwitcherA11y(client) {
  const result = await client.evaluate(`
    (() => {
      const buttons = Array.from(document.querySelectorAll('.theme-btn'));
      const ocean = document.querySelector('.theme-btn.ocean');
      const warm = document.querySelector('.theme-btn.warm');
      if (!ocean || !warm) return { ok: false, reason: 'missing theme buttons' };
      ocean.click();
      const oceanOk = document.documentElement.dataset.theme === 'ocean' &&
        ocean.getAttribute('aria-pressed') === 'true' &&
        buttons.filter((btn) => btn.getAttribute('aria-pressed') === 'true').length === 1;
      warm.click();
      const labelsOk = buttons.length === 4 &&
        buttons.every((btn) => (btn.getAttribute('aria-label') || '').startsWith('切换主题：'));
      const warmOk = document.documentElement.dataset.theme === 'warm' &&
        warm.getAttribute('aria-pressed') === 'true' &&
        buttons.filter((btn) => btn.getAttribute('aria-pressed') === 'true').length === 1;
      return { ok: labelsOk && oceanOk && warmOk, labelsOk, oceanOk, warmOk };
    })()
  `);
  assert.ok(result.ok, `theme switcher aria state invalid: ${JSON.stringify(result)}`);
}

async function assertAudioToggleA11y(client) {
  const result = await client.evaluate(`
    (() => {
      const btn = document.getElementById('bgm-toggle-btn');
      const icon = btn?.querySelector('.audio-icon');
      const text = btn?.querySelector('.audio-text');
      if (!btn || !icon || !text) return { ok: false, reason: 'missing audio toggle' };
      const before = {
        pressed: btn.getAttribute('aria-pressed'),
        label: btn.getAttribute('aria-label'),
        icon: icon.textContent,
        text: text.textContent
      };
      const beforeOk = before.pressed === 'true' &&
        before.label === '关闭时光背景音乐' &&
        before.icon === '🔊' &&
        before.text.includes('播放中');
      btn.click();
      const after = {
        pressed: btn.getAttribute('aria-pressed'),
        label: btn.getAttribute('aria-label'),
        icon: icon.textContent,
        text: text.textContent
      };
      const afterOk = after.pressed === 'false' &&
        after.label === '播放时光背景音乐' &&
        after.icon === '🔇' &&
        after.text.includes('静音');
      return { ok: beforeOk && afterOk, beforeOk, afterOk, before, after };
    })()
  `);
  assert.ok(result.ok, `audio toggle aria state invalid: ${JSON.stringify(result)}`);
}

async function assertHubTabsA11y(client) {
  const result = await client.evaluate(`
    (async () => {
      const first = document.getElementById('hub-tab-capsules');
      const brain = document.getElementById('hub-tab-brain');
      const firstPanel = document.getElementById('hub-panel-capsules');
      const brainPanel = document.getElementById('hub-panel-brain');
      if (!first || !brain || !firstPanel || !brainPanel) return { ok: false, reason: 'missing tab or panel' };
      first.focus();
      first.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true, cancelable: true }));
      await new Promise((resolve) => requestAnimationFrame(resolve));
      const switched = brain.getAttribute('aria-selected') === 'true' &&
        brain.getAttribute('tabindex') === '0' &&
        brainPanel.getAttribute('aria-hidden') === 'false' &&
        first.getAttribute('aria-selected') === 'false' &&
        first.getAttribute('tabindex') === '-1' &&
        firstPanel.getAttribute('aria-hidden') === 'true' &&
        document.activeElement === brain;
      first.click();
      const restored = first.getAttribute('aria-selected') === 'true' &&
        firstPanel.getAttribute('aria-hidden') === 'false' &&
        brainPanel.getAttribute('aria-hidden') === 'true';
      return { ok: switched && restored, switched, restored, activeId: document.activeElement && document.activeElement.id };
    })()
  `);
  assert.ok(result.ok, `hub tab a11y state invalid: ${JSON.stringify(result)}`);
}

async function assertSecurityAndAudioGuards(client) {
  const result = await client.evaluate(`
    (() => {
      const dirtySvg = '<svg onload="alert(1)"><foreignObject><iframe srcdoc="<script>bad()</script>"></iframe></foreignObject><a xlink:href="javascript:alert(1)">x</a><g style="background:url(javascript:alert(1));color:red"></g><script>alert(1)</script></svg>';
      const cleanSvg = String(sanitizeHTML(dirtySvg));
      const dirtyHtml = '<a href=" \\n java\\tscript:alert(1)" style="background:url(java\\nscript:alert(1));color:red" data-ok="1">link</a><img src=" data:text/html,<script>x</script>" alt="x">';
      const cleanHtml = String(sanitizeHTML(dirtyHtml));
      const safeHtml = String(sanitizeHTML('<span style="color:red" data-note="ok">safe</span>'));
      let unifiedQuizEscaped = false;
      let quizHost = null;
      let quizEngine = null;
      const oldStats = JSON.parse(JSON.stringify(gameState.gameStats || {}));
      const oldPlayed = gameState.totalGamesPlayed;
      try {
        quizHost = document.createElement('div');
        quizHost.innerHTML = '<div id="quiz-xss-area"></div><div id="quiz-xss-explain"></div>';
        document.body.appendChild(quizHost);
        quizEngine = new UnifiedQuizEngine({
          gameId: 'quiz-xss',
          gameAreaId: 'quiz-xss-area',
          explainAreaId: 'quiz-xss-explain',
          questions: [{
            text: '<img src=x onerror=alert(1)>公益题',
            options: ['<script>bad()</script>', '安全'],
            correct: 0,
            explain: '<img src=x onerror=alert(2)>解析'
          }]
        });
        quizEngine.init('easy', 'classic');
        const option = quizHost.querySelector('.quiz-option-btn');
        const questionText = quizHost.querySelector('.quiz-q-text')?.textContent || '';
        const questionOk = !quizHost.querySelector('.quiz-q-text img, .quiz-q-text script, .quiz-option-btn script') &&
          questionText.includes('<img') &&
          (option?.textContent || '').includes('<script>');
        if (option) option.click();
        const explain = document.getElementById('quiz-xss-explain');
        const explainOk = !explain?.querySelector('img, script') &&
          (explain?.textContent || '').includes('<img');
        unifiedQuizEscaped = questionOk && explainOk;
      } catch (err) {
        unifiedQuizEscaped = false;
      } finally {
        if (quizEngine) quizEngine.destroy();
        if (quizHost) quizHost.remove();
        gameState.gameStats = oldStats;
        gameState.totalGamesPlayed = oldPlayed;
      }
      const oldAlbum = gameState.albumEntries.slice();
      gameState.albumEntries = [{
        id: 'radio',
        title: '<img src=x onerror=alert(1)>',
        storyText: '第一行<img src=x onerror=alert(1)>\\n<script>alert(2)</script>',
        date: '<b>bad date</b>'
      }, {
        id: 'unknown-item',
        title: '旧存档未知物件',
        storyText: '<script>bad()</script>',
        date: 'old'
      }];
      let albumRenderOk = true;
      try {
        renderAlbum();
      } catch (err) {
        albumRenderOk = false;
      }
      const album = document.getElementById('album-pages-container');
      const albumEscaped = albumRenderOk &&
        !album.querySelector('.entry-story img, .entry-story script, .entry-badge b') &&
        album.querySelector('.entry-story')?.textContent.includes('<img') &&
        album.querySelector('.entry-badge')?.textContent.includes('<b>bad date</b>') &&
        !album.textContent.includes('旧存档未知物件');
      gameState.albumEntries = oldAlbum;
      renderAlbum();
      let speakOk = false;
      try {
        audio.speak(null);
        audio.speak('');
        speakOk = true;
      } catch (err) {
        speakOk = false;
      }
      const probe = document.createElement('button');
      document.body.appendChild(probe);
      let bindCount = 0;
      safeBindClick(probe, () => { bindCount += 1; });
      safeBindClick(probe, () => { bindCount += 100; });
      probe.click();
      probe.remove();
      return {
        cleanSvg,
        cleanHtml,
        safeHtml,
        keepsSvg: /<svg/i.test(cleanSvg),
        hasSvgDanger: /<script|foreignObject|iframe|onload|javascript:|xlink:href|data:text\\/html|expression\\s*\\(/i.test(cleanSvg),
        hasHtmlDanger: /href\\s*=|src\\s*=|style\\s*=|javascript:|data:text\\/html|expression\\s*\\(/i.test(cleanHtml),
        keepsSafeStyle: /style\\s*=/.test(safeHtml) && /color\\s*:\\s*red/i.test(safeHtml) && /data-note/.test(safeHtml),
        unifiedQuizEscaped,
        albumEscaped,
        speakOk,
        bindCount
      };
    })()
  `);
  assert.ok(result.keepsSvg, 'SVG sanitizer should preserve safe SVG wrappers');
  assert.strictEqual(result.hasSvgDanger, false, `SVG sanitizer left dangerous content: ${result.cleanSvg}`);
  assert.strictEqual(result.hasHtmlDanger, false, `HTML sanitizer left dangerous attributes: ${result.cleanHtml}`);
  assert.strictEqual(result.keepsSafeStyle, true, `HTML sanitizer should keep safe inline styles: ${result.safeHtml}`);
  assert.strictEqual(result.unifiedQuizEscaped, true, 'UnifiedQuizEngine should render question and explanation text without HTML injection');
  assert.strictEqual(result.albumEscaped, true, 'album renderer should escape saved text fields before HTML insertion');
  assert.strictEqual(result.speakOk, true, 'audio.speak should ignore empty or null text without throwing');
  assert.strictEqual(result.bindCount, 1, 'safeBindClick should ignore duplicate bindings on the same element');
}

async function assertNoHorizontalOverflow(client, label) {
  const result = await client.evaluate(`
    (() => {
      const vw = document.documentElement.clientWidth;
      const active = document.querySelector('.game-screen.active') || document.body;
      const activeScroll = active.scrollWidth || 0;
      const rootScroll = document.documentElement.scrollWidth || 0;
      const bad = Array.from(active.querySelectorAll('*')).filter((el) => {
        if (el.ownerSVGElement) return false;
        const style = getComputedStyle(el);
        if (style.position === 'fixed' || style.visibility === 'hidden' || style.display === 'none') return false;
        const rect = el.getBoundingClientRect();
        if (rect.width < 2 || rect.height < 2) return false;
        return rect.left < -3 || rect.right > vw + 3;
      }).slice(0, 4).map((el) => ({
        tag: el.tagName,
        id: el.id || '',
        className: String(el.className || '').slice(0, 80),
        left: Math.round(el.getBoundingClientRect().left),
        right: Math.round(el.getBoundingClientRect().right)
      }));
      return { ok: rootScroll <= vw + 3 && activeScroll <= vw + 3 && bad.length === 0, vw, rootScroll, activeScroll, bad };
    })()
  `);
  assert.ok(result.ok, `${label} has horizontal overflow: ${JSON.stringify(result)}`);
}

async function assertReducedMotion(client) {
  await client.send('Emulation.setEmulatedMedia', {
    features: [{ name: 'prefers-reduced-motion', value: 'reduce' }]
  });
  const result = await client.evaluate(`
    (() => {
      const card = document.querySelector('.game-card');
      const style = card ? getComputedStyle(card) : null;
      return {
        ok: !!style && parseFloat(style.transitionDuration) <= 0.01,
        transitionDuration: style ? style.transitionDuration : ''
      };
    })()
  `);
  assert.ok(result.ok, `reduced-motion should minimize transitions: ${JSON.stringify(result)}`);
  await waitFor(client, `!window._ambientParticles || window._ambientParticles.frameId == null`, 'ambient particles should pause under reduced motion');
  const screenTransition = await client.evaluate(`
    (() => {
      transitionToScreen('screen-start');
      const flashAfterStart = document.getElementById('screen-flash')?.classList.contains('active') || false;
      const leavingAfterStart = document.querySelectorAll('.game-screen.leaving').length;
      transitionToScreen('screen-hub');
      const flashAfterHub = document.getElementById('screen-flash')?.classList.contains('active') || false;
      const leavingAfterHub = document.querySelectorAll('.game-screen.leaving').length;
      return {
        ok: !flashAfterStart && !flashAfterHub && leavingAfterStart === 0 && leavingAfterHub === 0 && gameState.currentScreen === 'screen-hub',
        flashAfterStart,
        flashAfterHub,
        leavingAfterStart,
        leavingAfterHub,
        currentScreen: gameState.currentScreen
      };
    })()
  `);
  assert.ok(screenTransition.ok, `reduced-motion should skip screen flash/leaving animation: ${JSON.stringify(screenTransition)}`);
  const transient = await client.evaluate(`
    (() => {
      document.querySelectorAll('.score-particle,.combo-particle,.touch-ripple').forEach((el) => el.remove());
      const btn = document.createElement('button');
      btn.textContent = 'motion probe';
      btn.style.position = 'relative';
      document.body.appendChild(btn);
      if (typeof spawnScoreParticle === 'function') spawnScoreParticle(24, 24, '+1', '#fff');
      if (typeof spawnComboBurst === 'function') spawnComboBurst(24, 24, 5, '#fff');
      if (typeof spawnTouchRipple === 'function') spawnTouchRipple(btn, { clientX: 30, clientY: 30 });
      btn.dispatchEvent(new MouseEvent('click', { bubbles: true, clientX: 30, clientY: 30 }));
      const counts = {
        score: document.querySelectorAll('.score-particle').length,
        combo: document.querySelectorAll('.combo-particle').length,
        ripple: document.querySelectorAll('.touch-ripple').length
      };
      btn.remove();
      return {
        ok: typeof spawnScoreParticle === 'function' &&
          typeof spawnComboBurst === 'function' &&
          typeof spawnTouchRipple === 'function' &&
          counts.score === 0 &&
          counts.combo === 0 &&
          counts.ripple === 0,
        counts
      };
    })()
  `);
  assert.ok(transient.ok, `reduced-motion should skip transient particles and ripples: ${JSON.stringify(transient)}`);
  await client.send('Emulation.setEmulatedMedia', { features: [] });
}

async function assertWorkbenchRuntimeCleanup(client) {
  await client.evaluate(`
    (() => {
      if (!gameState.unlockedItems.includes('sewing')) gameState.unlockedItems.push('sewing');
      gameState.completedItems = gameState.completedItems.filter((id) => id !== 'sewing');
      if (typeof syncHubState === 'function') syncHubState();
    })()
  `);
  await click(client, '#capsule-sewing');
  await waitFor(client, `gameState.currentScreen === 'screen-workspace'`, 'sewing capsule did not enter workspace');
  const started = await client.evaluate(`
    (() => {
      if (typeof setupInteractiveToy !== 'function') return false;
      setupInteractiveToy('radio');
      const slider = document.querySelector('#radio-tuning-slider');
      const radioOk = workbench._radioSlider === slider && typeof slider?.oninput === 'function';
      setupInteractiveToy('camera');
      const camera = document.querySelector('#btn-camera-shutter');
      const cameraOk = workbench._radioSlider == null &&
        workbench._cameraButton === camera &&
        typeof camera?.onclick === 'function';
      if (typeof setupInteractiveToy === 'function') setupInteractiveToy('sewing');
      const btn = document.querySelector('#btn-sewing-pedal');
      if (!btn || typeof workbench?.cleanupActiveRuntime !== 'function') return false;
      btn.dispatchEvent(new PointerEvent('pointerdown', {
        bubbles: true,
        cancelable: true,
        pointerId: 7,
        clientX: 10,
        clientY: 10
      }));
      workbench.celebration.burst(20, 20, '#fff');
      window.__workbenchTimerLeak = false;
      workbench.scheduleAwakeTimer(() => { window.__workbenchTimerLeak = true; }, 120);
      return radioOk &&
        cameraOk &&
        workbench._cameraButton == null &&
        workbench._sewingInterval != null &&
        workbench._sewingButton === btn &&
        workbench._awakeTimers.length > 0 &&
        workbench.celebration.isLooping === true &&
        workbench.celebration.sparkles.length > 0;
    })()
  `);
  assert.ok(started, 'workbench sewing interval should be tracked while pedal is held');
  await click(client, '#btn-back-to-hub');
  await waitFor(client, `gameState.currentScreen === 'screen-hub'`, 'workspace did not return to hub');
  await delay(180);
  const cleaned = await client.evaluate(`
    (() => {
      const btn = document.querySelector('#btn-sewing-pedal');
      return !!workbench &&
        workbench._sewingInterval == null &&
        workbench._sewingButton == null &&
        workbench._radioSlider == null &&
        workbench._cameraButton == null &&
        workbench._awakeTimers.length === 0 &&
        window.__workbenchTimerLeak === false &&
        workbench.celebration.frameId == null &&
        workbench.celebration.isLooping === false &&
        workbench.celebration.sparkles.length === 0 &&
        (!btn || (btn.onpointerdown == null && btn.onpointerup == null && btn.onpointercancel == null)) &&
        gameState.draggedElement == null &&
        gameState.activeDragPart == null;
    })()
  `);
  assert.ok(cleaned, 'workbench runtime should clear sewing handlers and drag state after leaving workspace');
}

async function assertShortcutCleanup(client) {
  await click(client, '#btn-open-water');
  await waitFor(client, `gameState.currentScreen === 'screen-water' && window._qadventure != null`, 'water adventure did not start for shortcut cleanup');
  await client.evaluate(`
    document.dispatchEvent(new KeyboardEvent('keydown', {
      key: 'Escape',
      bubbles: true,
      cancelable: true
    }))
  `);
  await waitFor(client, `gameState.currentScreen === 'screen-hub'`, 'Escape did not return to hub');
  await waitFor(client, `window._qadventure == null`, 'Escape shortcut did not destroy QAdventure engine');

  await client.evaluate(`document.getElementById('btn-open-shop')?.focus()`);
  await click(client, '#btn-open-shop');
  await waitFor(client, `document.getElementById('shop-overlay')?.classList.contains('active')`, 'shop modal did not open for Escape cleanup');
  await waitFor(client, `document.activeElement?.id === 'btn-close-shop'`, 'shop modal did not move focus to its close button');
  await client.evaluate(`
    document.dispatchEvent(new KeyboardEvent('keydown', {
      key: 'Escape',
      bubbles: true,
      cancelable: true
    }))
  `);
  await delay(1600);
  const modalState = await client.evaluate(`
    (() => ({
      closed: !document.querySelector('.modal-overlay.active'),
      shopHidden: document.getElementById('shop-overlay')?.getAttribute('aria-hidden') === 'true',
      activeId: document.activeElement?.id || '',
      activeTag: document.activeElement?.tagName || ''
    }))()
  `);
  assert.ok(
    modalState.closed && modalState.shopHidden && modalState.activeId === 'btn-open-shop',
    `Escape did not close the active hub modal overlay: ${JSON.stringify(modalState)}`
  );
}

async function assertTouchTargets(client, label) {
  const result = await client.evaluate(`
    (() => {
      const selectors = [
        '.coach-tip-btn',
        '.theme-btn',
        '.hub-tab',
        '.game-card',
        '.timeline-card:not(.placed)',
        '.timeline-slot',
        '.hidden-object:not(.found)',
        '.maze-cell',
        '.color-card:not(.placed)',
        '.color-group',
        '.face-card:not(.matched)',
        '.rhythm-btn',
        '.eco-item:not(.done)',
        '.eco-bin',
        '.ap-option-btn',
        '.ap-pu-btn'
      ];
      const bad = Array.from(document.querySelectorAll(selectors.join(','))).filter((el) => {
        const style = getComputedStyle(el);
        if (style.display === 'none' || style.visibility === 'hidden' || style.pointerEvents === 'none') return false;
        const rect = el.getBoundingClientRect();
        if (rect.width < 2 || rect.height < 2) return false;
        return rect.width < 43.5 || rect.height < 43.5;
      }).slice(0, 8).map((el) => {
        const rect = el.getBoundingClientRect();
        return {
          tag: el.tagName,
          id: el.id || '',
          className: String(el.className || '').slice(0, 80),
          width: Math.round(rect.width),
          height: Math.round(rect.height)
        };
      });
      return { ok: bad.length === 0, bad };
    })()
  `);
  assert.ok(result.ok, `${label} has undersized touch targets: ${JSON.stringify(result.bad)}`);
}

async function assertMobileFloatingControls(client) {
  const result = await client.evaluate(`
    (() => {
      const theme = document.querySelector('.theme-switcher');
      const coach = document.querySelector('#gameplay-coach');
      const audio = document.querySelector('#audio-control');
      const audioText = document.querySelector('.audio-text');
      if (!theme || !audio || !audioText) return { ok: false, reason: 'missing floating control' };
      const themeStyle = getComputedStyle(theme);
      const audioTextStyle = getComputedStyle(audioText);
      const audioRect = audio.getBoundingClientRect();
      const themeRect = theme.getBoundingClientRect();
      const coachRect = coach && !coach.classList.contains('hidden') ? coach.getBoundingClientRect() : null;
      const overlapsCoach = coachRect
        ? !(themeRect.right <= coachRect.left || themeRect.left >= coachRect.right || themeRect.bottom <= coachRect.top || themeRect.top >= coachRect.bottom)
        : false;
      return {
        ok:
          themeStyle.flexDirection === 'row' &&
          audioTextStyle.display === 'none' &&
          audioRect.width <= 64 &&
          audioRect.height <= 64 &&
          !overlapsCoach,
        themeFlex: themeStyle.flexDirection,
        audioTextDisplay: audioTextStyle.display,
        audioWidth: Math.round(audioRect.width),
        audioHeight: Math.round(audioRect.height),
        overlapsCoach
      };
    })()
  `);
  assert.ok(result.ok, `mobile floating controls overlap content: ${JSON.stringify(result)}`);
}

async function assertInteractiveSemantics(client, label) {
  const result = await client.evaluate(`
    (() => {
      const selectors = [
        '.color-card',
        '.color-group',
        '.hidden-object',
        '.maze-cell',
        '.face-card',
        '.rhythm-btn',
        '#a11y-canvas',
        '.ap-option-btn',
        '.ap-pu-btn'
      ];
      const bad = Array.from(document.querySelectorAll(selectors.join(','))).filter((el) => {
        const style = getComputedStyle(el);
        if (style.display === 'none' || style.visibility === 'hidden' || style.pointerEvents === 'none') return false;
        if (el.getAttribute('aria-disabled') === 'true' || el.classList.contains('placed') || el.classList.contains('matched')) return false;
        const label = (el.getAttribute('aria-label') || '').trim();
        return el.getAttribute('role') !== 'button' ||
          el.tabIndex < 0 ||
          !label ||
          /^(Color card|Color group|Face memory card|Rhythm pad)\\b/.test(label);
      }).slice(0, 8).map((el) => ({
        tag: el.tagName,
        className: String(el.className || '').slice(0, 80),
        role: el.getAttribute('role') || '',
        tabIndex: el.tabIndex,
        ariaLabel: el.getAttribute('aria-label') || ''
      }));
      return { ok: bad.length === 0, bad };
    })()
  `);
  assert.ok(result.ok, `${label} custom controls lack button semantics: ${JSON.stringify(result.bad)}`);
}

async function mobileLayoutSmoke(client) {
  await client.send('Emulation.setDeviceMetricsOverride', {
    width: 390,
    height: 844,
    deviceScaleFactor: 2,
    mobile: true
  });
  await client.send('Emulation.setTouchEmulationEnabled', { enabled: true });
  await waitFor(client, `gameState.currentScreen === 'screen-hub'`, 'mobile smoke should start at hub');
  await assertNoHorizontalOverflow(client, 'mobile hub');
  await assertTouchTargets(client, 'mobile hub');
  await assertMobileFloatingControls(client);

  const mobileSpecs = [
    { screen: 'screen-timeline', open: '#btn-open-timeline', back: '#btn-timeline-back' },
    { screen: 'screen-hidden', open: '#btn-open-hidden', back: '#btn-hidden-back' },
    { screen: 'screen-maze', open: '#btn-open-maze', back: '#btn-maze-back' },
    { screen: 'screen-color', open: '#btn-open-color', back: '#btn-color-back' },
    { screen: 'screen-face', open: '#btn-open-face', back: '#btn-face-back' },
    { screen: 'screen-rhythm', open: '#btn-open-rhythm', back: '#btn-rhythm-back' },
    { screen: 'screen-eco', open: '#btn-open-eco', back: '#btn-eco-back' },
    { screen: 'screen-water', open: '#btn-open-water', back: '#btn-water-back' },
    { screen: 'screen-ocean', open: '#btn-open-ocean', back: '#btn-ocean-back' },
    { screen: 'screen-heart', open: '#btn-open-heart', back: '#btn-heart-back' },
    { screen: 'screen-grain', open: '#btn-open-grain', back: '#btn-grain-back' }
  ];

  for (const spec of mobileSpecs) {
    await click(client, spec.open);
    await waitFor(client, `gameState.currentScreen === ${JSON.stringify(spec.screen)}`, `mobile did not enter ${spec.screen}`);
    await assertNoHorizontalOverflow(client, `mobile ${spec.screen}`);
    await assertTouchTargets(client, `mobile ${spec.screen}`);
    await assertInteractiveSemantics(client, `mobile ${spec.screen}`);
    await click(client, spec.back);
    await waitFor(client, `gameState.currentScreen === 'screen-hub'`, `mobile did not return from ${spec.screen}`);
  }

  await client.send('Emulation.clearDeviceMetricsOverride');
  await client.send('Emulation.setTouchEmulationEnabled', { enabled: false });
}

async function main() {
  if (typeof WebSocket === 'undefined') {
    throw new Error('This smoke test requires Node.js with a global WebSocket implementation.');
  }

  const chrome = findChrome();
  assert.ok(chrome, 'Chrome or Edge executable not found. Set CHROME_PATH to run browser smoke tests.');

  appPort = await resolveSmokePort('SMOKE_APP_PORT');
  cdpPort = await resolveSmokePort('SMOKE_CDP_PORT');
  baseUrl = `http://127.0.0.1:${appPort}`;
  console.log(`browser smoke ports app=${appPort} cdp=${cdpPort}`);

  const server = await startStaticServer();
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'shanxing-smoke-'));
  const chromeProcess = spawn(chrome, [
    '--headless=new',
    `--remote-debugging-port=${cdpPort}`,
    '--disable-gpu',
    '--no-first-run',
    '--no-default-browser-check',
    `--user-data-dir=${profile}`,
    'about:blank'
  ], { stdio: 'ignore' });

  let client;
  const runtimeErrors = [];

  try {
    let target;
    for (let i = 0; i < 60; i += 1) {
      try {
        target = await fetchJson(`http://127.0.0.1:${cdpPort}/json/new?${encodeURIComponent('about:blank')}`, { method: 'PUT' });
        break;
      } catch (err) {
        await delay(100);
      }
    }
    assert.ok(target && target.webSocketDebuggerUrl, 'Chrome DevTools endpoint did not become ready');

    client = new CdpClient(target.webSocketDebuggerUrl);
    await client.connect();
    client.on('Runtime.exceptionThrown', (params) => {
      runtimeErrors.push(params.exceptionDetails?.text || 'Runtime exception');
    });
    client.on('Runtime.consoleAPICalled', (params) => {
      if (params.type === 'error') {
        runtimeErrors.push((params.args || []).map((arg) => arg.value || arg.description || '').join(' '));
      }
    });
    await client.send('Page.enable');
    await client.send('Runtime.enable');
    const loaded = client.waitForEvent('Page.loadEventFired');
    await client.send('Page.navigate', { url: baseUrl });
    await loaded;
    await waitFor(client, `document.readyState === 'complete' && typeof transitionToScreen === 'function'`, 'app did not load');
    await assertSecurityAndAudioGuards(client);

    await click(client, '#btn-start-game');
    await waitFor(client, `gameState.currentScreen === 'screen-hub'`, 'start did not enter hub');
    await assertThemeSwitcherA11y(client);
    await assertAudioToggleA11y(client);
    await assertHubTabsA11y(client);
    await assertReducedMotion(client);
    await assertWorkbenchRuntimeCleanup(client);
    await assertShortcutCleanup(client);

    const specs = [
      {
        gameId: 'memory-match',
        screen: 'screen-match',
        open: '#btn-open-match',
        back: '#btn-match-back',
        beforeBack: `
          (() => {
            const game = window._memoryMatchGame;
            const cards = Array.from(document.querySelectorAll('.match-card'));
            if (!game || cards.length < 2 || typeof cognitiveRuntimeTimerCount !== 'function') return false;
            let pair = null;
            for (let i = 0; i < cards.length && !pair; i += 1) {
              for (let j = i + 1; j < cards.length; j += 1) {
                const a = cards[i].querySelector('.match-card-back')?.textContent;
                const b = cards[j].querySelector('.match-card-back')?.textContent;
                if (a && b && a !== b) {
                  pair = [cards[i], cards[j]];
                  break;
                }
              }
            }
            if (!pair) return false;
            pair[0].click();
            pair[1].click();
            return game.locked && game.mismatchTimer != null && cognitiveRuntimeTimerCount() > 0;
          })()
        `,
        afterBack: `
          new Promise((resolve) => {
            setTimeout(() => {
              const game = window._memoryMatchGame;
              resolve(
                (typeof cognitiveRuntimeTimerCount !== 'function' || cognitiveRuntimeTimerCount() === 0) &&
                (!game || (game.mismatchTimer == null && game.locked === false))
              );
            }, 850);
          })
        `
      },
      {
        gameId: 'timeline',
        screen: 'screen-timeline',
        open: '#btn-open-timeline',
        back: '#btn-timeline-back',
        runtimeCheck: `
          (() => {
            if (typeof cognitiveRuntimeTimerCount !== 'function') return false;
            const beforeCompleted = gameState.gameStats.timeline?.completed || 0;
            const beforeSilver = gameState.memorySilver;
            const check = document.querySelector('#btn-timeline-check');
            const result = document.querySelector('#timeline-result');
            const title = document.querySelector('#timeline-result-title');
            if (!check || !result || !title) return false;
            check.click();
            const blocked =
              !title.textContent.includes('完全正确') &&
              (gameState.gameStats.timeline?.completed || 0) === beforeCompleted &&
              gameState.memorySilver === beforeSilver &&
              window._timelineResetTimer != null &&
              cognitiveRuntimeTimerCount() > 0;
            if (window._timelineResetTimer) {
              clearTrackedCognitiveTimeout(window._timelineResetTimer);
              window._timelineResetTimer = null;
            }
            result.classList.add('hidden');
            return blocked;
          })()
        `,
        beforeBack: `
          (() => {
            const firstSlot = document.querySelector('.timeline-slot:not(.filled)');
            const check = document.querySelector('#btn-timeline-check');
            const wrongCard = Array.from(document.querySelectorAll('.timeline-card:not(.placed)'))
              .find((card) => card.dataset.year !== firstSlot?.textContent.trim());
            if (!wrongCard || !firstSlot || !check || typeof cognitiveRuntimeTimerCount !== 'function') return false;
            wrongCard.click();
            const selected = !!window._timelineTapCard && wrongCard.classList.contains('tap-place-selected');
            firstSlot.click();
            check.click();
            const dragCard = document.querySelector('.timeline-card:not(.placed)');
            if (dragCard) {
              dragCard.dispatchEvent(new PointerEvent('pointerdown', {
                bubbles: true,
                cancelable: true,
                pointerId: 1,
                clientX: 120,
                clientY: 120
              }));
            }
            return (
              selected &&
              wrongCard.classList.contains('placed') &&
              window._timelineTapCard == null &&
              window._timelineResetTimer != null &&
              cognitiveRuntimeTimerCount() > 0 &&
              window._timelineCleanup?.clone?.isConnected === true
            );
          })()
        `,
        afterBack: `
          new Promise((resolve) => {
            setTimeout(() => {
              const bodyClone = Array.from(document.body.children)
                .some((el) => el.classList && el.classList.contains('timeline-card'));
              resolve(
                window._timelineResetTimer == null &&
                window._timelineCleanup == null &&
                !bodyClone &&
                (typeof cognitiveRuntimeTimerCount !== 'function' || cognitiveRuntimeTimerCount() === 0)
              );
            }, 120);
          })
        `
      },
      {
        gameId: 'hidden',
        screen: 'screen-hidden',
        open: '#btn-open-hidden',
        back: '#btn-hidden-back',
        keyboardCheck: `
          (() => {
            const obj = document.querySelector('.hidden-object:not(.found)');
            const found = document.querySelector('#hidden-found');
            if (!obj || !found) return false;
            const before = Number(found.textContent || 0);
            obj.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }));
            return (
              obj.classList.contains('found') &&
              obj.getAttribute('aria-disabled') === 'true' &&
              Number(found.textContent || 0) === before + 1
            );
          })()
        `
      },
      {
        gameId: 'maze',
        screen: 'screen-maze',
        open: '#btn-open-maze',
        back: '#btn-maze-back',
        runtimeCheck: `
          (() => {
            if (typeof cognitiveRuntimeTimerCount !== 'function') return false;
            const wrong = Array.from(document.querySelectorAll('.maze-cell'))
              .find((cell) => Number(cell.dataset.number) !== 1);
            if (!wrong) return false;
            wrong.click();
            return wrong.classList.contains('wrong') && cognitiveRuntimeTimerCount() > 0;
          })()
        `,
        keyboardCheck: `
          (() => {
            const next = document.querySelector('.maze-cell.next');
            const scoreEl = document.querySelector('#maze-score');
            if (!next || !scoreEl) return false;
            const before = Number(scoreEl.textContent || 0);
            next.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }));
            return next.classList.contains('correct') && Number(scoreEl.textContent || 0) > before;
          })()
        `
      },
      {
        gameId: 'color',
        screen: 'screen-color',
        open: '#btn-open-color',
        back: '#btn-color-back',
        tapReady: `document.querySelector('.color-card') && document.querySelector('.color-group')`,
        tapPlacement: `
          (async () => {
            const cards = Array.from(document.querySelectorAll('.color-card:not(.placed)'));
            const groups = Array.from(document.querySelectorAll('.color-group'));
            const card = cards.find((item) => groups.some((group) => group.dataset.group !== item.dataset.group));
            const wrongGroup = card && groups.find((group) => group.dataset.group !== card.dataset.group);
            if (!card || !wrongGroup) return false;
            card.click();
            wrongGroup.click();
            await new Promise((resolve) => setTimeout(resolve, 450));
            return !card.classList.contains('placed') && card.getAttribute('aria-disabled') !== 'true';
          })()
        `,
        keyboardCheck: `
          (() => {
            const card = document.querySelector('.color-card:not(.placed)');
            const group = card ? document.querySelector('.color-group[data-group="' + card.dataset.group + '"]') : null;
            if (!card || !group) return false;
            card.dispatchEvent(new KeyboardEvent('keydown', { key: ' ', bubbles: true, cancelable: true }));
            const selected = card.classList.contains('selected');
            group.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }));
            return selected && card.classList.contains('placed') && card.getAttribute('aria-disabled') === 'true';
          })()
        `
      },
      {
        gameId: 'face',
        screen: 'screen-face',
        open: '#btn-open-face',
        back: '#btn-face-back',
        keyboardCheck: `
          (() => {
            const card = document.querySelector('.face-card:not(.matched):not(.flipped)');
            if (!card) return false;
            card.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }));
            return card.classList.contains('flipped');
          })()
        `
      },
      {
        gameId: 'word',
        screen: 'screen-word',
        open: '#btn-open-word',
        back: '#btn-word-back',
        runtimeCheck: `
          (() => {
            if (typeof cognitiveRuntimeTimerCount !== 'function') return false;
            const option = document.querySelector('.word-option[data-index="0"]');
            const scoreEl = document.querySelector('#word-score');
            if (!option || !scoreEl || !option.getAttribute('aria-label')?.includes('词语联想选项')) return false;
            const before = Number(scoreEl.textContent || 0);
            option.click();
            return (
              option.disabled === true &&
              option.getAttribute('aria-disabled') === 'true' &&
              option.getAttribute('aria-label')?.includes('正确选项') &&
              Number(scoreEl.textContent || 0) > before &&
              !!document.querySelector('.word-round [role="status"]') &&
              cognitiveRuntimeTimerCount() > 0
            );
          })()
        `
      },
      {
        gameId: 'rhythm',
        screen: 'screen-rhythm',
        open: '#btn-open-rhythm',
        back: '#btn-rhythm-back',
        assistCheck: `document.querySelector('#btn-rhythm-start')?.style.display === 'none' || document.querySelectorAll('.rhythm-btn.coach-highlight').length > 0`,
        runtimeCheck: `
          (async () => {
            const start = document.querySelector('#btn-rhythm-start');
            if (!start || typeof cognitiveRuntimeTimerCount !== 'function') return false;
            start.click();
            await new Promise((resolve) => setTimeout(resolve, 1500));
            return cognitiveRuntimeTimerCount() === 0;
          })()
        `,
        keyboardCheck: `
          (() => {
            const btn = document.querySelector('.rhythm-btn');
            const scoreEl = document.querySelector('#rhythm-score');
            const result = document.querySelector('#rhythm-result');
            if (!btn || !scoreEl || !result) return false;
            const beforeScore = Number(scoreEl.textContent || 0);
            const beforeTimerCount = typeof cognitiveRuntimeTimerCount === 'function' ? cognitiveRuntimeTimerCount() : 0;
            btn.dispatchEvent(new KeyboardEvent('keydown', { key: ' ', bubbles: true, cancelable: true }));
            const afterScore = Number(scoreEl.textContent || 0);
            const afterTimerCount = typeof cognitiveRuntimeTimerCount === 'function' ? cognitiveRuntimeTimerCount() : 0;
            return afterScore !== beforeScore || !result.classList.contains('hidden') || afterTimerCount > beforeTimerCount;
          })()
        `
      },
      {
        gameId: 'spatial',
        screen: 'screen-spatial',
        open: '#btn-open-spatial',
        back: '#btn-spatial-back',
        keyboardCheck: `
          (() => {
            const board = document.querySelector('#maze-board[role="grid"]');
            const cells = Array.from(document.querySelectorAll('#maze-board [role="gridcell"]'));
            const right = document.querySelector('.spatial-dir[data-dir="right"][aria-label="向右移动"]');
            if (!board || cells.length !== 25 || !right || typeof window._spatialKeyHandler !== 'function') return false;
            document.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true, cancelable: true }));
            const movedCells = Array.from(document.querySelectorAll('#maze-board [role="gridcell"]'));
            return (
              movedCells[1]?.textContent.includes('🏠') &&
              movedCells[1]?.getAttribute('aria-label')?.includes('当前位置') &&
              document.querySelector('#spatial-live')?.textContent.includes('第1行第2列')
            );
          })()
        `,
        afterBack: `window._spatialKeyHandler == null`
      },
      {
        gameId: 'eco',
        screen: 'screen-eco',
        open: '#btn-open-eco',
        back: '#btn-eco-back',
        transientRef: '_ecoGame',
        tapReady: `document.querySelector('.eco-item:not(.done)') && document.querySelector('.eco-bin')`,
        tapPlacement: `
          (() => {
            const item = document.querySelector('.eco-item:not(.done)');
            const bin = item ? document.querySelector('.eco-bin[data-bin="' + item.dataset.answer + '"]') : null;
            if (!item || !bin) return false;
            item.click();
            bin.click();
            return item.classList.contains('done');
          })()
        `,
        beforeBack: `
          (() => {
            const item = document.querySelector('.eco-item:not(.done)');
            const game = window._ecoGame;
            if (!item || !game || typeof game.checkAnswer !== 'function' || typeof game._onWin !== 'function') return false;
            item.click();
            const selectedOk = !!game.tapSelectedItem && item.classList.contains('tap-place-selected');
            window._ecoDestroyedWinCount = 0;
            const originalWin = game._onWin.bind(game);
            game._onWin = function() {
              window._ecoDestroyedWinCount += 1;
              return originalWin.apply(game, arguments);
            };
            document.querySelectorAll('.eco-item:not(.done)').forEach((candidate) => {
              game.checkAnswer(candidate, candidate.dataset.answer, candidate.dataset.answer);
            });
            return selectedOk && game.correctCount >= game.totalItems && game.winTimer != null;
          })()
        `,
        afterBack: `
          new Promise((resolve) => {
            setTimeout(() => {
              resolve(
                window._ecoGame == null &&
                (window._ecoDestroyedWinCount || 0) === 0 &&
                !document.querySelector('.eco-bin.correct-flash, .eco-bin.wrong-flash, .eco-item.eco-wrong-flash')
              );
            }, 650);
          })
        `
      },
      {
        gameId: 'fraud',
        screen: 'screen-fraud',
        open: '#btn-open-fraud',
        back: '#btn-fraud-back',
        transientRef: '_fraudGame',
        beforeBack: `
          (() => {
            const toggle = document.getElementById('fraud-flash-toggle');
            if (!toggle || !window._fraudGame || typeof initFraudGame !== 'function') return false;
            window._fraudGame.destroy();
            initFraudGame('hard');
            const hardGame = window._fraudGame;
            const scenario = hardGame?.scenarios?.[hardGame.currentIdx];
            if (!hardGame || !scenario) return false;
            hardGame.answer(!scenario.isScam);
            const hardTimersScheduled = hardGame.timerColorTimer != null && hardGame.nextScenarioTimer != null;
            window._fraudColorProbe = hardGame;
            toggle.classList.add('active');
            hardGame.destroy();
            initFraudGame('easy');
            const game = window._fraudGame;
            if (!game || !game.flashMode || !game.flashTimer || !hardTimersScheduled) return false;
            if (window._fraudColorProbe.timerColorTimer != null || window._fraudColorProbe.nextScenarioTimer != null) return false;
            window._fraudDestroyedAnswerCount = 0;
            window._fraudFlashProbe = game;
            const originalAnswer = game.answer.bind(game);
            game.answer = function() {
              window._fraudDestroyedAnswerCount += 1;
              return originalAnswer.apply(game, arguments);
            };
            game._flashTimeLeft = 0.05;
            return true;
          })()
        `,
        afterBack: `
          new Promise((resolve) => {
            setTimeout(() => {
              const colorProbe = window._fraudColorProbe;
              const flashProbe = window._fraudFlashProbe;
              const timerEl = document.getElementById('fraud-timer');
              const ok =
                window._fraudGame == null &&
                (window._fraudDestroyedAnswerCount || 0) === 0 &&
                (!colorProbe || (colorProbe.timerColorTimer == null && colorProbe.nextScenarioTimer == null)) &&
                (!flashProbe || flashProbe.flashTimer == null) &&
                (!timerEl || timerEl.style.color === '');
              window._fraudColorProbe = null;
              window._fraudFlashProbe = null;
              resolve(ok);
            }, 350);
          })
        `
      },
      {
        gameId: 'a11y',
        screen: 'screen-a11y',
        open: '#btn-open-a11y',
        back: '#btn-a11y-back',
        skillRef: true,
        keyboardCheck: `
          (() => {
            const canvas = document.getElementById('a11y-canvas');
            if (!canvas || canvas.getAttribute('role') !== 'button' || canvas.tabIndex < 0) return false;
            const before = window._a11yStage;
            canvas.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }));
            canvas.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }));
            return window._a11yStage === before + 1 &&
              canvas.getAttribute('aria-label')?.includes('按回车') &&
              document.getElementById('a11y-found')?.textContent === String(before + 1);
          })()
        `
      },
      { gameId: 'trace', screen: 'screen-trace', open: '#btn-open-trace', back: '#btn-trace-back', skillRef: true },
      { gameId: 'decode', screen: 'screen-decode', open: '#btn-open-decode', back: '#btn-decode-back', skillRef: true },
      qAdventureSpec('water'),
      qAdventureSpec('carbon'),
      qAdventureSpec('repair'),
      qAdventureSpec('aid'),
      qAdventureSpec('food'),
      qAdventureSpec('animal'),
      qAdventureSpec('phish'),
      qAdventureSpec('script'),
      qAdventureSpec('identity'),
      qAdventureSpec('transfer'),
      qAdventureSpec('leak'),
      qAdventureSpec('evidence'),
      qAdventureSpec('alert'),
      {
        gameId: 'ocean',
        screen: 'screen-ocean',
        open: '#btn-open-ocean',
        back: '#btn-ocean-back',
        transientRef: '_oceanGame',
        tapReady: `document.querySelector('.coral-fragment:not(.placed)') && document.querySelector('.ocean-slot')`,
        tapPlacement: tapPlaceScript('.coral-fragment:not(.placed)', 'coral', 'ocean-slot-'),
        beforeBack: `
          (() => {
            const game = window._oceanGame;
            if (!game || typeof game._snapCoral !== 'function' || typeof game._onTimeUp !== 'function') return false;
            window._oceanDestroyedTimeUpCount = 0;
            const originalTimeUp = game._onTimeUp.bind(game);
            game._onTimeUp = function() {
              window._oceanDestroyedTimeUpCount += 1;
              return originalTimeUp.apply(game, arguments);
            };
            document.querySelectorAll('.coral-fragment:not(.placed)').forEach((card) => {
              game._snapCoral(card.dataset.coral, card);
            });
            return Object.keys(game.placed || {}).length >= game.totalCorals && game.timeUpTimer != null && game.particleTimers.length > 0;
          })()
        `,
        afterBack: `
          new Promise((resolve) => {
            setTimeout(() => {
              resolve(
                window._oceanGame == null &&
                (window._oceanDestroyedTimeUpCount || 0) === 0 &&
                document.querySelectorAll('.ocean-bubble-particle, .ocean-sparkle, .ocean-pollution').length === 0
              );
            }, 750);
          })
        `
      },
      {
        gameId: 'oracle',
        screen: 'screen-oracle',
        open: '#btn-open-oracle',
        back: '#btn-oracle-back',
        transientRef: '_oracleGame',
        tapReady: `document.querySelector('.oracle-fragment:not(.placed)') && document.querySelector('.oracle-slot')`,
        tapPlacement: tapPlaceScript('.oracle-fragment:not(.placed)', 'fragId', 'oracle-slot-'),
        beforeBack: `
          (() => {
            const game = window._oracleGame;
            if (!game || typeof game._snapFrag !== 'function' || typeof game._onAssembleComplete !== 'function') return false;
            window._oracleDestroyedAssembleCount = 0;
            const originalAssemble = game._onAssembleComplete.bind(game);
            game._onAssembleComplete = function() {
              window._oracleDestroyedAssembleCount += 1;
              return originalAssemble.apply(game, arguments);
            };
            document.querySelectorAll('.oracle-fragment:not(.placed)').forEach((card) => {
              game._snapFrag(card.dataset.fragId, card);
            });
            return Object.keys(game.placed || {}).length >= game.totalFrags;
          })()
        `,
        afterBack: `
          new Promise((resolve) => {
            setTimeout(() => {
              const traceHidden = document.getElementById('oracle-trace-area')?.classList.contains('hidden');
              resolve(window._oracleGame == null && (window._oracleDestroyedAssembleCount || 0) === 0 && traceHidden);
            }, 950);
          })
        `
      },
      {
        gameId: 'truth',
        screen: 'screen-truth',
        open: '#btn-open-truth',
        back: '#btn-truth-back',
        transientRef: '_truthGame',
        tapReady: `document.querySelector('.truth-card:not(.placed)') && document.querySelector('.truth-slot')`,
        tapPlacement: tapPlaceScript('.truth-card:not(.placed)', 'evidence', 'truth-slot-'),
        beforeBack: `
          (() => {
            const game = window._truthGame;
            if (!game || typeof game._snapEvidence !== 'function' || typeof game._onEvidenceComplete !== 'function') return false;
            window._truthDestroyedEvidenceCount = 0;
            const originalEvidence = game._onEvidenceComplete.bind(game);
            game._onEvidenceComplete = function() {
              window._truthDestroyedEvidenceCount += 1;
              return originalEvidence.apply(game, arguments);
            };
            document.querySelectorAll('.truth-card:not(.placed)').forEach((card) => {
              game._snapEvidence(card.dataset.evidence, card);
            });
            return Object.keys(game.placed || {}).length >= game.total && game.evidenceTimer != null;
          })()
        `,
        afterBack: `
          new Promise((resolve) => {
            setTimeout(() => {
              const judgeHidden = document.getElementById('truth-judge-area')?.classList.contains('hidden');
              resolve(window._truthGame == null && (window._truthDestroyedEvidenceCount || 0) === 0 && judgeHidden);
            }, 950);
          })
        `
      },
      {
        gameId: 'heart',
        screen: 'screen-heart',
        open: '#btn-open-heart',
        back: '#btn-heart-back',
        transientRef: '_heartGame',
        tapReady: `document.querySelector('.heart-card:not(.placed)') && document.querySelector('.heart-slot')`,
        tapPlacement: tapPlaceScript('.heart-card:not(.placed)', 'emotion', 'heart-slot-'),
        beforeBack: `
          (() => {
            const game = window._heartGame;
            if (!game || typeof game._snapEmotion !== 'function' || typeof game._onWheelComplete !== 'function') return false;
            window._heartDestroyedWheelCount = 0;
            const originalWheel = game._onWheelComplete.bind(game);
            game._onWheelComplete = function() {
              window._heartDestroyedWheelCount += 1;
              return originalWheel.apply(game, arguments);
            };
            document.querySelectorAll('.heart-card:not(.placed)').forEach((card) => {
              game._snapEmotion(card.dataset.emotion, card, { clientX: 10, clientY: 10 });
            });
            return Object.keys(game.placed || {}).length >= game.total && game.wheelTimer != null && game.rippleIntervals.length > 0;
          })()
        `,
        afterBack: `
          new Promise((resolve) => {
            setTimeout(() => {
              const diaryHidden = document.getElementById('heart-diary-container')?.classList.contains('hidden');
              resolve(
                window._heartGame == null &&
                (window._heartDestroyedWheelCount || 0) === 0 &&
                diaryHidden &&
                document.querySelectorAll('#heart-wheel-svg .heart-ripple').length === 0
              );
            }, 1400);
          })
        `
      },
      {
        gameId: 'grain',
        screen: 'screen-grain',
        open: '#btn-open-grain',
        back: '#btn-grain-back',
        transientRef: '_grainGame',
        tapReady: `document.querySelector('.grain-card:not(.placed)') && document.querySelector('.grain-slot')`,
        tapPlacement: tapPlaceScript('.grain-card:not(.placed)', 'belongsTo', 'grain-slot-'),
        beforeBack: `
          (() => {
            const game = window._grainGame;
            const cards = document.getElementById('grain-waste-cards');
            if (!game || !cards || typeof game._startWasteChallenge !== 'function') return false;
            game.savedFood = 0;
            game._startWasteChallenge();
            const card = document.querySelector('.grain-waste-card');
            if (!card || !game.wasteTimer) return false;
            window._grainDestroyedShowCount = 0;
            const originalShow = game._showWasteCard.bind(game);
            game._showWasteCard = function() {
              window._grainDestroyedShowCount += 1;
              return originalShow.apply(game, arguments);
            };
            card.click();
            return game.nextWasteTimer != null;
          })()
        `,
        afterBack: `
          new Promise((resolve) => {
            setTimeout(() => {
              resolve(window._grainGame == null && (window._grainDestroyedShowCount || 0) === 0);
            }, 1200);
          })
        `
      },
      qAdventureSpec('forest'),
      qAdventureSpec('light'),
      qAdventureSpec('seed'),
      qAdventureSpec('civil')
    ];

    for (const spec of specs) {
      await smokeGame(client, spec);
    }

    await assertHubCardA11yLabels(client);
    await mobileLayoutSmoke(client);

    assert.deepStrictEqual(runtimeErrors, []);
    console.log('browser smoke ok');
  } finally {
    if (client) client.close();
    await stopProcess(chromeProcess);
    await new Promise((resolve) => server.close(resolve));
    await removeDirWithRetry(profile);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
