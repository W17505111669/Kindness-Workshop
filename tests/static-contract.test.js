const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.resolve(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

const html = read('index.html');
const css = read('style.css');
const game = read('game.js');
const sound = read('sound.js');
const browserSmoke = read(path.join('tests', 'browser-smoke.cjs'));
const pkg = JSON.parse(read('package.json'));

function ids(source, prefix) {
  const pattern = new RegExp(`id="${prefix}[^"]+"`, 'g');
  return (source.match(pattern) || []).map((match) => match.slice(4, -1));
}

const screenIds = ids(html, 'screen-');
assert(screenIds.length >= 40, `expected at least 40 screens, got ${screenIds.length}`);
assert.strictEqual(new Set(screenIds).size, screenIds.length, 'screen ids must be unique');

const viewportMatch = html.match(/<meta name="viewport" content="([^"]+)">/);
assert(viewportMatch, 'viewport meta tag missing');
assert(!/user-scalable\s*=\s*no/i.test(viewportMatch[1]), 'mobile viewport must not disable user zoom');
assert(!/maximum-scale\s*=\s*1(?:\.0)?/i.test(viewportMatch[1]), 'mobile viewport must not cap zoom at 1x');
assert(viewportMatch[1].includes('viewport-fit=cover'), 'viewport should preserve safe-area support');

const blankLinks = Array.from(html.matchAll(/<a\b(?=[^>]*target="_blank")[^>]*>/g)).map((match) => match[0]);
blankLinks.forEach((tag) => {
  assert(/\brel="[^"]*\bnoopener\b[^"]*\bnoreferrer\b[^"]*"/.test(tag), `target=_blank link missing noopener noreferrer: ${tag}`);
});

const staticButtonsMissingType = Array.from(html.matchAll(/<button\b(?![^>]*\btype=)[^>]*>/g)).map((match) => match[0]);
assert.deepStrictEqual(staticButtonsMissingType, [], 'all static buttons should declare type="button"');
const dynamicButtonMarkupMissingType = Array.from(game.matchAll(/<button\b(?![^>]*\btype=)[^>]*>/g)).map((match) => match[0]);
assert.deepStrictEqual(dynamicButtonMarkupMissingType, [], 'dynamic button markup should declare type="button"');
const rawButtonCreates = Array.from(game.matchAll(/document\.createElement\((['"])button\1\)/g));
assert.strictEqual(rawButtonCreates.length, 1, 'raw button element creation should be centralized in createButtonElement');
assert(/function createButtonElement\(\)[\s\S]*document\.createElement\('button'\)[\s\S]*button\.type = 'button'/.test(game), 'createButtonElement should default buttons to type=button');

const hubGameOpenIds = Array.from(html.matchAll(/<button\b(?=[^>]*\bid="(btn-open-[^"]+)")(?=[^>]*\bclass="game-card")/g)).map((match) => match[1]);
assert(hubGameOpenIds.length >= 30, `expected at least 30 hub game cards, got ${hubGameOpenIds.length}`);
hubGameOpenIds.forEach((id) => {
  assert(game.includes(`['${id}',`), `hub game card missing guarded open binding: ${id}`);
  const gameKey = id.replace('btn-open-', '');
  assert(
    browserSmoke.includes(`#${id}`) || browserSmoke.includes(`qAdventureSpec('${gameKey}')`),
    `hub game card missing browser smoke coverage: ${id}`
  );
});

[
  'transitionToScreen',
  'bindAllGameButtons',
  'unifiedRewardCalc',
  'trackGamePlay',
  'trackGameComplete',
  'QAdventureEngine',
  'persistGameState',
  'cleanupTransientGames',
  'destroyTransientGameRef',
  'initNavigationFallbacks',
  'enhanceHubCardsWithPlayStats',
  'updateGameplayCoach',
  'showGameplayToast',
  'applyGameplayAssist',
  'pulseGameplayAssist',
  'assistMemoryMatch',
  'assistSpatialGame',
  'assistFraudGame',
  'assistA11yGame',
  'assistTraceGame',
  'assistDecodeGame',
  'GAMEPLAY_TIPS',
  '_updatePowerUI'
].forEach((name) => {
  assert(game.includes(name), `missing public contract: ${name}`);
});
assert(/function escapeTextForHTML\(value\)[\s\S]*replace\(\/\[&<>"'\]\/g/.test(game), 'text-to-HTML escaping helper missing');
assert(/function renderAlbum\(\)[\s\S]*const blueprint = itemBlueprints\[entry\.id\][\s\S]*if \(!blueprint \|\| !Array\.isArray\(blueprint\.parts\)\) return[\s\S]*const entryDate = escapeTextForHTML\(entry\.date\)[\s\S]*const entryTitle = escapeTextForHTML\(entry\.title\)[\s\S]*const entryStory = escapeTextForHTML\(entry\.storyText\)\.replace/.test(game), 'album entries should skip unknown ids and escape saved text before HTML rendering');
assert(/_showAchievement: function\(id\)[\s\S]*el\.innerHTML = safeHTML\('[\s\S]*escapeTextForHTML\(name\)[\s\S]*escapeTextForHTML\(desc\)/.test(game), 'achievement toast should escape dynamic achievement text before HTML rendering');

['warm', 'ocean', 'forest', 'cyber'].forEach((theme) => {
  assert(css.includes(`[data-theme="${theme}"]`), `missing theme CSS: ${theme}`);
});
assert(game.includes("btn.setAttribute('aria-label', '切换主题：' + t.label)") && game.includes("b.setAttribute('aria-pressed'"), 'theme buttons should expose aria-label and aria-pressed state');

const hubTabs = Array.from(html.matchAll(/<button id="(hub-tab-([^"]+))" class="hub-tab[^"]*"[^>]*>/g));
assert.strictEqual(hubTabs.length, 5, `expected 5 hub tabs, got ${hubTabs.length}`);
hubTabs.forEach((match) => {
  const [tag, id, key] = match;
  const panelId = `hub-panel-${key}`;
  assert(tag.includes('type="button"'), `hub tab should declare button type: ${id}`);
  assert(tag.includes('role="tab"'), `hub tab missing role=tab: ${id}`);
  assert(tag.includes(`aria-controls="${panelId}"`), `hub tab missing aria-controls: ${id}`);
  assert(html.includes(`id="${panelId}"`) && html.includes(`role="tabpanel"`) && html.includes(`aria-labelledby="${id}"`), `hub panel missing tabpanel linkage: ${panelId}`);
});
assert(/function activateHubTab\(tab, shouldFocus\)[\s\S]*aria-selected[\s\S]*setAttribute\('tabindex'[\s\S]*setAttribute\('aria-hidden'[\s\S]*focusElementSafely\(tab\)/.test(game), 'hub tab switching should sync selected, tabindex, panel visibility, and focus');
assert(/function activateHubTab\(tab, shouldFocus\)[\s\S]*requestAnimationFrame\(function\(\) \{[\s\S]*focusWasLostToScreen[\s\S]*contains\('game-screen'\)[\s\S]*focusElementSafely\(tab\)/.test(game), 'hub tab keyboard focus should recover if delayed screen focus steals it');
assert(/tab\.addEventListener\('keydown'[\s\S]*ArrowRight[\s\S]*ArrowLeft[\s\S]*Home[\s\S]*End[\s\S]*activateHubTab\(tabs\[next\], true\)/.test(game), 'hub tabs should support arrow/Home/End keyboard navigation');

const modalOverlays = Array.from(html.matchAll(/<div id="([^"]+-overlay)" class="modal-overlay"[^>]*>/g));
assert(modalOverlays.length >= 4, `expected at least 4 modal overlays, got ${modalOverlays.length}`);
modalOverlays.forEach((match) => {
  const [tag, id] = match;
  assert(tag.includes('role="dialog"'), `modal overlay missing dialog role: ${id}`);
  assert(tag.includes('aria-modal="true"'), `modal overlay missing aria-modal: ${id}`);
  assert(tag.includes('aria-hidden="true"'), `modal overlay should start hidden from assistive tech: ${id}`);
  const labelMatch = tag.match(/aria-labelledby="([^"]+)"/);
  assert(labelMatch, `modal overlay missing aria-labelledby: ${id}`);
  assert(html.includes(`id="${labelMatch[1]}"`), `modal overlay labelledby target missing: ${id}`);
});
const iconCloseButtons = Array.from(html.matchAll(/<button\b(?=[^>]*class="[^"]*\bbtn-close\b[^"]*")[^>]*>/g)).map((match) => match[0]);
assert(iconCloseButtons.length >= 3, `expected at least 3 icon close buttons, got ${iconCloseButtons.length}`);
iconCloseButtons.forEach((tag) => {
  assert(tag.includes('type="button"'), `icon close button should declare button type: ${tag}`);
  assert(/aria-label="关闭[^"]+"/.test(tag), `icon close button needs a Chinese aria-label: ${tag}`);
});
assert(/function getModalFocusTarget\(overlay\)[\s\S]*querySelector\('\[autofocus\], button:not\(\[disabled\]\)/.test(game), 'modal focus target helper should find a safe initial focus control');
assert(/function focusElementSafely\(el\)[\s\S]*preventScroll: true[\s\S]*catch/.test(game), 'modal focus helper should avoid scroll jumps and tolerate unsupported options');
assert(/function focusModalIfNeeded\(overlay\)[\s\S]*overlay\.contains\(document\.activeElement\)[\s\S]*focusElementSafely\(getModalFocusTarget\(overlay\)\)/.test(game), 'modal focus helper should retry only until focus enters the dialog');
assert(/function restoreModalFocus\(previousFocus, overlay\)[\s\S]*previousFocus\.isConnected[\s\S]*getClientRects\(\)\.length === 0[\s\S]*focusWasReclaimedByScreen[\s\S]*focusStillInClosingModal[\s\S]*focusElementSafely\(previousFocus\)/.test(game), 'modal focus restore helper should tolerate detached triggers and avoid stealing user focus');
assert(/function setModalOpen\(overlay, isOpen, returnFocusEl\)[\s\S]*overlay\._previousFocus = returnFocusEl \|\| document\.activeElement[\s\S]*classList\.toggle\('active', Boolean\(isOpen\)\)[\s\S]*setAttribute\('aria-hidden', isOpen \? 'false' : 'true'\)[\s\S]*focusModalIfNeeded\(overlay\)[\s\S]*setTimeout\(function\(\) \{ focusModalIfNeeded\(overlay\); \}, 520\)[\s\S]*restoreModalFocus\(previousFocus, overlay\)[\s\S]*setTimeout\(function\(\) \{ restoreModalFocus\(previousFocus, overlay\); \}, 1400\)/.test(game), 'modal open helper should keep active class, aria-hidden, and focus in sync');
assert(/const openGuideBtn = document\.getElementById\('btn-open-guide'\)[\s\S]*setModalOpen\(guideOverlay, true, openGuideBtn\)[\s\S]*setModalOpen\(shopOverlay, true, openShopBtn\)[\s\S]*setModalOpen\(posterOverlay, true, btnGeneratePoster\)/.test(game), 'modal open paths should pass their trigger element for focus restoration');
assert(/function closeOpenModalOverlays\(\)[\s\S]*querySelectorAll\('\.modal-overlay\.active'\)[\s\S]*setModalOpen\(overlay, false\)[\s\S]*return closed/.test(game), 'open modal overlays should have a centralized close helper');
assert(/case 'Escape':[\s\S]*closeOpenModalOverlays\(\)[\s\S]*e\.preventDefault\(\)[\s\S]*returnToHubWithCleanup\(\)/.test(game), 'Escape should close active modal overlays before returning to hub');

const staticInputs = Array.from(html.matchAll(/<input\b[^>]*>/g)).map((match) => match[0]);
staticInputs.forEach((tag) => {
  const idMatch = tag.match(/\bid="([^"]+)"/);
  const id = idMatch && idMatch[1];
  const hasAccessibleName = /\baria-label="[^"]+"/.test(tag) ||
    /\baria-labelledby="[^"]+"/.test(tag) ||
    (id && new RegExp(`<label[^>]*\\bfor="${id}"`).test(html));
  assert(hasAccessibleName, `static input missing accessible name: ${tag}`);
});
assert(/id="album-custom-message"[^>]*maxlength="120"/.test(html), 'album poster message input should cap text length');
assert(/const messageText = String\(customMessage \|\| ''\)\.trim\(\)\.slice\(0, 120\)/.test(game), 'poster generator should bound custom message length');
assert(/gameState\.albumEntries\.slice\(\)\.reverse\(\)\.find\(entry => entry && itemBlueprints\[entry\.id\]\)[\s\S]*没有可生成海报的完整器物记忆/.test(game), 'poster generation should skip unknown legacy album ids');
assert(html.includes('id="workspace-particle-canvas" role="presentation" aria-hidden="true"'), 'workspace particle canvas should be hidden as decorative');
assert(game.includes('id="focus-adjust-slider" aria-label="记忆镜头对焦调节"'), 'dynamic focus slider should expose an accessible name');
assert(html.includes('id="a11y-canvas" width="500" height="320" role="button" tabindex="0" aria-label="视觉障碍模拟画布"'), 'a11y canvas should start with keyboard-reachable button semantics');
assert(/function loadA11yStage\(\)[\s\S]*canvas\.setAttribute\('aria-label', '视觉障碍模拟：' \+ s\.desc[\s\S]*function completeCurrentA11yStage\(\)[\s\S]*if \(stageCompleted\) return[\s\S]*canvas\.onkeydown = function\(e\)[\s\S]*e\.key !== 'Enter' && e\.key !== ' '/.test(game), 'a11y canvas should support guarded keyboard activation');
assert(/function onA11yWin\(\)[\s\S]*canvas\.onclick = null[\s\S]*canvas\.onkeydown = null[\s\S]*setAttribute\('aria-disabled', 'true'\)/.test(game), 'a11y canvas should disable handlers after completion');

assert(html.includes('engine/state-persistence.js'), 'state persistence script must load before game.js');
assert(css.includes('.skip-link'), 'skip-link style missing');
assert(html.includes('<main id="app-container" tabindex="-1">'), 'skip-link target main should be programmatically focusable');
assert(/function enhanceScreenA11y\(activeScreen\)[\s\S]*requestAnimationFrame\(function\(\) \{[\s\S]*focusAlreadyClaimed[\s\S]*getClientRects\(\)\.length > 0[\s\S]*if \(focusAlreadyClaimed\) return[\s\S]*activeScreen\.focus/.test(game), 'screen a11y focus should not steal focus after the user has already moved it');
assert(css.includes('.sr-only'), 'sr-only style missing');
assert(/input\[type="text"\][\s\S]*\.entry-story[\s\S]*user-select: text/.test(css), 'text inputs and album stories should remain selectable despite global user-select reset');
assert(/id="bgm-toggle-btn"[^>]*type="button"[^>]*aria-label="播放时光背景音乐"[^>]*aria-pressed="false"/.test(html), 'audio toggle should expose initial button semantics and accessible state');
assert(/function updateAudioButtonUI\(isPlaying\)[\s\S]*setAttribute\('aria-pressed', isPlaying \? 'true' : 'false'\)[\s\S]*setAttribute\('aria-label', isPlaying \? '关闭时光背景音乐' : '播放时光背景音乐'\)/.test(game), 'audio toggle UI should sync aria-label and aria-pressed');
assert(css.includes('.gameplay-coach'), 'gameplay coach style missing');
assert(css.includes('.game-card-meta'), 'hub play-stat style missing');
assert(/function enhanceHubCardsWithPlayStats\(\)[\s\S]*meta\.innerHTML = safeHTML\('<span>' \+ escapeTextForHTML\(status\) \+ '<\/span><span>' \+ escapeTextForHTML\(best\) \+ '<\/span>'\)/.test(game), 'hub play-stat metadata should escape dynamic status text before HTML rendering');
assert(css.includes('.gameplay-toast'), 'gameplay toast style missing');
assert(css.includes('.coach-highlight'), 'coach highlight style missing');
assert(css.includes('.coach-peek'), 'coach peek style missing');
assert(css.includes('.coach-generated-marker'), 'canvas coach marker style missing');
assert(css.includes('.tap-place-selected'), 'tap placement selection style missing');
assert(css.includes('.ap-option-btn.eliminated'), 'QAdventure hint-elimination style missing');
assert(css.includes('@media (pointer: coarse)'), 'coarse pointer touch-target media rule missing');
assert(css.includes('min-height: 48px !important'), 'touch targets should keep a 48px coarse-pointer buffer');
assert(css.includes('.timeline-slot') && css.includes('min-height: 70px !important'), 'timeline slots should keep large touch targets on coarse pointers');
assert(css.includes('.color-card:focus-visible'), 'custom cognitive controls should expose visible focus styles');
assert(css.includes('.hidden-object:focus-visible') && css.includes('.maze-cell:focus-visible'), 'hidden-object and maze controls should expose visible focus styles');
assert(css.includes('@media (max-width: 520px)') && css.includes('#rhythm-pad') && css.includes('grid-template-columns: repeat(3, minmax(56px, 1fr)) !important'), 'cognitive games should have compact mobile layout overrides');
assert(css.includes('.hidden-hitbox') && game.includes('class="hidden-hitbox"'), 'hidden-object SVG controls should include enlarged transparent hitboxes');
assert(css.includes('bottom: calc(96px + env(safe-area-inset-bottom, 0px))') && css.includes('.audio-text') && css.includes('display: none'), 'mobile floating controls should avoid covering game content and coach');
assert(css.includes('prefers-reduced-motion: reduce'), 'reduced-motion media rule missing');
assert(/class AmbientParticles[\s\S]*reducedMotionQuery[\s\S]*visibilitychange[\s\S]*animate\(\)[\s\S]*this\.reducedMotionQuery && this\.reducedMotionQuery\.matches[\s\S]*stop\(\)[\s\S]*cancelAnimationFrame\(this\.frameId\)/.test(game), 'ambient particles should pause for reduced motion and hidden pages');
assert(game.includes('window._ambientParticles = spaceParticles'), 'ambient particle instance should be visible to browser smoke tests');
assert(/transitionToScreen = function\(targetScreenId\) \{[\s\S]*prefersReducedMotion\(\)[\s\S]*existingFlash\.classList\.remove\('active'\)[\s\S]*querySelectorAll\('\.game-screen\.leaving'\)[\s\S]*_originalTransition\(targetScreenId\)[\s\S]*return/.test(game), 'screen transitions should skip flash/leaving animations under reduced motion');
assert(/class CelebrationParticles[\s\S]*this\.frameId = null[\s\S]*this\._resizeHandler = \(\) => this\.resize\(\)[\s\S]*requestAnimationFrame\(\(\) => \{[\s\S]*this\.frameId = null[\s\S]*stop\(\)[\s\S]*cancelAnimationFrame\(this\.frameId\)[\s\S]*destroy\(\)[\s\S]*removeEventListener\('resize', this\._resizeHandler\)/.test(game), 'celebration particles should track animation frames and clean resize listeners');
assert(game.includes('function prefersReducedMotion()'), 'reduced-motion preference helper missing');
assert(/function spawnScoreParticle\(x, y, text, color\) \{[\s\S]*if \(prefersReducedMotion\(\)\) return;[\s\S]*className = 'score-particle'/.test(game), 'score particles should not spawn when reduced motion is requested');
assert(/function spawnComboBurst\(x, y, count, color\) \{[\s\S]*if \(prefersReducedMotion\(\)\) return;[\s\S]*className = 'combo-particle'/.test(game), 'combo particles should not spawn when reduced motion is requested');
assert(/function spawnTouchRipple\(el, e\) \{[\s\S]*if \(prefersReducedMotion\(\)\) return;[\s\S]*className = 'touch-ripple'/.test(game), 'touch ripples should not spawn when reduced motion is requested');
assert(game.includes('skGuardedClick'), 'game open buttons should be guarded against duplicate listeners');
assert(/function safeBindClick\(elementId, callback\)[\s\S]*dataset\.safeBindClickBound === 'true'[\s\S]*dataset\.safeBindClickBound = 'true'/.test(game), 'safeBindClick should guard duplicate element bindings');
assert(game.includes('setTapPlaceSelection'), 'tap-to-place helper missing');
assert(game.includes("trackGamePlay('memory-' + id)"), 'memory capsules must track reconstruction starts');
assert(game.includes("trackGameComplete('memory-' + itemId"), 'memory capsules must track reconstruction completions');
assert(game.includes("e.key !== 'Enter' && e.key !== ' '"), 'capsule cards must support keyboard activation');
assert(!/<button\b[^>]*class="btn-capsule-action"/.test(html), 'capsule card action labels should not be nested buttons inside role=button cards');
assert((html.match(/<span class="btn-capsule-action" aria-hidden="true">/g) || []).length >= 9, 'capsule action labels should be decorative spans hidden from assistive tech');
assert(/\.btn-capsule-action\s*\{[\s\S]*display:\s*inline-flex[\s\S]*justify-content:\s*center/.test(css), 'capsule action labels should preserve button-like full-width centering after becoming spans');
assert(/class PuzzleWorkbench[\s\S]*cleanupActiveRuntime\(\)[\s\S]*document\.removeEventListener\('pointermove', this\._activeDragMove\)[\s\S]*clearInterval\(this\._sewingInterval\)[\s\S]*this\._lanternCleanup\(\)[\s\S]*clearInterval\(this\.watchTickInterval\)[\s\S]*destroy\(\)[\s\S]*this\.cleanupActiveRuntime\(\)/.test(game), 'PuzzleWorkbench should centrally clean active drag, sewing, lantern, and watch runtime');
assert(/cleanupActiveRuntime\(\)[\s\S]*audio\.stopRadioStatic\(\)[\s\S]*audio\.stopRadioMelody\(\)[\s\S]*audio\.stopOperaMelody\(\)[\s\S]*audio\.stopNewsBroadcast\(\)[\s\S]*audio\.stopSewingLoop\(\)/.test(game), 'PuzzleWorkbench cleanup should stop all interactive toy audio loops');
assert(/cleanupActiveRuntime\(\)[\s\S]*this\._radioSlider\.oninput = null[\s\S]*this\._cameraButton\.onclick = null/.test(game), 'PuzzleWorkbench cleanup should clear radio and camera toy handlers');
assert(/cleanupActiveRuntime\(\)[\s\S]*this\.celebration\.stop\(\)[\s\S]*destroy\(\)[\s\S]*this\.celebration\.destroy\(\)/.test(game), 'PuzzleWorkbench should stop celebration particles on cleanup and destroy');
assert(/class PuzzleWorkbench[\s\S]*this\._awakeTimers = \[\][\s\S]*scheduleAwakeTimer\(callback, delay\)[\s\S]*this\._awakeTimers\.push\(timerId\)[\s\S]*cleanupActiveRuntime\(\)[\s\S]*this\._awakeTimers\.forEach\(id => clearTimeout\(id\)\)/.test(game), 'PuzzleWorkbench should track and clear delayed awake timers');
assert(/class PuzzleWorkbench[\s\S]*tipEl\.innerHTML = safeHTML\(`[\s\S]*escapeTextForHTML\(part\.name\)[\s\S]*escapeTextForHTML\(part\.hint\)[\s\S]*toast\.innerHTML = safeHTML\(`[\s\S]*escapeTextForHTML\(part\.name\)[\s\S]*escapeTextForHTML\(part\.hint\)/.test(game), 'PuzzleWorkbench part tips should escape dynamic part text before HTML rendering');
assert(/function triggerRadioFact\(type\)[\s\S]*\$\{escapeTextForHTML\(text\)\}/.test(game), 'radio fact toast should escape dynamic fact text before HTML rendering');
assert(/triggerObjectAwake\(\)[\s\S]*this\.scheduleAwakeTimer[\s\S]*gameState\.currentScreen !== 'screen-workspace'[\s\S]*showAwakeNarrative\(this\.activeBlueprintId\)/.test(game), 'awake narrative delay should be cancelled or guarded after leaving workspace');
assert(/PuzzleWorkbench\.prototype\.triggerObjectAwake = function\(\)[\s\S]*var isNewFraudCompletion = !gameState\.fraudCompleted\.includes\(itemId\)[\s\S]*if \(isNewFraudCompletion\) \{[\s\S]*gameState\.fraudCompleted\.push\(itemId\)[\s\S]*gameState\.memorySilver \+= 30[\s\S]*global-silver-balance/.test(game), 'fraud case completion should only grant the one-time silver reward for newly completed cases');
assert(/setupItem\(itemId\) \{[\s\S]*this\.cleanupActiveRuntime\(\)[\s\S]*this\.activeBlueprintId = itemId/.test(game), 'PuzzleWorkbench setup should clear stale item runtime before loading another item');
assert(/function transitionToScreen\(targetScreenId\)[\s\S]*cleanupMemoryWorkbenchRuntime\(targetScreenId\)[\s\S]*cleanupSpatialRuntime\(\)/.test(game), 'screen transitions should clear active workbench runtime when leaving workspace');
assert(/function cleanupMemoryWorkbenchRuntime\(targetScreenId\)[\s\S]*gameState\.currentScreen !== 'screen-workspace'[\s\S]*workbench\.cleanupActiveRuntime\(\)/.test(game), 'memory workbench runtime cleanup helper missing or incomplete');
assert(/function setupInteractiveToy\(itemId\)[\s\S]*const toyRuntime = \(typeof workbench !== 'undefined' && workbench\) \? workbench : window[\s\S]*toyRuntime\.cleanupActiveRuntime\(\)/.test(game), 'interactive toy runtime should explicitly target the workbench instance and clear previous toy runtime');
assert(/function setupInteractiveToy\(itemId\)[\s\S]*toyRuntime\._radioSlider = slider[\s\S]*toyRuntime\._cameraButton = btn/.test(game), 'interactive toy handlers should be tracked on the workbench runtime');
assert(/timer = setInterval\(\(\) => \{[\s\S]*executeStitch\(3\)[\s\S]*toyRuntime\._sewingInterval = timer/.test(game), 'sewing long-press interval should be tracked on the workbench instance');
assert(game.includes("trackGamePlay('grain')"), 'grain game must track starts');
assert(game.includes("trackGameComplete('grain'"), 'grain game must track completions');
assert(game.includes("trackGamePlay('heart')"), 'heart game must track starts');
assert(game.includes('ensureA11yLiveRegion'), 'coach assists should announce via live region');
assert(game.includes("card.setAttribute('role', 'button')"), 'color/face cards should expose button semantics');
assert(game.includes("btn.setAttribute('role', 'button')"), 'rhythm pads should expose button semantics');
assert(game.includes('颜色卡片') && game.includes('面孔记忆卡片') && game.includes('节律按钮'), 'custom cognitive controls should use Chinese aria-labels');
assert(!game.includes('Color card ') && !game.includes('Face memory card ') && !game.includes('Rhythm pad '), 'custom cognitive controls should not use English placeholder aria-labels');
assert(/function initColorGame\(\)[\s\S]*escapeTextForHTML\(item\.color\)[\s\S]*escapeTextForHTML\(item\.group\)[\s\S]*area\.innerHTML = safeHTML\(html\)[\s\S]*card\.setAttribute\('aria-pressed', 'false'\)[\s\S]*selectedCard\.setAttribute\('aria-pressed', 'false'\)[\s\S]*this\.setAttribute\('aria-pressed', 'true'\)[\s\S]*wrongCard\.classList\.remove\('selected'\)[\s\S]*wrongCard\.setAttribute\('aria-pressed', 'false'\)/.test(game), 'color game should sanitize card markup and keep selected/pressed state in sync after wrong placement');
assert(/function initFaceGame\(\)[\s\S]*escapeTextForHTML\(faces\[i\]\)[\s\S]*area\.innerHTML = safeHTML\(html\)[\s\S]*card\.setAttribute\('aria-pressed', 'false'\)[\s\S]*this\.setAttribute\('aria-pressed', 'true'\)[\s\S]*flipped\[0\]\.setAttribute\('aria-pressed', 'false'\)[\s\S]*flipped\[1\]\.setAttribute\('aria-pressed', 'false'\)/.test(game), 'face game should sanitize card markup and keep flipped pressed state in sync');
assert(/function initRhythmGame\(\)[\s\S]*escapeTextForHTML\(c\.id\)[\s\S]*escapeTextForHTML\(c\.color\)[\s\S]*escapeTextForHTML\(c\.emoji\)[\s\S]*area\.innerHTML = safeHTML\(html\)[\s\S]*var acceptingInput = false[\s\S]*var gameEnded = false[\s\S]*function setPadInputEnabled\(enabled\)[\s\S]*btn\.setAttribute\('aria-disabled', enabled \? 'false' : 'true'\)[\s\S]*btn\.tabIndex = enabled \? 0 : -1[\s\S]*if \(gameEnded \|\| isPlaying \|\| !acceptingInput\) return[\s\S]*gameEnded = true[\s\S]*setPadInputEnabled\(false\)/.test(game), 'rhythm game should sanitize pad markup, expose disabled state, and prevent pre-start or post-game input');
assert(game.includes('cleanupCognitiveRuntime'), 'cognitive runtime timers should be centrally cleaned');
assert(game.includes('trackCognitiveTimeout'), 'cognitive delayed tasks should be tracked');
assert(game.includes('trackCognitiveInterval'), 'cognitive intervals should be tracked');
assert(game.includes('clearTrackedCognitiveTimeout'), 'cognitive delayed tasks should support targeted cleanup');
assert(/class MemoryMatchGame[\s\S]*mismatchTimer[\s\S]*trackCognitiveTimeout[\s\S]*_clearMismatchTimer\(\)[\s\S]*clearTrackedCognitiveTimeout\(this\.mismatchTimer\)[\s\S]*destroy\(\)[\s\S]*this\.active = false[\s\S]*this\._clearMismatchTimer\(\)/.test(game), 'MemoryMatchGame should clear delayed mismatch flips on destroy');
assert(/class MemoryMatchGame[\s\S]*el\.setAttribute\('aria-pressed', 'false'\)[\s\S]*el\.innerHTML = safeHTML\('[\s\S]*escapeTextForHTML\(card\.emoji\)[\s\S]*el\.addEventListener\('keydown'[\s\S]*cardEl\.setAttribute\('aria-disabled', 'true'\)[\s\S]*cardEl\.tabIndex = -1[\s\S]*setAttribute\('aria-pressed', 'false'\)/.test(game), 'MemoryMatchGame cards should escape emoji HTML, expose pressed state, and remove matched cards from tab order');
assert(game.includes('cleanupSkillGameState'), 'skill game globals should be centrally cleaned');
assert(game.includes('trackSkillTimeout'), 'skill game delayed tasks should be tracked');
assert(/function cleanupSkillGameState\(\)[\s\S]*var traceCanvas = document\.getElementById\('trace-canvas'\)[\s\S]*traceCanvas\.onpointerdown = null[\s\S]*traceCanvas\.onkeydown = null/.test(game), 'skill cleanup should detach trace canvas pointer and keyboard handlers');
assert(/function initTraceGame\(\)[\s\S]*window\._traceCompleted = false[\s\S]*function loadTraceLevel\(\)[\s\S]*if \(window\._traceCompleted\) return[\s\S]*function onTraceWin\(\)[\s\S]*if \(window\._traceCompleted\) return[\s\S]*window\._traceCompleted = true[\s\S]*canvas\.onpointerdown = null[\s\S]*gameState\.memorySilver \+= 50/.test(game), 'trace game should guard async completion and disable canvas handlers after win');
assert(html.includes('id="trace-canvas" role="button" tabindex="0" aria-label="信号溯源画布'), 'trace canvas should start with keyboard-reachable button semantics');
assert(/function loadTraceLevel\(\)[\s\S]*canvas\.setAttribute\('aria-disabled', 'false'\)[\s\S]*function updateTraceCanvasLabel\(\)[\s\S]*canvas\.setAttribute\('aria-label', label\)[\s\S]*function advanceTraceKeyboardStep\(\)[\s\S]*window\._tracePath\.push\(expectedIdx\)[\s\S]*canvas\.onkeydown = function\(e\)[\s\S]*e\.key !== 'Enter' && e\.key !== ' '/.test(game), 'trace canvas should expose dynamic labels and keyboard step activation');
assert(/function onTraceWin\(\)[\s\S]*canvas\.onpointerdown = null[\s\S]*canvas\.onkeydown = null[\s\S]*setAttribute\('aria-disabled', 'true'\)/.test(game), 'trace canvas should disable pointer and keyboard handlers after completion');
assert(/function initDecodeGame\(\)[\s\S]*window\._decodeCompleted = false[\s\S]*window\._decodePuzzleLocked = false[\s\S]*function loadDecodePuzzle\(\)[\s\S]*if \(window\._decodeCompleted\) return[\s\S]*window\._decodePuzzleLocked = false[\s\S]*if \(window\._decodeCompleted \|\| window\._decodePuzzleLocked\) return[\s\S]*window\._decodePuzzleLocked = true[\s\S]*function onDecodeWin\(\)[\s\S]*if \(window\._decodeCompleted\) return[\s\S]*window\._decodeCompleted = true[\s\S]*window\._decodePuzzleLocked = true[\s\S]*gameState\.memorySilver \+= 50/.test(game), 'decode game should lock solved puzzles and guard final async completion');
assert(/function loadDecodePuzzle\(\)[\s\S]*function bindDecodeKeyActivation\(node, handler\)[\s\S]*e\.key !== 'Enter' && e\.key !== ' '[\s\S]*el\.setAttribute\('role', 'button'\)[\s\S]*el\.setAttribute\('aria-disabled', 'false'\)[\s\S]*el\.setAttribute\('aria-label', '选择反诈字符：' \+ tile\)[\s\S]*el\.setAttribute\('aria-disabled', 'true'\)[\s\S]*el\.tabIndex = -1[\s\S]*tileEl\.setAttribute\('role', 'button'\)[\s\S]*tileEl\.setAttribute\('aria-label', '移除反诈字符：' \+ tile\)[\s\S]*bindDecodeKeyActivation\(tileEl, removeAnswerTile\)[\s\S]*t\.setAttribute\('aria-disabled', 'false'\)[\s\S]*bindDecodeKeyActivation\(el, chooseTile\)/.test(game), 'decode tiles should expose button semantics, keyboard activation, and disabled-state recovery');
assert(game.includes('cleanupTapPlaceState'), 'tap-to-place selections should be centrally cleaned');
assert(/function transitionToScreen\(targetScreenId\)[\s\S]*clearGameplayAssistHighlights\(\)[\s\S]*cleanupTapPlaceState\(\)/.test(game), 'screen transitions should clear gameplay assist highlights before leaving a game');
assert(/function initKeyboardShortcuts\(\)[\s\S]*function returnToHubWithCleanup\(\)[\s\S]*cleanupTransientGames\(\)[\s\S]*transitionToScreen\('screen-hub'\)[\s\S]*case 'Escape'[\s\S]*returnToHubWithCleanup\(\)[\s\S]*case 'h': case 'H'[\s\S]*returnToHubWithCleanup\(\)/.test(game), 'Esc/H shortcuts should clean transient games before returning to hub');
assert(game.includes('cleanupTimelineRuntime'), 'timeline runtime cleanup helper should be centralized');
assert(/function cleanupTimelineRuntime\(\)[\s\S]*window\._timelineCleanup\.clone[\s\S]*clearTrackedCognitiveTimeout\(window\._timelineResetTimer\)[\s\S]*setTapPlaceSelection\(null, 'timeline'\)/.test(game), 'timeline cleanup should remove drag clones, delayed resets, and tap selection');
assert(/function initTimelineGame\(\)[\s\S]*cleanupTimelineRuntime\(\)[\s\S]*window\._timelineCleanup = \{ move: move, up: up, clone: clone \}/.test(game), 'timeline init should clear old drag runtime and track drag clones');
assert(/function initTimelineGame\(\)[\s\S]*track\.innerHTML = safeHTML\(timelineEvents\.map[\s\S]*escapeTextForHTML\(e\.year\)[\s\S]*\.join\(''\)\)/.test(game), 'timeline slots should escape dynamic year text before HTML rendering');
assert(/function initTimelineGame\(\)[\s\S]*window\._timelineCompleted = false[\s\S]*checkBtn\.disabled = false[\s\S]*function checkTimeline\(\) \{[\s\S]*if \(window\._timelineCompleted\) return[\s\S]*if \(allCorrect\) \{[\s\S]*window\._timelineCompleted = true[\s\S]*checkBtn\.disabled = true[\s\S]*checkBtn\.setAttribute\('aria-disabled', 'true'\)[\s\S]*gameState\.memorySilver \+= 50/.test(game), 'timeline check should reset completion state on replay and prevent repeated success rewards');
assert(/function checkTimeline\(\)[\s\S]*clearTrackedCognitiveTimeout\(window\._timelineResetTimer\)[\s\S]*window\._timelineResetTimer = trackCognitiveTimeout/.test(game), 'timeline failed-check reset should be tracked and cancellable');
assert(/function checkTimeline\(\)[\s\S]*else \{ allCorrect = false; \}[\s\S]*correctCount \+ '\/' \+ timelineEvents\.length/.test(game), 'timeline should treat empty slots as incomplete and report the real event count');
assert(game.includes('window._timelineTapCard = null'), 'timeline tap selection should be cleared on cleanup');
assert(/function initHiddenGame\(\)[\s\S]*el\.setAttribute\('role', 'button'\)[\s\S]*el\.setAttribute\('tabindex', '0'\)[\s\S]*el\.setAttribute\('aria-label', '寻找失物：'[\s\S]*el\.addEventListener\('keydown'/.test(game), 'hidden-object SVG controls should expose button semantics and keyboard activation');
assert(/function initHiddenGame\(\)[\s\S]*if \(found === hiddenObjects\.length\) onHiddenWin\(\)/.test(game), 'hidden-object completion should use the data length instead of a hard-coded count');
assert(/function initHiddenGame\(\)[\s\S]*checklist\.innerHTML = safeHTML\(hiddenObjects\.map[\s\S]*escapeTextForHTML\(o\.id\)[\s\S]*escapeTextForHTML\(o\.emoji\)[\s\S]*escapeTextForHTML\(o\.name\)[\s\S]*escapeTextForHTML\(o\.hint\)/.test(game), 'hidden-object checklist should escape dynamic item text before HTML rendering');
assert(/function initMazeGame\(\)[\s\S]*cleanupCognitiveRuntime\(\)[\s\S]*trackGamePlay\('maze'\)/.test(game), 'maze init should clear prior cognitive runtime timers before replay');
assert(/function initMazeGame\(\)[\s\S]*cell\.setAttribute\('role', 'button'\)[\s\S]*cell\.setAttribute\('aria-label', '数字迷宫格 '[\s\S]*cell\.addEventListener\('keydown'/.test(game), 'maze cells should expose button semantics and keyboard activation');
assert(/function initMazeGame\(\)[\s\S]*var gameEnded = false[\s\S]*function disableMazeCell\(cell, label\)[\s\S]*cell\.setAttribute\('aria-disabled', 'true'\)[\s\S]*cell\.tabIndex = -1[\s\S]*function disableAllMazeCells\(\)[\s\S]*querySelectorAll\('\.maze-cell'\)[\s\S]*if \(gameEnded \|\| this\.getAttribute\('aria-disabled'\) === 'true'\) return[\s\S]*disableMazeCell\(this, '数字迷宫格 ' \+ num \+ '，已完成'\)[\s\S]*gameEnded = true[\s\S]*disableAllMazeCells\(\)/.test(game), 'maze cells should be disabled after completion and all cells disabled after game end');
assert(/function initMazeGame\(\)[\s\S]*trackCognitiveTimeout\(function\(\) \{ if \(this\.isConnected\) this\.classList\.remove\('wrong'\); \}\.bind\(this\), 400\)/.test(game), 'maze wrong feedback should use tracked cognitive timeout');
assert(game.includes('function cleanupSpatialRuntime()') && game.includes('window._spatialKeyHandler'), 'spatial key runtime should have centralized cleanup');
assert(/function transitionToScreen\(targetScreenId\)[\s\S]*cleanupSpatialRuntime\(\)[\s\S]*cleanupCognitiveRuntime\(\)/.test(game), 'screen transitions should clear spatial keyboard handlers');
assert(/function cleanupTransientGames\(\)[\s\S]*cleanupTapPlaceState\(\)[\s\S]*cleanupSpatialRuntime\(\)[\s\S]*cleanupCognitiveRuntime\(\)/.test(game), 'transient cleanup should clear spatial keyboard handlers');
assert(/function initSpatialGame\(\)[\s\S]*cleanupSpatialRuntime\(\)[\s\S]*cleanupCognitiveRuntime\(\)[\s\S]*trackGamePlay\('spatial'\)/.test(game), 'spatial init should clear stale keyboard/runtime state before replay');
assert(/function initSpatialGame\(\)[\s\S]*role="grid"[\s\S]*role="gridcell"[\s\S]*aria-label="向上移动"[\s\S]*aria-label="向右移动"/.test(game), 'spatial maze should expose grid semantics and labeled direction controls');
assert(/function initSpatialGame\(\)[\s\S]*var gameEnded = false[\s\S]*function setSpatialControlsEnabled\(enabled\)[\s\S]*btn\.disabled = !enabled[\s\S]*btn\.setAttribute\('aria-disabled', enabled \? 'false' : 'true'\)[\s\S]*area\.innerHTML = safeHTML\(html\)[\s\S]*if \(gameEnded\) return[\s\S]*gameEnded = true[\s\S]*setSpatialControlsEnabled\(false\)[\s\S]*function handleSpatialKey\(e\)[\s\S]*if \(gameEnded\) return/.test(game), 'spatial game should sanitize maze markup and disable pointer/keyboard input after completion or failure');
assert(/function handleSpatialKey\(e\)[\s\S]*ArrowUp: 'up'[\s\S]*ArrowRight: 'right'[\s\S]*w: 'up'[\s\S]*d: 'right'[\s\S]*movePlayer\(dir\)/.test(game), 'spatial game should support arrow-key and WASD movement');
assert(!/function initWordGame\(\)[\s\S]*quiz-prev-btn/.test(game), 'word game should not keep stale quiz navigation handlers');
assert(/function initWordGame\(\)[\s\S]*type="button" class="word-option[\s\S]*aria-label="词语联想选项：[\s\S]*setAttribute\('aria-disabled', 'true'\)[\s\S]*setAttribute\('role', 'status'\)[\s\S]*gameState\.currentScreen !== 'screen-word'/.test(game), 'word game options should expose accessible state and guard delayed rerenders after navigation');
assert(game.includes('this.nextScenarioTimer') && game.includes('this.timerColorTimer'), 'fraud delayed scenario and timer-color timers should be tracked');
assert(/function showAwakeNarrative\(itemId\)[\s\S]*btn\.innerHTML = safeHTML\(`[\s\S]*escapeTextForHTML\(ch\.category\)[\s\S]*escapeTextForHTML\(ch\.text\)[\s\S]*`\)/.test(game), 'memory narrative choices should escape category and choice text before HTML rendering');
assert(/class FraudGame[\s\S]*_clearTimers\(\)[\s\S]*clearInterval\(this\.flashTimer\)[\s\S]*clearTimeout\(this\.nextScenarioTimer\)[\s\S]*clearTimeout\(this\.timerColorTimer\)[\s\S]*destroy\(\)[\s\S]*this\.active = false[\s\S]*this\._clearTimers\(\)/.test(game), 'fraud destroy should clear flash, delayed scenario, and timer-color timers');
assert(/class FraudGame[\s\S]*var safeTip = escapeTextForHTML\(s\.tip\)[\s\S]*feedback\.innerHTML = safeHTML\([\s\S]*safeTip[\s\S]*var correctFeedback = [\s\S]* \+ safeTip[\s\S]*feedback\.innerHTML = safeHTML\(correctFeedback\)[\s\S]*var wrongFeedback = [\s\S]* \+ safeTip[\s\S]*feedback\.innerHTML = safeHTML\(wrongFeedback\)/.test(game), 'fraud feedback should escape scenario tips before rendering dynamic HTML');
assert(game.includes('this.nextQuestionTimer') && game.includes('this.questionFrameId'), 'UnifiedQuizEngine should track delayed question and animation-frame work');
assert(/class UnifiedQuizEngine[\s\S]*destroy\(\)[\s\S]*clearTimeout\(this\.nextQuestionTimer\)[\s\S]*cancelAnimationFrame\(this\.questionFrameId\)/.test(game), 'UnifiedQuizEngine destroy should clear delayed question and animation-frame work');
assert(/class UnifiedQuizEngine[\s\S]*var questionText = escapeTextForHTML\(\(q\.emoji \? q\.emoji \+ ' ' : ''\) \+ \(q\.text \|\| ''\)\)[\s\S]*area\.innerHTML = safeHTML\([\s\S]*quiz-q-text[\s\S]*questionText[\s\S]*ea\.textContent = \(correct \? '[^']+' : '[^']+'\) \+ ' ' \+ \(q\.explain \|\| ''\)/.test(game), 'UnifiedQuizEngine should escape question text and render explanations as text');
assert(/function loadA11yStage\(\)[\s\S]*tip\.innerHTML = safeHTML\('[\s\S]*' \+ escapeTextForHTML\(s\.explain\) \+ '[\s\S]*'\)/.test(game), 'a11y stage explanations should be escaped before HTML rendering');
assert(/class HeartBridgeGame[\s\S]*feedback\.innerHTML = safeHTML\('[\s\S]*' \+ escapeTextForHTML\(diary\.tip\) \+[\s\S]*escapeTextForHTML\(diary\.mhTip \|\| ''\)[\s\S]*var correctEm = emotions\.find[\s\S]*feedback\.innerHTML = safeHTML\('[\s\S]*escapeTextForHTML\(correctEm \? correctEm\.emoji : ''\)[\s\S]*escapeTextForHTML\(correctEm \? correctEm\.label : ''\)[\s\S]*escapeTextForHTML\(correctEm \? correctEm\.desc\.split/.test(game), 'heart diary feedback should escape diary and emotion text before HTML rendering');
assert(/function initWordGame\(\)[\s\S]*var hintText = escapeTextForHTML\(r\.hint\)[\s\S]*var optionText = escapeTextForHTML\(r\.options\[i\]\)[\s\S]*aria-label="[^"]*' \+ optionText \+ '[\s\S]*>' \+ optionText \+ '<\/button>'[\s\S]*explainDiv\.innerHTML = safeHTML\('[\s\S]*' \+ escapeTextForHTML\(rounds\[currentRound\]\.explain\) \+ '[\s\S]*'\)/.test(game), 'word game hint, options, and explanations should be escaped before HTML rendering');
assert(game.includes('this.questionAnimTimer') && game.includes('this.nodeErrorTimer') && game.includes('this.charJumpTimer'), 'QAdventureEngine should track delayed animation timers');
assert(/class QAdventureEngine[\s\S]*_setTimer\(name, callback, delay\)[\s\S]*_clearTimers\(\)[\s\S]*clearTimeout\(this\.nextQuestionTimer\)[\s\S]*clearTimeout\(this\.questionAnimTimer\)[\s\S]*clearTimeout\(this\.nodeErrorTimer\)[\s\S]*clearTimeout\(this\.charJumpTimer\)[\s\S]*destroy\(\)[\s\S]*this\.active = false[\s\S]*this\._clearTimers\(\)/.test(game), 'QAdventureEngine destroy should clear delayed question, animation, and node timers');
assert(/class QAdventureEngine[\s\S]*type="button" class="ap-pu-btn"[\s\S]*btn\.setAttribute\('aria-label', '冒险答题选项'[\s\S]*syncPowerButton[\s\S]*aria-disabled[\s\S]*aria-pressed[\s\S]*setAttribute\('aria-label', '已排除：'/.test(game), 'QAdventure controls should expose option labels, power-up state, and eliminated state');
assert(game.includes('this.nextWasteTimer') && game.includes('this.chainCompleteTimer') && game.includes('this.costTimer'), 'GrainJourneyGame should track delayed waste, chain, and cost timers');
assert(/class GrainJourneyGame[\s\S]*_clearTimers\(\)[\s\S]*clearTimeout\(this\.wasteTimer\)[\s\S]*clearTimeout\(this\.nextWasteTimer\)[\s\S]*clearTimeout\(this\.chainCompleteTimer\)[\s\S]*clearTimeout\(this\.costTimer\)[\s\S]*destroy\(\)[\s\S]*this\.active = false[\s\S]*this\._clearTimers\(\)/.test(game), 'GrainJourneyGame destroy should clear all delayed timers');
assert(/class GrainJourneyGame[\s\S]*card\.innerHTML = safeHTML\(escapeTextForHTML\(res\.emoji\) \+ ' ' \+ escapeTextForHTML\(res\.label\) \+ '<br><small>' \+ escapeTextForHTML\(res\.hint\) \+ '<\/small>'\)/.test(game), 'grain resource cards should escape dynamic text before HTML rendering');
assert(game.includes('this.assembleTimer') && game.includes('this.traceTimer') && game.includes('this.bakeTimer'), 'OracleRepairGame should track delayed phase timers');
assert(/class OracleRepairGame[\s\S]*_clearTimers\(\)[\s\S]*clearInterval\(this\.tempInterval\)[\s\S]*clearTimeout\(this\.assembleTimer\)[\s\S]*clearTimeout\(this\.traceTimer\)[\s\S]*clearTimeout\(this\.bakeTimer\)[\s\S]*destroy\(\)[\s\S]*this\.active = false[\s\S]*this\._clearTimers\(\)[\s\S]*canvas\.onpointerdown = null[\s\S]*fireBtn\.onclick = null/.test(game), 'OracleRepairGame destroy should clear delayed timers and direct DOM handlers');
assert(game.includes('this.wheelTimer') && game.includes('this.diaryTimer') && game.includes('this.reflectTimer') && game.includes('this.rippleIntervals'), 'HeartBridgeGame should track delayed phase timers and ripple intervals');
assert(/class HeartBridgeGame[\s\S]*_clearTimers\(\)[\s\S]*clearTimeout\(this\.wheelTimer\)[\s\S]*clearTimeout\(this\.diaryTimer\)[\s\S]*clearTimeout\(this\.reflectTimer\)[\s\S]*clearTimeout\(this\._knowledgeTimer\)[\s\S]*rippleIntervals\.forEach[\s\S]*clearInterval[\s\S]*destroy\(\)[\s\S]*this\.active = false[\s\S]*this\._clearTimers\(\)[\s\S]*knowledgeCard\.onclick = null[\s\S]*submitBtn\.onclick = null[\s\S]*slider\.oninput = null/.test(game), 'HeartBridgeGame destroy should clear delayed timers, ripple intervals, and direct DOM handlers');
assert(/class HeartBridgeGame[\s\S]*card\.innerHTML = safeHTML\('<span class="hc-emoji">' \+ escapeTextForHTML\(em\.emoji\) \+ '<\/span><span class="hc-label">' \+ escapeTextForHTML\(em\.label\) \+ '<\/span>'\)[\s\S]*btn\.innerHTML = safeHTML\('<span class="hdo-emoji">' \+ escapeTextForHTML\(em\.emoji\) \+ '<\/span>' \+ escapeTextForHTML\(em\.label\)\)/.test(game), 'heart emotion cards and diary options should escape dynamic text before HTML rendering');
assert(/class HeartBridgeGame[\s\S]*btn\.dataset\.emotionColor = em\.color[\s\S]*btn\.setAttribute\('aria-pressed', 'false'\)[\s\S]*b\.setAttribute\('aria-pressed', 'false'\)[\s\S]*b\.style\.background = ''[\s\S]*b\.style\.borderColor = \(b\.dataset\.emotionColor \|\| ''\) \+ '55'[\s\S]*btn\.setAttribute\('aria-pressed', 'true'\)/.test(game), 'heart diary options should expose pressed state and reset stale selected inline styles');
assert(game.includes('this.timeUpTimer') && game.includes('this.factTimer') && game.includes('this.pollutionMsgTimer') && game.includes('this.particleTimers'), 'OceanRepairGame should track delayed phase, message, and particle timers');
assert(/class OceanRepairGame[\s\S]*_clearTimers\(\)[\s\S]*clearInterval\(this\.timerInterval\)[\s\S]*clearInterval\(this\._pollutionInterval\)[\s\S]*clearInterval\(this\.bubbleInterval\)[\s\S]*clearTimeout\(this\.comboTimer\)[\s\S]*clearTimeout\(this\.timeUpTimer\)[\s\S]*clearTimeout\(this\.factTimer\)[\s\S]*clearTimeout\(this\.pollutionMsgTimer\)[\s\S]*particleTimers\.forEach[\s\S]*clearTimeout[\s\S]*destroy\(\)[\s\S]*this\.active = false[\s\S]*this\._clearTimers\(\)[\s\S]*setTapPlaceSelection\(null, 'ocean'\)/.test(game), 'OceanRepairGame destroy should clear delayed timers, intervals, particles, and tap state');
assert(game.includes('(function(node)') && game.includes('self.particleTimers.push(cleanupTimer)'), 'OceanRepairGame sparkle cleanup should capture each particle node');
assert(game.includes('this.evidenceTimer') && /class TruthPuzzleGame[\s\S]*_clearTimers\(\)[\s\S]*clearInterval\(this\.judgeInterval\)[\s\S]*clearTimeout\(this\.evidenceTimer\)[\s\S]*destroy\(\)[\s\S]*this\.active = false[\s\S]*this\._clearTimers\(\)[\s\S]*setTapPlaceSelection\(null, 'truth'\)/.test(game), 'TruthPuzzleGame destroy should clear evidence delay, judge interval, and tap state');
assert(/class TruthPuzzleGame[\s\S]*card\.innerHTML = safeHTML\('<strong>' \+ escapeTextForHTML\(ev\.label\) \+ '<\/strong><br><small>' \+ escapeTextForHTML\(ev\.detail\) \+ '<\/small>'\)[\s\S]*card\.innerHTML = safeHTML\('<strong>' \+ escapeTextForHTML\(ev\.label\) \+ '<\/strong><br><small>' \+ escapeTextForHTML\(ev\.detail \|\| ev\.tip \|\| ''\) \+ '<\/small>'\)/.test(game), 'truth evidence and judge cards should escape dynamic text before HTML rendering');
assert(/class TruthPuzzleGame[\s\S]*card\.className = 'truth-judge-card'[\s\S]*setAttribute\('role', 'button'\)[\s\S]*setAttribute\('tabindex', '0'\)[\s\S]*setAttribute\('aria-label'[\s\S]*addEventListener\('keydown'[\s\S]*self\._judgeCard\(card, ev\)[\s\S]*setAttribute\('aria-disabled', 'true'\)[\s\S]*card\.tabIndex = -1/.test(game), 'truth judge cards should expose keyboard button semantics and disabled state after judging');
assert(game.includes('this.winTimer') && game.includes('this.itemFlashTimers') && game.includes('this.binFlashTimers'), 'EcoGame should track delayed win and feedback timers');
assert(/class EcoGame[\s\S]*_clearTimers\(\)[\s\S]*clearInterval\(this\.timerId\)[\s\S]*clearTimeout\(this\.winTimer\)[\s\S]*clearTimeout\(this\.timerColorTimer\)[\s\S]*itemFlashTimers\.forEach[\s\S]*binFlashTimers\.forEach[\s\S]*document\.querySelectorAll\('\.eco-bin'\)[\s\S]*destroy\(\)[\s\S]*this\.active = false[\s\S]*this\._clearTimers\(\)[\s\S]*setTapPlaceSelection\(null, 'eco'\)[\s\S]*this\.tapSelectedItem = null/.test(game), 'EcoGame destroy should clear timers, feedback classes, and tap state');
assert(game.includes("coach.setAttribute('role', 'complementary')"), 'gameplay coach should expose a complementary landmark');
assert(game.includes("coach.setAttribute('aria-live', 'polite')"), 'gameplay coach should announce updates politely');
assert(browserSmoke.includes("const net = require('net');"), 'browser smoke should allocate dynamic ports');
assert(browserSmoke.includes('getFreePort'), 'browser smoke should discover free ports at runtime');
assert(browserSmoke.includes("resolveSmokePort('SMOKE_APP_PORT')"), 'browser smoke app port should be runtime-resolved');
assert(browserSmoke.includes("resolveSmokePort('SMOKE_CDP_PORT')"), 'browser smoke CDP port should be runtime-resolved');
assert(!/\b(18080|9224)\b/.test(browserSmoke), 'browser smoke should not hard-code smoke ports');
assert(game.includes('foreignObject|style|link|meta|base'), 'SVG sanitizer should strip dangerous embedded SVG/HTML tags');
assert(game.includes('xlink:href|src|action'), 'SVG sanitizer should strip dangerous URL-bearing attributes');
assert(game.includes('normalizeDangerousValue'), 'HTML sanitizer should normalize whitespace/control characters in dangerous values');
assert(game.includes('isDangerousUrl'), 'HTML sanitizer should centralize dangerous URL detection');
assert(game.includes('isDangerousStyle'), 'HTML sanitizer should reject dangerous inline style payloads');
assert(game.includes("URL_ATTRS.has(attrName) && isDangerousUrl(attrValue)"), 'HTML sanitizer should use normalized URL checks');
assert(game.includes("attrName === 'style' && isDangerousStyle(attrValue)"), 'HTML sanitizer should check inline styles');
assert(game.includes('_bindPowerButtons'), 'QAdventure power buttons should bind through addEventListener');
assert(!game.includes('onclick="window._qadventure.usePower'), 'QAdventure power buttons must not use inline onclick handlers');
assert(sound.includes("String(text || '')"), 'audio.speak should tolerate null or missing text');
assert(sound.includes('if (!cleanText) return'), 'audio.speak should skip empty narration text');
assert(sound.includes('cleanTrustedTypeUrl'), 'Trusted Types default policy should sanitize script URLs');
assert(!sound.includes('createScriptURL: (string) => string'), 'Trusted Types default policy must not pass script URLs through');
assert(sound.includes("createScript: () => ''"), 'Trusted Types default policy should not pass dynamic script text through');
assert(browserSmoke.includes('assertSecurityAndAudioGuards'), 'browser smoke should cover sanitizer and audio guards');
assert(browserSmoke.includes('hasHtmlDanger'), 'browser smoke should cover ordinary HTML sanitizer bypasses');
assert(browserSmoke.includes('unifiedQuizEscaped'), 'browser smoke should verify UnifiedQuizEngine text escaping at runtime');
assert(game.includes('window[refName] = null'), 'transient game cleanup should release global references');
assert(game.includes("destroyTransientGameRef('_qadventure')"), 'QAdventure guarded buttons should clear the global engine reference');
assert(browserSmoke.includes('transientRef'), 'browser smoke should verify transient game references are cleared after returning to Hub');
assert(browserSmoke.includes('assertReducedMotion'), 'browser smoke should verify reduced-motion CSS behavior');
assert(browserSmoke.includes('assertThemeSwitcherA11y'), 'browser smoke should verify theme switcher accessibility state');
assert(browserSmoke.includes('assertAudioToggleA11y'), 'browser smoke should verify audio toggle accessibility state');
assert(browserSmoke.includes('nestedCapsuleControls'), 'browser smoke should verify capsule cards do not contain nested interactive controls');
assert(browserSmoke.includes('ambient particles should pause under reduced motion'), 'browser smoke should verify reduced-motion pauses ambient particles');
assert(browserSmoke.includes('assertTouchTargets'), 'browser smoke should verify mobile touch target sizes');
assert(browserSmoke.includes('assertMobileFloatingControls'), 'browser smoke should verify mobile floating controls avoid the coach');
assert(browserSmoke.includes('assertInteractiveSemantics'), 'browser smoke should verify custom control semantics');
assert(browserSmoke.includes("screen-hidden") && browserSmoke.includes("screen-maze"), 'browser smoke should include hidden and maze mobile checks');
assert(browserSmoke.includes('cognitiveRuntimeTimerCount() === 0'), 'browser smoke should verify cognitive timer cleanup');
assert(browserSmoke.includes('runtimeCheck'), 'browser smoke should support targeted runtime checks');
assert(browserSmoke.includes('beforeBack'), 'browser smoke should cover state cleanup after selected controls return to hub');
assert(browserSmoke.includes('tap-to-place state leaked'), 'browser smoke should verify tap-to-place state cleanup');
assert(browserSmoke.includes('gameplay assist highlights leaked'), 'browser smoke should verify gameplay assist highlights are cleared after returning to hub');
assert(browserSmoke.includes('assertWorkbenchRuntimeCleanup') && browserSmoke.includes('_sewingInterval'), 'browser smoke should verify workbench runtime cleanup');
assert(browserSmoke.includes('assertShortcutCleanup') && browserSmoke.includes("key: 'Escape'"), 'browser smoke should verify shortcut-triggered cleanup');
assert(browserSmoke.includes('keyboardCheck'), 'browser smoke should verify keyboard activation for custom controls');
assert(browserSmoke.includes("new KeyboardEvent('keydown'"), 'browser smoke should dispatch real keyboard events');
assert(browserSmoke.includes('Color card|Color group|Face memory card|Rhythm pad'), 'browser smoke should reject placeholder custom-control labels');
assert(browserSmoke.includes('skillRef'), 'browser smoke should cover lightweight skill game cleanup');
assert(browserSmoke.includes('skill runtime state leaked'), 'browser smoke should verify skill runtime state cleanup');
assert(browserSmoke.includes('__qaLifecycleProbe') && browserSmoke.includes('charJumpTimer'), 'browser smoke should verify QAdventure delayed timer cleanup');
assert(browserSmoke.includes('_fraudColorProbe') && browserSmoke.includes('timerColorTimer'), 'browser smoke should verify FraudGame delayed timer-color cleanup');
assert(!/translate\.google\.com|translate_tts|Google Cloud TTS/i.test(sound), 'sound engine must not stream external TTS audio');
assert(/startVinylNoise\(\)[\s\S]*if \(!this\.ctx \|\| this\.noiseNode\) return/.test(sound), 'vinyl noise should not create duplicate loop nodes');
assert(/startBGM\(\)[\s\S]*this\.ctx\.resume\(\)[\s\S]*this\.startVinylNoise\(\)/.test(sound), 'vinyl noise should start with BGM, not generic audio init');
assert(/stopVinylNoise\(\)[\s\S]*this\.noiseNode\.stop\(\)[\s\S]*this\.noiseNode\.disconnect\(\)[\s\S]*this\.noiseNode = null/.test(sound), 'vinyl noise should have an explicit cleanup path');
assert(/stopBGM\(\)[\s\S]*clearTimeout\(this\.bgmInterval\)[\s\S]*this\.stopVinylNoise\(\)/.test(sound), 'BGM stop should also stop vinyl noise');
assert(!/init\(\)[\s\S]*Start Vinyl Tape Crackle Noise[\s\S]*this\.startVinylNoise\(\)/.test(sound), 'generic audio init should not start background vinyl noise');
assert(/playError\(\)[\s\S]*gain\.connect\(this\.sfxVolume\)/.test(sound), 'error sound must respect the SFX volume chain');
assert(!/playError\(\)[\s\S]*gain\.connect\(this\.ctx\.destination\)/.test(sound), 'error sound must not bypass master/SFX volume');
assert(pkg.scripts && pkg.scripts.check && pkg.scripts.verify, 'package scripts should include check and verify gates');

[
  '_selectTapCoral',
  '_placeTapCoral',
  '_selectTapFrag',
  '_placeTapFrag',
  '_selectTapEvidence',
  '_placeTapEvidence',
  '_selectTapEmotion',
  '_placeTapEmotion',
  '_selectTapResource',
  '_placeTapResource'
].forEach((name) => {
  assert(game.includes(name), `missing tap-to-place contract: ${name}`);
});

const stateEngine = read('engine/state-persistence.js');
assert(stateEngine.includes('MAX_ALBUM_TEXT'), 'state persistence should bound album story length');
assert(stateEngine.includes('normalizeGameStats'), 'state persistence should normalize game statistics');
assert(stateEngine.includes('normalizeBooleanMap'), 'state persistence should normalize achievement booleans');
const sandbox = {
  console,
  setTimeout,
  clearTimeout,
  localStorage: (() => {
    const data = new Map();
    return {
      getItem: (key) => data.has(key) ? data.get(key) : null,
      setItem: (key, value) => data.set(key, String(value)),
      removeItem: (key) => data.delete(key)
    };
  })()
};
sandbox.globalThis = sandbox;
vm.runInNewContext(stateEngine, sandbox);

assert(sandbox.SKStatePersistence, 'SKStatePersistence should be exported');
const defaults = {
  unlockedItems: ['radio'],
  completedItems: [],
  fraudCompleted: [],
  albumEntries: [],
  fraudAlbumEntries: [],
  progress: 0,
  memorySilver: 0,
  totalEmpathy: 0,
  lastMaxCombo: 0,
  totalGamesPlayed: 0,
  totalGamesCompleted: 0,
  upgrades: { cleaner: { level: 1, baseCost: 100 } },
  achievements: { firstWin: false },
  gameStats: {},
  dailyChallenge: { date: '', target: 0, reward: 100, progress: 0, completed: false }
};
const normalized = sandbox.SKStatePersistence.test.extract({
  ...defaults,
  unlockedItems: ['radio', 'radio', 'camera'],
  albumEntries: [
    { id: 'old', title: 'old', storyText: 'x' },
    { id: 'radio', title: 123, choiceId: 'memory'.repeat(60), storyText: 'A'.repeat(9000), date: 'D'.repeat(1000), extra: '<script>x</script>' }
  ],
  progress: 999,
  memorySilver: -5,
  achievements: { firstWin: true, injected: true },
  gameStats: {
    'memory-match': { played: '7', completed: '-3', bestScore: Infinity },
    '<bad>': { played: 9, completed: 9, bestScore: 9 }
  },
  dailyChallenge: { date: 'Z'.repeat(200), target: 9999, reward: -1, progress: -1, completed: 1 }
}, defaults);

assert.deepStrictEqual(Array.from(normalized.unlockedItems), ['radio', 'camera']);
assert.strictEqual(normalized.progress, 100);
assert.strictEqual(normalized.memorySilver, 0);
assert.strictEqual(normalized.achievements.firstWin, true);
assert.strictEqual(Object.prototype.hasOwnProperty.call(normalized.achievements, 'injected'), false);
assert.strictEqual(normalized.albumEntries.length, 2);
assert.strictEqual(normalized.albumEntries[1].storyText.length, 6000);
assert.strictEqual(normalized.albumEntries[1].choiceId.length, 160);
assert.strictEqual(Object.prototype.hasOwnProperty.call(normalized.albumEntries[1], 'extra'), false);
assert.strictEqual(normalized.gameStats['memory-match'].played, 7);
assert.strictEqual(normalized.gameStats['memory-match'].completed, 0);
assert.strictEqual(normalized.gameStats['memory-match'].bestScore, 0);
assert.strictEqual(Object.prototype.hasOwnProperty.call(normalized.gameStats, '<bad>'), false);
assert.strictEqual(normalized.dailyChallenge.date.length, 40);
assert.strictEqual(normalized.dailyChallenge.target, 999);
assert.strictEqual(normalized.dailyChallenge.reward, 0);
assert.strictEqual(normalized.dailyChallenge.progress, 0);
assert.strictEqual(normalized.dailyChallenge.completed, true);
assert(stateEngine.includes('mergeSavedState'), 'state persistence should whitelist saved keys during hydration');

const mergedState = sandbox.SKStatePersistence.test.mergeSavedState(defaults, JSON.parse('{"memorySilver":42,"injected":"bad","__proto__":{"polluted":true}}'));
assert.strictEqual(mergedState.memorySilver, 42);
assert.strictEqual(Object.prototype.hasOwnProperty.call(mergedState, 'injected'), false);
assert.strictEqual({}.polluted, undefined);

const throwingStorageSandbox = {
  console: { warn: () => {}, log: () => {}, error: console.error },
  setTimeout,
  clearTimeout,
  localStorage: {
    setItem: () => {},
    removeItem: () => {},
    getItem: () => { throw new Error('blocked getItem'); }
  }
};
throwingStorageSandbox.globalThis = throwingStorageSandbox;
vm.runInNewContext(stateEngine, throwingStorageSandbox);
let blockedLoad = 'unset';
assert.doesNotThrow(() => { blockedLoad = throwingStorageSandbox.SKStatePersistence.load(); }, 'state load should tolerate storage getItem failures');
assert.strictEqual(blockedLoad, null);
assert.doesNotThrow(() => throwingStorageSandbox.SKStatePersistence.clear(), 'state clear should tolerate storage removeItem failures');

console.log('static contracts ok');
