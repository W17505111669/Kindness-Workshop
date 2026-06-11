/**
 * Time's Echo: Memory Weaver - Core Game Logic & Systems
 * Designed for the Tencent Cloud Hackathon public welfare game track.
 */

// ============================================================================
// 0. SECURITY: Real Trusted Types Sanitizer (DOMPurify Lite)
// ============================================================================
// 生产级 HTML 消毒器 —— 不再透传，而是真正过滤 XSS 注入向量
const SAFE_TAGS = new Set([
    'div','span','p','h1','h2','h3','h4','hgroup','ul','li','ol','section','header','main','footer',
    'svg','rect','circle','path','line','ellipse','text','g','defs','filter','radialgradient','stop',
    'button','input','strong','em','br','a','img','canvas','label','small','sub','sup'
]);
const SAFE_ATTRS = new Set([
    'class','id','style','href','target','rel','alt','title','role','aria-label','aria-hidden',
    'aria-live','aria-expanded','tabindex','type','value','min','max','step','placeholder',
    'download','width','height',
    // SVG 属性白名单
    'viewBox','fill','stroke','cx','cy','r','d','x','y','x1','y1','x2','y2','rx','ry',
    'opacity','transform','font-family','font-size','font-weight','text-anchor',
    'stroke-width','stroke-linecap','stroke-dasharray','filter','points',
    'dominant-baseline','alignment-baseline','text-align','letter-spacing'
]);
const FORBIDDEN_PREFIXES = ['on', 'javascript:', 'data:text/html', 'vbscript:'];
const URL_ATTRS = new Set(['href', 'src', 'action', 'xlink:href']);

function normalizeDangerousValue(value) {
    return String(value || '').replace(/[\u0000-\u001F\u007F\s]+/g, '').toLowerCase();
}

function isDangerousUrl(value) {
    return /^(javascript:|vbscript:|data:text\/html)/.test(normalizeDangerousValue(value));
}

function isDangerousStyle(value) {
    const raw = String(value || '').toLowerCase();
    const compact = normalizeDangerousValue(value);
    return /javascript:|vbscript:|data:text\/html|expression\s*\(|@import/.test(raw) ||
        /javascript:|vbscript:|data:text\/html|expression\(|@import/.test(compact);
}

function sanitizeHTML(htmlString) {
    if (!htmlString || typeof htmlString !== 'string') return '';
    try {
        // SVG 内容检测：本项目所有 SVG 均来自硬编码的 itemBlueprints，非用户输入
        // DOMParser 的 text/html 模式会破坏 SVG 命名空间，导致元素无法渲染
        // 因此对含 SVG 元素的内容仅做轻量正则清洗（剥离 on* 事件），不交给 DOMParser
        if (/<svg[\s>]/.test(htmlString) || /<g[\s>]/.test(htmlString) || /<(rect|circle|path|line|ellipse|polygon|polyline|text|defs|filter|stop|use)[\s/>]/.test(htmlString)) {
            return _sanitizeSVGString(htmlString);
        }
        // 非 SVG 内容走完整 DOMParser 消毒流程
        const parser = new DOMParser();
        const doc = parser.parseFromString(htmlString, 'text/html');
        _sanitizeNode(doc.body);
        return doc.body.innerHTML;
    } catch (e) {
        console.warn('HTML sanitization failed, returning empty:', e);
        return '';
    }
}

/** 对 SVG 字符串做轻量安全清洗：仅去除 on* 事件处理器和危险标签 */
function _sanitizeSVGString(svgStr) {
    return svgStr
        // 移除所有 on* 事件属性 (如 onload, onclick, onerror 等)
        .replace(/\s+on\w+\s*=\s*["'][^"']*["']/gi, '')
        .replace(/\s+on\w+\s*=\s*[^\s>]+/gi, '')
        .replace(/<script[\s\S]*?<\/script>/gi, '')
        .replace(/<\/?(script|iframe|object|embed|foreignObject|style|link|meta|base)[^>]*>/gi, '')
        .replace(/\s+(href|xlink:href|src|action)\s*=\s*["']\s*(?:javascript:|vbscript:|data:text\/html)[^"']*["']/gi, '')
        .replace(/\s+(href|xlink:href|src|action)\s*=\s*[^\s>]*(?:javascript:|vbscript:|data:text\/html)[^\s>]*/gi, '')
        .replace(/\s+style\s*=\s*["'][^"']*(?:javascript:|vbscript:|data:text\/html|expression\s*\(|@import)[^"']*["']/gi, '')
        .replace(/\s+style\s*=\s*[^\s>]*(?:javascript:|vbscript:|data:text\/html|expression\s*\(|@import)[^\s>]*/gi, '')
        // 移除 <script> 块
        .replace(/<script[\s\S]*?<\/script>/gi, '')
        // 移除 javascript: 协议
        .replace(/javascript\s*:/gi, '');
}

function _sanitizeNode(node) {
    // 移除危险节点
    const toRemove = [];
    for (let i = 0; i < node.childNodes.length; i++) {
        const child = node.childNodes[i];
        if (child.nodeType === 1) { // Element node
            const tagName = child.tagName.toLowerCase();
            if (tagName === 'script' || tagName === 'iframe' || tagName === 'object' ||
                tagName === 'embed' || tagName === 'style' || tagName === 'link' ||
                tagName === 'meta' || tagName === 'base') {
                toRemove.push(child);
                continue;
            }
            // 白名单检查
            if (!SAFE_TAGS.has(tagName)) {
                toRemove.push(child);
                continue;
            }
            // 清理属性
            if (child.attributes) {
                const attrsToRemove = [];
                for (let j = 0; j < child.attributes.length; j++) {
                    const attr = child.attributes[j];
                    const attrName = attr.name.toLowerCase();
                    const attrValue = attr.value || '';
                    // 移除所有 on* 事件处理器
                    if (attrName.startsWith('on')) {
                        attrsToRemove.push(attr.name);
                        continue;
                    }
                    // 移除危险协议
                    if (URL_ATTRS.has(attrName) && isDangerousUrl(attrValue)) {
                        attrsToRemove.push(attr.name);
                        continue;
                    }
                    if (attrName === 'style' && isDangerousStyle(attrValue)) {
                        attrsToRemove.push(attr.name);
                        continue;
                    }
                    // 白名单检查
                    if (!SAFE_ATTRS.has(attrName) && !attrName.startsWith('data-')) {
                        attrsToRemove.push(attr.name);
                    }
                }
                attrsToRemove.forEach(a => child.removeAttribute(a));
            }
            // 递归处理子节点
            _sanitizeNode(child);
        } else if (child.nodeType === 3) { // Text node — 保留
            // 安全
        } else if (child.nodeType === 8) { // Comment node — 移除
            toRemove.push(child);
        }
    }
    toRemove.forEach(n => n.remove());
}

// Strict Chromium Environment: Establish resilient Named Trusted Types Policy
let trustedPolicy = {
    createHTML: (s) => sanitizeHTML(s)
};
if (window.trustedTypes && window.trustedTypes.createPolicy) {
    try {
        trustedPolicy = window.trustedTypes.createPolicy('gamePolicy', {
            createHTML: (string) => sanitizeHTML(string)
        });
    } catch (e) {
        console.warn("Trusted Types policy creation failed, checking fallback:", e);
        if (window.trustedTypes.defaultPolicy) {
            trustedPolicy = window.trustedTypes.defaultPolicy;
        } else {
            // 降级到本地 sanitizer
            trustedPolicy = { createHTML: (s) => sanitizeHTML(s) };
        }
    }
}

function safeHTML(htmlString) {
    return trustedPolicy ? trustedPolicy.createHTML(htmlString) : sanitizeHTML(htmlString);
}

function escapeTextForHTML(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, function(ch) {
        return {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        }[ch];
    });
}

function createButtonElement() {
    const button = document.createElement('button');
    button.type = 'button';
    return button;
}

// ============================================================================
// 1. GAME STATE MANAGEMENT
// ============================================================================
const gameState = {
    currentScreen: 'screen-start',
    currentMode: 'nostalgia', // 'nostalgia' | 'fraud' — 温情重构 / 赛博反诈
    activeItem: null,
    unlockedItems: ['radio','camera','sewing','lantern','watch','telephone','musicbox','abacus','television'],
    fraudUnlocked: ['fraud_voice','fraud_phish','fraud_romance'], // 反诈案件
    completedItems: [],
    fraudCompleted: [], // 反诈案件完成列表
    albumEntries: [],
    fraudAlbumEntries: [], // 反诈破案记录
    progress: 0,
    activeDragPart: null,
    dragOffset: { x: 0, y: 0 },
    draggedElement: null,
    snappedCount: 0,
    totalPartsCount: 0,

    // Progression values
    memorySilver: 0,
    totalEmpathy: 0,
    lastMaxCombo: 0,
    totalGamesPlayed: 0,
    totalGamesCompleted: 0,
    upgrades: {
        cleaner: { level: 1, baseCost: 100 },
        tuner: { level: 1, baseCost: 100 },
        stitch: { level: 1, baseCost: 100 }
    },
    // 成就系统
    achievements: {
        firstWin: false,      // 首次通关任意游戏
        comboMaster: false,   // 达成10连击
        silverHoarder: false, // 累计获得500银币
        gameExplorer: false,  // 玩过10个不同游戏
        perfectScore: false,  // 任意游戏获得满分
        speedRunner: false,   // 15秒内完成深蓝修复者任一关
        emotionGuru: false,   // 心桥计划全对
        foodSaver: false      // 拯救15份食物
    },
    // 游戏统计
    gameStats: {},
    // 每日挑战
    dailyChallenge: { date: '', target: 0, reward: 100, progress: 0, completed: false }
};

function loadPersistedGameState() {
    if (window.SKStatePersistence && window.SKStatePersistence.hydrate) {
        window.SKStatePersistence.hydrate(gameState);
    }
}

function persistGameState() {
    if (window.SKStatePersistence && window.SKStatePersistence.save) {
        window.SKStatePersistence.save(gameState);
    }
}

function persistGameStateSoon() {
    if (window.SKStatePersistence && window.SKStatePersistence.saveDebounced) {
        window.SKStatePersistence.saveDebounced(gameState);
    }
}

loadPersistedGameState();

window.addEventListener('beforeunload', persistGameState);
document.addEventListener('visibilitychange', function() {
    if (document.visibilityState === 'hidden') persistGameState();
});

// Global Modular Sensor and Disease Decay Controllers will be safely instantiated below after their class declarations to prevent ReferenceErrors.

/**
 * 公益成长循环数值管理器 (GameEconomyManager)
 */
const economyManager = {
    /**
     * 单次关卡「共情力 E」结算函数
     * E = BaseScore * (1 + MaxCombo * 0.15) * (1 + EncyclopediaBonus)
     */
    calculateEmpathy(baseScore, maxCombo, encyclopediaBonus) {
        const comboBonus = 1.0 + (maxCombo * 0.15);
        const totalBonus = 1.0 + encyclopediaBonus;
        const empathyValue = Math.round(baseScore * comboBonus * totalBonus);
        
        // 汇率换算：共情值以 2:1 结汇成记忆银币
        const silverEarned = Math.round(empathyValue * 0.5);
        gameState.memorySilver += silverEarned;

        return {
            empathy: empathyValue,
            silverEarned: silverEarned
        };
    },

    /**
     * 商店道具「升级消耗 Cost(L)」计算函数
     * Cost(L) = BaseCost * (1.8 ^ (L - 1))
     */
    getUpgradeCost(baseCost, currentLevel) {
        if (currentLevel < 1) currentLevel = 1;
        return Math.round(baseCost * Math.pow(1.8, currentLevel - 1));
    }
};

// ============================================================================
// 全局成就与每日挑战系统
// ============================================================================
const achievementSystem = {
    check: function(achievementId) {
        if (!gameState.achievements[achievementId]) {
            gameState.achievements[achievementId] = true;
            this._showAchievement(achievementId);
            persistGameStateSoon();
            return true;
        }
        return false;
    },
    _achievementNames: {
        firstWin: '🏆 初露锋芒', comboMaster: '🔥 连击大师', silverHoarder: '💰 银币达人',
        gameExplorer: '🎮 游戏探险家', perfectScore: '⭐ 满分达成', speedRunner: '⚡ 闪电修复',
        emotionGuru: '💜 情绪导师', foodSaver: '🍚 粮食守护者'
    },
    _achievementDesc: {
        firstWin: '首次通关任意游戏', comboMaster: '达成10连击', silverHoarder: '累计获得500银币',
        gameExplorer: '玩过10个不同游戏', perfectScore: '任意游戏获得满分', speedRunner: '15秒内完成深蓝修复者任一关',
        emotionGuru: '心桥计划全对', foodSaver: '拯救15份食物'
    },
    _showAchievement: function(id) {
        var name = this._achievementNames[id] || id;
        var desc = this._achievementDesc[id] || '';
        var el = document.getElementById('achievement-toast');
        if (!el) {
            el = document.createElement('div');
            el.id = 'achievement-toast';
            el.className = 'achievement-toast';
            document.body.appendChild(el);
        }
        el.innerHTML = safeHTML('<div class="ach-icon">🏆</div><div><strong>' + escapeTextForHTML(name) + '</strong><br><small>' + escapeTextForHTML(desc) + '</small></div>');
        el.classList.add('show');
        setTimeout(function() { el.classList.remove('show'); }, 3000);
        if (typeof audio !== 'undefined' && audio.playAwake) audio.playAwake();
    },
    countUnlocked: function() { return Object.values(gameState.achievements).filter(Boolean).length; },
    totalAchievements: 8
};

function initDailyChallenge() {
    var today = new Date().toDateString();
    if (gameState.dailyChallenge.date !== today) {
        gameState.dailyChallenge = {
            date: today,
            target: Math.floor(Math.random() * 3) + 3,
            reward: 100 + Math.floor(Math.random() * 100),
            progress: 0,
            completed: false
        };
    }
    var dc = gameState.dailyChallenge;
    var el = document.getElementById('daily-challenge-info');
    if (el) {
        el.textContent = '📅 今日挑战：完成' + dc.target + '个游戏 (' + dc.progress + '/' + dc.target + ') 奖励+' + dc.reward;
    }
}

function trackDailyProgress() {
    var dc = gameState.dailyChallenge;
    if (!dc.completed && dc.date === new Date().toDateString()) {
        dc.progress++;
        if (dc.progress >= dc.target && !dc.completed) {
            dc.completed = true;
            gameState.memorySilver += dc.reward;
            document.getElementById('global-silver-balance').textContent = gameState.memorySilver;
            var el = document.getElementById('daily-challenge-info');
            if (el) el.textContent = '🎉 每日挑战完成！获得 +' + dc.reward + ' 银币';
            if (typeof audio !== 'undefined' && audio.playAwake) audio.playAwake();
        } else {
            initDailyChallenge();
        }
        persistGameStateSoon();
    }
}

function trackGamePlay(gameId) {
    gameState.totalGamesPlayed++;
    if (!gameState.gameStats[gameId]) gameState.gameStats[gameId] = { played: 0, completed: 0, bestScore: 0 };
    gameState.gameStats[gameId].played++;
    if (gameState.totalGamesPlayed >= 10) achievementSystem.check('gameExplorer');
    initDailyChallenge();
    persistGameStateSoon();
}

function trackGameComplete(gameId, score) {
    gameState.totalGamesCompleted++;
    if (!gameState.gameStats[gameId]) gameState.gameStats[gameId] = { played: 0, completed: 0, bestScore: 0 };
    var stat = gameState.gameStats[gameId];
    var isNewBest = score > stat.bestScore;
    stat.completed++;
    if (isNewBest) stat.bestScore = score;
    achievementSystem.check('firstWin');
    if (gameState.memorySilver >= 500) achievementSystem.check('silverHoarder');
    trackDailyProgress();
    showGameplayToast(isNewBest ? '本局完成，最佳成绩已更新。' : '本局完成，进度已保存。', 'success');
    persistGameStateSoon();
}

// 统一奖励计算引擎
function unifiedRewardCalc(baseScore, combo, difficulty, timeBonus, accuracyPct) {
    var diffMultiplier = { easy: 0.8, normal: 1.0, hard: 1.5, lightning: 2.0 };
    var dm = diffMultiplier[difficulty] || 1.0;
    var comboBonus = Math.min(combo, 20) * 3;
    var accuracyBonus = Math.round(accuracyPct * 0.5);
    var total = Math.round((baseScore + comboBonus) * dm) + accuracyBonus + (timeBonus || 0);
    total = Math.max(10, total);
    gameState.memorySilver += total;
    gameState.totalEmpathy += total;
    document.getElementById('global-silver-balance').textContent = gameState.memorySilver;
    persistGameStateSoon();
    return total;
}

// ============================================================================
// 1.5. HARDWARE INTEGRATION & PATHOLOGICAL DECAY & AIGC MODULE DEFINITIONS
// ============================================================================

/**
 * 🌬️ 跨次元硬件级交互：高保真频响吹气感应分析器 (MicBlowerAPI)
 */
class MicBlowerAPI {
    constructor() {
        this.audioCtx = null;
        this.analyser = null;
        this.dataArray = null;
        this.source = null;
        this.stream = null;
        this.isMeasuring = false;
        this.hasPermission = null;
        this.onBlowLevel = null; // 吹气强度回调
    }

    async init() {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            this.stream = stream;
            this.audioCtx = new (window.AudioContext || window.webkitAudioContext)();
            this.analyser = this.audioCtx.createAnalyser();
            this.analyser.fftSize = 256;
            this.source = this.audioCtx.createMediaStreamSource(stream);
            this.source.connect(this.analyser);
            this.dataArray = new Uint8Array(this.analyser.frequencyBinCount);
            this.hasPermission = true;
            console.log("MicBlowerAPI 初始化成功。已开启硬件录音分析器。");
            return true;
        } catch (err) {
            console.warn("麦克风权限被拒绝或初始化失败，启用经典滑鼠拖拽降级:", err);
            this.hasPermission = false;
            return false;
        }
    }

    start(callback) {
        if (this.hasPermission === false) return;
        this.onBlowLevel = callback;
        if (this.isMeasuring) return;
        this.isMeasuring = true;
        this.measure();
    }

    measure() {
        if (!this.isMeasuring) return;
        if (this.analyser && this.dataArray) {
            this.analyser.getByteFrequencyData(this.dataArray);
            
            // 重点分析 100Hz - 800Hz 湍流频段（排除极低频底噪与背景高频啸叫）
            let sum = 0;
            for (let i = 1; i < 8; i++) {
                sum += this.dataArray[i];
            }
            const average = sum / 7; // 0 - 255
            const level = average / 255; // 0.0 - 1.0

            if (this.onBlowLevel) {
                this.onBlowLevel(level);
            }
        }
        requestAnimationFrame(() => this.measure());
    }

    stop() {
        this.isMeasuring = false;
        this.onBlowLevel = null;
        if (this.stream) {
            this.stream.getTracks().forEach(track => track.stop());
        }
        if (this.audioCtx) {
            try {
                this.audioCtx.close();
            } catch (e) {}
        }
        this.audioCtx = null;
        this.analyser = null;
        this.dataArray = null;
        this.source = null;
        this.stream = null;
    }
}

/**
 * 🧠 病理级 UI 感官衰退管理器 (CognitiveDecayManager)
 * 周期性模拟阿尔茨海默病“模糊、灰度、语言失认乱码”的过程，成功拼图净化后瞬间清空
 */
class CognitiveDecayManager {
    constructor() {
        this.decayValue = 0; // 0 - 100
        this.timer = null;
        this.lastActionTime = Date.now();
        this.originalTextMap = new Map(); // 原始文案缓存
        this.glitchedElements = new Set();
        this.isDecaying = false;
    }

    start() {
        if (this.timer) return;
        this.lastActionTime = Date.now();
        this.isDecaying = true;
        // 性能优化：从 1s 降至 3s，减少重复 DOM 读写
        this.timer = setInterval(() => this.tick(), 3000);
    }

    recordAction() {
        this.lastActionTime = Date.now();
        if (this.decayValue > 0) {
            // 每次点击交互均可轻微唤醒认知度（减少衰退值）
            this.decayValue = Math.max(0, this.decayValue - 15);
            this.applyFilters();
            if (this.decayValue === 0) {
                this.restoreText();
            }
        }
    }

    tick() {
        if (!this.isDecaying) return;
        const idleTime = Date.now() - this.lastActionTime;
        
        // 仅在阁楼/工作台场景激活认知衰退效果
        if (gameState.currentScreen !== 'screen-hub' && gameState.currentScreen !== 'screen-workspace') return;
        
        // 玩家停顿 7 秒以上，大脑认知迷雾再度积累
        if (idleTime > 7000) {
            this.decayValue = Math.min(100, this.decayValue + 3);
            this.applyFilters();
            
            // 大于 40% 开启文字语义失认乱码风暴 (使用 requestIdleCallback 避免阻塞主线程)
            if (this.decayValue > 40) {
                if (window.requestIdleCallback) {
                    requestIdleCallback(() => this.scrambleUI());
                } else {
                    setTimeout(() => this.scrambleUI(), 0);
                }
            }
        }
    }

    applyFilters() {
        const app = document.getElementById('app-container');
        if (!app) return;

        if (this.decayValue === 0) {
            app.style.filter = "none";
            return;
        }

        // 色彩褪去为灰度
        const grayscaleVal = Math.min(90, (this.decayValue / 100) * 90);
        // 视觉边界模糊化
        const blurVal = Math.min(4.0, (this.decayValue / 100) * 4.0);

        app.style.filter = `grayscale(${grayscaleVal}%) blur(${blurVal}px)`;
    }

    scrambleUI() {
        const textElements = document.querySelectorAll('.capsule-desc, .workspace-tip, .toy-instructions, .intro-text');
        const glitchChars = "░▒▓█@%&#$░▒▓";

        textElements.forEach(el => {
            if (!this.originalTextMap.has(el)) {
                this.originalTextMap.set(el, el.textContent);
            }
            
            const original = this.originalTextMap.get(el);
            let scrambled = "";
            const ratio = (this.decayValue - 40) / 60; // 0.0 - 1.0
            
            for (let i = 0; i < original.length; i++) {
                if (original[i] === " " || original[i] === "\n") {
                    scrambled += original[i];
                } else if (Math.random() < ratio * 0.4) {
                    scrambled += glitchChars[Math.floor(Math.random() * glitchChars.length)];
                } else {
                    scrambled += original[i];
                }
            }
            
            el.textContent = scrambled;
            el.classList.add('cognitive-glitch');
            this.glitchedElements.add(el);
        });
    }

    restoreText() {
        this.glitchedElements.forEach(el => {
            if (this.originalTextMap.has(el)) {
                el.textContent = this.originalTextMap.get(el);
            }
            el.classList.remove('cognitive-glitch');
        });
        this.glitchedElements.clear();
    }

    restoreSanity() {
        // 瞬间释放强烈净化白光特写
        const flash = document.getElementById('sanity-flash-overlay');
        if (flash) {
            flash.classList.remove('flash-active');
            flash.offsetHeight; // 强制触发重绘
            flash.classList.add('flash-active');
            setTimeout(() => {
                flash.classList.remove('flash-active');
            }, 800);
        }

        // 播发清脆的苏醒唤灵声
        try {
            audio.playAwake();
        } catch (e) {}

        // 重置所有衰退值与滤镜
        this.decayValue = 0;
        this.lastActionTime = Date.now();
        this.applyFilters();
        this.restoreText();
    }

    stop() {
        this.isDecaying = false;
        if (this.timer) {
            clearInterval(this.timer);
            this.timer = null;
        }
        this.decayValue = 0;
        this.applyFilters();
        this.restoreText();
    }
}

/**
 * 📝 AIGC 情感羁绊：神经网络独白拼装生成器 (AIGCStoryTeller)
 * 实时提取玩家的清扫时间、是否温柔、Combo次数，为老物件生成感人肺腑、宛若真实的奶奶回应
 */
class AIGCStoryTeller {
    static async fetchAIStory(itemId, stats) {
        console.log("AIGCStoryTeller 正在分析您的操作轨迹向量并拼装 Prompt...", itemId, stats);
        
        // 拟真 AI 动态生成所使用的系统 Prompt
        const systemPrompt = `[系统Prompt]：你是一位患有老年痴呆症的慈祥老奶奶。孙辈刚刚为你擦亮重构了尘封的器物【${itemId}】。
        老人在这次交互中体现出的情感特质画像如下：
        - 擦拭时是否温柔耐心: ${stats.isGentle ? '极为温柔舒缓，符合长辈护理规范' : '动作有些仓促急切'}
        - 调频锁波谐振精度: ${stats.tunerPrecision ? stats.tunerPrecision + '%' : '默认精准'}
        - 缝纫踩踏时手脑突触连击数: ${stats.maxCombo ? stats.maxCombo + ' Combo' : '无'}
        请结合上述行为特征，生成一段不超过120字且极具共情力与文学美感的温馨奶奶回应独白。`;

        console.log("大模型接入 Prompt 发送成功: \n", systemPrompt);

        // 模拟网络请求延迟，体现 AI 流式分析过程，确保 Hackathon 现场即便没有外网也能极速渲染
        const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));
        await delay(1200);

        let simulatedResponse = "";
        
        if (itemId === 'radio') {
            if (stats.isGentle) {
                simulatedResponse = "好孩子，奶奶听见这出昆曲一唱啊，脑瓜子里黑乎乎的浓雾就全散了。你调表盘时真是心细如发，一下就拨准了。看你这温柔又耐心的劲儿，我就知道我大孙子在外面办事稳妥、不急不躁。这戏呀，当年还是你爷爷带我听的第一场戏呢……";
            } else {
                simulatedResponse = "好孩子，这咿咿呀呀的声音一响，奶奶的耳朵眼儿就清亮了。你刚才拨弄那个小铜表盘时是不是有点急呀？是不是工作太累了……孩子，别急，不管外面风雨再大，在这收音机小声响里，奶奶总能听见大孙子回家的脚步。";
            }
        } else if (itemId === 'camera') {
            simulatedResponse = "好孩子，这聚光镜一闪，照片一洗出来，奶奶的魂儿就飘回去了。你看，照片上的我们多俊俏。你找镜头的焦距找得那么认真，那么爱惜这张老相片。孩子，虽然奶奶的记忆像洗旧的宣纸，可你孝顺温顺的心思，就像这闪光灯一样，早就刻在我脑瓜深处了……";
        } else if (itemId === 'sewing') {
            const comboText = stats.maxCombo > 1 ? `你刚才踩那缝纫机踏板时的动静，欢快得像鸟儿叫，踩出了 ${stats.maxCombo} 下漂亮的突触连针，` : '';
            simulatedResponse = `好大儿，这红棉袄织得真暖和啊。${comboText}手脚这般利索，做事这般专注。奶奶看见这针脚，就想起你小时候总喜欢拽着我的衣角。看着你这一针一线织出来的棉袄，奶奶心里呀，热乎乎的，连这痴傻病都好了一半……`;
        } else if (itemId === 'lantern') {
            simulatedResponse = "好孩子，这马灯一亮，这小小的火苗被你托得平平稳稳的，没有一丝晃悠。奶奶知道，你是个有耐心的好孩子。这人老了，脑子里黑漆漆的一片，就盼着这点微弱的亮光。这灯火呀，把咱俩的手照得暖呼呼的，照亮了奶奶回家的路。";
        } else if (itemId === 'watch') {
            simulatedResponse = "好孩子，听见这滴答滴答的时钟声了吗？你拧那发条拧得那么沉稳，一下一下的，多有力气。哪怕时光像个破漏斗存不住水，奶奶把你的容貌名字全忘了，可这怀表的钟摆一响，我的心就踏实了。孩子，奶奶忘不了你，忘不了咱们一家人聚在发条钟下的那些好时光……";
        } else if (itemId === 'telephone') {
            simulatedResponse = "好孩子，这电话机一拼好，奶奶的心里那根断开的线好像一下子就被接通了。以前，不管外面雨下得多大，只要这铃声一响，听见你的声音，奶奶的头疼脑热就全好了。孩子，不管奶奶以后还能不能叫出你的名字，只要这电话铃一响，奶奶就知道是你……";
        } else if (itemId === 'musicbox') {
            simulatedResponse = "好孩子，这八音盒里叮叮咚咚的小曲子一响，奶奶的脑子就亮堂起来了。你刚才擦拭它的时候那么轻柔，像怕碰碎了奶奶的梦似的。听着这熟悉的曲调，奶奶就想起你小时候，奶奶抱着你，一边拍着你，一边听着这个音乐哄你睡觉的日子……";
        } else if (itemId === 'abacus') {
            simulatedResponse = "好孩子，听见这劈里啪啦的算盘珠子声了吗？你刚才把算珠一个个拨回原位，就像把奶奶脑子里乱成一团的账目，一条条理清了一样。你爷爷以前最会打算盘，每次看到你这么聪明能干、条理清晰，奶奶就像看见你爷爷年轻时一样骄傲……";
        } else if (itemId === 'television') {
            simulatedResponse = "好孩子，这电视机的雪花屏总算被你擦干净了。奶奶的脑子里，原本也都是这样沙沙响的雪花，是你用这双温暖的手，帮奶奶找回了当年咱们一家人围坐在小木凳上、吃着西瓜看电视的画面。孩子，谢谢你，让奶奶又看清了你的脸……";
        } else {
            simulatedResponse = "好孩子，看着你一点一点把这些尘封的记忆拼凑擦亮，奶奶心里真高兴。不管时间带走了什么，只要有你陪着，这回响就一直都在。";
        }

        return simulatedResponse;
    }
}

/**
 * 🎨 裂变海报生成器 (CanvasPosterGenerator)
 * 高分辨率离屏 HTML5 Canvas 重度渲染合成技术，产出可下载的时光胶囊海报
 */
class CanvasPosterGenerator {
    static async generate(blueprint, storyText, customMessage) {
        console.log("CanvasPosterGenerator 正在拉取素材并渲染高清卡片...", blueprint.title);
        
        // 🔑 GC 优化：清理上一次生成的 blob URL 防止内存泄漏
        if (CanvasPosterGenerator._lastBlobURL) {
            const URLObj = window.URL || window.webkitURL || window;
            URLObj.revokeObjectURL(CanvasPosterGenerator._lastBlobURL);
            CanvasPosterGenerator._lastBlobURL = null;
        }
        
        // 1. 创建高规格离屏 Canvas (1200 x 1800，确保保存到手机端极其清晰)
        const canvas = document.createElement('canvas');
        canvas.width = 1200;
        canvas.height = 1800;
        const ctx = canvas.getContext('2d');

        // 2. 绘制牛皮纸黄铜复古渐变背景
        const bgGrad = ctx.createLinearGradient(0, 0, 0, 1800);
        bgGrad.addColorStop(0, '#f2ead8');
        bgGrad.addColorStop(0.5, '#eae0cc');
        bgGrad.addColorStop(1, '#dfd4bc');
        ctx.fillStyle = bgGrad;
        ctx.fillRect(0, 0, 1200, 1800);

        // 注入高质感牛皮纸胶片杂色噪点
        ctx.fillStyle = 'rgba(0, 0, 0, 0.012)';
        for (let i = 0; i < 40000; i++) {
            const rx = Math.random() * 1200;
            const ry = Math.random() * 1800;
            ctx.fillRect(rx, ry, 1.5, 1.5);
        }

        // 绘制复古内外层金色与褐色双线框
        ctx.strokeStyle = '#8c765c';
        ctx.lineWidth = 4;
        ctx.strokeRect(40, 40, 1120, 1720);
        ctx.strokeStyle = 'rgba(140, 118, 92, 0.35)';
        ctx.lineWidth = 1;
        ctx.strokeRect(52, 52, 1096, 1696);

        // 3. 绘制报头文字
        ctx.fillStyle = '#6b5344';
        ctx.font = "bold 44px 'Noto Serif SC', Serif";
        ctx.textAlign = 'center';
        ctx.fillText("时 光 的 回 响", 600, 130);
        
        ctx.font = "26px 'Outfit', sans-serif";
        ctx.fillStyle = '#a38a75';
        ctx.fillText("M E M O R Y   W E A V E R", 600, 175);

        // 分割细虚线
        ctx.beginPath();
        ctx.moveTo(400, 210);
        ctx.lineTo(800, 210);
        ctx.strokeStyle = 'rgba(107, 83, 68, 0.25)';
        ctx.lineWidth = 2;
        ctx.stroke();

        // 4. 将苏醒物件的 SVG Segment 转化并绘制到 Canvas 画布中
        let completedSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200" width="400" height="400">`;
        // 背景同心圆刻度装饰
        completedSvg += `<circle cx="100" cy="100" r="85" fill="none" stroke="#6b5344" stroke-width="0.75" stroke-dasharray="3,3" opacity="0.3"/>`;
        completedSvg += `<circle cx="100" cy="100" r="95" fill="none" stroke="#6b5344" stroke-width="0.5" opacity="0.2"/>`;
        blueprint.parts.forEach(p => {
            completedSvg += p.svg;
        });
        completedSvg += `</svg>`;
        
        const svgBlob = new Blob([completedSvg], {type: 'image/svg+xml;charset=utf-8'});
        const URLObj = window.URL || window.webkitURL || window;
        const blobURL = URLObj.createObjectURL(svgBlob);
        CanvasPosterGenerator._lastBlobURL = blobURL; // 记录用于下次清理

        const img = new Image();
        img.src = blobURL;

        await new Promise((resolve) => {
            img.onload = () => {
                // 绘制极具艺术感的白色胶片垫背相框
                ctx.fillStyle = 'rgba(255, 255, 255, 0.65)';
                ctx.fillRect(320, 260, 560, 560);
                ctx.strokeStyle = 'rgba(107, 83, 68, 0.4)';
                ctx.lineWidth = 2;
                ctx.strokeRect(320, 260, 560, 560);
                
                // 将转化的图片完美的压制进相框
                ctx.drawImage(img, 360, 300, 480, 480);
                URLObj.revokeObjectURL(blobURL);
                resolve();
            };
            img.onerror = () => {
                ctx.fillStyle = '#6b5344';
                ctx.font = "bold 38px 'Noto Serif SC', Serif";
                ctx.fillText(`✨ 《${blueprint.title}》已苏醒 ✨`, 600, 540);
                resolve();
            };
        });

        // 5. 写入大物件名称
        ctx.fillStyle = '#4a3225';
        ctx.font = "bold 52px 'Noto Serif SC', Serif";
        ctx.fillText(`《${blueprint.title}》`, 600, 900);

        // 6. 绘制 AI 奶奶的情感独白 (支持完美的中文折行折返渲染)
        ctx.font = "34px 'Noto Serif SC', Serif";
        ctx.fillStyle = '#6b5344';
        ctx.textAlign = 'left';
        
        const wrapText = (text, x, y, maxWidth, lineHeight) => {
            const words = text.split('');
            let line = '';
            for (let n = 0; n < words.length; n++) {
                let testLine = line + words[n];
                let metrics = ctx.measureText(testLine);
                let testWidth = metrics.width;
                if (testWidth > maxWidth && n > 0) {
                    ctx.fillText(line, x, y);
                    line = words[n];
                    y += lineHeight;
                } else {
                    line = testLine;
                }
            }
            ctx.fillText(line, x, y);
            return y + lineHeight;
        };

        ctx.font = "italic 32px 'Noto Serif SC', Serif";
        ctx.fillStyle = 'rgba(107, 83, 68, 0.6)';
        ctx.fillText("“ 奶奶的独白：", 160, 985);

        ctx.font = "34px 'Noto Serif SC', Serif";
        ctx.fillStyle = '#5c3e30';
        let currentY = wrapText(storyText, 160, 1045, 880, 55);

        ctx.font = "italic 32px 'Noto Serif SC', Serif";
        ctx.fillStyle = 'rgba(107, 83, 68, 0.6)';
        ctx.fillText("”", 1010, currentY - 15);

        // 细线条横向区隔
        currentY += 40;
        ctx.beginPath();
        ctx.moveTo(250, currentY);
        ctx.lineTo(950, currentY);
        ctx.strokeStyle = 'rgba(107, 83, 68, 0.15)';
        ctx.lineWidth = 1.5;
        ctx.stroke();

        // 7. 写入玩家自定义时空寄语
        currentY += 80;
        ctx.fillStyle = '#d48a85'; // 玫瑰红
        ctx.font = "bold 34px 'Noto Serif SC', Serif";
        ctx.fillText("💌 岁月的时空回响寄语：", 160, currentY);

        currentY += 60;
        ctx.fillStyle = '#4a3225';
        ctx.font = "36px 'Noto Serif SC', Serif";
        const messageText = String(customMessage || '').trim().slice(0, 120) || "亲爱的长辈，祝您岁岁平安，记忆常青...";
        currentY = wrapText(messageText, 160, currentY, 880, 55);

        // 压盖红色泥塑“记忆守护”印章
        const sealX = 1000;
        const sealY = currentY - 60;
        ctx.beginPath();
        ctx.arc(sealX, sealY, 55, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(163, 38, 38, 0.76)';
        ctx.fill();
        ctx.lineWidth = 3;
        ctx.strokeStyle = 'rgba(130, 20, 20, 0.9)';
        ctx.stroke();
        
        ctx.fillStyle = '#ffffff';
        ctx.font = "bold 26px 'Noto Serif SC', Serif";
        ctx.textAlign = 'center';
        ctx.fillText("记忆", sealX, sealY - 10);
        ctx.fillText("守护", sealX, sealY + 25);

        // 8. 绘制底部公益小红花
        const flowerX = 220;
        const flowerY = 1620;
        ctx.fillStyle = '#ff4d4f';
        for (let i = 0; i < 5; i++) {
            const angle = (i * 2 * Math.PI) / 5;
            const px = flowerX + Math.cos(angle) * 32;
            const py = flowerY + Math.sin(angle) * 32;
            ctx.beginPath();
            ctx.arc(px, py, 26, 0, Math.PI * 2);
            ctx.fill();
        }
        ctx.beginPath();
        ctx.arc(flowerX, flowerY, 18, 0, Math.PI * 2);
        ctx.fillStyle = '#ffec3d';
        ctx.fill();

        ctx.textAlign = 'left';
        ctx.fillStyle = '#6b5344';
        ctx.font = "bold 34px 'Noto Serif SC', Serif";
        ctx.fillText("腾讯公益 · 小红花游戏", flowerX + 75, 1605);
        ctx.font = "24px 'Outfit', sans-serif";
        ctx.fillStyle = 'rgba(107, 83, 68, 0.65)';
        ctx.fillText("用爱与科技，守护千万阿尔茨海默家庭", flowerX + 75, 1648);

        // 绘制微缩二维码
        const qrX = 920;
        const qrY = 1530;
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(qrX, qrY, 160, 160);
        ctx.lineWidth = 2;
        ctx.strokeStyle = '#8c765c';
        ctx.strokeRect(qrX, qrY, 160, 160);
        
        ctx.fillStyle = '#6b5344';
        for (let ix = 4; ix < 156; ix += 8) {
            for (let iy = 4; iy < 156; iy += 8) {
                if ((ix < 40 && iy < 40) || (ix > 116 && iy < 40) || (ix < 40 && iy > 116)) {
                    ctx.fillRect(qrX + ix, qrY + iy, 8, 8);
                } else if (Math.random() < 0.46) {
                    ctx.fillRect(qrX + ix, qrY + iy, 8, 8);
                }
            }
        }
        
        ctx.fillStyle = 'rgba(107, 83, 68, 0.65)';
        ctx.font = "18px 'Noto Serif SC', Serif";
        ctx.textAlign = 'center';
        ctx.fillText("微信扫码关注关怀计划", qrX + 80, qrY + 195);

        // 9. 转录并输出 dataURL
        return canvas.toDataURL('image/png');
    }
}

// ============================================================================
// 1.8. GLOBAL MODULE INSTANTIATIONS (Safe after class declarations)
// ============================================================================
const micBlower = new MicBlowerAPI();
const cognitiveDecay = new CognitiveDecayManager();

// Track any player user action to combat cognitive sensory loss
window.addEventListener('pointerdown', () => {
    cognitiveDecay.recordAction();
});
window.addEventListener('keydown', () => {
    cognitiveDecay.recordAction();
});

// ============================================================================
// 2. ITEM VECTOR BLUEPRINTS (INLINE SVG DEFINITIONS)
// ============================================================================
// Defining extremely beautiful vintage SVG designs directly in JS to prevent image loading failures
// and enable clean layered sub-component dragging!
const itemBlueprints = {
    radio: {
        title: "老式收音机",
        desc: "吱呀吱呀的声音里，藏着那年秋天桂花的香气。",
        choices: [
            { id: "radio_folk", text: "📻 调频到 98.7MHz 唤醒：民谣《送别》与陈年往事", category: "青春与爱情" },
            { id: "radio_news", text: "📢 调频到 102.4MHz 唤醒：1978年金秋的广播新闻", category: "时代巨变" },
            { id: "radio_opera", text: "📻 调频到 93.5MHz 唤醒：经典昆曲《牡丹亭》与童年摇篮曲", category: "童年与母爱" }
        ],
        stories: {
            radio_folk: "收音机发出沙沙的底噪，随后，悠扬的吉他和口琴声缓缓流淌出来。奶奶的双眼突然明亮起来，嘴角浮现出一抹久违的少女般微笑：\n\n“那是1982年的深秋，天上正飘着桂花香。你爷爷为了给我买这台双音轨收音机，省吃俭用了三个月……我们坐在小河边的石阶上，吹着风，听着这首《送别》。他说，人这一辈子，总要有些声音是忘不掉的。”\n\n这一刻，时光仿佛在这间阁楼里逆流，桂花的香气和少年的歌声重新在空气中弥漫开来。",
            radio_news: "收音机粗粝的声音在屋中回荡：“中央广播电台，现在播送重要新闻……”\n\n奶奶的双手微微颤抖，泪水在眼眶里打转。她轻抚着粗糙的收音机外壳，喃喃自语：\n\n“就是这一天……那天大喇叭里广播了恢复高考的消息。当时你爸爸正在地里干活，听到这个广播，他扔下锄头就往家里跑，抱着我哭。这块铁疙瘩，不仅带给了我们外面的世界，更让我们一家人看到了希望。原来，日子是真的能变好的……”",
            radio_opera: "收音机里传出沙沙的电波声，随后，婉转悠扬的昆曲唱腔飘落下来：“原来姹紫嫣红开遍，似这般都付与断井颓垣……”\n\n奶奶的嘴唇轻轻颤动着，跟着旋律轻声哼唱起来。她那布满皱纹的双眼眯成了一弯月牙，盛满了道不尽的温柔：\n\n“我小的时候，我母亲总是在夏天的傍晚，摇着大蒲扇，在月光下的院子里给我唱《牡丹亭》……后来我有了你爸爸，蚊子多的夜里，我也给他摇着蒲扇唱这出戏。这声音啊，像是一直在脑子里扎着根。只要它一响，我就觉得自己又躺在母亲的膝头，凉快得很，什么忧心事都没有了……”"
        },
        // Detailed SVG paths for all individual components (width: 200, height: 200)
        parts: [
            {
                id: "radio_shell",
                name: "木质外壳",
                targetX: 10, targetY: 20, w: 180, h: 150,
                hint: "温热粗粝的杉木外壳，沉静而安详，那是旧日时光的优雅底色。",
                svg: `<rect x="10" y="20" width="180" height="150" rx="15" fill="#5c3a21" stroke="#e5a93b" stroke-width="2"/>
                      <rect x="20" y="30" width="160" height="130" rx="10" fill="#3e2513" opacity="0.8"/>`
            },
            {
                id: "radio_speaker",
                name: "喇叭网罩",
                targetX: 25, targetY: 45, w: 150, h: 75,
                hint: "暗金色的防尘网罩，层层叠叠，过滤出无数个清晨温暖的歌声。",
                svg: `<rect x="25" y="45" width="150" height="75" rx="5" fill="#b0916d" stroke="#e5a93b" stroke-width="1.5"/>
                      <line x1="25" y1="60" x2="175" y2="60" stroke="#8c6a46" stroke-width="1" stroke-dasharray="2,2"/>
                      <line x1="25" y1="75" x2="175" y2="75" stroke="#8c6a46" stroke-width="1" stroke-dasharray="2,2"/>
                      <line x1="25" y1="90" x2="175" y2="90" stroke="#8c6a46" stroke-width="1" stroke-dasharray="2,2"/>
                      <line x1="25" y1="105" x2="175" y2="105" stroke="#8c6a46" stroke-width="1" stroke-dasharray="2,2"/>`
            },
            {
                id: "radio_dial",
                name: "调频表盘",
                targetX: 35, targetY: 132, w: 90, h: 28,
                hint: "红色的刻度指针，悄悄搜寻着那些漂浮在虚空中、已经消逝的微波频段。",
                svg: `<rect x="35" y="132" width="90" height="28" fill="#1f1810" stroke="#e5a93b" stroke-width="1.5"/>
                      <line x1="45" y1="146" x2="115" y2="146" stroke="#c2b6ab" stroke-width="1"/>
                      <line x1="80" y1="135" x2="80" y2="155" stroke="#d48a85" stroke-width="2"/> <!-- Pointer -->
                      <circle cx="45" cy="146" r="2" fill="#e5a93b"/>
                      <circle cx="115" cy="146" r="2" fill="#e5a93b"/>`
            },
            {
                id: "radio_knobs",
                name: "金属旋钮",
                targetX: 138, targetY: 132, w: 44, h: 28,
                hint: "黄铜旋钮轻轻转动，拂去岁月的沙沙杂音，那段思念的旋律近在咫尺。",
                svg: `<g>
                        <circle cx="148" cy="146" r="11" fill="#c2b6ab" stroke="#e5a93b" stroke-width="1"/>
                        <circle cx="148" cy="146" r="8" fill="#2a2420"/>
                        <line x1="148" y1="138" x2="148" y2="146" stroke="#e5a93b" stroke-width="2"/>
                      </g>
                      <g>
                        <circle cx="172" cy="146" r="8" fill="#c2b6ab" stroke="#e5a93b" stroke-width="1"/>
                        <circle cx="172" cy="146" r="5" fill="#2a2420"/>
                        <line x1="172" y1="141" x2="172" y2="146" stroke="#e5a93b" stroke-width="1.5"/>
                      </g>`
            }
        ]
    },
    camera: {
        title: "复古照相机",
        desc: "按下快门的那一瞬，青春的笑脸被定格为永恒。",
        choices: [
            { id: "camera_outing", text: "📸 唤醒胶片记忆：1985年春天的那次全家福野餐", category: "家庭温馨" },
            { id: "camera_studio", text: "🏬 唤醒奋斗记忆：红星老照相馆里的青春岁月", category: "青春奋斗" }
        ],
        stories: {
            camera_outing: "老旧的相机快门发出“咔嚓”一声干脆的声音。奶奶的视线落在一张泛黄的老照片上，仿佛重新置身于那片开满野花的油菜花田里：\n\n“那年春天，你爸爸刚学会走路。我们借了这台相机，带他去公园野餐。风一吹，花瓣飘了一身。我们对着镜头笑，快门按下的瞬间，你爷爷脚一滑歪了身子。你看，这张照片上我们三个人都在笑，虽然有点糊，但那是我们最年轻、最幸福的一天……”\n\n照片里静止的春天，在这一刻随着快门声，在奶奶干涸的记忆之井里重新泛起了涟漪。",
            camera_studio: "指尖摩挲着斑驳的快门按键，奶奶的眼神仿佛穿透了时光，回到了那间挂满红布背景的老式照相馆：\n\n“这是我进照相馆当学徒时买的第一台海鸥牌相机。那时候没有数码，每一张底片都珍贵得不得了。红星照相馆里总是弥漫着药水的味道。那会儿啊，结婚的小两口、当兵的小伙子、满月的婴孩，都坐在我的镜头前。每次按下快门，我感觉自己不仅仅是拍照片，更是在帮人们锁住一辈子的幸福。一晃，竟然这么多年了……”"
        },
        parts: [
            {
                id: "camera_body",
                name: "相机机身",
                targetX: 15, targetY: 50, w: 170, h: 110,
                hint: "斑驳沧桑的金属与蒙皮机身，沉甸甸的，默默承载并珍藏着一整个家庭的故事。",
                svg: `<rect x="15" y="50" width="170" height="110" rx="8" fill="#2a2420" stroke="#c2b6ab" stroke-width="2"/>
                      <rect x="15" y="50" width="170" height="35" rx="3" fill="#c2b6ab"/>
                      <rect x="55" y="32" width="90" height="18" fill="#c2b6ab" stroke="#8c8279" stroke-width="1"/>`
            },
            {
                id: "camera_lens",
                name: "光学镜头",
                targetX: 60, targetY: 65, w: 80, h: 80,
                hint: "剔透清亮的玻璃镜片，曾深情地凝视过那片金灿灿的油菜花田，和家人们朝气蓬勃的笑脸。",
                svg: `<circle cx="100" cy="105" r="40" fill="#12100e" stroke="#c2b6ab" stroke-width="3"/>
                      <circle cx="100" cy="105" r="32" fill="#1b2430" stroke="#e5a93b" stroke-width="1"/>
                      <circle cx="100" cy="105" r="24" fill="radial-gradient(circle, #3e587a, #0d121b)"/>
                      <!-- Glass Lens Reflection -->
                      <path d="M 88,88 A 20,20 0 0,1 112,88" fill="none" stroke="#ffffff" stroke-width="2.5" stroke-linecap="round" opacity="0.7"/>
                      <circle cx="108" cy="98" r="4" fill="#ffffff" opacity="0.8"/>`
            },
            {
                id: "camera_controls",
                name: "快门旋钮",
                targetX: 25, targetY: 20, w: 153, h: 15,
                hint: "清脆的“咔嚓”一声，如同一道时间锁扣，将漫天飞舞的春风与欢笑永久定格。",
                svg: `<rect x="25" y="25" width="22" height="8" fill="#c2b6ab" stroke="#8c8279" stroke-width="1"/>
                      <circle cx="150" cy="26" r="7" fill="#e5a93b"/>
                      <rect x="146" y="20" width="8" height="6" fill="#c2b6ab"/>
                      <circle cx="172" cy="27" r="6" fill="#c2b6ab"/>`
            },
            {
                id: "camera_strap",
                name: "皮质肩带",
                targetX: 5, targetY: 48, w: 190, h: 50,
                hint: "磨损断裂的红皮带，曾挂在爷爷宽厚坚实的肩头，踏遍千山万水去捕捉美好的瞬间。",
                svg: `<path d="M 5,90 Q 2,40 15,55" fill="none" stroke="#d48a85" stroke-width="6" stroke-linecap="round"/>
                      <path d="M 195,90 Q 198,40 185,55" fill="none" stroke="#d48a85" stroke-width="6" stroke-linecap="round"/>
                      <circle cx="15" cy="55" r="4" fill="#c2b6ab"/>
                      <circle cx="185" cy="55" r="4" fill="#c2b6ab"/>`
            }
        ]
    },
    sewing: {
        title: "足踏缝纫机",
        desc: "密密麻麻的针脚里，织进了一辈子的温柔与叮咛。",
        choices: [
            { id: "sewing_jacket", text: "🧥 缝补往昔温暖：那件亲手缝制的红棉袄", category: "母爱与传承" },
            { id: "sewing_midnight", text: "🕯 编织深夜梦想：缝纫机转动时的温暖灯火", category: "艰辛与坚韧" }
        ],
        stories: {
            sewing_jacket: "缝纫机针头“哒哒哒”轻快走线的声音，宛如旧日的晨曲。奶奶轻轻抚摸着老木桌上的磨损刻痕，语气里是道不尽的柔情：\n\n“你爸爸小时候怕冷，每到十月，我就翻出家里的碎棉花，在缝纫机前赶工。这缝纫机吃厚，我一脚一脚地踩着踏板，哒哒哒，哒哒哒，灯光把影子拉得长长的。赶了两个通宵，缝出一件大红色的棉袄。你爸爸穿上它，活像个红苹果，笑得嘴都合不拢。看着他在雪地里跑来跑去的样子，我踩着踏板的脚啊，一点都不酸了……”\n\n针线穿过的，不止是一件冬衣，更是拉扯两代人长大的绵长深情。",
            sewing_midnight: "缝纫机的皮带轮发出呼呼的摩擦声。奶奶闭上眼，仿佛回到了那个充满柴米油盐却闪着光的清贫年代：\n\n“那个时候，家里的床单、被罩、你们的校服、裤腿的补丁，全靠这台大铁疙瘩。白天要上班，只有夜深人静了，才能点起一盏煤油灯，在缝纫机旁缝缝补补。踩水车一样的踏板声，陪伴了我无数个漫长黑夜。邻居们都笑称我是‘深夜裁缝’。苦是真的苦，但看着这台缝纫机走过的一针一线，把破烂的生活缝补得结实漂亮，我就觉得一切奔波都有了底气。”"
        },
        parts: [
            {
                id: "sewing_arm",
                name: "铸铁机身主臂",
                targetX: 20, targetY: 30, w: 165, h: 97,
                hint: "沉重古雅的黑铁主臂，曾掠过无数经纬红线，把破损斑驳的生活缝合得牢固而漂亮。",
                svg: `<path d="M 25,120 L 40,65 Q 50,30 90,30 L 165,30 Q 185,30 185,55 L 180,120 Z" fill="#12100e" stroke="#e5a93b" stroke-width="1.5"/>
                      <rect x="25" y="115" width="160" height="12" rx="3" fill="#e5a93b"/>
                      <path d="M 90,45 L 155,45" stroke="#e5a93b" stroke-width="1.5" stroke-dasharray="4,2"/>`
            },
            {
                id: "sewing_wheel",
                name: "惯性皮带轮",
                targetX: 140, targetY: 50, w: 56, h: 56,
                hint: "飞轮呼呼转动，带起长长的皮带，驱动着那些陪伴了奶奶一辈子的深夜歌谣。",
                svg: `<circle cx="168" cy="78" r="28" fill="#12100e" stroke="#e5a93b" stroke-width="2"/>
                      <circle cx="168" cy="78" r="22" fill="none" stroke="#c2b6ab" stroke-width="1" stroke-dasharray="8,4"/>
                      <circle cx="168" cy="78" r="8" fill="#e5a93b"/>
                      <!-- Spokes -->
                      <line x1="168" y1="50" x2="168" y2="106" stroke="#e5a93b" stroke-width="2"/>
                      <line x1="140" y1="78" x2="196" y2="78" stroke="#e5a93b" stroke-width="2"/>`
            },
            {
                id: "sewing_plate",
                name: "压脚与针头",
                targetX: 18, targetY: 72, w: 24, h: 53,
                hint: "缝针像冬日早晨跳跃的云雀，在哒哒哒的节奏中织进叮咛，守护游子衣履安稳。",
                svg: `<rect x="28" y="80" width="18" height="40" fill="#c2b6ab" stroke="#8c8279"/>
                      <line x1="37" y1="72" x2="37" y2="125" stroke="#ffffff" stroke-width="2.5"/> <!-- Needle -->
                      <path d="M 32,125 L 42,125 L 42,120" fill="none" stroke="#ffffff" stroke-width="2"/> <!-- Presser Foot -->
                      <circle cx="37" cy="88" r="3" fill="#e5a93b"/>`
            },
            {
                id: "sewing_spool",
                name: "木质线轴",
                targetX: 108, targetY: 8, w: 29, h: 20,
                hint: "红色的线圈缠了一层又一层，牵引着剪不断的悠长深情，延绵进回忆的最深处。",
                svg: `<rect x="115" y="14" width="22" height="18" fill="#d48a85" rx="2" stroke="#e5a93b" stroke-width="1"/>
                      <line x1="126" y1="8" x2="126" y2="28" stroke="#c2b6ab" stroke-width="2"/>
                      <!-- Red wound thread lines -->
                      <line x1="117" y1="17" x2="135" y2="17" stroke="#ffffff" stroke-width="1" opacity="0.6"/>
                      <line x1="117" y1="20" x2="135" y2="20" stroke="#ffffff" stroke-width="1" opacity="0.6"/>
                      <line x1="117" y1="23" x2="135" y2="23" stroke="#ffffff" stroke-width="1" opacity="0.6"/>`
            }
        ]
    },
    lantern: {
        title: "煤油马灯",
        desc: "微弱温热的火苗里，照亮了风雨泥泞中的期盼与坚守。",
        choices: [
            { id: "lantern_reading", text: "🕯 唤醒寒窗记忆：马灯下的挑灯夜读与金榜题名", category: "奋斗与期盼" },
            { id: "lantern_waiting", text: "👣 唤醒守候记忆：漫水桥头的提灯等候与深夜接归", category: "相濡以沫" }
        ],
        stories: {
            lantern_reading: "马灯的防风罩上映出一圈温润的橙红色火苗。奶奶布满深壑的手掌仿佛又摸到了那截温热的玻璃，回忆里充满了油墨和煤油香气：\n\n“那时候你爸爸要参加高考，家里穷，供不起电。夜里九点一断电，他就趴在土炕上，点起这盏煤油马灯，一个字一个字地背书。马灯火小，烟大，熏得他鼻孔里全是黑灰。我坐在一旁，用蒲扇帮他赶蚊子，时不时帮他挑一挑灯芯。那一年的冬天真冷啊，但这盏马灯，却照亮了我们一家人走出的第一条路。他拿到录取通知书那天，抱着这盏马灯笑了好久好久……”\n\n那簇燃烧的火苗，曾把最黑暗的寒夜，烤得如春天般温暖明亮。",
            lantern_waiting: "轻轻拧动煤油灯的黄铜调节阀，一缕微光重新照亮了阁楼的角落。奶奶擦了擦眼角的泪花，浅浅笑着：\n\n“有一年秋天连续下了三天暴雨，村头的小桥被淹了。你爷爷深夜下班骑车回来，路上连个手电都没有。我急得坐立难安，提着这盏煤油马灯，打着油纸伞跑到漫水桥头去等他。雨太大了，风把伞都吹飞了，我双手死死护着这盏马灯，生怕风雨把它吹灭。不知道等了多久，终于看见泥泞里有一晃一晃的车灯。你爷爷一看见这马灯的红光，就在雨里大喊：‘媳妇！我看着灯了！我这就过桥！’那光虽然小，但只要它亮着，回家的路就永远丢不了。”"
        },
        parts: [
            {
                id: "lantern_base",
                name: "马灯底座",
                targetX: 45, targetY: 135, w: 110, h: 45,
                hint: "沉重结实的铁铸底座，曾盛满清亮的煤油，点燃了长达数十载的寒窗冷暖。",
                svg: `<ellipse cx="100" cy="155" rx="55" ry="20" fill="#3e503c" stroke="#e5a93b" stroke-width="2"/>
                      <rect x="70" y="135" width="60" height="20" fill="#2d3b2b" stroke="#e5a93b" stroke-width="1.5"/>`
            },
            {
                id: "lantern_glass",
                name: "防风玻璃罩",
                targetX: 62, targetY: 55, w: 76, h: 80,
                hint: "玲珑剔透的防风玻璃罩，小心呵护着中心那一簇橘红色的火苗，任风雨不灭。",
                svg: `<path d="M 70,135 Q 55,95 72,55 L 128,55 Q 145,95 130,135 Z" fill="rgba(200, 220, 255, 0.15)" stroke="#c2b6ab" stroke-width="1.5"/>
                      <!-- Glowing Flame inside Glass -->
                      <path d="M 100,80 Q 90,115 100,128 Q 110,115 100,80" fill="#ff7f50" filter="drop-shadow(0 0 10px #ff4500)" opacity="0.9"/>
                      <path d="M 100,95 Q 95,115 100,123 Q 105,115 100,95" fill="#ffd700" filter="drop-shadow(0 0 5px #ffd700)" opacity="0.9"/>`
            },
            {
                id: "lantern_cage",
                name: "防护网罩",
                targetX: 52, targetY: 55, w: 96, h: 80,
                hint: "纵横交错的防护钢丝网，像一双有力的大手，小心包裹并保护着脆弱的温度与微光。",
                svg: `<path d="M 68,55 L 55,135" fill="none" stroke="#e5a93b" stroke-width="2"/>
                      <path d="M 132,55 L 145,135" fill="none" stroke="#e5a93b" stroke-width="2"/>
                      <path d="M 68,55 C 80,75 120,75 132,55" fill="none" stroke="#e5a93b" stroke-width="1.5"/>
                      <path d="M 60,95 C 75,115 125,115 140,95" fill="none" stroke="#e5a93b" stroke-width="1.5"/>`
            },
            {
                id: "lantern_burner",
                name: "调节阀顶盖",
                targetX: 65, targetY: 42, w: 70, h: 13,
                hint: "黄铜阀门和顶盖，轻轻拧动灯芯就能升起一室光明，散去深夜的清冷。",
                svg: `<rect x="65" y="42" width="70" height="13" rx="3" fill="#c2b6ab" stroke="#e5a93b" stroke-width="1.5"/>`
            },
            {
                id: "lantern_handle",
                name: "提手铁挽手",
                targetX: 30, targetY: 5, w: 140, h: 60,
                hint: "半圆形的弯曲铁提手，曾被母亲温热的双手紧紧手提，提着照亮无数泥泞小路。",
                svg: `<path d="M 45,65 Q 40,5 100,5 Q 160,5 155,65" fill="none" stroke="#c2b6ab" stroke-width="3" stroke-linecap="round"/>`
            }
        ]
    },
    watch: {
        title: "时光怀表",
        desc: "表盘指针的走动中，镌刻着岁月的步伐与无声的陪伴。",
        choices: [
            { id: "watch_tick", text: "🕰 唤醒流转时光：听怀表滴答声寻回往日记忆", category: "永恒守候" },
            { id: "watch_family", text: "🤝 唤醒离别记忆：表背相片里的执手相看与深深期盼", category: "深情寄托" }
        ],
        stories: {
            watch_tick: "拧紧发条后，怀表发出了细密、有节奏的“滴答、滴答”声。奶奶轻轻闭上眼睛，仿佛又摸到了那截泛起油光的黑牛皮挂绳：\n\n“这是当年你爷爷在矿山得劳动模范发下的怀表，他当宝贝一样揣在兜里，走哪带哪。后来他走不动了，躺在床上，就喜欢抓着这只怀表听它的声音。他说：‘老伴啊，你听，这滴答声就像我的心跳。只要这表还走，我就一直陪着你。’如今表还在走，爷爷却已经走了……但这滴答的声音啊，一响起来，我就觉得他还坐在我身边，暖和地看着我。”\n\n那一下下富有韵律的声响，穿透了重重的岁月与遗忘，织成了一曲超越生死的相伴之歌。",
            watch_family: "轻轻合上怀表的黄铜表盖，表背那一小块被摩挲得发亮的地方，曾嵌着一张极小的双人合照。奶奶的嘴角满是怀念与释然：\n\n“当年爷爷要去远方修水坝，一去就是大半年。临行前，他把这只表塞进我手心里，表壳背面塞了我们结婚时的合影。他说，想他了就看看表背。那几百个夜里，每当我听到大风刮过窗子，心里发慌，就把它贴在胸口，听着发条均匀的走动，看着照片里他那坚毅的笑脸，心里就踏实了。这怀表，是我们一辈子的挂念，也是我风雨半生的主心骨。”"
        },
        parts: [
            {
                id: "watch_shell",
                name: "黄铜雕花外壳",
                targetX: 25, targetY: 25, w: 150, h: 150,
                hint: "雕刻着复古花纹的厚实黄铜外表壳，牢牢守护着流淌在时光中的温度。",
                svg: `<circle cx="100" cy="100" r="70" fill="#8c6a46" stroke="#e5a93b" stroke-width="3.5"/>
                      <circle cx="100" cy="100" r="62" fill="#5c3a21" stroke="#e5a93b" stroke-width="1.5" stroke-dasharray="3,3"/>
                      <rect x="94" y="10" width="12" height="20" fill="#e5a93b" rx="2" stroke="#8c6a46" stroke-width="1"/>
                      <circle cx="100" cy="15" r="10" fill="none" stroke="#e5a93b" stroke-width="3"/>`
            },
            {
                id: "watch_gears",
                name: "精密摆轮齿轮",
                targetX: 45, targetY: 45, w: 110, h: 110,
                hint: "层层咬合的黄铜齿轮与金色游丝，一秒一秒咬合出对家的牵挂与守护。",
                svg: `<g>
                        <circle cx="85" cy="95" r="28" fill="none" stroke="#e5a93b" stroke-width="2.5" stroke-dasharray="6,4"/>
                        <circle cx="85" cy="95" r="14" fill="none" stroke="#c2b6ab" stroke-width="1.5"/>
                        <line x1="85" y1="67" x2="85" y2="123" stroke="#e5a93b" stroke-width="1"/>
                        <line x1="57" y1="95" x2="113" y2="95" stroke="#e5a93b" stroke-width="1"/>
                      </g>
                      <g>
                        <circle cx="115" cy="108" r="18" fill="none" stroke="#d48a85" stroke-width="2" stroke-dasharray="4,3"/>
                        <circle cx="115" cy="108" r="8" fill="none" stroke="#c2b6ab" stroke-width="1"/>
                      </g>`
            },
            {
                id: "watch_dial",
                name: "珐琅对时表盘",
                targetX: 38, targetY: 38, w: 124, h: 124,
                hint: "温润的白珐琅表盘，古朴的罗马刻度，静静记录着爷爷每天准时归家的幸福刻度。",
                svg: `<circle cx="100" cy="100" r="54" fill="#ece3d5" stroke="#e5a93b" stroke-width="2"/>
                      <circle cx="100" cy="100" r="48" fill="none" stroke="#8c6a46" stroke-width="1" stroke-dasharray="1,6"/>
                      <text x="94" y="62" font-size="8" font-family="Georgia" fill="#5c3a21" font-weight="bold">XII</text>
                      <text x="136" y="103" font-size="8" font-family="Georgia" fill="#5c3a21" font-weight="bold">III</text>
                      <text x="97" y="144" font-size="8" font-family="Georgia" fill="#5c3a21" font-weight="bold">VI</text>
                      <text x="59" y="103" font-size="8" font-family="Georgia" fill="#5c3a21" font-weight="bold">IX</text>`
            },
            {
                id: "watch_hands",
                name: "古典蓝钢时光指针",
                targetX: 60, targetY: 60, w: 80, h: 80,
                hint: "精钢蓝指针永恒地指在早上 8:05，那是记忆中爷爷背上行囊、踏上修坝远行之路前的深情对视时刻。",
                svg: `<g>
                        <line x1="100" y1="100" x2="80" y2="90" stroke="#12100e" stroke-width="2.5" stroke-linecap="round"/>
                        <circle cx="80" cy="90" r="2.5" fill="#12100e"/>
                        <line x1="100" y1="100" x2="115" y2="74" stroke="#d48a85" stroke-width="1.8" stroke-linecap="round"/>
                        <circle cx="115" cy="74" r="1.5" fill="#d48a85"/>
                        <circle cx="100" cy="100" r="4" fill="#e5a93b"/>
                        <circle cx="100" cy="100" r="1.5" fill="#12100e"/>
                      </g>`
            }
        ]
    },

    // ============================================================
    // 6️⃣ 老式拨盘电话 - 失语症与认知断联隐喻
    // ============================================================
    telephone: {
        title: "老式拨盘电话",
        desc: "失语症的电路隐喻——拨通那根断开的记忆线路。",
        choices: [
            { id: "telephone_connect", text: "📞 接通断线：修复失联的语言神经回路", category: "语言重建" },
            { id: "telephone_ring", text: "🔔 等待响铃：聆听来自记忆深处的声音", category: "情感共鸣" }
        ],
        stories: {
            telephone_connect: "电话线重新连通的瞬间，沉默许久的声音终于穿透了那道无形的迷雾。奶奶颤抖着拿起听筒，泪水顺着眼角滑落：\n\n\u201C孩子……是你吗？奶奶……奶奶想了你好久好久了。这个电话号码，是奶奶这辈子记得最清楚的一串数字。不管忘了多少事，这几个数字，奶奶永远不会忘……\u201D\n\n那根细细的电话线，原来一直连着两颗心，从未真正断开过。",
            telephone_ring: "拨号盘缓缓转动，每一格都是一声呼唤。电话那头响起的铃声，穿越了漫长的岁月，将奶奶拉回到那个一家人守在电话机旁翘首期盼的温暖傍晚……"
        },
        parts: [
            {
                id: "telephone_body",
                name: "复古机身",
                targetX: 20, targetY: 40, w: 160, h: 130,
                hint: "沉甸甸的黑色胶木机身，握在手里有一种岁月沉淀的踏实感。",
                svg: `<rect x="20" y="40" width="160" height="130" rx="12" fill="#1a1a1a" stroke="#c2b6ab" stroke-width="2"/>
                      <rect x="30" y="50" width="140" height="110" rx="8" fill="#2a2420"/>`
            },
            {
                id: "telephone_dial",
                name: "旋转拨号盘",
                targetX: 40, targetY: 55, w: 100, h: 100,
                hint: "黑色圆盘上，十个数字孔像记忆的碎片，每拨一格都带着期待。",
                svg: `<circle cx="100" cy="105" r="50" fill="#12100e" stroke="#c2b6ab" stroke-width="2"/>
                      <circle cx="100" cy="105" r="42" fill="#1a1a1a" stroke="#8c8279" stroke-width="1"/>
                      <circle cx="100" cy="68" r="6" fill="none" stroke="#c2b6ab" stroke-width="1.5"/>
                      <circle cx="126" cy="80" r="6" fill="none" stroke="#c2b6ab" stroke-width="1.5"/>
                      <circle cx="137" cy="105" r="6" fill="none" stroke="#c2b6ab" stroke-width="1.5"/>
                      <circle cx="126" cy="130" r="6" fill="none" stroke="#c2b6ab" stroke-width="1.5"/>
                      <circle cx="100" cy="142" r="6" fill="none" stroke="#c2b6ab" stroke-width="1.5"/>
                      <circle cx="74" cy="130" r="6" fill="none" stroke="#c2b6ab" stroke-width="1.5"/>
                      <circle cx="63" cy="105" r="6" fill="none" stroke="#c2b6ab" stroke-width="1.5"/>
                      <circle cx="74" cy="80" r="6" fill="none" stroke="#c2b6ab" stroke-width="1.5"/>
                      <circle cx="100" cy="105" r="10" fill="#2a2420"/>`
            },
            {
                id: "telephone_receiver",
                name: "听筒",
                targetX: 25, targetY: 15, w: 150, h: 35,
                hint: "凑近耳边，那静电沙沙声里，是遥远岁月里熟悉的呼吸。",
                svg: `<path d="M 30,32 Q 100,18 170,32" fill="none" stroke="#1a1a1a" stroke-width="14" stroke-linecap="round"/>
                      <circle cx="35" cy="32" r="10" fill="#2a2420" stroke="#c2b6ab" stroke-width="1.5"/>
                      <circle cx="165" cy="32" r="10" fill="#2a2420" stroke="#c2b6ab" stroke-width="1.5"/>`
            },
            {
                id: "telephone_wire",
                name: "弹簧电话线",
                targetX: 5, targetY: 130, w: 30, h: 70,
                hint: "螺旋弹簧线，承载着那头传来的每一句叮咛与牵挂。",
                svg: `<path d="M 20,135 Q 10,145 20,155 Q 30,165 20,175 Q 10,185 20,195" fill="none" stroke="#8c6a46" stroke-width="2.5" stroke-linecap="round"/>`
            }
        ]
    },

    // ============================================================
    // 7️⃣ 木质八音盒 - 记忆碎片化隐喻
    // ============================================================
    musicbox: {
        title: "木质八音盒",
        desc: "碎片化的记忆旋律——补全失落的音符，让歌声重新完整。",
        choices: [
            { id: "musicbox_lullaby", text: "🎵 修复摇篮曲：拼接童年记忆中那首不完整的旋律", category: "童年温情" },
            { id: "musicbox_waltz", text: "💃 唤醒圆舞曲：八音盒奏响的那个春日午后", category: "青春往昔" }
        ],
        stories: {
            musicbox_lullaby: "八音盒的音筒缓缓转动，缺失的音符被一一填补，那首不完整的摇篮曲终于在时隔多年后，再次奏出了完整的旋律。奶奶闭上眼睛，嘴角浮现出一抹安详的微笑：\n\n\u201C这首歌……是你太奶奶哼给我听的。后来我哼给你爷爷，再后来……哼给你爸爸。孩子，音乐是不会消失的，它藏在心里最深的地方，等着我们想起它……\u201D\n\n有些旋律，不需要记忆，它们早已刻在灵魂里。",
            musicbox_waltz: "发条上紧的瞬间，清脆悦耳的圆舞曲从精巧的木匣中流淌而出，将整个房间都浸染在温柔的音符里……"
        },
        parts: [
            {
                id: "musicbox_case",
                name: "胡桃木外壳",
                targetX: 15, targetY: 30, w: 170, h: 130,
                hint: "温润的胡桃木纹理，散发着淡淡的木香，是匠人手作的温度。",
                svg: `<rect x="15" y="30" width="170" height="130" rx="10" fill="#6b3a1f" stroke="#e5a93b" stroke-width="2"/>
                      <rect x="25" y="40" width="150" height="110" rx="6" fill="#8b4d2a"/>
                      <line x1="15" y1="95" x2="185" y2="95" stroke="#5c3215" stroke-width="2"/>`
            },
            {
                id: "musicbox_cylinder",
                name: "金属音筒",
                targetX: 30, targetY: 50, w: 140, h: 50,
                hint: "布满精密凸点的金属滚筒，每一个凸点都是一个跳动的音符。",
                svg: `<ellipse cx="100" cy="75" rx="65" ry="20" fill="#c2b6ab" stroke="#8c8279" stroke-width="1.5"/>
                      <rect x="35" y="55" width="130" height="40" fill="#c2b6ab" stroke="#8c8279" stroke-width="1"/>
                      <ellipse cx="100" cy="95" rx="65" ry="20" fill="#a89c8f" stroke="#8c8279" stroke-width="1.5"/>
                      <circle cx="55" cy="75" r="3" fill="#5c3a21"/>
                      <circle cx="70" cy="68" r="3" fill="#5c3a21"/>
                      <circle cx="85" cy="80" r="3" fill="#5c3a21"/>
                      <circle cx="100" cy="65" r="3" fill="#5c3a21"/>
                      <circle cx="115" cy="78" r="3" fill="#5c3a21"/>
                      <circle cx="130" cy="70" r="3" fill="#5c3a21"/>
                      <circle cx="145" cy="82" r="3" fill="#5c3a21"/>`
            },
            {
                id: "musicbox_comb",
                name: "钢制发音梳",
                targetX: 20, targetY: 120, w: 160, h: 30,
                hint: "薄如蝉翼的钢齿，被音筒凸点拨动时，颤鸣出令人动容的旋律。",
                svg: `<rect x="20" y="125" width="160" height="8" fill="#8c8279"/>
                      <line x1="35" y1="133" x2="35" y2="155" stroke="#c2b6ab" stroke-width="3"/>
                      <line x1="50" y1="133" x2="50" y2="152" stroke="#c2b6ab" stroke-width="3"/>
                      <line x1="65" y1="133" x2="65" y2="150" stroke="#c2b6ab" stroke-width="3"/>
                      <line x1="80" y1="133" x2="80" y2="153" stroke="#c2b6ab" stroke-width="3"/>
                      <line x1="95" y1="133" x2="95" y2="149" stroke="#c2b6ab" stroke-width="3"/>
                      <line x1="110" y1="133" x2="110" y2="154" stroke="#c2b6ab" stroke-width="3"/>
                      <line x1="125" y1="133" x2="125" y2="151" stroke="#c2b6ab" stroke-width="3"/>
                      <line x1="140" y1="133" x2="140" y2="156" stroke="#c2b6ab" stroke-width="3"/>
                      <line x1="155" y1="133" x2="155" y2="148" stroke="#c2b6ab" stroke-width="3"/>`
            },
            {
                id: "musicbox_crank",
                name: "手摇曲柄",
                targetX: 155, targetY: 35, w: 40, h: 60,
                hint: "轻轻摇动曲柄，记忆的旋律便随之缓缓流淌。",
                svg: `<rect x="160" y="40" width="8" height="40" rx="4" fill="#c2b6ab" stroke="#8c8279"/>
                      <rect x="155" y="75" width="25" height="8" rx="4" fill="#c2b6ab" stroke="#8c8279"/>
                      <circle cx="178" cy="79" r="7" fill="#e5a93b" stroke="#8c6a46" stroke-width="1.5"/>`
            }
        ]
    },

    // ============================================================
    // 8️⃣ 古典算盘 - 计算障碍隐喻
    // ============================================================
    abacus: {
        title: "古典算盘",
        desc: "计算障碍的隐喻——拨动散乱的算珠，重建清晰的逻辑秩序。",
        choices: [
            { id: "abacus_calculate", text: "🔢 重建计算：帮奶奶理清那些混乱的账目记忆", category: "逻辑重建" },
            { id: "abacus_memory", text: "🧮 珠心算忆：那些奶奶曾用算盘教会我们的数字智慧", category: "知识传承" }
        ],
        stories: {
            abacus_calculate: "算珠在指尖归位的清脆声中，奶奶浑浊的眼神渐渐明亮起来。她的手指犹豫地触碰着算盘，随后，肌肉记忆接管了一切——手指开始灵活地拨动，那些曾经烂熟于心的口诀，从嘴里轻声漏出：\n\n\u201C三下五去二……二一添作五……孩子，奶奶教过你这个吗？这算盘啊，是奶奶用来养活你爸爸他们几兄弟的。每个月底对账，一颗算珠都不能差……\u201D\n\n有些技能，即便记忆消退，仍然留存在手指的记忆里。",
            abacus_memory: "清脆的算珠碰撞声，是奶奶这一生最熟悉的音乐，也是无数个清晨和深夜里，家庭记账本翻页的声音……"
        },
        parts: [
            {
                id: "abacus_frame",
                name: "红木边框",
                targetX: 10, targetY: 20, w: 180, h: 160,
                hint: "厚重的红木边框，散发着温润的木质香气，是几十年风雨的见证。",
                svg: `<rect x="10" y="20" width="180" height="160" rx="6" fill="#8b3a1f" stroke="#c2b6ab" stroke-width="3"/>
                      <rect x="20" y="30" width="160" height="140" rx="3" fill="#a04525"/>`
            },
            {
                id: "abacus_beam",
                name: "横梁",
                targetX: 10, targetY: 90, w: 180, h: 20,
                hint: "将算盘分为上下两区的横梁，上方一珠当五，下方五珠各一。",
                svg: `<rect x="10" y="95" width="180" height="10" fill="#c2a060" stroke="#8c6a46" stroke-width="1"/>`
            },
            {
                id: "abacus_beads",
                name: "算珠",
                targetX: 20, targetY: 30, w: 160, h: 140,
                hint: "象牙色的算珠，每一颗都承载着奶奶精打细算、操持家务的一生。",
                svg: `<line x1="40" y1="32" x2="40" y2="168" stroke="#5c3215" stroke-width="2"/>
                      <line x1="70" y1="32" x2="70" y2="168" stroke="#5c3215" stroke-width="2"/>
                      <line x1="100" y1="32" x2="100" y2="168" stroke="#5c3215" stroke-width="2"/>
                      <line x1="130" y1="32" x2="130" y2="168" stroke="#5c3215" stroke-width="2"/>
                      <line x1="160" y1="32" x2="160" y2="168" stroke="#5c3215" stroke-width="2"/>
                      <ellipse cx="40" cy="75" rx="13" ry="9" fill="#f0e6d0" stroke="#c2a060" stroke-width="1"/>
                      <ellipse cx="70" cy="70" rx="13" ry="9" fill="#f0e6d0" stroke="#c2a060" stroke-width="1"/>
                      <ellipse cx="100" cy="78" rx="13" ry="9" fill="#f0e6d0" stroke="#c2a060" stroke-width="1"/>
                      <ellipse cx="130" cy="72" rx="13" ry="9" fill="#f0e6d0" stroke="#c2a060" stroke-width="1"/>
                      <ellipse cx="160" cy="76" rx="13" ry="9" fill="#f0e6d0" stroke="#c2a060" stroke-width="1"/>
                      <ellipse cx="40" cy="120" rx="13" ry="9" fill="#f0e6d0" stroke="#c2a060" stroke-width="1"/>
                      <ellipse cx="40" cy="138" rx="13" ry="9" fill="#f0e6d0" stroke="#c2a060" stroke-width="1"/>
                      <ellipse cx="70" cy="122" rx="13" ry="9" fill="#f0e6d0" stroke="#c2a060" stroke-width="1"/>
                      <ellipse cx="70" cy="140" rx="13" ry="9" fill="#f0e6d0" stroke="#c2a060" stroke-width="1"/>
                      <ellipse cx="100" cy="118" rx="13" ry="9" fill="#f0e6d0" stroke="#c2a060" stroke-width="1"/>
                      <ellipse cx="100" cy="136" rx="13" ry="9" fill="#f0e6d0" stroke="#c2a060" stroke-width="1"/>
                      <ellipse cx="130" cy="124" rx="13" ry="9" fill="#f0e6d0" stroke="#c2a060" stroke-width="1"/>
                      <ellipse cx="130" cy="142" rx="13" ry="9" fill="#f0e6d0" stroke="#c2a060" stroke-width="1"/>
                      <ellipse cx="160" cy="120" rx="13" ry="9" fill="#f0e6d0" stroke="#c2a060" stroke-width="1"/>
                      <ellipse cx="160" cy="138" rx="13" ry="9" fill="#f0e6d0" stroke="#c2a060" stroke-width="1"/>`
            }
        ]
    },

    // ============================================================
    // 9️⃣ 黑白电视机 - 视觉失认与幻觉隐喻
    // ============================================================
    television: {
        title: "黑白电视机",
        desc: "视觉失认的隐喻——驱散屏幕上的白噪声，找回清晰的往昔影像。",
        choices: [
            { id: "television_drama", text: "📺 唤醒戏曲频道：那年除夕夜里全家人围坐的春晚记忆", category: "家庭温情" },
            { id: "television_news", text: "📰 唤醒新闻频道：那些改变时代的重要历史时刻", category: "时代记忆" }
        ],
        stories: {
            television_drama: "电视机的白噪声渐渐平息，画面从模糊到清晰，一个黑白的世界在老式显像管上重新显现。奶奶激动地往前倾了倾身子，颤颤巍巍地指着屏幕：\n\n\u201C这个！这个我记得！就是这个频道，那年大年三十，你爷爷把电视机搬到了院子里，全村的人都挤过来看……那时候整个村就我们家有一台电视，黑白的，还经常没信号，但大家都觉得新鲜极了……\u201D\n\n那道银灰色的光，穿越了几十年的时光隧道，照亮了奶奶心里那个最温暖的除夕夜。",
            television_news: "调台旋钮咔哒一声，屏幕上的雪花消散了，播音员字正腔圆的声音从老式喇叭里传来，将奶奶带回到那个充满激情与希望的年代……"
        },
        parts: [
            {
                id: "television_cabinet",
                name: "木质外壳",
                targetX: 10, targetY: 15, w: 180, h: 165,
                hint: "方正厚实的木纹外壳，是那个年代工业美学的代表，也是一家人共同记忆的容器。",
                svg: `<rect x="10" y="15" width="180" height="165" rx="8" fill="#6b4c2a" stroke="#c2b6ab" stroke-width="2"/>
                      <rect x="20" y="25" width="160" height="145" rx="5" fill="#7d5a35"/>`
            },
            {
                id: "television_screen",
                name: "显像管屏幕",
                targetX: 25, targetY: 25, w: 130, h: 110,
                hint: "圆润的显像管屏幕泛着幽幽蓝光，其中藏着无数个家庭共同凝视的珍贵瞬间。",
                svg: `<rect x="28" y="28" width="120" height="100" rx="12" fill="#0a0f1a" stroke="#2a3a5c" stroke-width="3"/>
                      <rect x="35" y="35" width="106" height="86" rx="8" fill="#050a12"/>
                      <line x1="35" y1="50" x2="141" y2="50" stroke="#1a2a40" stroke-width="1" opacity="0.5"/>
                      <line x1="35" y1="65" x2="141" y2="65" stroke="#1a2a40" stroke-width="1" opacity="0.5"/>
                      <line x1="35" y1="80" x2="141" y2="80" stroke="#1a2a40" stroke-width="1" opacity="0.5"/>
                      <line x1="35" y1="95" x2="141" y2="95" stroke="#1a2a40" stroke-width="1" opacity="0.5"/>
                      <line x1="35" y1="110" x2="141" y2="110" stroke="#1a2a40" stroke-width="1" opacity="0.5"/>
                      <circle cx="80" cy="78" r="20" fill="none" stroke="#1e3050" stroke-width="1" opacity="0.6"/>`
            },
            {
                id: "television_antenna",
                name: "双杆天线",
                targetX: 50, targetY: 0, w: 100, h: 30,
                hint: "金属天线微微倾斜，搜寻着远方传来的模糊信号，就像老人努力寻找的记忆。",
                svg: `<line x1="80" y1="25" x2="45" y2="5" stroke="#c2b6ab" stroke-width="3" stroke-linecap="round"/>
                      <line x1="80" y1="25" x2="120" y2="5" stroke="#c2b6ab" stroke-width="3" stroke-linecap="round"/>
                      <circle cx="80" cy="25" r="4" fill="#8c8279"/>`
            },
            {
                id: "television_knob",
                name: "换台旋钮",
                targetX: 155, targetY: 50, w: 35, h: 80,
                hint: "咔哒一声，频道切换，每个台都是一段不同的人生记忆。",
                svg: `<circle cx="167" cy="75" r="14" fill="#2a2420" stroke="#c2b6ab" stroke-width="1.5"/>
                      <circle cx="167" cy="75" r="9" fill="#1a1a1a"/>
                      <line x1="167" y1="65" x2="167" y2="75" stroke="#e5a93b" stroke-width="2" stroke-linecap="round"/>
                      <circle cx="167" cy="115" r="12" fill="#2a2420" stroke="#c2b6ab" stroke-width="1.5"/>
                      <circle cx="167" cy="115" r="8" fill="#1a1a1a"/>
                      <line x1="167" y1="106" x2="167" y2="115" stroke="#c2b6ab" stroke-width="2" stroke-linecap="round"/>`
            }
        ]
    },

    // ============================================
    // ⭐ 星海寻光 — 赛博反诈案件蓝图
    // ============================================
    fraud_voice: {
        title: 'AI拟声诈骗电话',
        itemId: 'fraud_voice',
        icon: '📞',
        description: '剥离 AI 伪造的音频噪音，抽取真实诈骗者原声',
        stage: 'clean', // 滑动频段清理AI噪声
        storyIntro: '一个深夜，独居的王奶奶接到"孙子"的求救电话——声音一模一样，但号码是陌生的……',
        parts: [
            { id: 'voice_waveform', name: '声纹频谱', targetX: 20, targetY: 15, w: 160, h: 90, hint: 'AI合成的声纹特征图谱，频谱边缘有诡异的锐利毛刺', svg: '<rect x="25" y="20" width="150" height="85" rx="4" fill="#0a0a1a" stroke="#00ff88" stroke-width="1.5"/><path d="M 30,70 Q 55,30 80,50 Q 105,65 130,40 Q 155,25 170,55" fill="none" stroke="#ff4444" stroke-width="2"/><circle cx="60" cy="45" r="2" fill="#ff4444"/><circle cx="110" cy="35" r="2" fill="#ff4444"/>' },
            { id: 'voice_origin', name: '真实声源片段', targetX: 60, targetY: 100, w: 80, h: 50, hint: '扒开AI外壳后露出的原始人声——这才是骗子的真实嗓音', svg: '<rect x="65" y="105" width="70" height="45" rx="3" fill="#003322" stroke="#00ff88" stroke-width="1.5"/><path d="M 80,125 Q 95,115 110,125 Q 120,135 130,125" fill="none" stroke="#00ff88" stroke-width="1.5"/><text x="100" y="140" text-anchor="middle" fill="#00ff88" font-size="8">ORIGIN</text>' },
            { id: 'voice_warning', name: '防诈警示牌', targetX: 110, targetY: 15, w: 60, h: 80, hint: '"遇事别慌，先挂电话，用已知号码回拨确认"', svg: '<rect x="112" y="20" width="55" height="75" rx="4" fill="#1a0000" stroke="#ff4444" stroke-width="2"/><text x="140" y="42" text-anchor="middle" fill="#ff4444" font-size="8">⚠️</text><text x="140" y="58" text-anchor="middle" fill="#ff4444" font-size="7">AI语音</text><text x="140" y="72" text-anchor="middle" fill="#ff4444" font-size="7">可被</text><text x="140" y="86" text-anchor="middle" fill="#ff4444" font-size="7">克隆！</text>' }
        ],
        stories: {
            voice_decoded: '声纹图谱拼合完成——骗子用一段仅3秒的社交媒体音频，就克隆出了"孙子"的声音。王奶奶差一点就把养老钱转出去了。'
        }
    },

    fraud_phish: {
        title: '高仿钓鱼网站',
        itemId: 'fraud_phish',
        icon: '🎣',
        description: '对焦模糊页面，拆穿精心伪造的山寨域名',
        stage: 'focus', // 调焦滑块发现taoba0.com
        storyIntro: '李大爷收到"淘宝客服"短信，说他的账号异常要重新验证。点开链接，页面跟真的一模一样……',
        parts: [
            { id: 'phish_urlbar', name: '伪造地址栏', targetX: 15, targetY: 10, w: 170, h: 40, hint: '注意看！taobao.com 被改成了 taoba0.com（数字0替代字母o）', svg: '<rect x="20" y="15" width="160" height="35" rx="6" fill="#111" stroke="#ff8800" stroke-width="1.5"/><text x="30" y="33" fill="#00ff88" font-size="8" font-family="monospace">🔒 https://taoba0.com/login</text><text x="30" y="45" fill="#ff4444" font-size="7" font-family="monospace">← taoba"0".com！字母o被换成了数字0！</text>' },
            { id: 'phish_login', name: '山寨登录弹窗', targetX: 30, targetY: 65, w: 140, h: 70, hint: '这个弹窗会窃取你的账号密码——真正的淘宝不会这样弹窗', svg: '<rect x="35" y="70" width="130" height="65" rx="8" fill="#1a1a1a" stroke="#ff4444" stroke-width="2"/><text x="100" y="90" text-anchor="middle" fill="#fff" font-size="8">登录</text><rect x="45" y="95" width="110" height="12" rx="2" fill="#333"/><rect x="45" y="110" width="110" height="12" rx="2" fill="#333"/><text x="100" y="130" text-anchor="middle" fill="#ff4444" font-size="7">提交=密码已泄露</text>' },
            { id: 'phish_warn', name: '防诈护盾', targetX: 105, targetY: 130, w: 70, h: 40, hint: '"陌生链接不乱点，官方渠道最安全"', svg: '<rect x="108" y="133" width="64" height="36" rx="6" fill="#003322" stroke="#00ff88" stroke-width="2"/><text x="140" y="150" text-anchor="middle" fill="#00ff88" font-size="8">🛡️</text><text x="140" y="163" text-anchor="middle" fill="#00ff88" font-size="6">谨慎链接</text>' }
        ],
        stories: {
            phish_exposed: '域名鉴定完成——钓鱼网站通过DNS劫持将用户引导到高仿页面，一旦输入密码，银行卡转眼被洗劫一空。'
        }
    },

    fraud_romance: {
        title: '杀猪盘虚假人设',
        itemId: 'fraud_romance',
        icon: '💔',
        description: '拦截轰炸式诈骗话术，拆穿盗用的虚假照片和名片',
        stage: 'stitch', // 快速点击拦截消息
        storyIntro: '张阿姨在交友App上认识了"海外工程师"。每天嘘寒问暖，照片帅气多金——可惜全都是偷来的……',
        parts: [
            { id: 'romance_chat', name: '诈骗话术记录', targetX: 10, targetY: 10, w: 90, h: 90, hint: '密集的"早安晚安""想你"轰炸——杀猪盘的标准套路', svg: '<rect x="15" y="15" width="80" height="85" rx="5" fill="#0a0a0a" stroke="#ff00ff" stroke-width="1.5"/><rect x="20" y="20" width="65" height="14" rx="3" fill="#ff00ff33"/><rect x="25" y="38" width="55" height="12" rx="3" fill="#ff00ff33"/><rect x="25" y="54" width="60" height="12" rx="3" fill="#ff00ff33"/><text x="55" y="85" text-anchor="middle" fill="#ff00ff" font-size="7">99+未读诈骗</text>' },
            { id: 'romance_photo', name: '盗用虚假照片', targetX: 100, targetY: 10, w: 80, h: 80, hint: '用百度识图一搜，发现"他"的照片出现在十几个不同名字的账号里', svg: '<rect x="104" y="15" width="72" height="72" rx="4" fill="#1a0033" stroke="#ff00ff" stroke-width="1.5"/><circle cx="140" cy="42" r="18" fill="#333" stroke="#ff00ff" stroke-width="1"/><text x="140" y="45" text-anchor="middle" fill="#fff" font-size="10">👤</text><text x="140" y="72" text-anchor="middle" fill="#ff4444" font-size="7">盗图×12</text>' },
            { id: 'romance_card', name: '伪造高管名片', targetX: 60, targetY: 105, w: 80, h: 50, hint: 'PS痕迹明显的高管名片——"某跨国集团副总裁"', svg: '<rect x="64" y="108" width="72" height="44" rx="4" fill="#fff" stroke="#ffaa00" stroke-width="1.5"/><text x="100" y="122" text-anchor="middle" fill="#333" font-size="7">某跨国集团</text><text x="100" y="134" text-anchor="middle" fill="#333" font-size="8" font-weight="bold">副总裁</text><text x="100" y="146" text-anchor="middle" fill="#888" font-size="6">（假）</text>' }
        ],
        stories: {
            romance_busted: '证据链重组完成——照片是盗用的、名片是PS的、"他"其实是一个窝在城中村的诈骗团伙成员。'
        }
    }
};

// ============================================================================
// 3. BACKGROUND DUST PARTICLES ENGINE (CANVAS)
// ============================================================================
class AmbientParticles {
    constructor() {
        this.canvas = document.getElementById('particle-canvas');
        this.ctx = this.canvas.getContext('2d');
        this.particles = [];
        this.frameId = null;
        this.reducedMotionQuery = window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)') : null;
        this.resize();
        window.addEventListener('resize', () => this.resize());
        if (this.reducedMotionQuery) {
            const handleMotionChange = (e) => {
                if (e.matches) this.stop();
                else this.animate();
            };
            if (this.reducedMotionQuery.addEventListener) this.reducedMotionQuery.addEventListener('change', handleMotionChange);
            else if (this.reducedMotionQuery.addListener) this.reducedMotionQuery.addListener(handleMotionChange);
        }
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) this.stop();
            else this.animate();
        });
        this.mouse = { x: -1000, y: -1000 };
        
        // 使用 pointermove 覆盖鼠標与触控
        window.addEventListener('pointermove', (e) => {
            this.mouse.x = e.clientX;
            this.mouse.y = e.clientY;
        });

        // 性能优化：移动端粒子数从 65 降至 40
        const particleCount = window.innerWidth < 768 ? 40 : 65;
        for (let i = 0; i < particleCount; i++) {
            this.particles.push(this.createParticle());
        }
    }

    resize() {
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
    }

    createParticle() {
        return {
            x: Math.random() * this.canvas.width,
            y: Math.random() * this.canvas.height,
            size: Math.random() * 2.5 + 0.5,
            speedX: (Math.random() - 0.5) * 0.25,
            speedY: -Math.random() * 0.35 - 0.15,
            opacity: Math.random() * 0.5 + 0.1,
            color: Math.random() < 0.6 ? '#e5a93b' : '#d48a85' // Warm amber & soft rose
        };
    }

    animate() {
        if (this.frameId) return;
        if (this.reducedMotionQuery && this.reducedMotionQuery.matches) {
            this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
            return;
        }
        this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
        
        this.particles.forEach(p => {
            // Physics: float upwards
            p.x += p.speedX;
            p.y += p.speedY;
            
            // Soft responsive drift to mouse proximity
            if (this.mouse.x > 0) {
                const dx = this.mouse.x - p.x;
                const dy = this.mouse.y - p.y;
                const dist = Math.hypot(dx, dy);
                if (dist < 180) {
                    const force = (180 - dist) / 180;
                    p.x -= dx * force * 0.015;
                    p.y -= dy * force * 0.015;
                }
            }

            // Loop edges
            if (p.y < -10) {
                p.y = this.canvas.height + 10;
                p.x = Math.random() * this.canvas.width;
            }
            if (p.x < -10 || p.x > this.canvas.width + 10) {
                p.x = Math.random() * this.canvas.width;
            }

            // Draw glowing particle
            this.ctx.beginPath();
            this.ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
            this.ctx.fillStyle = p.color;
            this.ctx.globalAlpha = p.opacity;
            this.ctx.shadowBlur = 8;
            this.ctx.shadowColor = p.color;
            this.ctx.fill();
        });
        
        this.ctx.shadowBlur = 0; // Reset
        this.ctx.globalAlpha = 1;
        this.frameId = requestAnimationFrame(() => {
            this.frameId = null;
            this.animate();
        });
    }

    stop() {
        if (this.frameId) cancelAnimationFrame(this.frameId);
        this.frameId = null;
    }
}

// ============================================================================
// 4. CANVAS SPARKLE CELEBRATION PARTICLES
// ============================================================================
class CelebrationParticles {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        this.ctx = this.canvas.getContext('2d');
        this.sparkles = [];
        this.isActive = false;
        this.isLooping = false;
        this.frameId = null;
        this._resizeHandler = () => this.resize();
        
        this.resize();
        window.addEventListener('resize', this._resizeHandler);
    }

    resize() {
        const rect = this.canvas.getBoundingClientRect();
        this.canvas.width = rect.width;
        this.canvas.height = rect.height;
    }

    burst(x, y, color = '#e5a93b') {
        if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
        this.resize();
        this.isActive = true;
        
        // 🔑 性能保护：最大粒子数上限 200，超出后移除最旧的
        const MAX_PARTICLES = 200;
        while (this.sparkles.length > MAX_PARTICLES - 30) {
            this.sparkles.shift(); // 移除最早生成的粒子
        }
        
        // Spawn particles radiating from coordinates
        for (let i = 0; i < 30; i++) {
            const angle = Math.random() * Math.PI * 2;
            const velocity = Math.random() * 3.5 + 1.5;
            this.sparkles.push({
                x: x,
                y: y,
                vx: Math.cos(angle) * velocity,
                vy: Math.sin(angle) * velocity - 0.5, // slight gravity bias
                size: Math.random() * 3 + 1.5,
                opacity: 1,
                decay: Math.random() * 0.02 + 0.015,
                color: color
            });
        }
        
        if (this.sparkles.length > 0 && !this.isLooping) {
            this.loop();
        }
    }

    loop() {
        if (this.sparkles.length === 0) {
            this.isActive = false;
            this.isLooping = false;
            this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
            return;
        }
        
        this.isLooping = true;
        this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
        
        this.sparkles.forEach((s, idx) => {
            s.x += s.vx;
            s.y += s.vy;
            s.vy += 0.03; // Soft gravity
            s.opacity -= s.decay;
            
            if (s.opacity <= 0) {
                this.sparkles.splice(idx, 1);
                return;
            }
            
            this.ctx.beginPath();
            this.ctx.arc(s.x, s.y, s.size, 0, Math.PI * 2);
            this.ctx.fillStyle = s.color;
            this.ctx.globalAlpha = s.opacity;
            this.ctx.shadowBlur = 6;
            this.ctx.shadowColor = s.color;
            this.ctx.fill();
        });
        
        this.ctx.shadowBlur = 0;
        this.ctx.globalAlpha = 1;
        this.frameId = requestAnimationFrame(() => {
            this.frameId = null;
            this.loop();
        });
    }

    stop() {
        if (this.frameId) cancelAnimationFrame(this.frameId);
        this.frameId = null;
        this.sparkles = [];
        this.isActive = false;
        this.isLooping = false;
        this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
    }

    destroy() {
        this.stop();
        if (this._resizeHandler) window.removeEventListener('resize', this._resizeHandler);
        this._resizeHandler = null;
    }
}

// ============================================================================
// 5. INTERACTION ENGINE (DRAG & DROP, TOUCH/POINTER EVENTS)
// ============================================================================
const getCoords = (e) => {
    if (e.touches && e.touches.length > 0) return e.touches[0];
    if (e.changedTouches && e.changedTouches.length > 0) return e.changedTouches[0];
    return e;
};

function safeBindClick(elementId, callback) {
    const el = typeof elementId === 'string' ? document.getElementById(elementId) : elementId;
    if (!el) return;
    if (el.dataset.safeBindClickBound === 'true') return;
    el.dataset.safeBindClickBound = 'true';
    let startY = 0, startX = 0, isDragging = false;
    
    const trigger = (e) => {
        if (el.dataset.clickLocked === "true") return;
        el.dataset.clickLocked = "true";
        setTimeout(() => el.dataset.clickLocked = "false", 300);
        callback(e);
    };

    el.addEventListener('pointerdown', (e) => { startX = e.clientX; startY = e.clientY; isDragging = false; }, { passive: true });
    el.addEventListener('pointermove', (e) => { if (Math.abs(e.clientX - startX) > 10 || Math.abs(e.clientY - startY) > 10) isDragging = true; }, { passive: true });
    el.addEventListener('pointerup', (e) => {
        if (!isDragging) { if (e.cancelable) e.preventDefault(); trigger(e); }
    });
    el.addEventListener('click', (e) => { trigger(e); });
}

const bindDoubleInsurance = (elementId, handler) => {
    const el = typeof elementId === 'string' ? document.getElementById(elementId) : elementId;
    if (!el) return;
    let handled = false;
    const safeHandler = (e) => {
        if (e.cancelable) {
            e.preventDefault();
        }
        if (handled) return;
        handled = true;
        setTimeout(() => { handled = false; }, 300); // 300ms debounce
        handler(e);
    };
    el.addEventListener('click', safeHandler);
    el.addEventListener('touchend', safeHandler, { passive: false });
};

class PuzzleWorkbench {
    constructor() {
        this.activeBlueprintId = null;
        this.trayZone = document.getElementById('parts-tray-zone');
        this.targetZone = document.getElementById('blueprint-target-zone');
        this.celebration = new CelebrationParticles('workspace-particle-canvas');
        
        // Multi-stage restoration status variables
        this.currentRestorationStage = 'clean'; // 'clean' -> 'polish' -> 'assemble'
        this.restorationProgress = 0;
        this.isRubbing = false;
        this._awakeTimers = [];

        // Restoration Swipe/Rubbing Listeners
        this._targetPointerDown = (e) => this.onTargetZonePointerDown(e);
        this._targetPointerMove = (e) => this.onTargetZonePointerMove(e);
        this._targetPointerUp = () => this.onTargetZonePointerUp();
        this.targetZone.addEventListener('pointerdown', this._targetPointerDown);
        document.addEventListener('pointermove', this._targetPointerMove);
        document.addEventListener('pointerup', this._targetPointerUp);
        document.addEventListener('pointercancel', this._targetPointerUp);
    }

    scheduleAwakeTimer(callback, delay) {
        const timerId = setTimeout(() => {
            this._awakeTimers = this._awakeTimers.filter(id => id !== timerId);
            callback();
        }, delay);
        this._awakeTimers.push(timerId);
        return timerId;
    }

    cleanupActiveRuntime() {
        this._awakeTimers.forEach(id => clearTimeout(id));
        this._awakeTimers = [];
        if (this._activeDragMove) {
            document.removeEventListener('pointermove', this._activeDragMove);
            this._activeDragMove = null;
        }
        if (this._activeDragEnd) {
            document.removeEventListener('pointerup', this._activeDragEnd);
            document.removeEventListener('pointercancel', this._activeDragEnd);
            this._activeDragEnd = null;
        }
        if (gameState.draggedElement) {
            gameState.draggedElement.style.cursor = 'grab';
            gameState.draggedElement.style.zIndex = '1';
        }
        gameState.draggedElement = null;
        gameState.activeDragPart = null;

        if (this._sewingInterval) {
            clearInterval(this._sewingInterval);
            this._sewingInterval = null;
        }
        if (this._sewingButton) {
            this._sewingButton.onclick = null;
            this._sewingButton.onpointerdown = null;
            this._sewingButton.onpointerup = null;
            this._sewingButton.onpointerleave = null;
            this._sewingButton.onpointercancel = null;
            this._sewingButton = null;
        }
        if (typeof audio !== 'undefined') {
            audio.stopRadioStatic();
            audio.stopRadioMelody();
            audio.stopOperaMelody();
            audio.stopNewsBroadcast();
            audio.stopSewingLoop();
        }

        if (this._radioSlider) {
            this._radioSlider.oninput = null;
            this._radioSlider = null;
        }
        if (this._cameraButton) {
            this._cameraButton.onclick = null;
            this._cameraButton = null;
        }

        if (this._lanternCleanup) {
            this._lanternCleanup();
            this._lanternCleanup = null;
        }
        if (this._lanternPermissionButton) {
            this._lanternPermissionButton.onclick = null;
            this._lanternPermissionButton.remove();
            this._lanternPermissionButton = null;
        }
        if (this._lanternSlider) {
            this._lanternSlider.oninput = null;
            this._lanternSlider = null;
        }

        if (this.watchTickInterval) {
            clearInterval(this.watchTickInterval);
            this.watchTickInterval = null;
        }
        if (this._watchButton) {
            this._watchButton.onclick = null;
            this._watchButton = null;
        }
        if (this.celebration && typeof this.celebration.stop === 'function') {
            this.celebration.stop();
        }
    }

    destroy() {
        this.cleanupActiveRuntime();
        if (this.celebration && typeof this.celebration.destroy === 'function') {
            this.celebration.destroy();
        }
        if (this._targetPointerDown) this.targetZone.removeEventListener('pointerdown', this._targetPointerDown);
        if (this._targetPointerMove) document.removeEventListener('pointermove', this._targetPointerMove);
        if (this._targetPointerUp) {
            document.removeEventListener('pointerup', this._targetPointerUp);
            document.removeEventListener('pointercancel', this._targetPointerUp);
        }
        this._targetPointerDown = null;
        this._targetPointerMove = null;
        this._targetPointerUp = null;
    }

    /** 更新进度条（视觉 + ARIA） */
    updateProgressBar(percent) {
        const fill = document.getElementById('restoration-bar-fill');
        if (fill) {
            fill.style.width = `${percent}%`;
            fill.setAttribute('aria-valuenow', Math.round(percent));
        }
    }

    setupItem(itemId) {
        this.cleanupActiveRuntime();
        this.activeBlueprintId = itemId;
        const data = itemBlueprints[itemId];
        
        // Reset geriatric gentleness tracker
        gameState.rubbedGentle = true;
        
        // Set Header Title
        document.getElementById('workspace-title').textContent = `记忆重构：${data.title}`;
        
        // Clear any previous custom setups
        document.getElementById('stitch-points-layer').innerHTML = '';
        document.getElementById('custom-prelude-gameplay-zone').innerHTML = '';
        
        // Reset Camera blur if present (reset inline styles for clean state)
        const svgContainer = document.getElementById('active-blueprint-svg');
        svgContainer.style.filter = 'none';
        svgContainer.style.opacity = ''; // 回退 CSS 默认值（clean 阶段 0.15）
        
        // Remove Lantern darkness mask if present
        const darkMask = document.getElementById('lantern-darkness-mask');
        if (darkMask) darkMask.remove();
        
        // Render dynamic breadcrumbs
        this.renderStageIndicator(itemId);
        
        // 1. Generate Target Outline Blueprint SVG
        let fullSilhouetteSVG = `<svg viewBox="0 0 200 200" width="100%" height="100%">`;
        
        // Assemble target slot paths
        data.parts.forEach(part => {
            fullSilhouetteSVG += `<g id="slot-${part.id}" class="target-slot-group">
                <path class="target-slot" id="slot-path-${part.id}" d="" />
                <!-- Invisible ghost rect overlay for bounding boxes -->
                <rect x="${part.targetX}" y="${part.targetY}" width="140" height="140" fill="transparent"/>
            </g>`;
        });
        fullSilhouetteSVG += `</svg>`;
        svgContainer.innerHTML = safeHTML(fullSilhouetteSVG);
        
        // Wait for DOM layout to set slot shapes
        data.parts.forEach(part => {
            const slotGroup = document.getElementById(`slot-${part.id}`);
            slotGroup.innerHTML = safeHTML(`<g class="blueprint-shape" opacity="0.12">${part.svg}</g>
            <rect x="${part.targetX}" y="${part.targetY}" width="${part.w}" height="${part.h}" fill="none" stroke="var(--accent-gold)" stroke-width="1.5" stroke-dasharray="4,4" class="target-slot" id="slot-rect-${part.id}"/>`);
        });
        
        // 2. Clear tray and generate draggable items
        this.trayZone.innerHTML = safeHTML('');
        gameState.snappedCount = 0;
        gameState.totalPartsCount = data.parts.length;
        
        const trayWidth = 320;
        
        data.parts.forEach((part, index) => {
            const partEl = document.createElement('div');
            partEl.classList.add('draggable-part');
            partEl.id = `part-${part.id}`;
            partEl.dataset.partId = part.id;
            
            // Render detailed SVG parts inside draggable card
            partEl.innerHTML = safeHTML(`<svg viewBox="0 0 200 200" width="100%" height="100%">${part.svg}</svg>`);
            
            // Randomize position inside Tray without stack overlapping
            const randX = Math.random() * (trayWidth - 140) + 10;
            const randY = (index * 85) + Math.random() * 20 + 10; // distributed spacing vertical
            
            partEl.style.left = `${randX}px`;
            partEl.style.top = `${randY}px`;
            partEl.style.transform = `rotate(${(Math.random() - 0.5) * 15}deg)`;
            
            // Play hover chimes
            partEl.addEventListener('mouseenter', () => audio.playHover());
            
            // Start Dragging — 统一使用 Pointer Events（覆盖鼠标 + 触控，避免双轨冲突）
            const handleStart = (e) => this.dragStart(e, partEl, part);
            partEl.addEventListener('pointerdown', handleStart, { passive: false });
            
            this.trayZone.appendChild(partEl);
        });

        // 3. Initiate dynamic starting stage per item!
        if (itemId === 'radio' || itemId === 'telephone' || itemId === 'musicbox' || itemId === 'abacus' || itemId === 'television') {
            this.transitionToStage('clean');
        } else if (itemId === 'camera') {
            this.transitionToStage('focus');
        } else if (itemId === 'sewing') {
            this.transitionToStage('stitch');
        } else if (itemId === 'lantern') {
            this.transitionToStage('ignite');
        } else if (itemId === 'watch') {
            this.transitionToStage('wind');
        }
    }

    renderStageIndicator(itemId) {
        const panel = document.querySelector('.restoration-stages');
        if (!panel) return;
        
        let html = '';
        if (itemId === 'radio' || itemId === 'telephone' || itemId === 'musicbox' || itemId === 'abacus' || itemId === 'television') {
            html = `
                <div class="stage-step active" id="stage-clean">
                    <span class="stage-icon">🌬️</span>
                    <span class="stage-name">首部曲：拨开认知迷雾</span>
                </div>
                <div class="stage-arrow">→</div>
                <div class="stage-step" id="stage-assemble">
                    <span class="stage-icon">🤝</span>
                    <span class="stage-name">二部曲：重建记忆连结</span>
                </div>`;
        } else if (itemId === 'camera') {
            html = `
                <div class="stage-step active" id="stage-focus">
                    <span class="stage-icon">📸</span>
                    <span class="stage-name">首部曲：虚像镜头调焦</span>
                </div>
                <div class="stage-arrow">→</div>
                <div class="stage-step" id="stage-assemble">
                    <span class="stage-icon">🤝</span>
                    <span class="stage-name">二部曲：重建记忆连结</span>
                </div>`;
        } else if (itemId === 'sewing') {
            html = `
                <div class="stage-step active" id="stage-stitch">
                    <span class="stage-icon">🧵</span>
                    <span class="stage-name">首部曲：缝合记忆引线</span>
                </div>
                <div class="stage-arrow">→</div>
                <div class="stage-step" id="stage-assemble">
                    <span class="stage-icon">🤝</span>
                    <span class="stage-name">二部曲：重建记忆连结</span>
                </div>`;
        } else if (itemId === 'lantern') {
            html = `
                <div class="stage-step active" id="stage-ignite">
                    <span class="stage-icon">🕯️</span>
                    <span class="stage-name">首部曲：擦亮心中微光</span>
                </div>
                <div class="stage-arrow">→</div>
                <div class="stage-step" id="stage-assemble">
                    <span class="stage-icon">🤝</span>
                    <span class="stage-name">二部曲：重建记忆连结</span>
                </div>`;
        } else if (itemId === 'watch') {
            html = `
                <div class="stage-step active" id="stage-wind">
                    <span class="stage-icon">⚙️</span>
                    <span class="stage-name">首部曲：旋转上紧发条</span>
                </div>
                <div class="stage-arrow">→</div>
                <div class="stage-step" id="stage-assemble">
                    <span class="stage-icon">🤝</span>
                    <span class="stage-name">二部曲：重建记忆连结</span>
                </div>`;
        }
        panel.innerHTML = safeHTML(html);
    }

    transitionToStage(stage) {
        this.currentRestorationStage = stage;
        this.restorationProgress = 0;

        // Reset progress fill
        this.updateProgressBar(0);

        // Clear active classes on stages indicators
        const steps = document.querySelectorAll('.stage-step');
        steps.forEach(el => el.classList.remove('active'));

        const dustOverlay = document.getElementById('blueprint-dust-overlay');
        const rustOverlay = document.getElementById('blueprint-rust-overlay');
        const toolCabinet = document.getElementById('restoration-tool-cabinet');
        const assemblyTray = document.getElementById('assembly-tray-content');
        const gameplayZone = document.getElementById('custom-prelude-gameplay-zone');
        const stitchLayer = document.getElementById('stitch-points-layer');

        // Reset overlays default display
        dustOverlay.style.display = 'none';
        rustOverlay.style.display = 'none';
        stitchLayer.innerHTML = '';
        stitchLayer.style.pointerEvents = 'none';
        gameplayZone.innerHTML = '';

        // 移除所有阶段的视觉引导
        const blueprintArea = document.querySelector('.blueprint-area');
        if (blueprintArea) blueprintArea.classList.remove('clean-stage-active');

        // Stop microphone hardware if not in clean stage to avoid persistent icon in browser
        if (stage !== 'clean') {
            try {
                micBlower.stop();
            } catch (e) {}
        }

        if (stage === 'clean') {
            const cleanBreadcrumb = document.getElementById('stage-clean');
            if (cleanBreadcrumb) cleanBreadcrumb.classList.add('active');
            
            document.getElementById('restoration-status-text').textContent = '老人的思绪正被重重迷雾笼罩。请对准麦克风轻吹，或用手轻抚滑动，为她驱散困惑 (0%)';
            
            // Show tool cabinet, hide assembly tray
            toolCabinet.classList.remove('hidden');
            assemblyTray.classList.add('hidden');

            document.getElementById('cabinet-title').textContent = '首部曲：拨开认知迷雾';
            document.getElementById('cabinet-sub').textContent = '吹散遮挡脑海的云雾，唤醒尘封的器物轮廓';
            document.getElementById('cabinet-tool-icon').textContent = '🌬️';
            document.getElementById('cabinet-instruction').textContent = '请【对准麦克风吹气/哈气】，或者像轻抚长辈额头那般，在左侧物件上反复轻扫滑动，以拂去重重叠叠的迷雾。';

            // Show dust overlay, hide rust overlay
            dustOverlay.style.display = 'flex';
            dustOverlay.style.opacity = '1';

            // 视觉引导：蓝图区脉冲动画提示交互
            const blueprintArea = document.querySelector('.blueprint-area');
            if (blueprintArea) blueprintArea.classList.add('clean-stage-active');

            // Workspace Tip
            document.querySelector('.workspace-tip').textContent = '🌬️ 首部曲：对麦克风【用力吹气】吹开尘土，或者用手在左侧画框内滑动擦除';

            // 🌬️ Start high-fidelity Microphone Blower hardware analysis
            this.hasTriggeredFogFact = false;
            micBlower.init().then(success => {
                if (success) {
                    micBlower.start((level) => {
                        if (this.currentRestorationStage !== 'clean') {
                            micBlower.stop();
                            return;
                        }
                        
                        // If microphone level exceeds threshold, dissolve fog!
                        if (level > 0.08) {
                            // Randomly burst cloud sparkles on left canvas
                            if (Math.random() < 0.28) {
                                const cx = Math.random() * this.targetZone.clientWidth;
                                const cy = Math.random() * this.targetZone.clientHeight;
                                this.celebration.burst(cx, cy, '#f5f5f5');
                                audio.playTypewriterClick();
                            }
                            
                            const levelMultiplier = 2.2 + (gameState.upgrades.cleaner.level - 1) * 0.55;
                            this.restorationProgress += level * levelMultiplier;
                            if (this.restorationProgress > 100) this.restorationProgress = 100;
                            
                            const roundedProgress = Math.round(this.restorationProgress);
                            
                            const dustEl = document.getElementById('blueprint-dust-overlay');
                            if (dustEl) {
                                dustEl.style.opacity = `${(100 - roundedProgress) / 100}`;
                            }

                            this.updateProgressBar(roundedProgress);
                            document.getElementById('restoration-status-text').textContent = `正在哈气/吹气，拨开认知迷雾... (迷雾消散: ${roundedProgress}%)`;

                            // Trigger cognitive clearance facts
                            if (this.restorationProgress > 30 && !this.hasTriggeredFogFact) {
                                this.hasTriggeredFogFact = true;
                                
                                const toast = document.createElement('div');
                                toast.className = 'poetic-toast';
                                toast.style.borderColor = 'var(--accent-gold)';
                                toast.innerHTML = safeHTML(`
                                    <div class="toast-glow"></div>
                                    <div class="toast-content">
                                        <span class="toast-part-name" style="color: var(--accent-gold);">💡 跨屏呼吸交互 💡</span>
                                        <p class="toast-part-hint" style="font-size: 0.88rem; line-height: 1.5;">深呼吸与用力气流交互能活化阿尔茨海默病患者的大脑体感运动神经，同时促进肺部换气与含氧量，是一场富有创意的趣味体感康复练习！</p>
                                    </div>
                                `);
                                document.body.appendChild(toast);
                                setTimeout(() => {
                                    toast.classList.add('fade-out');
                                    setTimeout(() => toast.remove(), 800);
                                }, 4500);
                            }

                            if (this.restorationProgress >= 100) {
                                micBlower.stop();
                                // Clean grayscale/blur visual filters back to normal
                                cognitiveDecay.restoreSanity();
                                this.transitionToStage('assemble');
                            }
                        }
                    });
                }
            });

        } else if (stage === 'focus') {
            const focusBreadcrumb = document.getElementById('stage-focus');
            if (focusBreadcrumb) focusBreadcrumb.classList.add('active');

            document.getElementById('restoration-status-text').textContent = '记忆像是蒙上水汽的镜片。请旋转右侧对焦环，直到画面重新清晰 (0%)';
            
            toolCabinet.classList.remove('hidden');
            assemblyTray.classList.add('hidden');

            document.getElementById('cabinet-title').textContent = '首部曲：虚像镜头调焦';
            document.getElementById('cabinet-sub').textContent = '拉近记忆的焦距，让失焦的珍贵旧照重新对准';
            document.getElementById('cabinet-tool-icon').textContent = '📸';
            document.getElementById('cabinet-instruction').textContent = '拖动下方的记忆对焦滑块。焦距越接近，左侧失焦的复古镜头与齿轮就会越清晰。';

            // Apply focus blur filter to active blueprint container
            const svgContainer = document.getElementById('active-blueprint-svg');
            svgContainer.style.filter = 'blur(15px)';

            // Inject range slider toy
            gameplayZone.innerHTML = safeHTML(`
                <div style="display:flex; flex-direction:column; align-items:center; width:100%; margin: 10px 0;">
                    <span style="font-size:0.8rem; color:var(--text-muted);">拖拽调焦环，让记忆原像准焦</span>
                    <input type="range" min="0" max="100" value="0" class="prelude-range-slider" id="focus-adjust-slider" aria-label="记忆镜头对焦调节">
                    <span id="focus-status" style="font-size:0.85rem; color:var(--accent-gold); font-weight:bold;">当前失焦度: 100%</span>
                </div>
            `);

            const slider = document.getElementById('focus-adjust-slider');
            slider.addEventListener('input', (e) => {
                const val = parseInt(e.target.value);
                this.restorationProgress = val;
                
                // Scale blur down to 0px
                const blurPx = (15 * (100 - val)) / 100;
                svgContainer.style.filter = `blur(${blurPx}px)`;
                
                this.updateProgressBar(val);
                document.getElementById('restoration-status-text').textContent = `正在调整记忆焦距，准焦进度: ${val}%`;
                document.getElementById('focus-status').textContent = val === 100 ? '调焦完成！准焦率 100%' : `当前失焦度: ${100 - val}%`;

                if (Math.random() < 0.15) {
                    audio.playHover();
                }

                if (val >= 100) {
                    setTimeout(() => {
                        svgContainer.style.filter = 'none';
                        this.transitionToStage('assemble');
                    }, 500);
                }
            });

            document.querySelector('.workspace-tip').textContent = '📸 首部曲：拨动右侧调焦环，将左侧模糊的世界重新归于清晰';

        } else if (stage === 'stitch') {
            const stitchBreadcrumb = document.getElementById('stage-stitch');
            if (stitchBreadcrumb) stitchBreadcrumb.classList.add('active');

            document.getElementById('restoration-status-text').textContent = '脑海的线索已寸寸断裂。请顺次点击左侧亮起的 1➔2➔3➔4 定位点，穿针引线重新缝合 (0%)';
            stitchLayer.style.pointerEvents = 'auto';
            
            toolCabinet.classList.remove('hidden');
            assemblyTray.classList.add('hidden');

            document.getElementById('cabinet-title').textContent = '首部曲：缝合记忆引线';
            document.getElementById('cabinet-sub').textContent = '将破损散落的关怀，一针一线缝合成完整的牵挂';
            document.getElementById('cabinet-tool-icon').textContent = '🧵';
            document.getElementById('cabinet-instruction').textContent = '在左侧的机身上顺次穿线。点击金色闪烁的穿针定位孔，每一针都将连起红色的心愿缝线。';

            // Generate 4 interactive stitch points on the left target zone
            const points = [
                { id: 1, x: 25, y: 70 },
                { id: 2, x: 90, y: 35 },
                { id: 3, x: 170, y: 35 },
                { id: 4, x: 160, y: 110 }
            ];

            let stitchedCount = 0;
            const linesGroup = document.createElementNS("http://www.w3.org/2000/svg", "svg");
            linesGroup.setAttribute("style", "position:absolute; top:0; left:0; width:100%; height:100%; pointer-events:none; z-index:24;");
            linesGroup.id = "sewing-stitch-lines-svg";
            stitchLayer.appendChild(linesGroup);

            points.forEach((pt) => {
                const dot = document.createElement('div');
                dot.classList.add('stitch-dot');
                // Coordinates are based on 200x200 viewBox, convert to percentage:
                dot.style.left = `${pt.x / 2}%`;
                dot.style.top = `${pt.y / 2}%`;
                dot.innerHTML = `<span class="stitch-dot-number">${pt.id}</span>`;
                
                dot.addEventListener('click', () => {
                    // Force strictly in sequence
                    if (pt.id !== stitchedCount + 1) {
                        audio.playHover();
                        return;
                    }

                    dot.classList.add('stitched');
                    stitchedCount++;
                    this.restorationProgress = (stitchedCount / 4) * 100;
                    
                    audio.playTypewriterClick();
                    
                    // Draw glowing line to previous point
                    if (stitchedCount > 1) {
                        const prevPt = points[stitchedCount - 2];
                        const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
                        line.setAttribute("x1", `${prevPt.x / 2}%`);
                        line.setAttribute("y1", `${prevPt.y / 2}%`);
                        line.setAttribute("x2", `${pt.x / 2}%`);
                        line.setAttribute("y2", `${pt.y / 2}%`);
                        line.setAttribute("stroke", "var(--accent-rose)");
                        line.setAttribute("stroke-width", "3");
                        line.setAttribute("filter", "drop-shadow(0 0 6px var(--accent-rose))");
                        linesGroup.appendChild(line);
                    }

                    this.updateProgressBar(this.restorationProgress);
                    document.getElementById('restoration-status-text').textContent = `正在引针缝线，缝合进度: ${this.restorationProgress}% (已穿刺第 ${stitchedCount}/4 针)`;

                    // Spark sparkles on click
                    const rect = this.targetZone.getBoundingClientRect();
                    this.celebration.burst((pt.x / 200) * rect.width, (pt.y / 200) * rect.height, '#e57373');

                    if (stitchedCount === 4) {
                        setTimeout(() => {
                            this.transitionToStage('assemble');
                        }, 500);
                    }
                });

                stitchLayer.appendChild(dot);
            });

            document.querySelector('.workspace-tip').textContent = '🧵 首部曲：顺次点击左侧亮起的 1➔2➔3➔4 穿针点，重新连起岁月的缝线';

        } else if (stage === 'ignite') {
            const igniteBreadcrumb = document.getElementById('stage-ignite');
            if (igniteBreadcrumb) igniteBreadcrumb.classList.add('active');

            document.getElementById('restoration-status-text').textContent = '老人的世界正被黑暗笼罩。请快速向右划动右侧的温馨火柴，重燃心中的温热微光 (0%)';
            
            toolCabinet.classList.remove('hidden');
            assemblyTray.classList.add('hidden');

            document.getElementById('cabinet-title').textContent = '首部曲：擦亮心中微光';
            document.getElementById('cabinet-sub').textContent = '划落一束火花，驱散冰冷孤独的黑暗脑海';
            document.getElementById('cabinet-tool-icon').textContent = '🕯️';
            document.getElementById('cabinet-instruction').textContent = '阿兹海默症带走了微光。请用指尖点住火柴，快速向右划过擦火带。重擦燃起的金色火光，将瞬间温暖整个阁楼。';

            // Create pitch dark overlay on target canvas
            const darkMask = document.createElement('div');
            darkMask.id = 'lantern-darkness-mask';
            darkMask.classList.add('lantern-darkness-mask');
            document.getElementById('blueprint-target-zone').appendChild(darkMask);

            // Inject match striker
            gameplayZone.innerHTML = safeHTML(`
                <div style="display:flex; flex-direction:column; align-items:center; width:100%; margin: 10px 0;">
                    <span style="font-size:0.8rem; color:var(--text-muted); margin-bottom:8px;">在擦火带上向右快速划动火柴</span>
                    <div class="matchbox-striker" id="lantern-striker-box">
                        <div class="striking-lane"></div>
                        <div class="match-stick" id="lantern-match-stick"></div>
                    </div>
                    <span id="match-status" style="font-size:0.85rem; color:var(--accent-gold); font-weight:bold;">点亮进度: 0%</span>
                </div>
            `);

            const match = document.getElementById('lantern-match-stick');
            const striker = document.getElementById('lantern-striker-box');
            let isDraggingMatch = false;

            match.addEventListener('pointerdown', (e) => {
                isDraggingMatch = true;
                match.setPointerCapture(e.pointerId);
                e.preventDefault();
            });

            document.addEventListener('pointermove', (e) => {
                if (!isDraggingMatch) return;
                const rect = striker.getBoundingClientRect();
                let newLeft = e.clientX - rect.left - 24; // center matching offset
                if (newLeft < 10) newLeft = 10;
                if (newLeft > 165) newLeft = 165; // max strike boundary
                
                match.style.left = `${newLeft}px`;
                
                const percent = Math.round(((newLeft - 10) / 155) * 100);
                this.restorationProgress = percent;
                
                this.updateProgressBar(percent);
                document.getElementById('match-status').textContent = `点亮进度: ${percent}%`;

                // Emit beautiful golden match scratch sparks as they drag!
                if (Math.random() < 0.25) {
                    audio.playTypewriterClick();
                    const targetZoneRect = this.targetZone.getBoundingClientRect();
                    // burst in match head area
                    this.celebration.burst(targetZoneRect.width - 40, targetZoneRect.height / 2, '#ffb74d');
                }
            });

            const handleMatchRelease = () => {
                if (!isDraggingMatch) return;
                isDraggingMatch = false;
                
                if (this.restorationProgress >= 90) {
                    // Strike ignited!
                    audio.playAwake();
                    document.getElementById('match-status').textContent = '重燃成功！温热微光已驱散黑暗';
                    document.getElementById('restoration-status-text').textContent = '心中微光已被擦亮！开始重建记忆连结 (100%)';
                    
                    // Burst bright sparkles and fade dark mask completely!
                    const targetZoneRect = this.targetZone.getBoundingClientRect();
                    for (let i = 0; i < 8; i++) {
                        setTimeout(() => {
                            this.celebration.burst(targetZoneRect.width / 2 + (Math.random() - 0.5) * 100, targetZoneRect.height / 2 + (Math.random() - 0.5) * 100, '#ffd700');
                        }, i * 80);
                    }

                    darkMask.style.opacity = '0';
                    setTimeout(() => {
                        darkMask.remove();
                        this.transitionToStage('assemble');
                    }, 800);
                } else {
                    // Spring back
                    match.style.left = '10px';
                    this.restorationProgress = 0;
                    this.updateProgressBar(0);
                    document.getElementById('match-status').textContent = '划动速度过轻，重燃失败';
                }
            };

            document.addEventListener('pointerup', handleMatchRelease);
            document.addEventListener('pointercancel', handleMatchRelease);

            document.querySelector('.workspace-tip').textContent = '🕯️ 首部曲：在右侧快速向右划动擦亮温馨的火柴，为奶奶重新燃起微弱的亮光';

        } else if (stage === 'wind') {
            const windBreadcrumb = document.getElementById('stage-wind');
            if (windBreadcrumb) windBreadcrumb.classList.add('active');

            document.getElementById('restoration-status-text').textContent = '发条已松弛，指针不再流转。请点击或旋转右侧发条旋钮上紧发条 (0%)';
            
            toolCabinet.classList.remove('hidden');
            assemblyTray.classList.add('hidden');

            document.getElementById('cabinet-title').textContent = '首部曲：上紧时光发条';
            document.getElementById('cabinet-sub').textContent = '拧紧发条旋钮，唤醒沉睡的时光齿轮';
            document.getElementById('cabinet-tool-icon').textContent = '⚙️';
            document.getElementById('cabinet-instruction').textContent = '阿兹海默症令记忆的时钟停摆。多次点击右侧发条旋钮，或者按住上下划动，将其拧满至 100%，让逝去的指针重新前行！';

            const svgContainer = document.getElementById('active-blueprint-svg');
            if (svgContainer) {
                svgContainer.style.filter = 'opacity(0.35) blur(2px)';
                svgContainer.style.transition = 'filter 0.5s ease';
            }

            // Winding Interactive Board
            gameplayZone.innerHTML = safeHTML(`
                <div style="display:flex; flex-direction:column; align-items:center; width:100%; margin: 10px 0;">
                    <span style="font-size:0.8rem; color:var(--text-muted); margin-bottom: 8px;">多次点击或按住上下拖动旋转发条</span>
                    <div style="position:relative; width:110px; height:110px; display:flex; align-items:center; justify-content:center;">
                        <div id="winding-crown" style="width:70px; height:70px; border-radius:50%; background:linear-gradient(135deg, var(--accent-gold), var(--accent-rose)); border:4px solid #1c1815; box-shadow:0 6px 15px rgba(229, 169, 59, 0.4); display:flex; align-items:center; justify-content:center; cursor:pointer; font-size:2.2rem; transition: transform 0.15s cubic-bezier(0.25, 0.8, 0.25, 1); user-select:none;">⚙️</div>
                        <div style="position:absolute; width:90px; height:90px; border-radius:50%; border:2px dashed rgba(229, 169, 59, 0.25); animation: rotateSlow 8s infinite linear; pointer-events:none;"></div>
                    </div>
                    <span id="wind-status" style="font-size:0.85rem; color:var(--accent-gold); font-weight:bold; margin-top:12px;">发条张力: 0%</span>
                </div>
            `);

            const crown = document.getElementById('winding-crown');
            let windValue = 0;
            let rotation = 0;

            const triggerWinding = () => {
                if (windValue >= 100) return;
                
                windValue += 8;
                if (windValue > 100) windValue = 100;
                
                rotation += 45;
                crown.style.transform = `rotate(${rotation}deg) scale(1.08)`;
                setTimeout(() => {
                    crown.style.transform = `rotate(${rotation}deg) scale(1.0)`;
                }, 100);

                this.restorationProgress = windValue;
                this.updateProgressBar(windValue);
                document.getElementById('wind-status').textContent = `发条张力: ${windValue}%`;
                document.getElementById('restoration-status-text').textContent = `正在拧紧发条旋钮，当前发条进度: ${windValue}%`;

                // Ratchet sounds
                audio.playTypewriterClick();
                
                // Burst beautiful sparkles in target zone
                const targetZoneRect = this.targetZone.getBoundingClientRect();
                this.celebration.burst(targetZoneRect.width / 2 + (Math.random() - 0.5) * 60, targetZoneRect.height / 2 + (Math.random() - 0.5) * 60, '#e5a93b');

                if (windValue >= 100) {
                    audio.playAwake();
                    document.getElementById('wind-status').textContent = '发条已拧满！时光指针开始流转';
                    document.getElementById('restoration-status-text').textContent = '发条已上紧，指针重新流转！开始重建记忆连结 (100%)';
                    
                    if (svgContainer) {
                        svgContainer.style.filter = '';
                    }
                    
                    // Gear ticking sound effect loop
                    let ticks = 0;
                    const tickingInterval = setInterval(() => {
                        if (ticks > 4) {
                            clearInterval(tickingInterval);
                            this.transitionToStage('assemble');
                        } else {
                            audio.playTypewriterClick();
                            ticks++;
                        }
                    }, 150);
                }
            };

            crown.addEventListener('click', triggerWinding);

            // Finger dragging support
            let lastY = 0;
            crown.addEventListener('pointerdown', (e) => {
                lastY = e.clientY;
                crown.setPointerCapture(e.pointerId);
            });
            crown.addEventListener('pointermove', (e) => {
                if (crown.hasPointerCapture(e.pointerId)) {
                    const deltaY = Math.abs(e.clientY - lastY);
                    if (deltaY > 15) {
                        triggerWinding();
                        lastY = e.clientY;
                    }
                }
            });

            document.querySelector('.workspace-tip').textContent = '⚙️ 首部曲：多次点击或划动旋转右侧发条齿轮，为沉睡的时光表上发条以让指针转动起来';

        } else if (stage === 'assemble') {
            const assembleBreadcrumb = document.getElementById('stage-assemble');
            if (assembleBreadcrumb) assembleBreadcrumb.classList.add('active');

            document.getElementById('restoration-status-text').textContent = '脑海重回清朗！让我们顺着记忆的线索，拼拢这支离破碎的心意 (100%)';
            this.updateProgressBar(100);
            audio.playAwake(); // play level chime

            // Trigger visual full canvas sparkles
            const rect = this.targetZone.getBoundingClientRect();
            for (let i = 0; i < 5; i++) {
                setTimeout(() => {
                    this.celebration.burst(rect.width / 2 + (Math.random() - 0.5) * 80, rect.height / 2 + (Math.random() - 0.5) * 80, '#ffd700');
                }, i * 150);
            }

            // Hide tool cabinet, reveal assembly tray with animation
            toolCabinet.classList.add('hidden');
            assemblyTray.classList.remove('hidden');
            assemblyTray.classList.add('fade-slide-in');

            // 完成清洁，移除脉冲引导动画
            const blueprintArea = document.querySelector('.blueprint-area');
            if (blueprintArea) blueprintArea.classList.remove('clean-stage-active');

            // Ensure filters are completely cleared and blueprint is fully visible
            const svgContainer = document.getElementById('active-blueprint-svg');
            svgContainer.style.filter = 'none';
            svgContainer.style.opacity = '1';
            
            const darkMask = document.getElementById('lantern-darkness-mask');
            if (darkMask) darkMask.remove();

            document.querySelector('.workspace-tip').textContent = '🤝 二部曲：将零星的记忆线索拼凑归位，编织完整的关怀连结';
        }
    }

    onTargetZonePointerDown(e) {
        // 仅当不在蓝图交互区时，才阻止误触按钮等 UI 元素
        const path = e.composedPath ? e.composedPath() : e.path || [];
        const isBlueprintArea = path.some(el => el && el.classList && el.classList.contains('blueprint-area'));
        const isUI = !isBlueprintArea && path.some(el => el && el.tagName && (el.tagName === 'BUTTON' || el.tagName === 'A' || el.tagName === 'INPUT' || (el.classList && (el.classList.contains('shop-item-card') || el.classList.contains('modal')))));
        if (isUI) return; 
        if (this.currentRestorationStage !== 'clean') return;
        this.isRubbing = true;
        this._progressAtDown = this.restorationProgress; // 记录按下时的进度，用于检测单击
        this.lastX = e.clientX;
        this.lastY = e.clientY;
        this.lastTime = Date.now();
        this.hasTriggeredFogFact = false;
        if (e && e.pointerId !== undefined && typeof this.targetZone.setPointerCapture === 'function') {
            try {
                this.targetZone.setPointerCapture(e.pointerId);
            } catch (err) {
                console.warn("Pointer capture failed:", err);
            }
        }
        e.preventDefault();
    }

    onTargetZonePointerMove(e) {
        if (!this.isRubbing || this.currentRestorationStage === 'assemble') return;
        
        const rect = this.targetZone.getBoundingClientRect();
        const localX = e.clientX - rect.left;
        const localY = e.clientY - rect.top;

        // Ensure pointer is active within bounds or captured
        if (localX < -20 || localX > rect.width + 20 || localY < -20 || localY > rect.height + 20) {
            return;
        }

        // Calculate gesture speed & cleaner level
        const level = gameState.upgrades.cleaner.level;
        const tolerance = 1.0 + (level - 1) * 0.25; // Cleaner Level tolerance
        
        const now = Date.now();
        const dist = Math.hypot(e.clientX - this.lastX, e.clientY - this.lastY);
        const duration = Math.max(1, now - this.lastTime);
        const speed = dist / duration; // pixels per millisecond
        
        // Track gentleness: moving too fast violates geriatric nursing principles!
        if (speed > 1.45) {
            gameState.rubbedGentle = false;
        }

        // Altzheimer's Empathy dampening:
        // Moving too fast reduces clearing efficiency, representing gentle care.
        const dampening = Math.max(0.12, (1.0 - (speed / (1.2 * tolerance))) * (1.0 + (level - 1) * 0.2));
        
        this.restorationProgress += 1.4 * dampening;
        if (this.restorationProgress > 100) this.restorationProgress = 100;
        
        this.lastX = e.clientX;
        this.lastY = e.clientY;
        this.lastTime = now;
        
        const roundedProgress = Math.round(this.restorationProgress);
        
        if (this.currentRestorationStage === 'clean') {
            // Sweep gray dust particles (representing cognitive haze scattering away)
            if (Math.random() < 0.28) {
                this.celebration.burst(localX, localY, '#cfcfcf');
                audio.playTypewriterClick();
            }

            const dustEl = document.getElementById('blueprint-dust-overlay');
            if (dustEl) {
                dustEl.style.opacity = `${(100 - roundedProgress) / 100}`;
            }

            this.updateProgressBar(roundedProgress);
            document.getElementById('restoration-status-text').textContent = `正在轻拂，拨开认知迷雾... (迷雾消散: ${roundedProgress}%)`;

            // Trigger cognitive clearance facts
            if (this.restorationProgress > 30 && !this.hasTriggeredFogFact) {
                this.hasTriggeredFogFact = true;
                
                // Spawn Poetic Floating Toast with Altzheimer's fact
                const toast = document.createElement('div');
                toast.className = 'poetic-toast';
                toast.style.borderColor = 'var(--accent-gold)';
                toast.innerHTML = safeHTML(`
                    <div class="toast-glow"></div>
                    <div class="toast-content">
                        <span class="toast-part-name" style="color: var(--accent-gold);">💡 脑康复科普 💡</span>
                        <p class="toast-part-hint" style="font-size: 0.88rem; line-height: 1.5;">反复进行温和、有节奏的轻抹能有效激活大脑体感皮层，增强老年患者的手脑视协调用力，有效延缓神经突触的退化萎缩！</p>
                    </div>
                `);
                document.body.appendChild(toast);
                setTimeout(() => {
                    toast.classList.add('fade-out');
                    setTimeout(() => toast.remove(), 800);
                }, 4500);
            }

            if (this.restorationProgress >= 100) {
                this.isRubbing = false;
                this.transitionToStage('assemble');
            }
        }
    }

    onTargetZonePointerUp() {
        // 单击支援：如果用户只是点击而未拖动，仍给予少量进度反馈
        if (this.isRubbing && this.restorationProgress < 5 && this.restorationProgress === (this._progressAtDown || 0)) {
            this.restorationProgress = Math.min(this.restorationProgress + 8, 100);
            this.updateProgressBar(this.restorationProgress);
            const dustEl = document.getElementById('blueprint-dust-overlay');
            if (dustEl) dustEl.style.opacity = `${(100 - this.restorationProgress) / 100}`;
            document.getElementById('restoration-status-text').textContent = 
                `💡 提示：请在左侧画框内【按住拖拽轻扫】以驱散迷雾，拖得越温柔效果越好 (${Math.round(this.restorationProgress)}%)`;
            audio.playHover();
        }
        this.isRubbing = false;
    }

    dragStart(e, element, partData) {
        // 仅当点击目标不属于拖拽零件本身或其子元素时，才检查是否误触 UI
        const path = e.composedPath ? e.composedPath() : e.path || [];
        const isDraggableArea = path.some(el => el && el.classList && el.classList.contains('draggable-part'));
        const isUI = !isDraggableArea && path.some(el => el && el.tagName && (el.tagName === 'BUTTON' || el.tagName === 'A' || el.tagName === 'INPUT' || (el.classList && (el.classList.contains('glass-panel') || el.classList.contains('shop-item-card') || el.classList.contains('modal')))));
        if (isUI) return; 
        // 🔑 多指防御：如果已有拖拽元素正在进行，直接拦截第二根手指的事件，防止坐标被覆写
        if (gameState.draggedElement) return;
        // Prevent assembly drag if we are in clean/polish stages!
        if (this.currentRestorationStage !== 'assemble') return;
        if (element.classList.contains('snapped-hidden')) return;

        // 🔑 阻止原生系统手势（如滑屏回弹、双击缩放等）
        if (e.cancelable) {
            e.preventDefault();
        }
        
        gameState.activeDragPart = partData;
        gameState.draggedElement = element;
        element.style.cursor = 'grabbing';
        element.style.transition = 'none';
        element.style.transform = 'scale(3.0)';
        
        audio.playGrab();
        
        // 🔑 统一坐标获取：使用 getCoords 处理 Touch/Pointer/Mouse 事件
        const coords = getCoords(e);
        gameState.startX = coords.clientX;
        gameState.startY = coords.clientY;
        gameState.startLeft = parseInt(element.style.left) || 0;
        gameState.startTop = parseInt(element.style.top) || 0;
        
        // 捕获指针，确保手机端手指移出元素后仍能收到 pointermove/pointerup
        if (e.pointerId !== undefined && typeof element.setPointerCapture === 'function') {
            try {
                element.setPointerCapture(e.pointerId);
            } catch (err) {
                console.warn('setPointerCapture failed:', err);
            }
        }
        
        element.style.zIndex = '9999'; /* 🔑 动态堆叠：拖拽时永远悬浮在最顶层 */

        // 🔑 Pointer Events 生命周期事件绑定：仅在拖拽开始时绑定，并在拖拽结束时卸载
        this._activeDragMove = (evt) => this.dragMove(evt);
        this._activeDragEnd = (evt) => this.dragEnd(evt);

        document.addEventListener('pointermove', this._activeDragMove, { passive: false });
        document.addEventListener('pointerup', this._activeDragEnd);
        document.addEventListener('pointercancel', this._activeDragEnd);
    }

    dragMove(e) {
        // 仅当不在拖拽零件区域时，才阻止误触 UI
        const path = e.composedPath ? e.composedPath() : e.path || [];
        const isDraggableArea = path.some(el => el && el.classList && el.classList.contains('draggable-part'));
        const isUI = !isDraggableArea && path.some(el => el && el.tagName && (el.tagName === 'BUTTON' || el.tagName === 'A' || el.tagName === 'INPUT' || (el.classList && (el.classList.contains('glass-panel') || el.classList.contains('shop-item-card') || el.classList.contains('modal')))));
        if (isUI) return; 
        if (!gameState.draggedElement || !gameState.activeDragPart) return;

        // 🔑 强制拦截 iOS Safari / WebView 页面级滚动干扰
        if (e.cancelable) {
            e.preventDefault();
        }

        const coords = getCoords(e);
        const deltaX = coords.clientX - gameState.startX;
        const deltaY = coords.clientY - gameState.startY;
        
        const targetLeft = gameState.startLeft + deltaX;
        const targetTop = gameState.startTop + deltaY;
        
        // 🔑 requestAnimationFrame 节流渲染：确保 60fps / 120fps 高刷屏性能不掉帧，消除卡顿
        if (!this.rafPending) {
            this.rafPending = true;
            requestAnimationFrame(() => {
                const el = gameState.draggedElement;
                if (el) {
                    el.style.left = `${targetLeft}px`;
                    el.style.top = `${targetTop}px`;
                    // 开启 GPU 3D 渲染加速
                    el.style.transform = 'scale(3.0) translate3d(0, 0, 0)';
                    
                    this.checkProximityGlow(coords.clientX, coords.clientY);
                }
                this.rafPending = false;
            });
        }
    }

    checkProximityGlow(clientX, clientY) {
        const part = gameState.activeDragPart;
        const slotRectEl = document.getElementById(`slot-rect-${part.id}`);
        if (!slotRectEl) return;
        
        const slotRect = slotRectEl.getBoundingClientRect();
        const slotCenterX = slotRect.left + slotRect.width / 2;
        const slotCenterY = slotRect.top + slotRect.height / 2;
        
        const distance = Math.hypot(clientX - slotCenterX, clientY - slotCenterY);
        
        if (distance < 95) {
            slotRectEl.classList.add('slot-active');
            slotRectEl.style.stroke = 'var(--accent-rose)';
            slotRectEl.style.filter = 'drop-shadow(0 0 10px var(--accent-rose))';
        } else {
            slotRectEl.classList.remove('slot-active');
            slotRectEl.style.stroke = 'var(--accent-gold)';
            slotRectEl.style.filter = 'none';
        }
    }

    dragEnd(e) {
        if (!gameState.draggedElement || !gameState.activeDragPart) return;
        
        const el = gameState.draggedElement;
        const part = gameState.activeDragPart;

        // 🔑 动态生命周期卸载：彻底终结事件流回调
        if (this._activeDragMove) {
            document.removeEventListener('pointermove', this._activeDragMove);
            this._activeDragMove = null;
        }
        if (this._activeDragEnd) {
            document.removeEventListener('pointerup', this._activeDragEnd);
            document.removeEventListener('pointercancel', this._activeDragEnd);
            this._activeDragEnd = null;
        }

        // 🔑 pointercancel 鲁棒性处理：系统手势中断时直接弹性复位
        if (!e || e.type === 'pointercancel' || e.type === 'touchcancel') {
            el.style.transition = 'all 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275)';
            el.style.left = `${gameState.startLeft}px`;
            el.style.top = `${gameState.startTop}px`;
            el.style.transform = `rotate(${(Math.random() - 0.5) * 10}deg) scale(1.0)`;
            el.style.zIndex = '1'; /* cancel: 复位至底层 */
            el.style.cursor = 'grab';
            gameState.draggedElement = null;
            gameState.activeDragPart = null;
            return;
        }
        
        // Check alignment with Blueprint Target Slot
        const slotRectEl = document.getElementById(`slot-rect-${part.id}`);
        const slotRect = slotRectEl.getBoundingClientRect();
        const elRect = el.getBoundingClientRect();
        
        const slotCenterX = slotRect.left + slotRect.width / 2;
        const slotCenterY = slotRect.top + slotRect.height / 2;
        
        // Compute precise visual center of the sub-component path inside the draggable element
        const scaleFactor = elRect.width / 200;
        const componentCenterX = elRect.left + (part.targetX + part.w / 2) * scaleFactor;
        const componentCenterY = elRect.top + (part.targetY + part.h / 2) * scaleFactor;
        
        const distance = Math.hypot(componentCenterX - slotCenterX, componentCenterY - slotCenterY);
        
        // 🔑 响应式相对吸附阈值：基于容器宽度的百分比，任何分辨率手感一致
        const blueprintInner = document.querySelector('.blueprint-inner');
        const containerWidth = blueprintInner ? blueprintInner.offsetWidth : 300;
        const snapThreshold = containerWidth * 0.22; // 22% 容器宽度 ≈ 移动端手指精度最优解

        if (distance < snapThreshold) {
            // 1. Success snap lock!
            el.classList.add('snapped-hidden');
            
            const slotGroup = document.getElementById(`slot-${part.id}`);
            slotGroup.innerHTML = safeHTML(`<g class="colored-shape" filter="drop-shadow(0 0 12px var(--accent-gold-glow))">${part.svg}</g>`);
            
            audio.playSnap();
            
            const workspaceRect = this.targetZone.getBoundingClientRect();
            const localX = slotCenterX - workspaceRect.left;
            const localY = slotCenterY - workspaceRect.top;
            this.celebration.burst(localX, localY, '#e5a93b');
            
            const tipEl = document.querySelector('.workspace-tip');
            if (tipEl) {
                tipEl.innerHTML = safeHTML(`✨ 已修复【${escapeTextForHTML(part.name)}】：${escapeTextForHTML(part.hint)}`);
            }

            const toast = document.createElement('div');
            toast.className = 'poetic-toast';
            toast.innerHTML = safeHTML(`
                <div class="toast-glow"></div>
                <div class="toast-content">
                    <span class="toast-part-name">✨ 已归位 · ${escapeTextForHTML(part.name)} ✨</span>
                    <p class="toast-part-hint">${escapeTextForHTML(part.hint)}</p>
                </div>
            `);
            document.body.appendChild(toast);
            
            setTimeout(() => {
                toast.classList.add('fade-out');
                setTimeout(() => toast.remove(), 800);
            }, 2600);

            gameState.snappedCount++;
            
            if (gameState.snappedCount === gameState.totalPartsCount) {
                this.scheduleAwakeTimer(() => this.triggerObjectAwake(), 900);
            }
        } else {
            // Fail rebound - elastic bounce back
            el.style.transition = 'all 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275)';
            const randX = Math.random() * (this.trayZone.clientWidth - 140) + 10;
            const randY = Math.random() * (this.trayZone.clientHeight - 140) + 10;
            
            el.style.left = `${randX}px`;
            el.style.top = `${randY}px`;
            el.style.transform = `rotate(${(Math.random() - 0.5) * 15}deg) scale(1.0)`;
            el.style.zIndex = '1'; /* fail: 弹回托盘，重置至底层 */
            
            slotRectEl.classList.remove('slot-active');
        }
        
        el.style.cursor = 'grab';
        gameState.draggedElement = null;
        gameState.activeDragPart = null;
    }

    triggerObjectAwake() {
        // Play epic awake sweep arpeggio
        audio.playAwake();
        
        // Trigger fullscreen sparkles on target zone
        const innerRect = this.targetZone.getBoundingClientRect();
        for (let i = 0; i < 4; i++) {
            this.scheduleAwakeTimer(() => {
                const rx = Math.random() * innerRect.width;
                const ry = Math.random() * innerRect.height;
                this.celebration.burst(rx, ry, i % 2 === 0 ? '#e5a93b' : '#d48a85');
            }, i * 200);
        }
        
        // Transition after 1 second delay to narrative panel
        this.scheduleAwakeTimer(() => {
            if (gameState.currentScreen !== 'screen-workspace') return;
            showAwakeNarrative(this.activeBlueprintId);
        }, 1200);
    }
}

function setupInteractiveToy(itemId) {
    const toyWrapper = document.getElementById('interactive-toy-wrapper');
    const toyRadio = document.getElementById('toy-radio');
    const toyCamera = document.getElementById('toy-camera');
    const toySewing = document.getElementById('toy-sewing');
    const toyLantern = document.getElementById('toy-lantern');
    const toyWatch = document.getElementById('toy-watch');
    const toyRuntime = (typeof workbench !== 'undefined' && workbench) ? workbench : window;
    if (toyRuntime && typeof toyRuntime.cleanupActiveRuntime === 'function') {
        toyRuntime.cleanupActiveRuntime();
    }

    // Reset showcase status labels
    const label = document.querySelector('.item-awakened-label');
    if (label) {
        label.textContent = "✨ 器物苏醒 · 情感互动 ✨";
    }

    // Reveal wrapper and hide all sub-toys first
    toyWrapper.classList.remove('hidden');
    toyRadio.classList.add('hidden');
    toyCamera.classList.add('hidden');
    toySewing.classList.add('hidden');
    if (toyLantern) toyLantern.classList.add('hidden');
    if (toyWatch) toyWatch.classList.add('hidden');

    // Clean any running synth sounds
    audio.stopRadioStatic();
    audio.stopRadioMelody();
    audio.stopSewingLoop();

    if (itemId === 'radio') {
        toyRadio.classList.remove('hidden');
        const slider = document.getElementById('radio-tuning-slider');
        const valText = document.getElementById('current-frequency-val');
        const pointer = document.getElementById('tuning-pointer-element');
        toyRuntime._radioSlider = slider;
        
        slider.value = 90.0;
        valText.textContent = "90.0";
        pointer.style.left = "0%";

        let wasMelodyPlaying = false;
        
        // Start metallic analog static hum immediately
        audio.startRadioStatic();
        audio.setRadioStaticVolume(0.32);

        slider.oninput = (e) => {
            const val = parseFloat(e.target.value);
            valText.textContent = val.toFixed(1);
            
            // Map 90.0MHz-106.0MHz into 0%-100% ruler width
            const percent = ((val - 90.0) / 16.0) * 100.0;
            pointer.style.left = `${percent}%`;

            // Proximity thresholds with golden window upgrades
            const tunerLvl = gameState.upgrades.tuner.level || 1;
            const threshold = 0.2 + (tunerLvl - 1) * 0.08;

            const dist935 = Math.abs(val - 93.5);
            const dist987 = Math.abs(val - 98.7);
            const dist1024 = Math.abs(val - 102.4);

            if (dist987 < threshold) {
                // Tuned to Grandma's Favorite Song station! (98.7MHz)
                audio.setRadioStaticVolume(0.01);
                if (!wasMelodyPlaying) {
                    audio.stopOperaMelody();
                    audio.stopNewsBroadcast();
                    audio.playRadioMelody();
                    wasMelodyPlaying = true;
                    pointer.style.background = "#00ffcc";
                    pointer.style.boxShadow = "0 0 15px #00ffcc, 0 0 25px #00ffcc";
                    
                    // Trigger Science Fact
                    triggerRadioFact("folk_rehab");
                }
            } else if (dist935 < threshold) {
                // Tuned to Opera station! (93.5MHz)
                audio.setRadioStaticVolume(0.01);
                if (!wasMelodyPlaying) {
                    audio.stopRadioMelody();
                    audio.stopNewsBroadcast();
                    audio.playOperaMelody();
                    wasMelodyPlaying = true;
                    pointer.style.background = "#ffd700";
                    pointer.style.boxShadow = "0 0 15px #ffd700, 0 0 25px #ffd700";
                    
                    // Trigger Science Fact
                    triggerRadioFact("opera_rehab");
                }
            } else if (dist1024 < threshold) {
                // Tuned to News station! (102.4MHz)
                audio.setRadioStaticVolume(0.01);
                if (!wasMelodyPlaying) {
                    audio.stopRadioMelody();
                    audio.stopOperaMelody();
                    audio.playNewsBroadcast();
                    wasMelodyPlaying = true;
                    pointer.style.background = "#ff9500";
                    pointer.style.boxShadow = "0 0 15px #ff9500, 0 0 25px #ff9500";
                    
                    // Trigger Science Fact
                    triggerRadioFact("news_rehab");
                }
            } else {
                wasMelodyPlaying = false;
                audio.stopRadioMelody();
                audio.stopOperaMelody();
                audio.stopNewsBroadcast();
                pointer.style.background = "#ff3b30";
                pointer.style.boxShadow = "0 0 10px #ff3b30, 0 0 15px #ff3b30";

                // Adjust static hum dynamically based on distance to nearest station
                const minDist = Math.min(dist935, dist987, dist1024);
                const staticVol = Math.min(1.0, minDist * 1.6);
                audio.setRadioStaticVolume(staticVol);
            }
        };

    } else if (itemId === 'camera') {
        toyCamera.classList.remove('hidden');
        const btn = document.getElementById('btn-camera-shutter');
        const frame = document.getElementById('photo-frame-polaroid');
        const sketch = document.getElementById('photo-sketch-container');
        toyRuntime._cameraButton = btn;

        frame.classList.add('hidden');
        sketch.innerHTML = safeHTML('');

        btn.onclick = () => {
            audio.playCameraShutter();
            
            // Apply shutter visual flash overlay to body
            document.body.classList.add('camera-flash-active');
            setTimeout(() => {
                document.body.classList.remove('camera-flash-active');
            }, 300);

            // Vector drawing family sketch on Polaroid film
            sketch.innerHTML = safeHTML(`
            <svg viewBox="0 0 100 100" width="100%" height="100%">
                <rect x="0" y="0" width="100%" height="100%" fill="#ece3d5"/>
                <!-- Sun outline -->
                <circle cx="78" cy="22" r="7" fill="none" stroke="#6b5344" stroke-width="1.2"/>
                <line x1="78" y1="12" x2="78" y2="15" stroke="#6b5344" stroke-width="0.8"/>
                <line x1="78" y1="29" x2="78" y2="32" stroke="#6b5344" stroke-width="0.8"/>
                <line x1="68" y1="22" x2="71" y2="22" stroke="#6b5344" stroke-width="0.8"/>
                <line x1="85" y1="22" x2="88" y2="22" stroke="#6b5344" stroke-width="0.8"/>

                <!-- Grandma and Grandpa outlines -->
                <circle cx="38" cy="52" r="6" fill="none" stroke="#6b5344" stroke-width="1.2"/>
                <path d="M 26,82 Q 26,65 38,65 Q 50,65 50,82" fill="none" stroke="#6b5344" stroke-width="1.2"/>
                
                <circle cx="62" cy="49" r="6" fill="none" stroke="#6b5344" stroke-width="1.2"/>
                <path d="M 50,82 Q 50,62 62,62 Q 74,62 74,82" fill="none" stroke="#6b5344" stroke-width="1.2"/>
                
                <!-- Tiny heart representing enduring love -->
                <path d="M 50,42 C 48,38 52,38 50,42" fill="#d48a85" stroke="#6b5344" stroke-width="0.5"/>
                
                <!-- Rolling Sepia hills -->
                <path d="M -10,88 Q 30,76 60,86 Q 80,78 110,88" fill="none" stroke="#6b5344" stroke-width="1.2"/>
            </svg>
            `);
            
            frame.classList.remove('hidden');
            audio.playSnap();
        };

    } else if (itemId === 'sewing') {
        toySewing.classList.remove('hidden');
        const btn = document.getElementById('btn-sewing-pedal');
        const counterText = document.getElementById('sewing-stitch-count');
        const fill = document.getElementById('sewing-progress-bar-fill');
        
        // 🔑 清理上一次的缝纫机状态防止监听器泄漏
        audio.stopSewingLoop();
        if (toyRuntime._sewingInterval) { clearInterval(toyRuntime._sewingInterval); toyRuntime._sewingInterval = null; }
        
        let count = 0;
        counterText.textContent = "0";
        fill.style.width = "0%";

        let timer = null;
        let isSewing = false;

        let lastClickTime = 0;
        let comboCount = 0;
        const maxInterval = 1200 + (gameState.upgrades.stitch.level - 1) * 200; // Stitch level increases window
        
        // Dynamic flywheel rotation helper
        const rotateFlywheel = (advPercent) => {
            const svgEl = document.querySelector('#narrative-item-showcase svg');
            if (svgEl) {
                const angle = Math.round((advPercent * 3.6) % 360);
                const wheelGroup = svgEl.querySelector('circle[cx="168"]')?.parentNode;
                if (wheelGroup) {
                    wheelGroup.setAttribute('transform', `rotate(${angle}, 168, 78)`);
                }
            }
        };

        const executeStitch = (amount) => {
            if (count >= 100) return;
            count += amount;
            if (count > 100) count = 100;
            counterText.textContent = count;
            fill.style.width = `${count}%`;
            
            rotateFlywheel(count);

            if (count >= 100) {
                stopSewing();
                audio.playSnap();
                
                // Awaken label update
                if (label) {
                    label.textContent = "✨ 红棉袄织成 ✨";
                }
            }
        };

        // Rhythmic tap click handler
        btn.onclick = (e) => {
            e.preventDefault();
            if (count >= 100) return;
            
            const now = Date.now();
            const interval = now - lastClickTime;
            
            if (interval < maxInterval) {
                comboCount++;
                if (comboCount >= 4 && comboCount % 4 === 0) {
                    // Trigger Science fact
                    triggerStitchFact();
                }
            } else {
                comboCount = 1;
            }
            lastClickTime = now;
            gameState.lastMaxCombo = Math.max(gameState.lastMaxCombo || 0, comboCount);
            
            // Speed boost with Combo
            const amount = 3 + Math.min(6, comboCount);
            executeStitch(amount);
            
            // Visual combo label inside status bar
            const statusDiv = document.querySelector('.sewing-machine-status');
            let comboIndicator = document.getElementById('sewing-combo-indicator');
            if (!comboIndicator) {
                comboIndicator = document.createElement('div');
                comboIndicator.id = 'sewing-combo-indicator';
                comboIndicator.style.color = 'var(--accent-rose)';
                comboIndicator.style.fontSize = '0.95rem';
                comboIndicator.style.fontWeight = 'bold';
                comboIndicator.style.marginTop = '6px';
                statusDiv.appendChild(comboIndicator);
            }
            
            if (comboCount > 1) {
                comboIndicator.innerHTML = `🔥 突触高能连击: ${comboCount} Combo <span style="color: var(--accent-gold); font-size: 0.8rem;">(E共情力倍数: x${(1.0 + comboCount * 0.15).toFixed(2)})</span>`;
                audio.playTypewriterClick();
            } else {
                comboIndicator.textContent = '';
            }
        };

        // Long press holding fallback (slow but steady)
        const startSewing = (e) => {
            e.preventDefault();
            if (isSewing || count >= 100) return;
            isSewing = true;
            audio.startSewingLoop();
            
            timer = setInterval(() => {
                executeStitch(3); // Slow linear stitching
            }, 120);
            toyRuntime._sewingInterval = timer;
        };

        const stopSewing = () => {
            if (!isSewing) return;
            isSewing = false;
            audio.stopSewingLoop();
            if (timer) {
                clearInterval(timer);
                timer = null;
            }
            if (toyRuntime._sewingInterval) {
                clearInterval(toyRuntime._sewingInterval);
                toyRuntime._sewingInterval = null;
            }
        };

        // Pointer gestures for tactile feedback
        toyRuntime._sewingButton = btn;
        btn.onpointerdown = startSewing;
        btn.onpointerup = stopSewing;
        btn.onpointerleave = stopSewing;
        btn.onpointercancel = stopSewing;
    } else if (itemId === 'lantern') {
        const toyLantern = document.getElementById('toy-lantern');
        toyLantern.classList.remove('hidden');
        const slider = document.getElementById('lantern-intensity-slider');
        const valText = document.getElementById('lantern-intensity-val');
        const indicator = document.querySelector('.lantern-visual-indicator');
        
        slider.value = 30;
        valText.textContent = "30";
        indicator.style.background = "rgba(229, 169, 59, 0.3)";
        indicator.style.boxShadow = "0 0 30px rgba(229, 169, 59, 0.3)";

        // Clear existing clean-up hooks to prevent listener piling/leaking
        if (toyRuntime._lanternCleanup) {
            toyRuntime._lanternCleanup();
            toyRuntime._lanternCleanup = null;
        }

        // 🕯️ Gyroscope / DeviceOrientation sensor physics integration
        const handleOrientation = (event) => {
            let tiltX = event.gamma || 0; //左右倾斜
            let tiltY = event.beta || 0;  //前后倾斜
            
            tiltX = Math.max(-45, Math.min(45, tiltX));
            tiltY = Math.max(-45, Math.min(45, tiltY));

            const svgEl = document.querySelector('#narrative-item-showcase svg');
            if (svgEl) {
                const flames = svgEl.querySelectorAll('path[fill^="#ff"]');
                flames.forEach(f => {
                    f.style.transformOrigin = "50% 100%";
                    f.style.transform = `skewX(${tiltX * 0.4}deg) rotate(${tiltX * 0.25}deg)`;
                });
            }
            
            // If tilted too far, trigger warnings and degrade intensity
            const absoluteTilt = Math.abs(tiltX) + Math.abs(tiltY);
            if (absoluteTilt > 40) {
                const currentVal = parseInt(slider.value);
                const degradedVal = Math.max(10, currentVal - 15);
                valText.textContent = `${degradedVal}% (⚠️ 马灯剧烈摇摆)`;
                indicator.style.background = "rgba(212, 138, 133, 0.5)";
                indicator.style.boxShadow = "0 0 30px rgba(212, 138, 133, 0.6)";
            }
        };
        
        // Desktop pointer fallback for testing on non-sensor devices
        const handlePointerSim = (e) => {
            const width = window.innerWidth;
            const clientX = e.clientX;
            const percentX = (clientX / width) - 0.5; // -0.5 to 0.5
            const simTilt = percentX * 60; // -30 to 30

            const svgEl = document.querySelector('#narrative-item-showcase svg');
            if (svgEl) {
                const flames = svgEl.querySelectorAll('path[fill^="#ff"]');
                flames.forEach(f => {
                    f.style.transformOrigin = "50% 100%";
                    f.style.transform = `skewX(${simTilt * 0.35}deg) rotate(${simTilt * 0.2}deg)`;
                });
            }
        };

        // iOS 13+ 需要用户主动授权 DeviceOrientation
        if (typeof DeviceOrientationEvent !== 'undefined' &&
            typeof DeviceOrientationEvent.requestPermission === 'function') {
            // 显示授权引导提示
            const btnGrant = createButtonElement();
            btnGrant.textContent = '🔓 点此开启陀螺仪感应';
            btnGrant.style.cssText = 'margin:8px 0; padding:8px 18px; border-radius:20px; background:var(--accent-gold); color:#1c1815; border:none; font-weight:bold; cursor:pointer;';
            toyRuntime._lanternPermissionButton = btnGrant;
            btnGrant.onclick = async () => {
                try {
                    const permission = await DeviceOrientationEvent.requestPermission();
                    if (permission === 'granted') {
                        window.addEventListener('deviceorientation', handleOrientation);
                        btnGrant.textContent = '✅ 陀螺仪已开启！晃动手机试试';
                        btnGrant.disabled = true;
                    }
                } catch (err) {
                    console.warn('DeviceOrientation permission denied:', err);
                    btnGrant.textContent = '⚠️ 权限被拒绝，将使用滑鼠模拟';
                }
            };
            toyLantern.querySelector('.toy-instructions')?.insertAdjacentElement('beforebegin', btnGrant);
        } else {
            // Android / Desktop: 直接添加监听
            window.addEventListener('deviceorientation', handleOrientation);
        }
        window.addEventListener('pointermove', handlePointerSim);

        // 使用实例属性管理清理，而非全局变量
        toyRuntime._lanternCleanup = () => {
            window.removeEventListener('deviceorientation', handleOrientation);
            window.removeEventListener('pointermove', handlePointerSim);
        };

        toyRuntime._lanternSlider = slider;
        slider.oninput = (e) => {
            const val = parseInt(e.target.value);
            valText.textContent = val + "%";
            
            // Adjust glowing indicators
            const alpha = val / 100;
            indicator.style.background = `rgba(229, 169, 59, ${alpha})`;
            indicator.style.boxShadow = `0 0 ${val * 1.2}px rgba(229, 169, 59, ${alpha * 0.9})`;
            
            // Link to main showcase opacity & drop shadow brightness
            const svgEl = document.querySelector('#narrative-item-showcase svg');
            if (svgEl) {
                // Glow fire flame inside SVG
                const flames = svgEl.querySelectorAll('path[fill^="#ff"]');
                flames.forEach(f => {
                    f.style.opacity = `${0.3 + alpha * 0.7}`;
                });
            }

            if (val >= 80) {
                const label = document.querySelector('.item-awakened-label');
                if (label) {
                    label.textContent = "🕯 马灯长明 · 温暖永驻 🕯";
                }
            } else {
                const label = document.querySelector('.item-awakened-label');
                if (label) {
                    label.textContent = "✨ 器物苏醒 · 情感互动 ✨";
                }
            }
        };
    } else if (itemId === 'watch') {
        const toyWatch = document.getElementById('toy-watch');
        toyWatch.classList.remove('hidden');
        const btnWind = document.getElementById('btn-wind-crown');
        const countText = document.getElementById('watch-spring-val');
        const gearIcon = document.getElementById('watch-gear-indicator');
        
        let springVal = 0;
        countText.textContent = "0";
        gearIcon.style.transform = "rotate(0deg)";

        // Stop previous tick intervals
        if (toyRuntime.watchTickInterval) {
            clearInterval(toyRuntime.watchTickInterval);
            toyRuntime.watchTickInterval = null;
        }

        const windAction = () => {
            if (springVal >= 100) return;
            
            springVal += 5;
            if (springVal > 100) springVal = 100;
            
            countText.textContent = springVal;
            gearIcon.style.transform = `rotate(${springVal * 7.2}deg)`;
            
            // Animate SVG gears dynamically
            const svgEl = document.querySelector('#narrative-item-showcase svg');
            if (svgEl) {
                const gears = svgEl.querySelectorAll('g');
                if (gears.length >= 2) {
                    // Big gear rotates clockwise
                    gears[0].setAttribute('transform', `rotate(${springVal * 1.8}, 85, 95)`);
                    // Small gear rotates counter-clockwise
                    gears[1].setAttribute('transform', `rotate(${-springVal * 2.8}, 115, 108)`);
                }
            }
            
            audio.playTypewriterClick();

            if (springVal >= 100) {
                audio.playAwake();
                const label = document.querySelector('.item-awakened-label');
                if (label) {
                    label.textContent = "🕰 时光流转 · 齿轮永恒 🕰";
                }

                // Tick tock perpetual heartbeat motion!
                let tickCount = 0;
                toyRuntime.watchTickInterval = setInterval(() => {
                    tickCount = (tickCount + 6) % 360;
                    
                    // Rotate the watch hands group
                    const svgElCurrent = document.querySelector('#narrative-item-showcase svg');
                    if (svgElCurrent) {
                        const groups = svgElCurrent.querySelectorAll('g');
                        if (groups.length >= 4) {
                            // Rotate hands (the 4th group, index 3)
                            groups[3].setAttribute('transform', `rotate(${tickCount}, 100, 100)`);
                        }
                    }
                    
                    // Mechanical soft heartbeat tick
                    audio.playTypewriterClick();
                }, 1000);
            }
        };

        toyRuntime._watchButton = btnWind;
        btnWind.onclick = windAction;
    }
}

let radioFactTriggered = new Set();
let stitchFactTriggered = false;

function triggerRadioFact(type) {
    if (radioFactTriggered.has(type)) return;
    radioFactTriggered.add(type);
    
    let text = "";
    if (type === "opera_rehab") {
        text = "📻 怀旧声学疗法：研究表明，青年时期的熟识曲调能唤醒患者的颞听觉皮层与内听觉记忆，降低皮质醇等压力荷尔蒙，带来极强的精神安抚作用！";
    } else if (type === "folk_rehab") {
        text = "🎵 音乐干预机制：优美轻缓的声波运动能有效激活脑部边缘系统（Limbic System），对缓解阿尔茨海默病患者的焦虑与烦躁极有成效！";
    } else {
        text = "📢 记忆时空定位：带有时代历史感的播音对阿尔茨海默病患者起到‘神经定位锚点’的作用，能够辅助大脑重建现实世界的信息连结！";
    }
    
    const toast = document.createElement('div');
    toast.className = 'poetic-toast';
    toast.style.borderColor = 'var(--accent-gold)';
    toast.innerHTML = safeHTML(`
        <div class="toast-glow"></div>
        <div class="toast-content">
            <span class="toast-part-name" style="color: var(--accent-gold);">📻 脑康复声波干预 📻</span>
            <p class="toast-part-hint" style="font-size: 0.88rem; line-height: 1.5;">${escapeTextForHTML(text)}</p>
        </div>
    `);
    document.body.appendChild(toast);
    setTimeout(() => {
        toast.classList.add('fade-out');
        setTimeout(() => toast.remove(), 800);
    }, 4500);
}

function triggerStitchFact() {
    if (stitchFactTriggered) return;
    stitchFactTriggered = true;
    
    const toast = document.createElement('div');
    toast.className = 'poetic-toast';
    toast.style.borderColor = 'var(--accent-gold)';
    toast.innerHTML = safeHTML(`
        <div class="toast-glow"></div>
        <div class="toast-content">
            <span class="toast-part-name" style="color: var(--accent-gold);">💡 脑部科学运动 💡</span>
            <p class="toast-part-hint" style="font-size: 0.88rem; line-height: 1.5;">突触微运动：连续、有节奏的手动点击能深度调动患者的眼手协调运动区，有助于激活受损的脑部神经通路，阻断认知障碍恶化！</p>
        </div>
    `);
    document.body.appendChild(toast);
    setTimeout(() => {
        toast.classList.add('fade-out');
        setTimeout(() => toast.remove(), 800);
    }, 4500);
}

function updateShopUI() {
    const shopBal = document.getElementById('shop-silver-balance');
    if (shopBal) {
        shopBal.textContent = gameState.memorySilver;
    }
    
    const cleanerLvl = document.getElementById('upgrade-cleaner-lvl');
    const tunerLvl = document.getElementById('upgrade-tuner-lvl');
    const stitchLvl = document.getElementById('upgrade-stitch-lvl');
    
    if (cleanerLvl) cleanerLvl.textContent = gameState.upgrades.cleaner.level;
    if (tunerLvl) tunerLvl.textContent = gameState.upgrades.tuner.level;
    if (stitchLvl) stitchLvl.textContent = gameState.upgrades.stitch.level;
    
    const cleanerCost = economyManager.getUpgradeCost(gameState.upgrades.cleaner.baseCost, gameState.upgrades.cleaner.level);
    const tunerCost = economyManager.getUpgradeCost(gameState.upgrades.tuner.baseCost, gameState.upgrades.tuner.level);
    const stitchCost = economyManager.getUpgradeCost(gameState.upgrades.stitch.baseCost, gameState.upgrades.stitch.level);
    
    const cleanerCostText = document.getElementById('upgrade-cleaner-cost');
    const tunerCostText = document.getElementById('upgrade-tuner-cost');
    const stitchCostText = document.getElementById('upgrade-stitch-cost');
    
    if (cleanerCostText) cleanerCostText.textContent = cleanerCost;
    if (tunerCostText) tunerCostText.textContent = tunerCost;
    if (stitchCostText) stitchCostText.textContent = stitchCost;
}

function getModalFocusTarget(overlay) {
    return overlay.querySelector('[autofocus], button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])');
}

function focusElementSafely(el) {
    if (!el || typeof el.focus !== 'function') return;
    try {
        el.focus({ preventScroll: true });
    } catch (err) {
        el.focus();
    }
}

function focusModalIfNeeded(overlay) {
    if (!overlay || !overlay.classList.contains('active')) return;
    if (overlay.contains(document.activeElement)) return;
    focusElementSafely(getModalFocusTarget(overlay));
}

function restoreModalFocus(previousFocus, overlay) {
    if (!previousFocus || !previousFocus.isConnected) return;
    if (previousFocus !== document.body && previousFocus.getClientRects && previousFocus.getClientRects().length === 0) return;
    var active = document.activeElement;
    var focusWasReclaimedByScreen = active && active.classList && active.classList.contains('game-screen');
    var focusStillInClosingModal = overlay && overlay.contains(active);
    if (active && active !== document.body && !focusWasReclaimedByScreen && !focusStillInClosingModal) return;
    focusElementSafely(previousFocus);
}

function setModalOpen(overlay, isOpen, returnFocusEl) {
    if (!overlay) return;
    if (isOpen) overlay._previousFocus = returnFocusEl || document.activeElement;
    overlay.classList.toggle('active', Boolean(isOpen));
    overlay.setAttribute('aria-hidden', isOpen ? 'false' : 'true');
    if (isOpen) {
        focusModalIfNeeded(overlay);
        requestAnimationFrame(function() { focusModalIfNeeded(overlay); });
        setTimeout(function() { focusModalIfNeeded(overlay); }, 80);
        setTimeout(function() { focusModalIfNeeded(overlay); }, 520);
    } else {
        var previousFocus = overlay._previousFocus;
        overlay._previousFocus = null;
        restoreModalFocus(previousFocus, overlay);
        requestAnimationFrame(function() { restoreModalFocus(previousFocus, overlay); });
        setTimeout(function() { restoreModalFocus(previousFocus, overlay); }, 80);
        setTimeout(function() { restoreModalFocus(previousFocus, overlay); }, 320);
        setTimeout(function() { restoreModalFocus(previousFocus, overlay); }, 680);
        setTimeout(function() { restoreModalFocus(previousFocus, overlay); }, 1400);
    }
}

function closeOpenModalOverlays() {
    let closed = false;
    document.querySelectorAll('.modal-overlay.active').forEach(function(overlay) {
        setModalOpen(overlay, false);
        closed = true;
    });
    return closed;
}

function showAwakeNarrative(itemId) {
    const overlay = document.getElementById('narrative-overlay');
    const blueprint = itemBlueprints[itemId];
    
    // Set showcase image
    const showcaseContainer = document.getElementById('narrative-item-showcase');
    // Combine all part svgs to render completed glowing SVG in modal
    let completedSvg = `<svg viewBox="0 0 200 200" width="100%" height="100%">`;
    blueprint.parts.forEach(p => completedSvg += p.svg);
    completedSvg += `</svg>`;
    showcaseContainer.innerHTML = safeHTML(completedSvg);
    
    // Set text
    document.getElementById('narrative-item-title').textContent = `${blueprint.title} 重构完成`;
    
    // Generate Choices list
    const choiceZone = document.getElementById('narrative-choice-zone');
    const textZone = document.getElementById('narrative-text-zone');
    const saveBtn = document.getElementById('btn-save-narrative');
    const toyWrapper = document.getElementById('interactive-toy-wrapper');
    
    choiceZone.classList.remove('hidden');
    textZone.classList.add('hidden');
    saveBtn.classList.add('hidden');
    toyWrapper.classList.add('hidden'); // hidden until choice made
    
    const choiceButtonsList = choiceZone.querySelector('.choice-buttons-list');
    choiceButtonsList.innerHTML = safeHTML('');
    
    blueprint.choices.forEach(ch => {
        const btn = createButtonElement();
        btn.classList.add('btn-choice');
        btn.innerHTML = safeHTML(`<span><strong>[${escapeTextForHTML(ch.category)}]</strong> ${escapeTextForHTML(ch.text)}</span>`);
        btn.addEventListener('click', () => triggerStoryGeneration(itemId, ch.id));
        choiceButtonsList.appendChild(btn);
    });
    
    setModalOpen(overlay, true);
}

async function triggerStoryGeneration(itemId, choiceId) {
    const choiceZone = document.getElementById('narrative-choice-zone');
    const textZone = document.getElementById('narrative-text-zone');
    
    choiceZone.classList.add('hidden');
    textZone.classList.remove('hidden');
    
    // Setup and trigger tactile interactive toy right below narrative
    setupInteractiveToy(itemId);
    
    // Simulate AI loading spinner/generation
    const typingTextEl = document.getElementById('narrative-typing-text');
    typingTextEl.innerHTML = safeHTML('<span class="ai-generating-text">💫 AIGC 神经网络正在对老人的行为物理轨特征进行情感流式独白拼装...</span>');
    
    // Gather sensory behavior profile
    const stats = {
        isGentle: gameState.rubbedGentle !== false,
        tunerPrecision: 98 + Math.floor(Math.random() * 2),
        maxCombo: gameState.lastMaxCombo || 1
    };

    try {
        // Fetch customized emotional story asynchronously from our AIGC Engine
        const story = await AIGCStoryTeller.fetchAIStory(itemId, stats);
        
        // Trigger accessibility spoken voice-over for Grandma's narration
        audio.speak(story);
        
        startTypewriterEffect(story, () => {
            // Complete typing callback
            const saveBtn = document.getElementById('btn-save-narrative');
            saveBtn.classList.remove('hidden');
            saveBtn.onclick = () => saveMemoryToAlbum(itemId, choiceId, story);
        });
    } catch (err) {
        console.error("AIGC Story Generation failed, falling back to static story blueprint:", err);
        const fallbackStory = itemBlueprints[itemId].stories[choiceId] || "好孩子，只要有你陪着，这回响就一直都在。";
        audio.speak(fallbackStory);
        startTypewriterEffect(fallbackStory, () => {
            const saveBtn = document.getElementById('btn-save-narrative');
            saveBtn.classList.remove('hidden');
            saveBtn.onclick = () => saveMemoryToAlbum(itemId, choiceId, fallbackStory);
        });
    }
}

function startTypewriterEffect(text, onComplete) {
    const el = document.getElementById('narrative-typing-text');
    el.textContent = '';
    
    let index = 0;
    const speed = 45; // ms per character
    
    function type() {
        if (index < text.length) {
            el.textContent += text.charAt(index);
            index++;
            
            // Synthesize typing sound effect ticks at random intervals to avoid monotone
            if (Math.random() < 0.35) {
                audio.playTypewriterClick();
            }
            
            setTimeout(type, speed);
        } else {
            if (onComplete) onComplete();
        }
    }
    
    type();
}

// ============================================================================
// 7. MEMORY ALBUM COMPILATION
// ============================================================================
function saveMemoryToAlbum(itemId, choiceId, storyText) {
    // Save to State
    const id = itemId;
    const blueprint = itemBlueprints[itemId];
    
    const existingIndex = gameState.albumEntries.findIndex(e => e.id === id);
    const dateStr = new Date().toLocaleDateString('zh-CN', { year: 'numeric', month: 'long', day: 'numeric' });
    
    const entry = {
        id: id,
        title: blueprint.title,
        choiceId: choiceId,
        storyText: storyText,
        date: dateStr
    };
    
    if (existingIndex > -1) {
        gameState.albumEntries[existingIndex] = entry; // Overwrite
    } else {
        gameState.albumEntries.push(entry);
    }
    
    // Add to Completed items list
    if (!gameState.completedItems.includes(itemId)) {
        gameState.completedItems.push(itemId);
    }
    
    // 非线性开放域：所有物件默认已解锁，无需顺序解锁
    // Recalculate progress: 9 objects total
    gameState.progress = Math.min(100, Math.round((gameState.completedItems.length / 9) * 100));

    // Calculate memory silver rewards using progression math formulas
    const baseScore = 200;
    const maxCombo = gameState.lastMaxCombo || 1;
    const encyclopediaBonus = gameState.albumEntries.length * 0.05;
    
    const econResult = economyManager.calculateEmpathy(baseScore, maxCombo, encyclopediaBonus);
    trackGameComplete('memory-' + itemId, econResult.silverEarned);
    
    // Reset max combo tracker
    gameState.lastMaxCombo = 0;
    persistGameStateSoon();
    
    // Spawn Poetic Floating Toast for coin reward
    setTimeout(() => {
        const coinToast = document.createElement('div');
        coinToast.className = 'poetic-toast';
        coinToast.style.borderColor = 'var(--accent-gold)';
        coinToast.innerHTML = safeHTML(`
            <div class="toast-glow" style="background: radial-gradient(circle, rgba(229,169,59,0.2) 0%, transparent 70%);"></div>
            <div class="toast-content">
                <span class="toast-part-name" style="color: var(--accent-gold);">🪙 共情结汇完成 🪙</span>
                <p class="toast-part-hint" style="font-size: 1rem; font-weight: bold; line-height: 1.6;">
                    您本次获得了 <span style="color: #ffd700;">+${econResult.silverEarned}</span> 记忆银币！<br>
                    <span style="font-size: 0.8rem; font-weight: normal; color: var(--text-muted);">
                        (共情值: ${econResult.empathy} = 基础 ${baseScore} · 连击 x${(1 + maxCombo * 0.15).toFixed(2)} · 图鉴 x${(1 + encyclopediaBonus).toFixed(2)})
                    </span>
                </p>
            </div>
        `);
        document.body.appendChild(coinToast);
        setTimeout(() => {
            coinToast.classList.add('fade-out');
            setTimeout(() => coinToast.remove(), 800);
        }, 4500);
    }, 1500);
    
    // Stop all active toy loops, static noises, and voice-overs
    audio.stopRadioStatic();
    audio.stopRadioMelody();
    audio.stopSewingLoop();
    audio.stopSpeak();

    // Close modal overlay
    setModalOpen(document.getElementById('narrative-overlay'), false);
    
    // Sync Hub screens and show updated locks
    syncHubState();
    
    // Direct navigate to Album Screen so the player feels their action was permanently saved
    transitionToScreen('screen-album');
    renderAlbum();
}

function syncHubState() {
    // Silver coins balance
    const coinBal = document.getElementById('global-silver-balance');
    if (coinBal) {
        coinBal.textContent = gameState.memorySilver;
    }

    // Progress Bar
    document.getElementById('memory-progress-fill').style.width = `${gameState.progress}%`;
    document.getElementById('progress-text').textContent = `${gameState.progress}%`;
    
    // Synchronize lock styles on Hub Cards
    const items = ['radio', 'camera', 'sewing', 'lantern', 'watch', 'telephone', 'musicbox', 'abacus', 'television'];
    items.forEach(id => {
        const card = document.getElementById(`capsule-${id}`);
        if (!card) return;
        const blueprint = itemBlueprints[id];
        
        // 1. Clean classes
        card.classList.remove('locked', 'unlocked', 'completed');
        
        // 2. Inject silhouette SVG if not already loaded
        const silContainer = document.getElementById(`silhouette-${id}-container`);
        if (silContainer && !silContainer.innerHTML) {
            let silhouetteSvg = `<svg viewBox="0 0 200 200" width="100%" height="100%">`;
            // Standard outline silhouette SVG style
            blueprint.parts.forEach(p => {
                silhouetteSvg += `<g opacity="0.25">${p.svg}</g>`;
            });
            silhouetteSvg += `</svg>`;
            silContainer.innerHTML = safeHTML(silhouetteSvg);
        }
        
        // 3. Update State Styles
        if (gameState.completedItems.includes(id)) {
            card.classList.add('completed');
            card.querySelector('.btn-capsule-action').textContent = '回顾记忆';
        } else if (gameState.unlockedItems.includes(id)) {
            card.classList.add('unlocked');
            card.querySelector('.btn-capsule-action').textContent = '重构记忆';
        } else {
            card.classList.add('locked');
            card.querySelector('.btn-capsule-action').textContent = '阁楼尘封中';
        }
    });
    enhanceHubCardsWithPlayStats();
    persistGameStateSoon();
}

function renderAlbum() {
    const container = document.getElementById('album-pages-container');
    
    if (gameState.albumEntries.length === 0) {
        container.innerHTML = safeHTML(`<div class="album-placeholder-page">
            <div class="placeholder-icon">📖</div>
            <h3>你的相册空空如也</h3>
            <p>回到阁楼去重构老物件，倾听奶奶的陈年旧事，这些闪光的时光切片将永久珍藏于此。</p>
            <button type="button" id="btn-album-go-hub" class="btn-primary">去重构物件</button>
        </div>`);
        
        document.getElementById('btn-album-go-hub').addEventListener('click', () => {
            transitionToScreen('screen-hub');
        });
        return;
    }
    
    // Map entries to gorgeous photography book layouts
    let html = `<div class="album-entry-list">`;
    gameState.albumEntries.forEach((entry, entryIndex) => {
        const blueprint = itemBlueprints[entry.id];
        if (!blueprint || !Array.isArray(blueprint.parts)) return;
        // SVG 缓存：首次生成后缓存到 blueprint
        if (!blueprint._cachedFullSvg) {
            blueprint._cachedFullSvg = `<svg viewBox="0 0 200 200" width="100%" height="100%">` +
                blueprint.parts.map(p => p.svg).join('') + `</svg>`;
        }
        const entryDate = escapeTextForHTML(entry.date);
        const entryTitle = escapeTextForHTML(entry.title);
        const entryStory = escapeTextForHTML(entry.storyText).replace(/\n/g, '<br>');
        
        html += `
        <div class="album-entry-card glass-panel">
            <div class="entry-visual">
                ${blueprint._cachedFullSvg}
                <div class="entry-badge">${entryDate}</div>
            </div>
            <div class="entry-details">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; gap: 15px;">
                    <h3 style="margin: 0;">已修复的 ${entryTitle} 回响</h3>
                    <button type="button" class="btn-audio-speak" data-story-index="${entryIndex}">🔊 聆听配音</button>
                </div>
                <p class="entry-story">${entryStory}</p>
            </div>
        </div>`;
    });
    html += `</div>`;
    
    container.innerHTML = safeHTML(html);

    // 事后绑定配音按钮 —— 防止 XSS 注入
    const speakButtons = container.querySelectorAll('.btn-audio-speak');
    speakButtons.forEach(btn => {
        const idx = parseInt(btn.dataset.storyIndex);
        if (!isNaN(idx) && gameState.albumEntries[idx]) {
            btn.addEventListener('click', () => {
                const story = gameState.albumEntries[idx].storyText;
                if (story) audio.speak(story);
            });
        }
    });
}

// ============================================================================
// 8. ROUTING & SCREEN SYSTEM TRANSITIONS
// ============================================================================
function getScreenReadableLabel(screen) {
    if (!screen) return '';
    var heading = screen.querySelector('h1, h2, h3');
    return (heading && heading.textContent ? heading.textContent : screen.id || '').trim();
}

function ensureA11yLiveRegion() {
    var live = document.getElementById('a11y-live-region');
    if (!live) {
        live = document.createElement('div');
        live.id = 'a11y-live-region';
        live.className = 'sr-only';
        live.setAttribute('role', 'status');
        live.setAttribute('aria-live', 'polite');
        live.setAttribute('aria-atomic', 'true');
        document.body.insertBefore(live, document.body.firstChild);
    }
    return live;
}

function announceScreenChange(screen) {
    var live = ensureA11yLiveRegion();
    var label = getScreenReadableLabel(screen);
    if (!label) return;
    live.textContent = '';
    setTimeout(function() {
        live.textContent = '已进入：' + label;
    }, 30);
}

function enhanceScreenA11y(activeScreen) {
    document.querySelectorAll('.game-screen').forEach(function(screen) {
        if (!screen.hasAttribute('role')) screen.setAttribute('role', 'region');
        if (!screen.hasAttribute('tabindex')) screen.setAttribute('tabindex', '-1');
        if (!screen.hasAttribute('aria-label')) {
            var label = getScreenReadableLabel(screen);
            if (label) screen.setAttribute('aria-label', label);
        }
        screen.setAttribute('aria-hidden', screen === activeScreen ? 'false' : 'true');
    });
    if (activeScreen) {
        announceScreenChange(activeScreen);
        requestAnimationFrame(function() {
            var active = document.activeElement;
            var focusAlreadyClaimed = active &&
                active !== document.body &&
                active !== document.documentElement &&
                active.isConnected &&
                (!active.getClientRects || active.getClientRects().length > 0);
            if (focusAlreadyClaimed) return;
            try {
                activeScreen.focus({ preventScroll: true });
            } catch (err) {
                activeScreen.focus();
            }
        });
    }
}

function initA11yNavigationHelpers() {
    if (!document.getElementById('skip-to-main')) {
        var skip = document.createElement('a');
        skip.id = 'skip-to-main';
        skip.className = 'skip-link';
        skip.href = '#app-container';
        skip.textContent = '跳到游戏主内容';
        document.body.insertBefore(skip, document.body.firstChild);
    }
    ensureA11yLiveRegion();
    enhanceScreenA11y(document.querySelector('.game-screen.active'));
}

function transitionToScreen(targetScreenId) {
    if (targetScreenId !== gameState.currentScreen) {
        closeOpenModalOverlays();
        clearGameplayAssistHighlights();
        cleanupTapPlaceState();
        cleanupMemoryWorkbenchRuntime(targetScreenId);
        cleanupSpatialRuntime();
        cleanupCognitiveRuntime();
        cleanupSkillGameState();
    }

    // 1. Remove active state from active screens & set aria-hidden for A11y
    const screens = document.querySelectorAll('.game-screen');
    screens.forEach(screen => {
        if (screen.classList.contains('active')) {
            screen.classList.remove('active');
            screen.setAttribute('aria-hidden', 'true');
        }
    });
    
    // 2. Set active on target & reveal to screen reader
    const target = document.getElementById(targetScreenId);
    if (!target) {
        console.warn('Cannot transition to missing screen:', targetScreenId);
        return;
    }
    target.classList.add('active');
    target.setAttribute('aria-hidden', 'false');
    gameState.currentScreen = targetScreenId;
    enhanceScreenA11y(target);
    updateGameplayCoach(targetScreenId);

    // Update global stats when returning to hub
    if (targetScreenId === 'screen-hub') {
        initDailyChallenge();
        enhanceHubCardsWithPlayStats();
        var gp = document.getElementById('stat-games-played');
        var gc = document.getElementById('stat-games-completed');
        var ach = document.getElementById('stat-achievements');
        if (gp) gp.textContent = gameState.totalGamesPlayed;
        if (gc) gc.textContent = gameState.totalGamesCompleted;
        if (ach) ach.textContent = achievementSystem.countUnlocked();
    }
    
    // Cognitive decay disabled for multi-mode platform — users complained about auto-blur
    cognitiveDecay.stop();
    
    // Initial triggers for sound engine activation
    if (targetScreenId !== 'screen-start') {
        // Ensure BGM plays when leaving the start menu
        if (!audio.isPlayingBGM) {
            audio.startBGM();
            updateAudioButtonUI(true);
        }
    }
    persistGameStateSoon();
}

function updateAudioButtonUI(isPlaying) {
    const btn = document.getElementById('bgm-toggle-btn');
    const icon = btn.querySelector('.audio-icon');
    const text = btn.querySelector('.audio-text');
    btn.setAttribute('aria-pressed', isPlaying ? 'true' : 'false');
    btn.setAttribute('aria-label', isPlaying ? '关闭时光背景音乐' : '播放时光背景音乐');
    
    if (isPlaying) {
        icon.textContent = '🔊';
        icon.classList.add('playing');
        text.textContent = '时光Lo-Fi音乐 (播放中)';
    } else {
        icon.textContent = '🔇';
        icon.classList.remove('playing');
        text.textContent = '时光Lo-Fi音乐 (静音)';
    }
}

// ============================================================================
// 主题切换系统
// ============================================================================
function loadThemePreference() {
    try {
        return localStorage.getItem('game-theme') || 'warm';
    } catch (err) {
        return 'warm';
    }
}

function saveThemePreference(theme) {
    try {
        localStorage.setItem('game-theme', theme);
    } catch (err) {
        // Theme preference is optional; continue when storage is blocked.
    }
}

var currentTheme = loadThemePreference();
function applyTheme(theme) {
    currentTheme = theme;
    document.documentElement.setAttribute('data-theme', theme);
    saveThemePreference(theme);
    document.querySelectorAll('.theme-btn').forEach(function(b) {
        b.classList.toggle('active', b.dataset.theme === theme);
        b.setAttribute('aria-pressed', b.dataset.theme === theme ? 'true' : 'false');
    });
}
function initThemeSwitcher() {
    var container = document.getElementById('theme-switcher');
    if (!container) {
        container = document.createElement('div');
        container.id = 'theme-switcher';
        container.className = 'theme-switcher';
        var themes = [
            { id: 'warm', label: '暖色黄昏', emoji: '🌅' },
            { id: 'ocean', label: '深蓝海洋', emoji: '🌊' },
            { id: 'forest', label: '翠绿森林', emoji: '🌿' },
            { id: 'cyber', label: '赛博霓虹', emoji: '🌃' }
        ];
        themes.forEach(function(t) {
            var btn = createButtonElement();
            btn.className = 'theme-btn ' + t.id;
            btn.dataset.theme = t.id;
            btn.type = 'button';
            btn.title = t.emoji + ' ' + t.label;
            btn.setAttribute('aria-label', '切换主题：' + t.label);
            btn.setAttribute('aria-pressed', 'false');
            btn.addEventListener('click', function() { applyTheme(t.id); });
            container.appendChild(btn);
        });
        document.body.appendChild(container);
    }
    applyTheme(currentTheme);
}

// ============================================================================
// 增强过渡动画
// ============================================================================
var _originalTransition = transitionToScreen;
transitionToScreen = function(targetScreenId) {
    if (typeof prefersReducedMotion === 'function' && prefersReducedMotion()) {
        var existingFlash = document.getElementById('screen-flash');
        if (existingFlash) existingFlash.classList.remove('active');
        document.querySelectorAll('.game-screen.leaving').forEach(function(s) { s.classList.remove('leaving'); });
        _originalTransition(targetScreenId);
        return;
    }

    // Flash effect
    var flash = document.getElementById('screen-flash');
    if (!flash) {
        flash = document.createElement('div');
        flash.id = 'screen-flash';
        flash.className = 'screen-flash';
        document.body.appendChild(flash);
    }
    flash.classList.add('active');
    setTimeout(function() { flash.classList.remove('active'); }, 150);

    // Mark leaving screens
    document.querySelectorAll('.game-screen.active').forEach(function(s) {
        s.classList.add('leaving');
        setTimeout(function() { s.classList.remove('leaving'); }, 250);
    });

    // Original transition
    _originalTransition(targetScreenId);
};

// ============================================================================
// 键盘快捷键系统
// ============================================================================
function initKeyboardShortcuts() {
    function returnToHubWithCleanup() {
        cleanupTransientGames();
        transitionToScreen('screen-hub');
    }

    document.addEventListener('keydown', function(e) {
        // Don't intercept when typing in inputs
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.isContentEditable) return;

        switch(e.key) {
            case 'Escape':
                if (closeOpenModalOverlays()) {
                    e.preventDefault();
                    if (gameState.currentScreen !== 'screen-start' && gameState.currentScreen !== 'screen-hub') {
                        returnToHubWithCleanup();
                    }
                    break;
                }
                // Go back to hub from any game screen
                if (gameState.currentScreen !== 'screen-start' && gameState.currentScreen !== 'screen-hub') {
                    returnToHubWithCleanup();
                }
                break;
            case '1': case '2': case '3': case '4': case '5':
                // Only in hub: switch tabs
                if (gameState.currentScreen === 'screen-hub') {
                    var tabIndex = parseInt(e.key) - 1;
                    var tabs = document.querySelectorAll('.hub-tab');
                    if (tabs[tabIndex]) tabs[tabIndex].click();
                }
                break;
            case 'h': case 'H':
                // Quick go home to hub
                if (gameState.currentScreen !== 'screen-start' && gameState.currentScreen !== 'screen-hub') {
                    returnToHubWithCleanup();
                }
                break;
            case 't': case 'T':
                // Cycle theme
                var themesList = ['warm', 'ocean', 'forest', 'cyber'];
                var idx = themesList.indexOf(currentTheme);
                applyTheme(themesList[(idx + 1) % 4]);
                break;
        }
    });
}

// ============================================================================
// 动态粒子反馈系统
// ============================================================================
function destroyTransientGameRef(refName) {
    var instance = window[refName];
    if (instance && typeof instance.destroy === 'function') {
        try {
            instance.destroy();
        } catch (err) {
            console.warn('Transient game cleanup failed for ' + refName, err);
        }
    }
    window[refName] = null;
}

var cognitiveRuntimeTimers = {
    timeouts: [],
    intervals: []
};

var skillRuntimeTimers = {
    timeouts: []
};

function trackCognitiveTimeout(callback, delay) {
    var timerId = setTimeout(function() {
        cognitiveRuntimeTimers.timeouts = cognitiveRuntimeTimers.timeouts.filter(function(id) { return id !== timerId; });
        callback();
    }, delay);
    cognitiveRuntimeTimers.timeouts.push(timerId);
    return timerId;
}

function clearTrackedCognitiveTimeout(timerId) {
    clearTimeout(timerId);
    cognitiveRuntimeTimers.timeouts = cognitiveRuntimeTimers.timeouts.filter(function(id) { return id !== timerId; });
}

function trackCognitiveInterval(callback, delay) {
    var intervalId = setInterval(callback, delay);
    cognitiveRuntimeTimers.intervals.push(intervalId);
    return intervalId;
}

function clearTrackedCognitiveInterval(intervalId) {
    clearInterval(intervalId);
    cognitiveRuntimeTimers.intervals = cognitiveRuntimeTimers.intervals.filter(function(id) { return id !== intervalId; });
}

function cleanupCognitiveRuntime() {
    cognitiveRuntimeTimers.timeouts.forEach(clearTimeout);
    cognitiveRuntimeTimers.intervals.forEach(clearInterval);
    cognitiveRuntimeTimers.timeouts = [];
    cognitiveRuntimeTimers.intervals = [];
}

function cognitiveRuntimeTimerCount() {
    return cognitiveRuntimeTimers.timeouts.length + cognitiveRuntimeTimers.intervals.length;
}

function trackSkillTimeout(callback, delay) {
    var timerId = setTimeout(function() {
        skillRuntimeTimers.timeouts = skillRuntimeTimers.timeouts.filter(function(id) { return id !== timerId; });
        callback();
    }, delay);
    skillRuntimeTimers.timeouts.push(timerId);
    return timerId;
}

function cleanupSkillRuntime() {
    skillRuntimeTimers.timeouts.forEach(clearTimeout);
    skillRuntimeTimers.timeouts = [];
}

function cleanupSkillGameState() {
    cleanupSkillRuntime();
    var tunnel = document.getElementById('a11y-tunnel-overlay');
    if (tunnel) tunnel.remove();
    var traceCanvas = document.getElementById('trace-canvas');
    if (traceCanvas) {
        traceCanvas.onpointerdown = null;
        traceCanvas.onpointermove = null;
        traceCanvas.onpointerup = null;
        traceCanvas.onkeydown = null;
        traceCanvas.setAttribute('aria-disabled', 'false');
    }
    window._a11yStage = null;
    [
        '_traceLevel',
        '_tracePath',
        '_traceDrawing',
        '_traceCurrentLine',
        '_traceCtx',
        '_traceData',
        '_traceNodes',
        '_traceDrawStatic',
        '_traceHexToRgba',
        '_traceNodeColors',
        '_traceLastNode',
        '_traceKeyHandler',
        '_decodeIndex',
        '_decodeCurrent',
        '_decodePuzzles'
    ].forEach(function(name) {
        window[name] = null;
    });
}

function skillRuntimeTimerCount() {
    return skillRuntimeTimers.timeouts.length;
}

function cleanupTapPlaceState() {
    setTapPlaceSelection(null);
    window._timelineTapCard = null;
    if (window._ecoGame) window._ecoGame.tapSelectedItem = null;
}

function cleanupTimelineRuntime() {
    if (window._timelineCleanup) {
        document.removeEventListener('pointermove', window._timelineCleanup.move);
        document.removeEventListener('pointerup', window._timelineCleanup.up);
        if (window._timelineCleanup.clone) window._timelineCleanup.clone.remove();
        window._timelineCleanup = null;
    }
    if (window._timelineResetTimer) {
        clearTrackedCognitiveTimeout(window._timelineResetTimer);
        window._timelineResetTimer = null;
    }
    setTapPlaceSelection(null, 'timeline');
    window._timelineTapCard = null;
}

function cleanupSpatialRuntime() {
    if (window._spatialKeyHandler) {
        document.removeEventListener('keydown', window._spatialKeyHandler);
        window._spatialKeyHandler = null;
    }
}

function cleanupMemoryWorkbenchRuntime(targetScreenId) {
    if (gameState.currentScreen !== 'screen-workspace' || targetScreenId === 'screen-workspace') return;
    if (typeof workbench !== 'undefined' && workbench && typeof workbench.cleanupActiveRuntime === 'function') {
        workbench.cleanupActiveRuntime();
    }
}

function cleanupTransientGames() {
    closeOpenModalOverlays();
    [
        '_qadventure',
        '_ecoGame',
        '_fraudGame',
        '_oceanGame',
        '_oracleGame',
        '_truthGame',
        '_heartGame',
        '_grainGame'
    ].forEach(destroyTransientGameRef);
    cleanupTimelineRuntime();
    if (window._ecoCleanup) {
        document.removeEventListener('pointermove', window._ecoCleanup.move);
        document.removeEventListener('pointerup', window._ecoCleanup.up);
        window._ecoCleanup = null;
    }
    cleanupTapPlaceState();
    cleanupMemoryWorkbenchRuntime('screen-hub');
    cleanupSpatialRuntime();
    cleanupCognitiveRuntime();
    cleanupSkillGameState();
}

function initNavigationFallbacks() {
    document.addEventListener('click', function(e) {
        var btn = e.target.closest ? e.target.closest('button[id]') : null;
        if (!btn || btn.id === 'btn-back-to-start') return;
        var isBackButton = /^btn-.+-back$/.test(btn.id) || btn.id === 'btn-back-to-hub';
        var isHubButton = /^btn-.+-hub$/.test(btn.id);
        if (!isBackButton && !isHubButton) return;

        setTimeout(function() {
            cleanupTransientGames();
            if (gameState.currentScreen !== 'screen-hub') {
                transitionToScreen('screen-hub');
            }
        }, 0);
    });
}

var GAMEPLAY_SCREEN_TO_GAME = {
    'screen-match': 'memory-match',
    'screen-timeline': 'timeline',
    'screen-hidden': 'hidden',
    'screen-maze': 'maze',
    'screen-color': 'color',
    'screen-face': 'face',
    'screen-word': 'word',
    'screen-rhythm': 'rhythm',
    'screen-spatial': 'spatial'
};

var GAMEPLAY_CATEGORY_BY_SCREEN = {
    'screen-workspace': 'memory',
    'screen-match': 'cognitive',
    'screen-timeline': 'cognitive',
    'screen-hidden': 'cognitive',
    'screen-maze': 'cognitive',
    'screen-color': 'cognitive',
    'screen-face': 'cognitive',
    'screen-word': 'cognitive',
    'screen-rhythm': 'cognitive',
    'screen-spatial': 'cognitive',
    'screen-eco': 'drag',
    'screen-ocean': 'drag',
    'screen-oracle': 'drag',
    'screen-truth': 'drag',
    'screen-heart': 'drag',
    'screen-grain': 'drag',
    'screen-a11y': 'skill',
    'screen-trace': 'skill',
    'screen-decode': 'skill'
};

['water','carbon','repair','aid','food','animal','phish','script','identity','transfer','leak','evidence','alert','forest','light','seed','civil'].forEach(function(id) {
    GAMEPLAY_SCREEN_TO_GAME['screen-' + id] = id;
    GAMEPLAY_CATEGORY_BY_SCREEN['screen-' + id] = 'adventure';
});
['eco','fraud','a11y','trace','decode','ocean','oracle','truth','heart','grain'].forEach(function(id) {
    GAMEPLAY_SCREEN_TO_GAME['screen-' + id] = id;
});

var GAMEPLAY_TIPS = {
    memory: ['先观察轮廓，再处理细节。', '拖拽前看清目标槽位，少走回头路。', '完成后记得保存故事，相册会记录进度。'],
    cognitive: ['先慢后快，正确率比速度更重要。', '遇到序列题先找固定点，再推空缺。', '失败时直接重玩，最佳成绩会持续刷新。'],
    adventure: ['先读题干关键词，再看选项。', '连对三题会明显提高收益。', '提示、护盾和双倍道具适合留给不确定题。'],
    drag: ['先把组件分组，再处理精确放置。', '靠近正确区域会更容易吸附。', '完成阶段目标后再追求连击和时间奖励。'],
    skill: ['把手势放慢一点，先完成形状再追求速度。', '提示文字通常包含正确方向。', '短局多次练习比一次硬撑更有效。'],
    generic: ['先看任务目标，再开始操作。', '错了也没关系，反馈会告诉你下一步。', '返回 Hub 后可以从最佳成绩继续挑战。']
};

function getGameIdForScreen(screenId) {
    return GAMEPLAY_SCREEN_TO_GAME[screenId] || (screenId || '').replace(/^screen-/, '');
}

function getScreenGameplayProfile(screenId) {
    var screen = document.getElementById(screenId);
    var heading = screen ? screen.querySelector('h1, h2, h3') : null;
    var tip = screen ? screen.querySelector('.workspace-tip') : null;
    var category = GAMEPLAY_CATEGORY_BY_SCREEN[screenId] || 'generic';
    return {
        gameId: getGameIdForScreen(screenId),
        title: heading && heading.textContent ? heading.textContent.trim() : screenId,
        objective: tip && tip.textContent ? tip.textContent.trim() : '完成本局任务并刷新最佳成绩。',
        category: category,
        tips: GAMEPLAY_TIPS[category] || GAMEPLAY_TIPS.generic
    };
}

function getGameStat(gameId) {
    return gameState.gameStats && gameState.gameStats[gameId] ? gameState.gameStats[gameId] : { played: 0, completed: 0, bestScore: 0 };
}

function enhanceHubCardsWithPlayStats() {
    document.querySelectorAll('.game-card[id^="btn-open-"]').forEach(function(card) {
        var gameKey = card.id.replace('btn-open-', '');
        var screenId = 'screen-' + gameKey;
        var profile = getScreenGameplayProfile(screenId);
        var stat = getGameStat(profile.gameId);
        var meta = card.querySelector('.game-card-meta');
        if (!meta) {
            meta = document.createElement('span');
            meta.className = 'game-card-meta';
            card.appendChild(meta);
        }
        var status = stat.played > 0 ? ('已玩 ' + stat.played + ' 次') : '新体验';
        var best = stat.bestScore > 0 ? ('最佳 ' + stat.bestScore) : '未挑战';
        meta.innerHTML = safeHTML('<span>' + escapeTextForHTML(status) + '</span><span>' + escapeTextForHTML(best) + '</span>');
        card.classList.toggle('played', stat.played > 0);
        var title = card.querySelector('.game-card-title');
        var desc = card.querySelector('.game-card-desc');
        var labelParts = [
            title ? title.textContent.trim() : '',
            desc ? desc.textContent.trim() : '',
            status,
            best
        ].filter(Boolean);
        card.setAttribute('aria-label', labelParts.join('，'));
    });
}

function ensureGameplayCoach() {
    var coach = document.getElementById('gameplay-coach');
    if (!coach) {
        coach = document.createElement('aside');
        coach.id = 'gameplay-coach';
        coach.className = 'gameplay-coach hidden';
        coach.setAttribute('role', 'complementary');
        coach.setAttribute('aria-live', 'polite');
        coach.setAttribute('aria-label', '游戏提示助手');
        coach.innerHTML =
            '<div class="coach-main">' +
                '<strong class="coach-title"></strong>' +
                '<span class="coach-objective"></span>' +
                '<span class="coach-meta"></span>' +
            '</div>' +
            '<button class="coach-tip-btn" type="button">提示</button>';
        document.body.appendChild(coach);
        coach.querySelector('.coach-tip-btn').addEventListener('click', function() {
            if (!applyGameplayAssist(gameState.currentScreen)) {
                var tips = coach._tips || GAMEPLAY_TIPS.generic;
                var idx = Number(coach.dataset.tipIndex || 0);
                showGameplayToast(tips[idx % tips.length], 'hint');
                coach.dataset.tipIndex = String(idx + 1);
            }
        });
    }
    return coach;
}

function updateGameplayCoach(screenId) {
    var coach = ensureGameplayCoach();
    var hiddenScreens = { 'screen-start': true, 'screen-hub': true, 'screen-album': true };
    if (hiddenScreens[screenId]) {
        coach.classList.add('hidden');
        return;
    }
    var profile = getScreenGameplayProfile(screenId);
    var stat = getGameStat(profile.gameId);
    coach._tips = profile.tips;
    coach.dataset.tipIndex = '0';
    coach.querySelector('.coach-title').textContent = profile.title;
    coach.querySelector('.coach-objective').textContent = profile.objective;
    coach.querySelector('.coach-meta').textContent = '已玩 ' + (stat.played || 0) + ' 次 · 完成 ' + (stat.completed || 0) + ' 次 · 最佳 ' + (stat.bestScore || 0);
    coach.classList.remove('hidden');
}

function showGameplayToast(text, tone) {
    if (!text) return;
    var toast = document.createElement('div');
    toast.className = 'gameplay-toast ' + (tone || 'info');
    toast.textContent = text;
    document.body.appendChild(toast);
    requestAnimationFrame(function() { toast.classList.add('show'); });
    setTimeout(function() {
        toast.classList.remove('show');
        setTimeout(function() { toast.remove(); }, 250);
    }, 1800);
}

var gameplayAssistTimer = null;

function clearGameplayAssistHighlights() {
    if (gameplayAssistTimer) {
        clearTimeout(gameplayAssistTimer);
        gameplayAssistTimer = null;
    }
    document.querySelectorAll('.coach-highlight, .coach-peek').forEach(function(el) {
        el.classList.remove('coach-highlight', 'coach-peek');
        if (el.dataset && el.dataset.coachOriginalText) {
            el.textContent = el.dataset.coachOriginalText;
            delete el.dataset.coachOriginalText;
        }
    });
    document.querySelectorAll('.coach-generated-marker').forEach(function(el) { el.remove(); });
    document.querySelectorAll('.tap-place-selected').forEach(function(el) { el.classList.remove('tap-place-selected'); });
}

function setTapPlaceSelection(el, group) {
    var selector = '.tap-place-selected' + (group ? '[data-tap-group="' + group + '"]' : '');
    document.querySelectorAll(selector).forEach(function(node) {
        node.classList.remove('tap-place-selected');
        delete node.dataset.tapGroup;
    });
    if (!el) return;
    el.dataset.tapGroup = group || 'global';
    el.classList.add('tap-place-selected');
}

function pulseGameplayAssist(elements, message, duration) {
    var list = elements.filter(function(el) { return !!el; });
    if (!list.length) return false;
    clearGameplayAssistHighlights();
    list.forEach(function(el) { el.classList.add('coach-highlight'); });
    if (list[0].scrollIntoView) {
        list[0].scrollIntoView({ block: 'center', inline: 'center', behavior: 'smooth' });
    }
    showGameplayToast(message || '下一步已经高亮。', 'hint');
    if (message && typeof ensureA11yLiveRegion === 'function') {
        var live = ensureA11yLiveRegion();
        live.textContent = '';
        setTimeout(function() { live.textContent = message; }, 30);
    }
    gameplayAssistTimer = setTimeout(clearGameplayAssistHighlights, duration || 2200);
    return true;
}

function revealCoachPair(cards, getKey, reveal, restore, message) {
    var groups = {};
    cards.forEach(function(card) {
        if (card.classList.contains('matched') || card.classList.contains('flipped')) return;
        var key = getKey(card);
        if (!key) return;
        if (!groups[key]) groups[key] = [];
        groups[key].push(card);
    });
    var pair = null;
    Object.keys(groups).some(function(key) {
        if (groups[key].length >= 2) {
            pair = groups[key].slice(0, 2);
            return true;
        }
        return false;
    });
    if (!pair) return false;
    clearGameplayAssistHighlights();
    pair.forEach(function(card) {
        card.classList.add('coach-peek', 'coach-highlight');
        reveal(card);
    });
    showGameplayToast(message, 'hint');
    gameplayAssistTimer = setTimeout(function() {
        pair.forEach(function(card) {
            if (!card.classList.contains('matched')) restore(card);
        });
        clearGameplayAssistHighlights();
    }, 1400);
    return true;
}

function assistMemoryMatch() {
    return revealCoachPair(
        Array.prototype.slice.call(document.querySelectorAll('.match-card')),
        function(card) {
            var back = card.querySelector('.match-card-back');
            return back ? back.textContent.trim() : '';
        },
        function(card) { card.classList.add('flipped'); },
        function(card) { card.classList.remove('flipped'); },
        '已短暂翻开一组可配对记忆。'
    );
}

function assistFaceGame() {
    return revealCoachPair(
        Array.prototype.slice.call(document.querySelectorAll('.face-card')),
        function(card) { return card.dataset.face || ''; },
        function(card) {
            card.dataset.coachOriginalText = card.textContent;
            card.textContent = card.dataset.face;
        },
        function(card) {
            card.textContent = card.dataset.coachOriginalText || '❓';
            delete card.dataset.coachOriginalText;
        },
        '已短暂揭示一组相同面孔。'
    );
}

function assistTimelineGame() {
    var slot = document.querySelector('.timeline-slot:not(.filled)');
    if (!slot) return false;
    var year = (slot.textContent || '').trim();
    var card = document.querySelector('.timeline-card[data-year="' + year + '"]:not(.placed)');
    return pulseGameplayAssist([slot, card], '先把这一张记忆卡放到高亮年份。');
}

function assistHiddenGame() {
    var obj = document.querySelector('.hidden-object:not(.found)');
    if (!obj) return false;
    var item = document.querySelector('.hidden-item[data-obj="' + obj.dataset.obj + '"]');
    return pulseGameplayAssist([obj, item], '下一个可寻找物件已经高亮。');
}

function assistMazeGame() {
    return pulseGameplayAssist([document.querySelector('.maze-cell.next')], '下一个数字已经高亮。');
}

function assistColorGame() {
    var card = document.querySelector('.color-card.selected:not(.placed)') || document.querySelector('.color-card:not(.placed)');
    if (!card) return false;
    var group = document.querySelector('.color-group[data-group="' + card.dataset.group + '"]');
    return pulseGameplayAssist([card, group], '把高亮色卡放入对应色组。');
}

function assistWordGame() {
    var option = document.querySelector('.word-option[data-index="0"]:not(:disabled)');
    return pulseGameplayAssist([option], '这个选项最贴近当前提示词。');
}

function markCanvasTarget(canvasId, x, y, baseWidth, baseHeight, message) {
    var canvas = document.getElementById(canvasId);
    if (!canvas || !canvas.parentElement) return false;
    clearGameplayAssistHighlights();
    var parent = canvas.parentElement;
    if (getComputedStyle(parent).position === 'static') parent.style.position = 'relative';
    var rect = canvas.getBoundingClientRect();
    var parentRect = parent.getBoundingClientRect();
    var marker = document.createElement('div');
    marker.className = 'coach-generated-marker coach-highlight';
    marker.setAttribute('aria-hidden', 'true');
    marker.style.left = (rect.left - parentRect.left + (x / baseWidth) * rect.width) + 'px';
    marker.style.top = (rect.top - parentRect.top + (y / baseHeight) * rect.height) + 'px';
    parent.appendChild(marker);
    return pulseGameplayAssist([marker, canvas], message, 2600);
}

function assistFraudGame() {
    var scenario = window._fraudGame && window._fraudGame.scenarios && window._fraudGame.scenarios[window._fraudGame.currentIdx];
    if (!scenario) return false;
    var target = document.getElementById(scenario.isScam ? 'btn-fraud-scam' : 'btn-fraud-safe');
    return pulseGameplayAssist([document.getElementById('fraud-card'), target], scenario.isScam ? '这条信息存在诈骗风险，优先选择“这是骗局”。' : '这条信息更像正常通知，选择“这是真的”。');
}

function assistA11yGame() {
    var stage = a11yStages[window._a11yStage || 0];
    if (!stage) return false;
    return markCanvasTarget('a11y-canvas', stage.targetX, stage.targetY, 500, 320, '画布上已标出这一步需要寻找的目标区域。');
}

function assistTraceGame() {
    var data = traceLevels[window._traceLevel || 0];
    if (!data || !data.path) return false;
    var expectedIdx = data.path[(window._tracePath || []).length];
    var node = data.nodes && data.nodes[expectedIdx];
    if (!node) return false;
    return markCanvasTarget('trace-canvas', node.x, node.y, 500, 400, '沿线索连接高亮节点，继续追踪诈骗源头。');
}

function assistDecodeGame() {
    var activePuzzles = window._decodePuzzles || decodePuzzles;
    var puzzle = activePuzzles[window._decodeIndex || 0];
    if (!puzzle) return false;
    var next = puzzle.answer[(window._decodeCurrent || []).length];
    var tile = Array.prototype.find.call(document.querySelectorAll('.decode-tile:not(.placed)'), function(el) {
        return el.textContent === next;
    });
    return pulseGameplayAssist([tile, document.getElementById('decode-answer')], '按顺序点选高亮字符，拼出完整反诈口诀。');
}

function assistRhythmGame() {
    var start = document.getElementById('btn-rhythm-start');
    if (start && start.offsetParent !== null) {
        start.click();
        showGameplayToast('已开始节奏演示，观察闪烁顺序后复刻。', 'hint');
        return true;
    }
    return pulseGameplayAssist(Array.prototype.slice.call(document.querySelectorAll('.rhythm-btn')), '闪烁结束后，按相同顺序点击色块。');
}

function assistSpatialGame() {
    var cells = Array.prototype.slice.call(document.querySelectorAll('#maze-board > div'));
    if (!cells.length) return false;
    var size = Math.round(Math.sqrt(cells.length));
    var start = -1, goal = -1;
    cells.forEach(function(cell, idx) {
        var text = cell.textContent || '';
        if (text.indexOf('🏠') >= 0) start = idx;
        if (text.indexOf('🌟') >= 0) goal = idx;
    });
    if (start < 0 || goal < 0) return false;
    var dirs = [
        { dx: 0, dy: -1, name: 'up' },
        { dx: 1, dy: 0, name: 'right' },
        { dx: 0, dy: 1, name: 'down' },
        { dx: -1, dy: 0, name: 'left' }
    ];
    var queue = [start], prev = {};
    prev[start] = null;
    while (queue.length) {
        var cur = queue.shift();
        if (cur === goal) break;
        var x = cur % size, y = Math.floor(cur / size);
        dirs.forEach(function(d) {
            var nx = x + d.dx, ny = y + d.dy;
            if (nx < 0 || nx >= size || ny < 0 || ny >= size) return;
            var ni = ny * size + nx;
            if (prev.hasOwnProperty(ni)) return;
            if ((cells[ni].textContent || '').indexOf('🧱') >= 0) return;
            prev[ni] = { from: cur, dir: d.name };
            queue.push(ni);
        });
    }
    if (!prev.hasOwnProperty(goal)) return false;
    var step = goal;
    while (prev[step] && prev[step].from !== start) step = prev[step].from;
    var dir = prev[step] ? prev[step].dir : null;
    var btn = dir ? document.querySelector('.spatial-dir[data-dir="' + dir + '"]') : null;
    return pulseGameplayAssist([cells[step], btn], '沿高亮方向走一步。');
}

function assistDragPair(cardSelector, slotPrefix, dataKey, message) {
    var card = document.querySelector(cardSelector);
    if (!card) return false;
    var targetId = card.dataset[dataKey];
    var slot = targetId ? document.getElementById(slotPrefix + targetId) : null;
    return pulseGameplayAssist([card, slot], message || '拖动高亮卡片到对应高亮区域。');
}

function assistTruthGame() {
    var fake = document.querySelector('.truth-judge-card[data-is-fake="true"]:not(.judged)');
    if (fake) return pulseGameplayAssist([fake], '优先点击这个可疑证据。');
    return assistDragPair('.truth-card:not(.placed)', 'truth-slot-', 'evidence', '把高亮证据放到同名位置。');
}

function assistHeartGame() {
    var diaryContainer = document.getElementById('heart-diary-container');
    if (diaryContainer && !diaryContainer.classList.contains('hidden')) {
        var currentDiary = window._heartGame && emotionDiaries[window._heartGame.diaryIndex];
        var selected = document.querySelector('.heart-diary-option.selected');
        var primary = currentDiary ? document.querySelector('.heart-diary-option[data-emotion="' + currentDiary.primary + '"]') : null;
        var secondary = currentDiary ? document.querySelector('.heart-diary-option[data-emotion="' + currentDiary.secondary + '"]') : null;
        var submit = document.getElementById('heart-diary-submit');
        if (selected && currentDiary && (selected.dataset.emotion === currentDiary.primary || selected.dataset.emotion === currentDiary.secondary)) {
            return pulseGameplayAssist([submit], '情绪已经选对了，确认后继续下一段日记。');
        }
        return pulseGameplayAssist([primary || secondary || document.querySelector('.heart-diary-option:not(.selected)')], '高亮的是当前场景最贴近的情绪，也可以调节感受强度。');
    }
    return assistDragPair('.heart-card:not(.placed)', 'heart-slot-', 'emotion', '把高亮情绪卡放入同名色轮位置。');
}

function assistGrainGame() {
    var waste = document.querySelector('.grain-waste-card');
    if (waste) return pulseGameplayAssist([waste], '点击高亮浪费事件，及时拯救食物。');
    return assistDragPair('.grain-card:not(.placed)', 'grain-slot-', 'belongsTo', '把高亮资源放到对应粮食旅程节点。');
}

function assistGameplayDragScreen(screenId) {
    if (screenId === 'screen-eco') {
        var item = document.querySelector('.eco-item:not(.done)');
        var bin = item ? document.querySelector('.eco-bin[data-bin="' + item.dataset.answer + '"]') : null;
        return pulseGameplayAssist([item, bin], '把高亮物品放入对应垃圾桶。');
    }
    if (screenId === 'screen-ocean') return assistDragPair('.coral-fragment:not(.placed)', 'ocean-slot-', 'coral', '把高亮珊瑚断枝移植到同名礁盘。');
    if (screenId === 'screen-oracle') return assistDragPair('.oracle-fragment:not(.placed)', 'oracle-slot-', 'fragId', '把高亮甲骨碎片拼到对应轮廓。');
    if (screenId === 'screen-truth') return assistTruthGame();
    if (screenId === 'screen-heart') return assistHeartGame();
    if (screenId === 'screen-grain') return assistGrainGame();
    return false;
}

function applyGameplayAssist(screenId) {
    if (window._qadventure && window._qadventure.active && window._qadventure.powerUps && window._qadventure.powerUps.hint > 0) {
        window._qadventure.usePower('hint');
        return true;
    }
    switch (screenId) {
        case 'screen-match': return assistMemoryMatch();
        case 'screen-timeline': return assistTimelineGame();
        case 'screen-hidden': return assistHiddenGame();
        case 'screen-maze': return assistMazeGame();
        case 'screen-color': return assistColorGame();
        case 'screen-face': return assistFaceGame();
        case 'screen-word': return assistWordGame();
        case 'screen-rhythm': return assistRhythmGame();
        case 'screen-spatial': return assistSpatialGame();
        case 'screen-fraud': return assistFraudGame();
        case 'screen-a11y': return assistA11yGame();
        case 'screen-trace': return assistTraceGame();
        case 'screen-decode': return assistDecodeGame();
        case 'screen-eco':
        case 'screen-ocean':
        case 'screen-oracle':
        case 'screen-truth':
        case 'screen-heart':
        case 'screen-grain':
            return assistGameplayDragScreen(screenId);
        default:
            return false;
    }
}

function prefersReducedMotion() {
    return !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
}

function spawnScoreParticle(x, y, text, color) {
    if (prefersReducedMotion()) return;
    var p = document.createElement('div');
    p.className = 'score-particle';
    p.textContent = text;
    p.style.left = x + 'px';
    p.style.top = y + 'px';
    if (color) p.style.color = color;
    document.body.appendChild(p);
    setTimeout(function() { p.remove(); }, 1200);
}

function spawnComboBurst(x, y, count, color) {
    if (prefersReducedMotion()) return;
    color = color || 'var(--accent-gold)';
    for (var i = 0; i < count; i++) {
        var p = document.createElement('div');
        p.className = 'combo-particle';
        p.style.left = x + 'px';
        p.style.top = y + 'px';
        p.style.background = color;
        var angle = (Math.PI * 2 * i) / count + Math.random() * 0.5;
        var dist = 40 + Math.random() * 60;
        p.style.setProperty('--cx', Math.cos(angle) * dist * 0.5 + 'px');
        p.style.setProperty('--cy', Math.sin(angle) * dist * 0.5 + 'px');
        p.style.setProperty('--ex', Math.cos(angle) * dist + 'px');
        p.style.setProperty('--ey', Math.sin(angle) * dist + 'px');
        document.body.appendChild(p);
        setTimeout(function() { p.remove(); }, 800);
    }
}

function spawnTouchRipple(el, e) {
    if (prefersReducedMotion()) return;
    var rect = el.getBoundingClientRect();
    var ripple = document.createElement('span');
    ripple.className = 'touch-ripple';
    ripple.style.left = (e.clientX - rect.left - 10) + 'px';
    ripple.style.top = (e.clientY - rect.top - 10) + 'px';
    el.style.position = el.style.position || 'relative';
    el.style.overflow = 'hidden';
    el.appendChild(ripple);
    setTimeout(function() { ripple.remove(); }, 600);
}

function shakeElement(el) {
    el.classList.add('shake');
    setTimeout(function() { el.classList.remove('shake'); }, 500);
}

// Hook into existing audio.playSnap to add visual feedback
var _originalPlaySnap = (typeof audio !== 'undefined' && audio.playSnap) ? audio.playSnap.bind(audio) : null;
if (typeof audio !== 'undefined' && _originalPlaySnap) {
    audio.playSnap = function() {
        _originalPlaySnap();
        // Spawn combo burst at center of screen for combos >= 3
        var comboIndicator = document.querySelector('.combo-indicator.active');
        if (comboIndicator) {
            spawnComboBurst(window.innerWidth / 2, window.innerHeight / 2, 12, 'var(--accent-gold)');
        }
    };
}

// DOM init
document.addEventListener('DOMContentLoaded', function() {
    initThemeSwitcher();
    initKeyboardShortcuts();

    // Global touch ripple on all buttons
    document.addEventListener('click', function(e) {
        var btn = e.target.closest('button, .hub-tab, .btn-primary, .btn-secondary, .btn-text');
        if (btn) spawnTouchRipple(btn, e);
    }, true);
});

// ============================================================================
// 9. EVENT BINDINGS & APP LAUNCH
// ============================================================================
let workbench;

// 🔑 防抖工具函数：防止 resize 高频触发导致布局计算风暴
function debounce(fn, delay) {
    let timer = null;
    return function(...args) {
        clearTimeout(timer);
        timer = setTimeout(() => fn.apply(this, args), delay);
    };
}

// 🔑 屏幕尺寸突变时，将所有未吸附零件安全复位到托盘中，防止坐标越界
const handleResize = debounce(() => {
    if (!workbench || workbench.currentRestorationStage !== 'assemble') return;
    const parts = document.querySelectorAll('.draggable-part:not(.snapped-hidden)');
    const tray = document.getElementById('parts-tray-zone');
    if (!tray) return;
    const trayW = tray.clientWidth;
    const trayH = tray.clientHeight;
    parts.forEach((el, i) => {
        el.style.transition = 'all 0.4s ease';
        el.style.left = `${Math.random() * Math.max(10, trayW - 150) + 5}px`;
        el.style.top = `${(i * 90) % Math.max(10, trayH - 150) + 5}px`;
        el.style.transform = `rotate(${(Math.random() - 0.5) * 12}deg) scale(1.0)`;
        el.style.zIndex = '1';
    });
    // 重置进行中的拖拽状态
    if (gameState.draggedElement) {
        gameState.draggedElement.style.zIndex = '1';
        gameState.draggedElement = null;
        gameState.activeDragPart = null;
    }
}, 250);

window.addEventListener('resize', handleResize);
window.addEventListener('orientationchange', () => setTimeout(handleResize, 300));

document.addEventListener('DOMContentLoaded', () => {
    initA11yNavigationHelpers();
    initNavigationFallbacks();

    // 🔑 精准触控拦截器（A11y 友好）：仅对拼图工作台区域阻止原生滚动，
    // 放行屏幕阅读器手势、模态滚动区、表单控件
    document.addEventListener('touchmove', (e) => {
        const target = e.target;
        // 1. 明确放行：可滚动区域、滑块、文本输入
        if (target.closest('.modal-scroll-body') ||
            target.closest('.album-pages-container') ||
            target.closest('.narrative-scroll-area') ||
            target.closest('input[type="range"]') ||
            target.closest('textarea') ||
            target.closest('input[type="text"]') ||
            target.closest('.shop-items-list')) {
            return;
        }
        // 2. A11y 保护：永远放行屏幕阅读器手势
        //    VoiceOver / TalkBack 使用系统级手势，我们无法直接检测，
        //    但任何不在游戏交互区内的 touchmove 都不应被拦截
        // 3. 仅对以下游戏交互区域拦截：
        if (target.closest('.blueprint-area') ||
            target.closest('.parts-tray-container') ||
            target.closest('.matchbox-striker') ||
            target.closest('.draggable-part')) {
            e.preventDefault();
            return;
        }
        // 4. 其他区域（胶囊卡片区、按钮区等）：放行原生滚动以防 A11y 工具手势被阻断
    }, { passive: false });

    // 禁用移动端默认上下文弹出菜单（防选中与长按菜单）
    document.addEventListener('contextmenu', (e) => {
        if (e.target.closest('.draggable-part') || 
            e.target.closest('.blueprint-area') || 
            e.target.closest('.btn-pedal') || 
            e.target.closest('.match-stick') || 
            e.target.closest('.watch-visual-indicator') ||
            e.target.closest('.matchbox-striker') ||
            e.target.id === 'winding-crown' ||
            e.target.id === 'btn-wind-crown' ||
            e.target.closest('#btn-sewing-pedal')) {
            e.preventDefault();
        }
    });

    // Instantiate core modules safely inside DOMContentLoaded
    workbench = new PuzzleWorkbench();

    // Run Ambient Particle Floating
    const spaceParticles = new AmbientParticles();
    window._ambientParticles = spaceParticles;
    spaceParticles.animate();
    
    // Sync Hub States Initially (Radio is unlocked, others locked)
    syncHubState();
    
    // Sound Button Click (Double Insurance)
    safeBindClick('bgm-toggle-btn', () => {
        const isPlaying = audio.toggleBGM();
        updateAudioButtonUI(isPlaying);
    });
    
    // Screen transition binds
    document.getElementById('btn-start-game')?.addEventListener('click', () => {
        transitionToScreen('screen-hub');
    });
    
    document.getElementById('btn-back-to-start')?.addEventListener('click', () => {
        transitionToScreen('screen-start');
    });
    
    document.getElementById('btn-back-to-hub')?.addEventListener('click', () => {
        transitionToScreen('screen-hub');
    });

    document.getElementById('btn-close-narrative')?.addEventListener('click', () => {
        // Stop all active toy loops and static noises
        audio.stopRadioStatic();
        audio.stopRadioMelody();
        audio.stopSewingLoop();

        if (workbench && typeof workbench.cleanupActiveRuntime === 'function') {
            workbench.cleanupActiveRuntime();
        }

        // Close modal overlay
        setModalOpen(document.getElementById('narrative-overlay'), false);
        
        // Sync Hub screens and show updated locks
        syncHubState();
        
        // Return to Cabin Hub
        transitionToScreen('screen-hub');
    });

    // Developer Easter Egg: double click workspace title to instantly solve puzzle for testing interactive toys
    document.getElementById('workspace-title')?.addEventListener('dblclick', () => {
        // Safe transition to assembly stage to instantly clear all dust/rust filters
        workbench.transitionToStage('assemble');

        const parts = document.querySelectorAll('.draggable-part');
        parts.forEach(el => el.classList.add('snapped-hidden'));
        
        gameState.snappedCount = gameState.totalPartsCount;
        
        const data = itemBlueprints[workbench.activeBlueprintId];
        data.parts.forEach(part => {
            const slotGroup = document.getElementById(`slot-${part.id}`);
            if (slotGroup) {
                slotGroup.innerHTML = safeHTML(`<g class="colored-shape" filter="drop-shadow(0 0 12px var(--accent-gold-glow))">${part.svg}</g>`);
            }
        });
        workbench.triggerObjectAwake();
    });
    
    document.getElementById('btn-album-back-to-hub')?.addEventListener('click', () => {
        transitionToScreen('screen-hub');
    });
    
    document.getElementById('btn-close-album-view')?.addEventListener('click', () => {
        transitionToScreen('screen-hub');
    });
    
    document.getElementById('btn-open-album')?.addEventListener('click', () => {
        transitionToScreen('screen-album');
        renderAlbum();
    });
    
    // Capsule Card Click/Keyboard Events (Starts workbench game)
    const cards = document.querySelectorAll('.capsule-card');
    const openCapsuleCard = (card) => {
        const id = card.dataset.item;
        if (gameState.completedItems.includes(id)) {
            // If already completed, just view story inside the album
            transitionToScreen('screen-album');
            renderAlbum();
        } else if (gameState.unlockedItems.includes(id)) {
            // Lock onto selected item and load workbench
            gameState.activeItem = id;
            trackGamePlay('memory-' + id);
            workbench.setupItem(id);
            transitionToScreen('screen-workspace');
        } else {
            // Locked capsule shake micro-interaction
            card.style.animation = 'none';
            card.offsetHeight; // Trigger reflow
            card.style.animation = 'floatAnim 0.3s ease-in-out';
            audio.playGrab(); // soft thud sound
        }
    };
    cards.forEach(card => {
        card.addEventListener('click', () => openCapsuleCard(card));
        card.addEventListener('keydown', (e) => {
            if (e.key !== 'Enter' && e.key !== ' ') return;
            e.preventDefault();
            openCapsuleCard(card);
        });
    });
    
    // Handbook / Guide Modals
    const guideOverlay = document.getElementById('guide-overlay');
    const openGuideBtn = document.getElementById('btn-open-guide');
    
    openGuideBtn?.addEventListener('click', () => {
        setModalOpen(guideOverlay, true, openGuideBtn);
    });
    
    document.getElementById('btn-close-guide')?.addEventListener('click', () => {
        setModalOpen(guideOverlay, false);
    });
    
    document.getElementById('btn-guide-got-it')?.addEventListener('click', () => {
        setModalOpen(guideOverlay, false);
        transitionToScreen('screen-hub');
    });

    // Shop Overlays Binds
    const shopOverlay = document.getElementById('shop-overlay');
    const openShopBtn = document.getElementById('btn-open-shop');
    
    if (openShopBtn) {
        openShopBtn.addEventListener('click', () => {
            updateShopUI();
            setModalOpen(shopOverlay, true, openShopBtn);
            audio.playHover();
        });
    }
    
    const closeShopBtn = document.getElementById('btn-close-shop');
    if (closeShopBtn) {
        closeShopBtn.addEventListener('click', () => {
            setModalOpen(shopOverlay, false);
            syncHubState();
        });
    }
    
    const shopGotItBtn = document.getElementById('btn-shop-got-it');
    if (shopGotItBtn) {
        shopGotItBtn.addEventListener('click', () => {
            setModalOpen(shopOverlay, false);
            syncHubState();
        });
    }
    
    // Purchase bindings (Double Insurance)
    if (document.getElementById('btn-buy-upgrade-cleaner')) {
        safeBindClick('btn-buy-upgrade-cleaner', () => {
            const cost = economyManager.getUpgradeCost(gameState.upgrades.cleaner.baseCost, gameState.upgrades.cleaner.level);
            if (gameState.memorySilver >= cost) {
                gameState.memorySilver -= cost;
                gameState.upgrades.cleaner.level++;
                updateShopUI();
                audio.playAwake();
            } else {
                audio.playGrab();
                alert("🪙 记忆银币不足！完成拼图或触发脑力共鸣可赚取银币噢。");
            }
        });
    }
    
    if (document.getElementById('btn-buy-upgrade-tuner')) {
        safeBindClick('btn-buy-upgrade-tuner', () => {
            const cost = economyManager.getUpgradeCost(gameState.upgrades.tuner.baseCost, gameState.upgrades.tuner.level);
            if (gameState.memorySilver >= cost) {
                gameState.memorySilver -= cost;
                gameState.upgrades.tuner.level++;
                updateShopUI();
                audio.playAwake();
            } else {
                audio.playGrab();
                alert("🪙 记忆银币不足！完成拼图或触发脑力共鸣可赚取银币噢。");
            }
        });
    }
    
    if (document.getElementById('btn-buy-upgrade-stitch')) {
        safeBindClick('btn-buy-upgrade-stitch', () => {
            const cost = economyManager.getUpgradeCost(gameState.upgrades.stitch.baseCost, gameState.upgrades.stitch.level);
            if (gameState.memorySilver >= cost) {
                gameState.memorySilver -= cost;
                gameState.upgrades.stitch.level++;
                updateShopUI();
                audio.playAwake();
            } else {
                audio.playGrab();
                alert("🪙 记忆银币不足！完成拼图或触发脑力共鸣可赚取银币噢。");
            }
        });
    }

    // ============================================================================
    // 10. POSTER SYNTHESIS & SAVE CARD BINDINGS
    // ============================================================================
    const btnGeneratePoster = document.getElementById('btn-generate-capsule-poster');
    if (btnGeneratePoster) {
        btnGeneratePoster.addEventListener('click', async () => {
            if (gameState.albumEntries.length === 0) {
                alert("相册内还没有重构完成的器物记忆，快去重构一件吧！");
                return;
            }
            
            // Generate poster for the latest completed/edited item in the album
            const latestEntry = gameState.albumEntries.slice().reverse().find(entry => entry && itemBlueprints[entry.id]);
            if (!latestEntry) {
                alert("相册内暂时没有可生成海报的完整器物记忆，请先重构一件物品。");
                return;
            }
            const blueprint = itemBlueprints[latestEntry.id];
            const customMessage = (document.getElementById('album-custom-message')?.value || "").slice(0, 120);

            // Show custom elegant loading toast
            const loadingToast = document.createElement('div');
            loadingToast.className = 'poetic-toast';
            loadingToast.style.borderColor = 'var(--accent-rose)';
            loadingToast.innerHTML = safeHTML(`
                <div class="toast-glow"></div>
                <div class="toast-content">
                    <span class="toast-part-name" style="color: var(--accent-rose);">🎨 正在合成高清海报 🎨</span>
                    <p class="toast-part-hint" style="font-size: 0.88rem; line-height: 1.5;">大模型情感与时空寄语正在压盖印章并生成高清时光海报，请稍候...</p>
                </div>
            `);
            document.body.appendChild(loadingToast);

            try {
                const dataURL = await CanvasPosterGenerator.generate(blueprint, latestEntry.storyText, customMessage);
                
                // Show modal overlay
                const posterOverlay = document.getElementById('poster-overlay');
                const posterImg = document.getElementById('poster-image');
                if (posterOverlay && posterImg) {
                    posterImg.src = dataURL;
                    setModalOpen(posterOverlay, true, btnGeneratePoster);
                }
                
                // Set download link
                const btnDownload = document.getElementById('btn-download-poster');
                if (btnDownload) {
                    btnDownload.onclick = () => {
                        const link = document.createElement('a');
                        link.download = `时光的回响-${blueprint.title}-寄语海报.png`;
                        link.href = dataURL;
                        link.click();
                        audio.playAwake();
                    };
                }
            } catch (err) {
                console.error("Poster synthesis failed:", err);
                alert("海报生成失败，请检查浏览器 Canvas 兼容设置。");
            } finally {
                loadingToast.remove();
            }
        });
    }

    // Modal Close logic for Poster Overlay (Double Insurance)
    if (document.getElementById('btn-close-poster')) {
        safeBindClick('btn-close-poster', () => {
            setModalOpen(document.getElementById('poster-overlay'), false);
        });
    }
    if (document.getElementById('btn-close-poster-view')) {
        safeBindClick('btn-close-poster-view', () => {
            setModalOpen(document.getElementById('poster-overlay'), false);
        });
    }
});

// ============================================================================
// 11. 记忆翻牌模式 — Memory Match Game
// ============================================================================
class MemoryMatchGame {

    constructor() {
        this.cards = [];
        this.flipped = [];
        this.matched = new Set();
        this.moves = 0;
        this.pairs = 0;
        this.locked = false;
        this.mismatchTimer = null;
        this.active = false;
    }

    init() {
        this._clearMismatchTimer();
        this.active = true;
        const pairs = ['🧶', '📻', '🕯️', '🌸', '🧵', '📖', '🫖', '🎵'];
        this.cards = [...pairs, ...pairs].map((emoji, i) => ({ emoji, id: i }));
        for (let i = this.cards.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [this.cards[i], this.cards[j]] = [this.cards[j], this.cards[i]];
        }
        this.flipped = []; this.matched = new Set(); this.moves = 0; this.pairs = 0; this.locked = false;
        this._render(); this._updateStats();
        trackGamePlay('memory-match');
    }

    _render() {
        const grid = document.getElementById('match-grid');
        grid.innerHTML = '';
        this.cards.forEach((card, index) => {
            const el = document.createElement('div');
            el.className = 'match-card';
            el.setAttribute('role', 'button');
            el.setAttribute('aria-label', '记忆卡片 ' + (index + 1));
            el.setAttribute('aria-pressed', 'false');
            el.tabIndex = 0;
            el.innerHTML = safeHTML('<div class="match-card-inner"><div class="match-card-front"></div><div class="match-card-back">' + escapeTextForHTML(card.emoji) + '</div></div>');
            el.addEventListener('click', () => this._flipCard(index, el));
            el.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    this._flipCard(index, el);
                }
            });
            grid.appendChild(el);
        });
        document.getElementById('match-result').classList.add('hidden');
    }

    _flipCard(index, el) {
        if (!this.active) return;
        if (this.locked || this.flipped.includes(index) || this.matched.has(index)) return;
        el.classList.add('flipped'); this.flipped.push(index);
        el.setAttribute('aria-pressed', 'true');
        if (this.flipped.length === 2) {
            this.moves++; this._updateStats();
            const [a, b] = this.flipped;
            if (this.cards[a].emoji === this.cards[b].emoji) {
                this.matched.add(a); this.matched.add(b); this.pairs++; this._updateStats(); this.flipped = [];
                const matchedCards = document.querySelectorAll('.match-card');
                [matchedCards[a], matchedCards[b]].forEach(function(cardEl) {
                    if (!cardEl) return;
                    cardEl.classList.add('matched');
                    cardEl.setAttribute('aria-disabled', 'true');
                    cardEl.tabIndex = -1;
                    cardEl.setAttribute('aria-label', (cardEl.getAttribute('aria-label') || '记忆卡片') + '，已配对');
                });
                audio.playSnap();
                if (this.pairs === 8) this._onWin();
            } else {
                this.locked = true;
                this.mismatchTimer = trackCognitiveTimeout(() => {
                    this.mismatchTimer = null;
                    if (!this.active) return;
                    const cards = document.querySelectorAll('.match-card');
                    if (cards[a]) {
                        cards[a].classList.remove('flipped');
                        cards[a].setAttribute('aria-pressed', 'false');
                    }
                    if (cards[b]) {
                        cards[b].classList.remove('flipped');
                        cards[b].setAttribute('aria-pressed', 'false');
                    }
                    this.flipped = []; this.locked = false;
                }, 700);
                audio.playHover();
            }
        }
    }

    _updateStats() {
        document.getElementById('match-moves').textContent = this.moves;
        document.getElementById('match-pairs').textContent = this.pairs;
    }

    _onWin() {
        if (!this.active) return;
        this.active = false;
        this._clearMismatchTimer();
        const baseScore = Math.max(10, 80 - this.moves);
        const reward = unifiedRewardCalc(baseScore, 0, 'easy', 0, 100);
        document.getElementById('match-score-text').textContent = '用了 ' + this.moves + ' 步完成！获得 +' + reward + ' 记忆银币';
        document.getElementById('match-result').classList.remove('hidden');
        trackGameComplete('memory-match', baseScore);
        audio.playAwake();
    }

    _clearMismatchTimer() {
        if (this.mismatchTimer) clearTrackedCognitiveTimeout(this.mismatchTimer);
        this.mismatchTimer = null;
    }

    destroy() {
        this.active = false;
        this._clearMismatchTimer();
        this.flipped = [];
        this.locked = false;
    }
}


// ============================================================================
// 12. 时光排序模式 — Timeline Sort Game
// ============================================================================
const timelineEvents = [
    { year: '1962', text: '奶奶初识爷爷，在桂花树下', emoji: '🌸' },
    { year: '1965', text: '奶奶与爷爷结婚，穿上红嫁衣', emoji: '💒' },
    { year: '1968', text: '爸爸出生，奶奶第一次当母亲', emoji: '👶' },
    { year: '1995', text: '孙辈出生，奶奶开心得合不拢嘴', emoji: '🎀' },
    { year: '2010', text: '爷爷奶奶退休，回到老宅种花', emoji: '🏡' },
    { year: '2024', text: '现在——奶奶的记忆开始模糊，但我们一直陪着', emoji: '💛' }
,
    { year: '1951', text: '奶奶一岁，开始学走路，在院子里追小鸡', emoji: '🐤' },
    { year: '1952', text: '奶奶两岁，家里添了第一只小花猫', emoji: '🐱' },
    { year: '1953', text: '奶奶三岁，跟着姐姐在河边洗衣服', emoji: '👧' },
    { year: '1954', text: '奶奶四岁，第一次吃到白糖糕，甜了一整天', emoji: '🍰' },
    { year: '1955', text: '奶奶五岁，爸爸给她做了第一个布娃娃', emoji: '🧸' },
    { year: '1956', text: '奶奶六岁，跟着哥哥去山上采野果', emoji: '🍓' },
    { year: '1957', text: '奶奶七岁，在村口的大槐树下学会了跳绳', emoji: '🪢' },
    { year: '1959', text: '奶奶九岁，第一次走进学堂，学写自己的名字', emoji: '✏️' },
    { year: '1961', text: '奶奶十一岁，饥荒年代学会了用野菜充饥', emoji: '🌿' },
    { year: '1964', text: '奶奶十四岁，第一次去县城看到了汽车', emoji: '🚗' },
    { year: '1966', text: '奶奶十六岁，绣了第一幅完整的鸳鸯戏水图', emoji: '🪡' },
    { year: '1969', text: '奶奶十九岁，镇上的媒人第一次上门说亲', emoji: '💌' },
    { year: '1970', text: '爷爷带奶奶去照相馆拍了第一张彩色合照', emoji: '📸' },
    { year: '1972', text: '奶奶怀上了第一个孩子，爷爷每天给她炖汤', emoji: '🍲' },
    { year: '1973', text: '奶奶生下爸爸，整个胡同的人都来贺喜', emoji: '🎉' },
    { year: '1974', text: '爸爸满周岁，奶奶给他做了第一双虎头鞋', emoji: '👟' },
    { year: '1976', text: '奶奶和爷爷第一次去北京，在天安门前合影', emoji: '🏛️' },
    { year: '1977', text: '奶奶的缝纫作品第一次在县展览馆展出', emoji: '🏅' },
    { year: '1978', text: '改革开放，奶奶接到的订单突然多了三倍', emoji: '📈' },
    { year: '1979', text: '奶奶买了一台收音机，全家每晚围在一起听评书', emoji: '📻' },
    { year: '1981', text: '奶奶被评为县里的三八红旗手', emoji: '🎖️' },
    { year: '1982', text: '奶奶的缝纫笔记写满了三本', emoji: '📒' },
    { year: '1983', text: '家里添了第一台黑白电视机，邻居都来看', emoji: '📺' },
    { year: '1984', text: '奶奶第一次用电熨斗，感叹科技进步真快', emoji: '🔌' },
    { year: '1986', text: '爸爸高考，奶奶紧张得一夜没睡', emoji: '📝' },
    { year: '1987', text: '爸爸考上大学，成了镇上第一个大学生', emoji: '🎓' },
    { year: '1988', text: '奶奶和爷爷第一次坐飞机，去送爸爸上学', emoji: '✈️' },
    { year: '1989', text: '奶奶用上了第一台电动缝纫机', emoji: '⚙️' },
    { year: '1991', text: '奶奶做了第一件旗袍，华丽得让人惊叹', emoji: '👘' },
    { year: '1992', text: '爷爷生日，奶奶偷偷学做了蛋糕', emoji: '🎂' },
    { year: '1993', text: '奶奶开始教镇上的姑娘学缝纫，不收学费', emoji: '👩‍🏫' },
    { year: '1994', text: '爸爸毕业工作了，寄回来第一份工资', emoji: '💰' },
    { year: '1996', text: '奶奶当上了外婆，抱着刚出生的你笑出了泪花', emoji: '👵' },
    { year: '1997', text: '香港回归，奶奶在电视上看直播', emoji: '🇭🇰' },
    { year: '1999', text: '澳门回归，奶奶说中国越来越强大了', emoji: '🇲🇴' },
    { year: '2000', text: '千禧年跨年夜，奶奶许愿全家平安健康', emoji: '🎆' },
    { year: '2001', text: '中国加入WTO，奶奶说生意更好做了', emoji: '🌏' },
    { year: '2002', text: '奶奶第一次用电脑，颤巍巍地学会了打字', emoji: '💻' },
    { year: '2004', text: '奶奶的缝纫店正式关门，她说时代变了', emoji: '🚪' },
    { year: '2005', text: '奶奶开始学跳广场舞，成了小区领舞', emoji: '💃' },
    { year: '2006', text: '奶奶六十六大寿，全家四代同堂', emoji: '🎂' },
    { year: '2007', text: '奶奶学会了发电子邮件给远方的老姐妹', emoji: '📧' },
    { year: '2009', text: '奶奶第一次看3D电影，被特效吓得抓住扶手', emoji: '🎬' },
    { year: '2011', text: '微信刚出来，奶奶就让爸爸给她装上了', emoji: '💚' },
    { year: '2013', text: '奶奶学会了用手机拍照，相册里全是花花草草', emoji: '📷' },
    { year: '2014', text: '奶奶养了一只博美犬，取名小福子', emoji: '🐕' },
    { year: '2016', text: '奶奶用手机点了人生第一份外卖', emoji: '🍜' },
    { year: '2017', text: '奶奶学会了发朋友圈，每天分享养生知识', emoji: '📱' },
    { year: '2019', text: '奶奶第一次用手机扫码支付，觉得太神奇了', emoji: '📲' },
    { year: '2021', text: '奶奶打完了新冠疫苗，说国家真好', emoji: '💉' },
    { year: '2022', text: '奶奶学会了刷短视频，每天看美食教程', emoji: '🎥' },
    { year: '2023', text: '奶奶的记忆越来越差，但还记得每个人爱吃的菜', emoji: '🍽️' },
    { year: '2025', text: '奶奶说这辈子最大的幸福就是有你们在身边', emoji: '💝' },
    { year: '1954', text: '奶奶四岁，在田埂上追蝴蝶摔了一跤', emoji: '🦋' },
    { year: '1962', text: '奶奶第一次穿上了自己缝的碎花裙子', emoji: '👗' },
    { year: '1965', text: '爷爷骑自行车带奶奶去看露天电影', emoji: '🎬' },
    { year: '1974', text: '奶奶接的第一笔大订单，镇上小学的全校校服', emoji: '🏫' },
    { year: '1980', text: '奶奶买了第一台14寸黑白电视机', emoji: '📺' },
    { year: '1983', text: '奶奶第一次烫了卷发，爷爷说好看极了', emoji: '💇' },
    { year: '1988', text: '奶奶去深圳看爸爸，第一次见到摩天大楼', emoji: '🏙️' },
    { year: '1992', text: '徒弟开了裁缝铺，她比自己开店还高兴', emoji: '🎊' },
    { year: '1995', text: '奶奶织了第一件毛衣给你，袖子一边长一边短', emoji: '🧶' },
    { year: '2000', text: '奶奶学会用手机，第一通电话打给了爷爷', emoji: '📞' },
    { year: '2002', text: '奶奶被邀请回镇上小学做校外辅导员', emoji: '🏫' },
    { year: '2005', text: '奶奶第一次出国旅游，去了新马泰', emoji: '✈️' },
    { year: '2007', text: '奶奶的缝纫手艺被收录进县非遗候选名单', emoji: '📜' },
    { year: '2010', text: '上海世博会，奶奶排了三小时队看中国馆', emoji: '🏛️' },
    { year: '2012', text: '奶奶开始用平板电视看甄嬛传', emoji: '📱' },
    { year: '2014', text: '奶奶学会发微信红包，过年给每个孙辈发', emoji: '🧧' },
    { year: '2016', text: '奶奶养了一只橘猫，取名小橘子', emoji: '🐱' },
    { year: '2018', text: '奶奶开始手写回忆录，已经写满了五本', emoji: '📝' },
    { year: '2020', text: '疫情封控期间，奶奶学会了视频通话买菜', emoji: '🥬' },
    { year: '2022', text: '奶奶八十二岁大寿，全家从各地赶回来团聚', emoji: '🎂' },
    { year: '2023', text: '奶奶的记忆开始模糊，但还会唱年轻时的歌', emoji: '🎵' },
    { year: '1950', text: '奶奶出生在江南水乡，院子里有一棵桂花树', emoji: '🌸' },
    { year: '1976', text: '唐山大地震，奶奶捐出了半个月的收入', emoji: '🙏' },
    { year: '1958', text: '奶奶八岁，第一次跟着外婆学缝纫', emoji: '🧵' },
    { year: '1960', text: '奶奶十岁，饿着肚子把粮食留给弟妹', emoji: '🍚' },
    { year: '1963', text: '奶奶进纺织厂当学徒，每天走五里路', emoji: '🏭' },
    { year: '1967', text: '奶奶和爷爷一起修好了第一台缝纫机', emoji: '🪡' },
    { year: '1971', text: '奶奶的母亲去世，她第一次经历至亲离别', emoji: '😢' },
    { year: '1975', text: '奶奶自己设计婚纱，帮镇上姑娘做嫁衣', emoji: '👗' },
    { year: '1985', text: '爸爸上学了，奶奶在缝纫机旁辅导作业', emoji: '📖' },
    { year: '1990', text: '爷爷奶奶攒了十年钱，终于盖起了新房', emoji: '🏠' },
    { year: '1998', text: '奶奶第一次坐火车，去省城看爸爸上大学', emoji: '🚂' },
    { year: '2003', text: '奶奶学会了用手机，每天给爸爸打电话', emoji: '📱' },
    { year: '2008', text: '爷爷突发心脏病，奶奶守在床前三天三夜', emoji: '🏥' },
    { year: '2015', text: '奶奶的缝纫机用了五十年，终于退休了', emoji: '🪑' },
    { year: '2018', text: '奶奶开始出现健忘症状', emoji: '🧠' },
    { year: '1950', text: '奶奶出生在江南水乡，院子里有一棵桂花树', emoji: '🌸' },
    { year: '1976', text: '唐山大地震，奶奶捐出了半个月的收入', emoji: '🙏' },
    { year: '1958', text: '奶奶八岁，第一次跟着外婆学缝纫', emoji: '🧵' },
    { year: '1960', text: '奶奶十岁，饿着肚子把粮食留给弟妹', emoji: '🍚' },
    { year: '1963', text: '奶奶进纺织厂当学徒，每天走五里路', emoji: '🏭' },
    { year: '1967', text: '奶奶和爷爷一起修好了第一台缝纫机', emoji: '🪡' },
    { year: '1971', text: '奶奶的母亲去世，她第一次经历至亲离别', emoji: '😢' },
    { year: '1975', text: '奶奶自己设计婚纱，帮镇上姑娘做嫁衣', emoji: '👗' },
    { year: '1985', text: '爸爸上学了，奶奶在缝纫机旁辅导作业', emoji: '📖' },
    { year: '1990', text: '爷爷奶奶攒了十年钱，终于盖起了新房', emoji: '🏠' },
    { year: '1998', text: '奶奶第一次坐火车，去省城看爸爸上大学', emoji: '🚂' },
];

function initTimelineGame() {
    cleanupTimelineRuntime();
    trackGamePlay('timeline');
    window._timelineCompleted = false;
    var checkBtn = document.getElementById('btn-timeline-check');
    if (checkBtn) {
        checkBtn.disabled = false;
        checkBtn.setAttribute('aria-disabled', 'false');
    }
    const shuffled = [...timelineEvents].sort(() => Math.random() - 0.5);
    const track = document.getElementById('timeline-track');
    const cardsContainer = document.getElementById('timeline-cards');

    track.innerHTML = safeHTML(timelineEvents.map((e, i) =>
        '<div class="timeline-slot" data-slot="' + i + '">' + escapeTextForHTML(e.year) + '</div>'
    ).join(''));

    cardsContainer.innerHTML = '';
    shuffled.forEach(evt => {
        const card = document.createElement('div');
        card.className = 'timeline-card';
        card.textContent = evt.emoji + ' ' + evt.text;
        card.draggable = true;
        card.dataset.year = evt.year;
        card.setAttribute('role', 'button');
        card.tabIndex = 0;

        card.addEventListener('dragstart', e => {
            e.dataTransfer.setData('text/plain', evt.year);
            card.style.opacity = '0.5';
        });
        card.addEventListener('dragend', () => { card.style.opacity = '1'; });

        card.addEventListener('pointerdown', function(e) {
            if (card.classList.contains('placed')) return;
            const clone = card.cloneNode(true);
            clone.style.cssText = 'position:fixed;z-index:9999;pointer-events:none;padding:10px 16px;background:rgba(229,169,59,0.2);border:2px solid var(--accent-gold);border-radius:12px;color:var(--text-primary);font-size:0.9rem;';
            clone.style.left = (e.clientX - 60) + 'px';
            clone.style.top = (e.clientY - 20) + 'px';
            document.body.appendChild(clone);

            const move = function(ev) { clone.style.left = (ev.clientX - 60) + 'px'; clone.style.top = (ev.clientY - 20) + 'px'; };
            const up = function(ev) {
                document.removeEventListener('pointermove', move);
                document.removeEventListener('pointerup', up);
                window._timelineCleanup = null;
                clone.remove();
                const slot = document.elementFromPoint(ev.clientX, ev.clientY);
                const targetSlot = slot ? slot.closest('.timeline-slot:not(.filled)') : null;
                if (targetSlot) {
                    targetSlot.classList.add('filled');
                    targetSlot.textContent = evt.emoji + ' ' + evt.text;
                    targetSlot.dataset.year = evt.year;
                    card.classList.add('placed');
                    audio.playHover();
                }
            };
            window._timelineCleanup = { move: move, up: up, clone: clone };
            document.addEventListener('pointermove', move);
            document.addEventListener('pointerup', up);
        });
        card.addEventListener('click', function() {
            if (card.classList.contains('placed')) return;
            window._timelineTapCard = { card: card, evt: evt };
            setTapPlaceSelection(card, 'timeline');
            showGameplayToast('已选中记忆卡，再点年份位置即可放置。', 'hint');
        });
        card.addEventListener('keydown', function(e) {
            if (e.key !== 'Enter' && e.key !== ' ') return;
            e.preventDefault();
            card.click();
        });

        cardsContainer.appendChild(card);
    });

    track.querySelectorAll('.timeline-slot').forEach(slot => {
        slot.setAttribute('role', 'button');
        slot.tabIndex = 0;
        function placeSelectedTimelineCard() {
            if (slot.classList.contains('filled') || !window._timelineTapCard) return;
            var selected = window._timelineTapCard;
            slot.classList.add('filled');
            slot.textContent = selected.evt.emoji + ' ' + selected.evt.text;
            slot.dataset.year = selected.evt.year;
            selected.card.classList.add('placed');
            setTapPlaceSelection(null, 'timeline');
            window._timelineTapCard = null;
            if (typeof audio !== 'undefined' && audio.playHover) audio.playHover();
        }
        slot.addEventListener('click', placeSelectedTimelineCard);
        slot.addEventListener('keydown', function(e) {
            if (e.key !== 'Enter' && e.key !== ' ') return;
            e.preventDefault();
            placeSelectedTimelineCard();
        });
        slot.addEventListener('dragover', e => { e.preventDefault(); slot.style.borderColor = 'var(--accent-rose)'; });
        slot.addEventListener('dragleave', () => { slot.style.borderColor = ''; });
        slot.addEventListener('drop', e => {
            e.preventDefault(); slot.style.borderColor = '';
            if (slot.classList.contains('filled')) return;
            const year = e.dataTransfer.getData('text/plain');
            const src = document.querySelector('.timeline-card[data-year="' + year + '"]:not(.placed)');
            if (src) {
                const evt = timelineEvents.find(e => e.year === year);
                slot.classList.add('filled');
                slot.textContent = (evt ? evt.emoji + ' ' + evt.text : '');
                slot.dataset.year = year;
                src.classList.add('placed');
            }
        });
    });

    document.getElementById('timeline-result').classList.add('hidden');
}

function checkTimeline() {
    if (window._timelineCompleted) return;
    if (window._timelineResetTimer) {
        clearTrackedCognitiveTimeout(window._timelineResetTimer);
        window._timelineResetTimer = null;
    }
    const slots = document.querySelectorAll('.timeline-slot');
    let allCorrect = true, correctCount = 0;
    slots.forEach((slot, i) => {
        if (slot.dataset.year === timelineEvents[i].year) { slot.classList.add('correct'); correctCount++; }
        else if (slot.dataset.year) { slot.classList.add('wrong'); allCorrect = false; }
        else { allCorrect = false; }
    });

    const result = document.getElementById('timeline-result');
    result.classList.remove('hidden');
    if (allCorrect) {
        window._timelineCompleted = true;
        var checkBtn = document.getElementById('btn-timeline-check');
        if (checkBtn) {
            checkBtn.disabled = true;
            checkBtn.setAttribute('aria-disabled', 'true');
        }
        gameState.memorySilver += 50;
        document.getElementById('global-silver-balance').textContent = gameState.memorySilver;
        document.getElementById('timeline-result-title').textContent = '完全正确！';
        document.getElementById('timeline-result-text').textContent = '奶奶的人生故事线重新连起来了——获得 +50 记忆银币';
        trackGameComplete('timeline', correctCount * 10);
        audio.playAwake();
    } else {
        document.getElementById('timeline-result-title').textContent = '对了 ' + correctCount + '/' + timelineEvents.length + ' 个';
        document.getElementById('timeline-result-text').textContent = '有些记忆还不在正确的位置，再试试看吧。';
        if (window._timelineResetTimer) clearTrackedCognitiveTimeout(window._timelineResetTimer);
        window._timelineResetTimer = trackCognitiveTimeout(() => {
            window._timelineResetTimer = null;
            slots.forEach((s, i) => {
                s.classList.remove('correct', 'wrong', 'filled');
                s.textContent = timelineEvents[i].year; s.dataset.year = '';
            });
            document.querySelectorAll('.timeline-card.placed').forEach(c => c.classList.remove('placed'));
            result.classList.add('hidden');
        }, 2000);
    }
}


// ============================================================================
// 13. 寻回失物模式
// ============================================================================
const hiddenObjects = [
    { id: 'key', emoji: '🗝️', name: '老钥匙', hint: '书桌抽屉旁' },
    { id: 'thimble', emoji: '🧵', name: '顶针', hint: '缝纫机附近' },
    { id: 'photo', emoji: '📷', name: '老照片', hint: '墙上的相框里' },
    { id: 'button', emoji: '🔘', name: '铜纽扣', hint: '地板角落' },
    { id: 'stamp', emoji: '💌', name: '旧邮票', hint: '桌面上' }
];

function initHiddenGame() {
    document.getElementById('hidden-found').textContent = '0';
    document.getElementById('hidden-result').classList.add('hidden');
    trackGamePlay('hidden');
    var svg = document.getElementById('hidden-scene-svg');
    svg.innerHTML = '<defs><radialGradient id="lampGlow" cx="50%" cy="50%"><stop offset="0%" stop-color="#ffd700" stop-opacity="0.25"/><stop offset="100%" stop-color="transparent"/></radialGradient></defs>' +
        '<rect width="600" height="400" fill="#1c1815"/>' +
        '<rect x="0" y="300" width="600" height="100" fill="#2a2018"/>' +
        '<line x1="0" y1="300" x2="600" y2="300" stroke="#3a3025" stroke-width="1.5"/>' +
        '<rect x="380" y="20" width="100" height="120" rx="4" fill="#1a2540" stroke="#5c3a21" stroke-width="3"/>' +
        '<line x1="430" y1="20" x2="430" y2="140" stroke="#5c3a21" stroke-width="2"/>' +
        '<line x1="380" y1="80" x2="480" y2="80" stroke="#5c3a21" stroke-width="2"/>' +
        '<circle cx="480" cy="150" r="30" fill="url(#lampGlow)"/>' +
        '<rect x="20" y="40" width="120" height="260" fill="#4a3520" stroke="#5c3a21" stroke-width="2"/>' +
        '<rect x="30" y="60" width="100" height="8" fill="#6b4c2a"/><rect x="30" y="110" width="100" height="8" fill="#6b4c2a"/><rect x="30" y="160" width="100" height="8" fill="#6b4c2a"/><rect x="30" y="210" width="100" height="8" fill="#6b4c2a"/>' +
        '<rect x="300" y="240" width="200" height="10" fill="#5c3a21" rx="3"/>' +
        '<rect x="310" y="180" width="60" height="60" fill="#3a2a1a" stroke="#5c3a21" stroke-width="1.5"/>' +
        '<rect x="380" y="190" width="50" height="50" fill="#4a3520" stroke="#5c3a21" stroke-width="1.5"/>' +
        '<path d="M 140,260 L 160,220 Q 170,200 190,200 L 230,200 Q 250,210 250,240 L 250,260 Z" fill="#2a2018" stroke="#5c3a21" stroke-width="2"/>' +
        '<circle cx="230" cy="220" r="15" fill="none" stroke="#5c3a21" stroke-width="1.5"/>' +
        '<g class="hidden-object" data-obj="key">' +
        '<rect class="hidden-hitbox" x="380" y="165" width="80" height="80" fill="#fff" opacity="0" pointer-events="all"/>' +
        '<circle cx="420" cy="185" r="14" fill="#c2a060" stroke="#8c6a46" stroke-width="1.5"/>' +
        '<rect x="416" y="192" width="8" height="18" fill="#c2a060" rx="1"/>' +
        '<circle cx="420" cy="212" r="5" fill="none" stroke="#c2a060" stroke-width="1.5"/></g>' +
        '<g class="hidden-object" data-obj="thimble">' +
        '<rect class="hidden-hitbox" x="145" y="240" width="80" height="80" fill="#fff" opacity="0" pointer-events="all"/>' +
        '<path d="M 175,275 Q 175,258 185,260 L 195,258 Q 205,260 205,275 L 200,290 L 180,290 Z" fill="#8c8279" stroke="#6b5b4a" stroke-width="1"/>' +
        '<circle cx="182" cy="265" r="1" fill="#6b5b4a"/><circle cx="190" cy="263" r="1" fill="#6b5b4a"/><circle cx="198" cy="267" r="1" fill="#6b5b4a"/></g>' +
        '<g class="hidden-object" data-obj="photo">' +
        '<rect class="hidden-hitbox" x="270" y="45" width="80" height="80" fill="#fff" opacity="0" pointer-events="all"/>' +
        '<rect x="290" y="65" width="40" height="50" fill="#ece3d5" stroke="#8c6a46" stroke-width="1.5" rx="2"/>' +
        '<rect x="294" y="69" width="32" height="42" fill="#f5ede0"/>' +
        '<circle cx="310" cy="82" r="7" fill="none" stroke="#6b5344" stroke-width="0.8"/></g>' +
        '<g class="hidden-object" data-obj="button">' +
        '<rect class="hidden-hitbox" x="65" y="315" width="80" height="80" fill="#fff" opacity="0" pointer-events="all"/>' +
        '<circle cx="105" cy="352" r="9" fill="#c2a060" stroke="#8c6a46" stroke-width="1.5"/>' +
        '<circle cx="102" cy="349" r="1.2" fill="#5c3215"/><circle cx="108" cy="349" r="1.2" fill="#5c3215"/>' +
        '<circle cx="102" cy="355" r="1.2" fill="#5c3215"/><circle cx="108" cy="355" r="1.2" fill="#5c3215"/></g>' +
        '<g class="hidden-object" data-obj="stamp">' +
        '<rect class="hidden-hitbox" x="320" y="190" width="80" height="80" fill="#fff" opacity="0" pointer-events="all"/>' +
        '<rect x="345" y="215" width="24" height="30" fill="#f5ede0" stroke="#8c6a46" stroke-width="1" rx="1"/>' +
        '<rect x="349" y="220" width="16" height="20" fill="#d4c5b0"/>' +
        '<circle cx="357" cy="230" r="4" fill="none" stroke="#8c6a46" stroke-width="0.8"/></g>';

    var checklist = document.getElementById('hidden-checklist');
    checklist.innerHTML = safeHTML(hiddenObjects.map(function(o) {
        return '<div class="hidden-item" data-obj="' + escapeTextForHTML(o.id) + '">' + escapeTextForHTML(o.emoji) + ' ' + escapeTextForHTML(o.name) + '<br><small>' + escapeTextForHTML(o.hint) + '</small></div>';
    }).join(''));

    svg.querySelectorAll('.hidden-object').forEach(function(el) {
        var objMeta = hiddenObjects.find(function(o) { return o.id === el.dataset.obj; });
        el.setAttribute('role', 'button');
        el.setAttribute('tabindex', '0');
        el.setAttribute('aria-label', '寻找失物：' + (objMeta ? objMeta.name + '，提示：' + objMeta.hint : el.dataset.obj));
        function revealHiddenObject(e) {
            if (e) e.stopPropagation();
            if (el.classList.contains('found')) return;
            el.classList.add('found');
            el.setAttribute('aria-disabled', 'true');
            if (objMeta) el.setAttribute('aria-label', '已找到：' + objMeta.name);
            var objId = el.dataset.obj;
            var item = document.querySelector('.hidden-item[data-obj="' + objId + '"]');
            if (item) item.classList.add('found');
            audio.playSnap();
            var found = svg.querySelectorAll('.hidden-object.found').length;
            document.getElementById('hidden-found').textContent = found;
            if (found === hiddenObjects.length) onHiddenWin();
        }
        el.addEventListener('click', revealHiddenObject);
        el.addEventListener('keydown', function(e) {
            if (e.key !== 'Enter' && e.key !== ' ') return;
            e.preventDefault();
            revealHiddenObject(e);
        });
    });
}

function onHiddenWin() {
    gameState.memorySilver += 40;
    document.getElementById('global-silver-balance').textContent = gameState.memorySilver;
    document.getElementById('hidden-score-text').textContent = '阁楼里每一件小物都找回来了！获得 +40 记忆银币';
    document.getElementById('hidden-result').classList.remove('hidden');
    trackGameComplete('hidden', 100);
    audio.playAwake();
}

// ============================================================================
// 14. 新模式导航绑定
// ============================================================================
document.addEventListener('DOMContentLoaded', function() {
    var matchGame = new MemoryMatchGame();
    window._memoryMatchGame = window._memoryMatchGame || matchGame;

    var btnMatch = document.getElementById('btn-open-match');
    if (btnMatch) btnMatch.addEventListener('click', function() { transitionToScreen('screen-match'); window._memoryMatchGame.init(); });
    var btnTimeline = document.getElementById('btn-open-timeline');
    if (btnTimeline) btnTimeline.addEventListener('click', function() { transitionToScreen('screen-timeline'); initTimelineGame(); });
    var btnHidden = document.getElementById('btn-open-hidden');
    if (btnHidden) btnHidden.addEventListener('click', function() { transitionToScreen('screen-hidden'); initHiddenGame(); });

    var btnMb = document.getElementById('btn-match-back');
    if (btnMb) btnMb.addEventListener('click', function() { if (window._memoryMatchGame) window._memoryMatchGame.destroy(); transitionToScreen('screen-hub'); });
    var btnTb = document.getElementById('btn-timeline-back');
    if (btnTb) btnTb.addEventListener('click', function() { transitionToScreen('screen-hub'); });
    var btnHb = document.getElementById('btn-hidden-back');
    if (btnHb) btnHb.addEventListener('click', function() { transitionToScreen('screen-hub'); });

    var btnMr = document.getElementById('btn-match-replay');
    if (btnMr) btnMr.addEventListener('click', function() { if (!window._memoryMatchGame) window._memoryMatchGame = matchGame; window._memoryMatchGame.init(); });
    var btnMh = document.getElementById('btn-match-hub');
    if (btnMh) btnMh.addEventListener('click', function() { if (window._memoryMatchGame) window._memoryMatchGame.destroy(); transitionToScreen('screen-hub'); });

    var btnTc = document.getElementById('btn-timeline-check');
    if (btnTc) btnTc.addEventListener('click', checkTimeline);
    var btnTr = document.getElementById('btn-timeline-replay');
    if (btnTr) btnTr.addEventListener('click', initTimelineGame);
    var btnTh = document.getElementById('btn-timeline-hub');
    if (btnTh) btnTh.addEventListener('click', function() { transitionToScreen('screen-hub'); });

    var btnHr = document.getElementById('btn-hidden-replay');
    if (btnHr) btnHr.addEventListener('click', initHiddenGame);
    var btnHh = document.getElementById('btn-hidden-hub');
    if (btnHh) btnHh.addEventListener('click', function() { transitionToScreen('screen-hub'); });
});


// ============================================================================
// 15. 环保分类模式 — Eco Sort Game (Hard Mode)
// ============================================================================
const ecoItemPool = [
    // Easy tier — common items
    { text: '废报纸', emoji: '📰', answer: 'recycle', tier: 'easy' },
    { text: '塑料瓶', emoji: '🧴', answer: 'recycle', tier: 'easy' },
    { text: '香蕉皮', emoji: '🍌', answer: 'kitchen', tier: 'easy' },
    { text: '茶叶渣', emoji: '🍵', answer: 'kitchen', tier: 'easy' },
    { text: '废电池', emoji: '🔋', answer: 'hazard', tier: 'easy' },
    { text: '过期药品', emoji: '💊', answer: 'hazard', tier: 'easy' },
    { text: '碎陶瓷碗', emoji: '🍶', answer: 'other', tier: 'easy' },
    { text: '用过的纸巾', emoji: '🧻', answer: 'other', tier: 'easy' },
    // Normal tier — moderately tricky
    { text: '旧衣物', emoji: '👕', answer: 'recycle', tier: 'normal' },
    { text: '空酒瓶', emoji: '🍾', answer: 'recycle', tier: 'normal' },
    { text: '鸡蛋壳', emoji: '🥚', answer: 'kitchen', tier: 'normal' },
    { text: '鱼骨头', emoji: '🐟', answer: 'kitchen', tier: 'normal' },
    { text: '荧光灯管', emoji: '💡', answer: 'hazard', tier: 'normal' },
    { text: '废油漆桶', emoji: '🪣', answer: 'hazard', tier: 'normal' },
    { text: '脏尿布', emoji: '👶', answer: 'other', tier: 'normal' },
    { text: '旧陶瓷马桶', emoji: '🚽', answer: 'other', tier: 'normal' },
    // Hard tier — commonly misclassified traps
    { text: '大骨头', emoji: '🦴', answer: 'other', tier: 'hard' },
    { text: '椰子壳', emoji: '🥥', answer: 'other', tier: 'hard' },
    { text: '指甲油瓶', emoji: '💅', answer: 'hazard', tier: 'hard' },
    { text: '废弃温度计', emoji: '🌡️', answer: 'hazard', tier: 'hard' },
    { text: '一次性筷子', emoji: '🥢', answer: 'other', tier: 'hard' },
    { text: '旧手机', emoji: '📱', answer: 'recycle', tier: 'hard' },
    { text: '中药渣', emoji: '🫖', answer: 'kitchen', tier: 'hard' },
    { text: '过期化妆品', emoji: '💄', answer: 'hazard', tier: 'hard' },

    { text: '核桃壳', emoji: '🥜', answer: 'other', tier: 'hard' },
    { text: '榴莲壳', emoji: '🫒', answer: 'other', tier: 'hard' },
    { text: '螃蟹壳', emoji: '🦀', answer: 'kitchen', tier: 'hard' },
    { text: '过期泡腾片', emoji: '💊', answer: 'hazard', tier: 'hard' },
    { text: '旧眼镜', emoji: '👓', answer: 'other', tier: 'hard' },
    { text: '废胶带', emoji: '📎', answer: 'other', tier: 'hard' },
    { text: '旧拖把', emoji: '🧹', answer: 'other', tier: 'hard' },
    { text: '废洗洁精瓶', emoji: '🧴', answer: 'recycle', tier: 'hard' },
    { text: '过期饮料', emoji: '🧃', answer: 'kitchen', tier: 'normal' },
    { text: '废灯泡', emoji: '💡', answer: 'hazard', tier: 'hard' },
    { text: '旧雨伞', emoji: '☂️', answer: 'other', tier: 'hard' },
    { text: '废光盘', emoji: '💿', answer: 'other', tier: 'hard' },
    { text: '旧书包', emoji: '🎒', answer: 'recycle', tier: 'normal' },
    { text: '过期豆腐乳', emoji: '🫙', answer: 'kitchen', tier: 'normal' },
    { text: '废贴纸', emoji: '🏷️', answer: 'other', tier: 'normal' },
    { text: '旧木筷', emoji: '🥢', answer: 'other', tier: 'normal' },
    { text: '过期调味料', emoji: '🧂', answer: 'kitchen', tier: 'normal' },
    { text: '废创可贴包装', emoji: '🩹', answer: 'other', tier: 'normal' },
    { text: '旧丝袜', emoji: '🧦', answer: 'other', tier: 'hard' },
    { text: '废农药瓶', emoji: '🧪', answer: 'hazard', tier: 'hard' },
    { text: '过期指甲油', emoji: '💅', answer: 'hazard', tier: 'normal' },
    { text: '旧毛绒玩具', emoji: '🧸', answer: 'other', tier: 'normal' },
    { text: '过期的花', emoji: '🥀', answer: 'kitchen', tier: 'normal' },
    { text: '旧铁锅', emoji: '🍳', answer: 'recycle', tier: 'normal' },
    { text: '过期染发膏', emoji: '💆', answer: 'hazard', tier: 'hard' },
    { text: '碎玻璃渣', emoji: '🪟', answer: 'other', tier: 'hard' },
    { text: '旧报纸', emoji: '📰', answer: 'recycle', tier: 'easy' },
    { text: '旧杂志', emoji: '📚', answer: 'recycle', tier: 'easy' },
    { text: '过期面包', emoji: '🍞', answer: 'kitchen', tier: 'easy' },
    { text: '剩菜剩饭', emoji: '🍛', answer: 'kitchen', tier: 'easy' },
    { text: '过期杀虫剂', emoji: '🪲', answer: 'hazard', tier: 'normal' },
    { text: '旧铝锅', emoji: '🥘', answer: 'recycle', tier: 'normal' },
    { text: '旧铜线', emoji: '🔗', answer: 'recycle', tier: 'normal' },
    { text: '碎花盆', emoji: '🪴', answer: 'other', tier: 'normal' },
    { text: '旧地毯', emoji: '🟫', answer: 'other', tier: 'hard' },
    { text: '过期农药', emoji: '🧴', answer: 'hazard', tier: 'hard' },
    { text: '旧沙发垫', emoji: '🛋️', answer: 'other', tier: 'hard' },
    { text: '过期药膏', emoji: '🧴', answer: 'hazard', tier: 'normal' },
    { text: '旧不锈钢盆', emoji: '🪣', answer: 'recycle', tier: 'normal' },
    { text: '枯萎盆栽', emoji: '🌱', answer: 'kitchen', tier: 'normal' },
    { text: '旧棉被', emoji: '🛏️', answer: 'other', tier: 'hard' },
    { text: '过期洗洁精', emoji: '🧴', answer: 'hazard', tier: 'normal' },
    { text: '旧塑料桶', emoji: '🪣', answer: 'recycle', tier: 'normal' },
    { text: '过期鱼食', emoji: '🐟', answer: 'kitchen', tier: 'normal' },
    { text: '旧皮带', emoji: '👔', answer: 'other', tier: 'hard' },
    { text: '废机油', emoji: '🛢️', answer: 'hazard', tier: 'hard' },
    { text: '旧铁钉', emoji: '📌', answer: 'recycle', tier: 'normal' },
    { text: '过期酱油', emoji: '🍾', answer: 'kitchen', tier: 'easy' },
    { text: '旧篮球', emoji: '🏀', answer: 'other', tier: 'hard' },
    { text: '废荧光棒', emoji: '💡', answer: 'hazard', tier: 'hard' },
    { text: '旧瓦片', emoji: '🧱', answer: 'other', tier: 'hard' },
    { text: '过期蜂蜜', emoji: '🍯', answer: 'kitchen', tier: 'normal' },
    { text: '旧铁桶', emoji: '🪣', answer: 'recycle', tier: 'normal' },
    { text: '废血压计', emoji: '🩺', answer: 'hazard', tier: 'hard' },
    { text: '旧草席', emoji: '🟨', answer: 'other', tier: 'hard' },
    { text: '过期果酱', emoji: '🍓', answer: 'kitchen', tier: 'normal' },
    { text: '旧铝罐', emoji: '🥫', answer: 'recycle', tier: 'easy' },
    { text: '废相片底片', emoji: '🎞️', answer: 'hazard', tier: 'hard' },
    { text: '旧竹篮', emoji: '🧺', answer: 'other', tier: 'normal' },
    { text: '过期醋', emoji: '🍶', answer: 'kitchen', tier: 'easy' },
    { text: '旧铁衣架', emoji: '👚', answer: 'recycle', tier: 'normal' },
    { text: '废定影液', emoji: '🧪', answer: 'hazard', tier: 'hard' },
    { text: '旧藤椅', emoji: '🪑', answer: 'other', tier: 'hard' },
    { text: '过期奶粉', emoji: '🍼', answer: 'kitchen', tier: 'normal' },
    { text: '废旧铁丝', emoji: '🔩', answer: 'recycle', tier: 'normal' },
    { text: '废温度计', emoji: '🌡️', answer: 'hazard', tier: 'hard' },
    { text: '旧扫帚', emoji: '🧹', answer: 'other', tier: 'normal' },
    { text: '过期番茄酱', emoji: '🍅', answer: 'kitchen', tier: 'normal' },
    { text: '旧铜壶', emoji: '🫖', answer: 'recycle', tier: 'normal' },
    { text: '废显影液', emoji: '🧪', answer: 'hazard', tier: 'hard' },
    { text: '旧拖鞋', emoji: '🩴', answer: 'other', tier: 'normal' },
    { text: '过期巧克力', emoji: '🍫', answer: 'kitchen', tier: 'easy' },
    { text: '旧钢管', emoji: '🔧', answer: 'recycle', tier: 'normal' },
    { text: '废镍镉电池', emoji: '🔋', answer: 'hazard', tier: 'hard' },
    { text: '旧草帽', emoji: '👒', answer: 'other', tier: 'hard' },
    { text: '过期沙拉酱', emoji: '🥗', answer: 'kitchen', tier: 'normal' },
    { text: '旧不锈钢管', emoji: '🔩', answer: 'recycle', tier: 'normal' },
    { text: '废铅酸电池', emoji: '🔋', answer: 'hazard', tier: 'hard' },
];

class EcoGame {
    constructor() {
        this.score = 0;
        this.combo = 1;
        this.streak = 0;
        this.correctCount = 0;
        this.totalItems = 0;
        this.timeLeft = 0;
        this.timerId = null;
        this.difficulty = 'easy';
        this.answered = new Map();
        this.dragState = null;
        this.active = false;
        this.winTimer = null;
        this.timerColorTimer = null;
        this.itemFlashTimers = [];
        this.binFlashTimers = [];
    }

    init(difficulty) {
        this._clearTimers();
        this.active = true;
        this.difficulty = difficulty || 'easy';
        this.score = 0;
        this.combo = 1;
        this.streak = 0;
        this.correctCount = 0;
        this.answered = new Map();
        this.dragState = null;

        // Select items based on difficulty
        var pool;
        var timerDuration = 0;
        switch (this.difficulty) {
            case 'normal':
                pool = ecoItemPool.filter(function(i) { return i.tier === 'easy' || i.tier === 'normal'; });
                timerDuration = 120;
                break;
            case 'hard':
                pool = [...ecoItemPool];
                timerDuration = 90;
                break;
            default:
                pool = ecoItemPool.filter(function(i) { return i.tier === 'easy'; });
                timerDuration = 0; // no timer for easy
        }
        this.totalItems = pool.length;
        this.timeLeft = timerDuration;

        // Update difficulty buttons
        document.querySelectorAll('.eco-diff-btn').forEach(function(b) {
            b.classList.toggle('active', b.dataset.diff === difficulty);
        });

        // UI reset
        document.getElementById('eco-score').textContent = '0';
        document.getElementById('eco-combo').textContent = '1';
        document.getElementById('eco-remaining').textContent = this.totalItems;
        document.getElementById('eco-result').classList.add('hidden');
        document.getElementById('eco-timer-display').style.display = timerDuration > 0 ? '' : 'none';
        document.getElementById('eco-timer').textContent = timerDuration;
        document.getElementById('eco-tip').textContent = this.difficulty === 'hard'
            ? '⏱ 限时90秒！错误扣5秒，连续正确触发连击！注意：大骨头/椰子壳=其他垃圾！'
            : this.difficulty === 'normal'
            ? '增加了易混淆物品，连续正确连击加分！'
            : '将废弃物拖放到正确的垃圾桶——连续正确触发连击加分！';
        trackGamePlay('eco');

        ['recycle','kitchen','hazard','other'].forEach(function(b) {
            document.getElementById('eco-count-' + b).textContent = '0';
        });

        // Render items
        var itemsEl = document.getElementById('eco-items');
        itemsEl.innerHTML = '';
        var shuffled = [...pool].sort(function() { return Math.random() - 0.5; });
        var self = this;
        this.tapSelectedItem = null;
        shuffled.forEach(function(item, idx) {
            var el = document.createElement('div');
            el.className = 'eco-item';
            el.textContent = item.emoji + ' ' + item.text;
            el.draggable = true;
            el.dataset.answer = item.answer;
            el.setAttribute('role', 'button');
            el.tabIndex = 0;

            el.addEventListener('dragstart', function(e) {
                if (el.classList.contains('done')) return;
                e.dataTransfer.setData('text/plain', item.answer);
                el.style.opacity = '0.5';
            });
            el.addEventListener('dragend', function() { el.style.opacity = '1'; });

            el.addEventListener('pointerdown', function(e) {
                if (el.classList.contains('done')) return;
                var clone = el.cloneNode(true);
                clone.style.cssText = 'position:fixed;z-index:9999;pointer-events:none;padding:10px 18px;background:rgba(34,197,94,0.2);border:2px solid #22c55e;border-radius:20px;color:#fff;font-size:1rem;';
                clone.style.left = (e.clientX - 50) + 'px';
                clone.style.top = (e.clientY - 18) + 'px';
                document.body.appendChild(clone);
                var move = function(ev) { clone.style.left = (ev.clientX - 50) + 'px'; clone.style.top = (ev.clientY - 18) + 'px'; };
                var up = function(ev) {
                    document.removeEventListener('pointermove', move);
                    document.removeEventListener('pointerup', up);
                    window._ecoCleanup = null;
                    clone.remove();
                    var bin = document.elementFromPoint(ev.clientX, ev.clientY);
                    var targetBin = bin ? bin.closest('.eco-bin') : null;
                    if (targetBin) {
                        targetBin.classList.add('highlight');
                        setTimeout(function() { targetBin.classList.remove('highlight'); }, 400);
                        self.checkAnswer(el, targetBin.dataset.bin, item.answer);
                    }
                };
                window._ecoCleanup = { move: move, up: up };
                document.addEventListener('pointermove', move);
                document.addEventListener('pointerup', up);
            });
            el.addEventListener('click', function() {
                if (el.classList.contains('done')) return;
                self.tapSelectedItem = { el: el, answer: item.answer };
                setTapPlaceSelection(el, 'eco');
                showGameplayToast('已选中物品，再点对应垃圾桶完成分类。', 'hint');
            });
            el.addEventListener('keydown', function(e) {
                if (e.key !== 'Enter' && e.key !== ' ') return;
                e.preventDefault();
                el.click();
            });
            itemsEl.appendChild(el);
        });

        // Bin drop events
        document.querySelectorAll('.eco-bin').forEach(function(bin) {
            bin.setAttribute('role', 'button');
            bin.tabIndex = 0;
            function placeSelectedEcoItem() {
                if (!self.tapSelectedItem || self.tapSelectedItem.el.classList.contains('done')) return;
                self.checkAnswer(self.tapSelectedItem.el, bin.dataset.bin, self.tapSelectedItem.answer);
                setTapPlaceSelection(null, 'eco');
                self.tapSelectedItem = null;
            }
            bin.addEventListener('click', placeSelectedEcoItem);
            bin.addEventListener('keydown', function(e) {
                if (e.key !== 'Enter' && e.key !== ' ') return;
                e.preventDefault();
                placeSelectedEcoItem();
            });
            bin.addEventListener('dragover', function(e) { e.preventDefault(); bin.classList.add('highlight'); });
            bin.addEventListener('dragleave', function() { bin.classList.remove('highlight'); });
            bin.addEventListener('drop', function(e) {
                e.preventDefault(); bin.classList.remove('highlight');
                var answer = e.dataTransfer.getData('text/plain');
                var item = document.querySelector('.eco-item[data-answer="' + answer + '"]:not(.done)');
                if (item) self.checkAnswer(item, bin.dataset.bin, answer);
            });
        });

        // Start timer for hard mode
        if (timerDuration > 0) {
            this.timerId = setInterval(function() { self._tick(); }, 1000);
        }
    }

    _tick() {
        if (!this.active) return;
        this.timeLeft--;
        document.getElementById('eco-timer').textContent = this.timeLeft;
        if (this.timeLeft <= 10) {
            document.getElementById('eco-timer').style.color = '#ef4444';
        }
        if (this.timeLeft <= 0) {
            clearInterval(this.timerId);
            this.timerId = null;
            this._onGameOver();
        }
    }

    checkAnswer(itemEl, binType, correctAnswer) {
        if (!this.active) return;
        if (itemEl.classList.contains('done')) return;
        var bin = document.querySelector('.eco-bin[data-bin="' + binType + '"]');
        var isCorrect = binType === correctAnswer;
        var self = this;

        if (isCorrect) {
            itemEl.classList.add('done', 'eco-correct');
            this.correctCount++;
            this.streak++;
            // Combo: every 3 consecutive correct = multiplier +1
            this.combo = 1 + Math.floor(this.streak / 3);
            var comboBonus = this.combo;
            this.score += 10 * comboBonus;
            document.getElementById('eco-score').textContent = this.score;
            document.getElementById('eco-combo').textContent = this.combo;
            document.getElementById('eco-count-' + binType).textContent =
                parseInt(document.getElementById('eco-count-' + binType).textContent) + 1;
            document.getElementById('eco-remaining').textContent =
                this.totalItems - this.correctCount;
            bin.classList.add('correct-flash');
            if (this.combo >= 3) {
                bin.style.setProperty('--flash-color', '#fbbf24');
            }
            if (typeof audio !== 'undefined' && audio.playSnap) audio.playSnap();
        } else {
            this.streak = 0;
            this.combo = 1;
            document.getElementById('eco-combo').textContent = '1';
            bin.classList.add('wrong-flash');
            // Penalty: lose 5 seconds in hard mode
            if (this.difficulty === 'hard') {
                this.timeLeft = Math.max(0, this.timeLeft - 5);
                document.getElementById('eco-timer').textContent = this.timeLeft;
                document.getElementById('eco-timer').style.color = '#ef4444';
                if (this.timerColorTimer) clearTimeout(this.timerColorTimer);
                this.timerColorTimer = setTimeout(function() {
                    this.timerColorTimer = null;
                    if (!this.active) return;
                    document.getElementById('eco-timer').style.color = '';
                }.bind(this), 600);
            }
            // Flash the item red briefly
            itemEl.classList.add('eco-wrong-flash');
            var itemFlashTimer = setTimeout(function() {
                this.itemFlashTimers = this.itemFlashTimers.filter(function(id) { return id !== itemFlashTimer; });
                if (!this.active) return;
                itemEl.classList.remove('eco-wrong-flash');
            }.bind(this), 500);
            this.itemFlashTimers.push(itemFlashTimer);
            if (typeof audio !== 'undefined' && audio.playHover) audio.playHover();
        }

        var binFlashTimer = setTimeout(function() {
            this.binFlashTimers = this.binFlashTimers.filter(function(id) { return id !== binFlashTimer; });
            if (!this.active) return;
            bin.classList.remove('correct-flash', 'wrong-flash');
            bin.style.removeProperty('--flash-color');
        }.bind(this), 400);
        this.binFlashTimers.push(binFlashTimer);

        // Check win
        if (this.correctCount >= this.totalItems) {
            clearInterval(this.timerId);
            this.timerId = null;
            if (this.winTimer) clearTimeout(this.winTimer);
            this.winTimer = setTimeout(function() {
                self.winTimer = null;
                if (!self.active) return;
                self._onWin();
            }, 500);
        }
    }

    _onWin() {
        if (!this.active) return;
        this.active = false;
        this._clearTimers();
        var maxCombo = 1 + Math.floor(this.streak / 3);
        var totalSilver = unifiedRewardCalc(this.score, maxCombo, this.difficulty, 0, 100);
        document.getElementById('eco-result-title').textContent = this.difficulty === 'hard'
            ? '🔥 极限分类完成！' : '🎯 全部分类正确！';
        document.getElementById('eco-result-text').textContent =
            '得分: ' + this.score + ' | 最高连击: ×' + maxCombo +
            (this.difficulty === 'hard' ? ' | 剩余时间: ' + this.timeLeft + 's' : '') +
            ' | 获得 +' + totalSilver + ' 记忆银币';
        document.getElementById('eco-result').classList.remove('hidden');
        if (maxCombo >= 10) achievementSystem.check('comboMaster');
        if (this.score >= 200) achievementSystem.check('perfectScore');
        trackGameComplete('eco', this.score);
        if (typeof audio !== 'undefined' && audio.playAwake) audio.playAwake();
    }

    _onGameOver() {
        if (!this.active) return;
        this.active = false;
        this._clearTimers();
        var totalSilver = unifiedRewardCalc(this.score, 1, this.difficulty, 0, Math.round(this.correctCount / this.totalItems * 100));
        document.getElementById('eco-result-title').textContent = '⏰ 时间到！';
        document.getElementById('eco-result-text').textContent =
            '完成: ' + this.correctCount + '/' + this.totalItems + ' | 得分: ' + this.score +
            ' | 获得 +' + totalSilver + ' 记忆银币\n\n提示: 大骨头、椰子壳、一次性筷子属于其他垃圾！';
        document.getElementById('eco-result').classList.remove('hidden');
        trackGameComplete('eco', this.score);
        if (typeof audio !== 'undefined' && audio.playHover) audio.playHover();
    }

    _clearTimers() {
        clearInterval(this.timerId);
        clearTimeout(this.winTimer);
        clearTimeout(this.timerColorTimer);
        this.itemFlashTimers.forEach(function(id) { clearTimeout(id); });
        this.binFlashTimers.forEach(function(id) { clearTimeout(id); });
        this.timerId = null;
        this.winTimer = null;
        this.timerColorTimer = null;
        this.itemFlashTimers = [];
        this.binFlashTimers = [];
        document.querySelectorAll('.eco-bin').forEach(function(bin) {
            bin.classList.remove('correct-flash', 'wrong-flash');
            bin.style.removeProperty('--flash-color');
        });
        document.querySelectorAll('.eco-item.eco-wrong-flash').forEach(function(item) {
            item.classList.remove('eco-wrong-flash');
        });
    }

    destroy() {
        this.active = false;
        this._clearTimers();
        setTapPlaceSelection(null, 'eco');
        this.tapSelectedItem = null;
        this.dragState = null;
    }
}

var _ecoGame = null;
function initEcoGame(difficulty) {
    _ecoGame = new EcoGame();
    _ecoGame.init(difficulty || 'easy');
}

function checkEcoAnswer(itemEl, binType) {
    // Legacy wrapper — no longer used directly
}

// ============================================================================
// 16. 防骗卫士模式 — Fraud Guard (Hard Mode)
// ============================================================================
const fraudPool = [
    // === 电话诈骗 (phone) ===
    { type: 'phone', badge: '来电', badgeClass: 'phone', scenario: '您好，我是公安局的，您的银行卡涉嫌洗钱，请立即转账到"安全账户"配合调查', detail: '自称公检法，要求转账到陌生账户', isScam: true, tip: '公安机关不会电话办案，更不会要求转账！挂断并拨打110核实。', tier: 'easy' },
    { type: 'phone', badge: '来电', badgeClass: 'phone', scenario: '奶奶，我是小明！我出车祸了在医院，急需3万手术费，快打钱到这个账户', detail: '声音像孙子但号码陌生，语气慌乱催促', isScam: true, tip: 'AI可模仿任何人的声音！先挂断，用家人已知号码回拨确认。', tier: 'easy' },
    { type: 'phone', badge: '来电', badgeClass: 'phone', scenario: '恭喜您中了我们公司的一等奖50万元！请先缴纳5000元手续费即可领取', detail: '陌生来电告知中奖，要求先付款', isScam: true, tip: '天上不会掉馅饼！任何要求先付款的中奖都是诈骗。', tier: 'easy' },
    { type: 'phone', badge: '来电', badgeClass: 'phone', scenario: '您好，这是社区医院张医生，您的体检报告出来了，各项指标都正常，工作日可以来取', detail: '熟悉的医生来电，通知常规体检结果', isScam: false, tip: '来自熟悉的社区医院，内容合理无紧迫感。注意核实来电号码是否为医院官方号。', tier: 'easy' },
    // === 短信诈骗 (sms) ===
    { type: 'sms', badge: '短信', badgeClass: 'sms', scenario: '【社保中心】您的社保卡已停用，请24小时内点击 http://sbk.xyz 重新激活，逾期将影响使用', detail: '短信号码陌生，包含不明链接，制造紧迫感', isScam: true, tip: '政府机构不会用陌生链接通知你！通过人社App或12333热线核实。', tier: 'easy' },
    { type: 'sms', badge: '短信', badgeClass: 'sms', scenario: '【中国移动】尊敬的客户，您本月的账单已生成，共计58元，可通过官方App查询详情', detail: '来自10086，常规月度账单提醒', isScam: false, tip: '来自官方号码的常规通知，无链接无紧迫感。但仍建议通过官方App查询。', tier: 'easy' },
    { type: 'sms', badge: '短信', badgeClass: 'sms', scenario: '【快递通知】您的快递因地址不详无法派送，请点击链接补充地址：kdd.xyz/update', detail: '冒充快递公司，要求点击链接输入个人信息', isScam: true, tip: '快递问题应通过官方App查询，不要点击陌生链接输入个人信息！', tier: 'normal' },
    { type: 'sms', badge: '短信', badgeClass: 'sms', scenario: '【中国银行】您尾号7788的信用卡本月账单金额为1230元，到期还款日3月25日。如有疑问请致电95566', detail: '来自95566，格式规范，无链接', isScam: false, tip: '来自银行官方号码的账单提醒，无链接无紧迫感。Tricky但真实！', tier: 'normal' },
    // === 网络诈骗 ===
    { type: 'app', badge: 'App', badgeClass: 'app', scenario: '下载此App每天签到领鸡蛋，邀请好友赚现金！仅需绑定银行卡验证身份即可提现', detail: 'App要求读取通讯录权限，绑定银行卡', isScam: true, tip: '来路不明的App索要敏感权限和银行卡信息，100%是为了盗取你的信息！', tier: 'easy' },
    { type: 'app', badge: 'App', badgeClass: 'app', scenario: '【社区通知】请各位居民下载"社区通"App便于接收社区通知，在官方应用商店即可搜索下载', detail: '来自居委会群通知，正规应用商店下载', isScam: false, tip: '来自可信来源，通过官方应用商店下载，内容合理。但仍需确认确实是居委会发布的。', tier: 'normal' },
    // === 上门诈骗 ===
    { type: 'door', badge: '上门', badgeClass: 'door', scenario: '您好，我们是燃气公司的，来给您做免费的燃气安全检查，这是我们的工作证', detail: '两个穿制服的人敲门，出示了证件', isScam: true, tip: '真正的燃气公司会提前通知！打电话给燃气公司客服核实当天是否有安排。不要随意开门！', tier: 'normal' },
    { type: 'door', badge: '上门', badgeClass: 'door', scenario: '您好，我们是社区工作人员，明天上午9点在居委会门口有免费体检活动', detail: '上门的是你认识的小区物管，来通知社区活动', isScam: false, tip: '来自认识的人，内容合理。确认活动确实由社区组织即可。', tier: 'hard' },
    // === 微信/QQ诈骗 ===
    { type: 'chat', badge: '微信', badgeClass: 'sms', scenario: '老同学，好久不见！我现在在国外遇到点急事，能借我5000吗？回国立刻还你。这是我的新号', detail: '微信上新添加的好友，头像是你老同学但微信号不对', isScam: true, tip: '骗子经常盗用头像冒充熟人！通过视频通话或其他方式确认对方身份。', tier: 'normal' },
    { type: 'chat', badge: '微信', badgeClass: 'sms', scenario: '妈，我手机进水了用的同学手机，这个月生活费花完了，能再转500吗？打到这个账号', detail: '孩子用陌生号码发消息，但语气和习惯用语都对', isScam: true, tip: '骗子可能通过社交媒体了解了你孩子的语气习惯。先打通孩子本人电话确认！', tier: 'hard' },
    // === 投资理财 ===
    { type: 'invest', badge: '理财', badgeClass: 'phone', scenario: '加入我们的内部股票群，有专业老师指导，保证月收益30%，亏损包赔！', detail: '承诺保证收益且远高于市场水平', isScam: true, tip: '任何保证收益的投资都是骗局！正规投资不会承诺收益率，更不会"包赔"。', tier: 'hard' },
    { type: 'invest', badge: '理财', badgeClass: 'phone', scenario: '您的银行理财到期收益已到账，年化2.8%，可登录手机银行查询', detail: '来自银行App推送，符合市场合理利率', isScam: false, tip: '来自官方App，收益在合理范围内（当前银行理财约2-3%），内容可信。', tier: 'hard' },

    { type: 'phone', badge: '来电', badgeClass: 'phone', scenario: '您好，我是XX市公安局的，您孙子嫖娼被抓了，交5万保证金就能放人', detail: '冒充公安，以家属犯事为由勒索', isScam: true, tip: '公检法不会电话要求缴纳保证金！先联系家人确认情况。', tier: 'normal' },
    { type: 'phone', badge: '来电', badgeClass: 'phone', scenario: '您好，我是通信管理局的，您的手机号群发了大量诈骗短信，需要您配合调查', detail: '冒充通信管理局，制造恐慌要求配合', isScam: true, tip: '通信管理局不会直接致电个人！挂断后拨打12321举报。', tier: 'normal' },
    { type: 'phone', badge: '来电', badgeClass: 'phone', scenario: '先生您好，我是您贷款的担保人，您申请的50万贷款已经批了，需要验证您的还款能力', detail: '冒充贷款担保人，索要银行卡信息', isScam: true, tip: '正规贷款机构不会找人担保！不要透露银行信息。', tier: 'hard' },
    { type: 'sms', badge: '短信', badgeClass: 'sms', scenario: '【ETC通知】您的ETC已过期，请24小时内点击链接重新认证', detail: '冒充ETC服务，钓鱼链接', isScam: true, tip: 'ETC业务通过银行App或网点办理，不点陌生链接！', tier: 'normal' },
    { type: 'sms', badge: '短信', badgeClass: 'sms', scenario: '【医保局】您的医保报销已到账，请点击链接查看明细', detail: '冒充医保局，钓鱼链接套取信息', isScam: true, tip: '医保报销通过国家医保服务平台App查询！', tier: 'normal' },
    { type: 'sms', badge: '短信', badgeClass: 'sms', scenario: '【天猫客服】您已成为天猫88VIP，每月将扣费888元，如需取消请回复TD', detail: '冒充天猫，制造扣费恐慌', isScam: true, tip: '回复TD可能被确认是活跃号码！直接忽略或通过官方App核实。', tier: 'hard' },
    { type: 'sms', badge: '短信', badgeClass: 'sms', scenario: '【交警】您的车辆在高速上超速50%，扣12分，请点击链接处理', detail: '冒充交警发违章短信，钓鱼网站', isScam: true, tip: '交通违章只通过12123App查询处理！', tier: 'normal' },
    { type: 'app', badge: 'App', badgeClass: 'app', scenario: '您收到一条共享屏幕请求，对方自称淘宝客服要给您退款', detail: '冒充客服要求开启屏幕共享', isScam: true, tip: '任何要求共享屏幕的客服都是诈骗！屏幕共享会泄露所有信息。', tier: 'hard' },
    { type: 'app', badge: 'App', badgeClass: 'app', scenario: '您的手机弹窗：系统检测到32个病毒，请立即下载安全卫士清理', detail: '虚假病毒警告诱导下载恶意App', isScam: true, tip: '手机系统不会弹窗说检测到病毒！这是诱导下载恶意软件的广告。', tier: 'normal' },
    { type: 'chat', badge: '微信', badgeClass: 'sms', scenario: '您被拉进炒股大师群，群里300人都在晒今天赚了多少，老师说带大家做庄股', detail: '微信荐股群，群友都是托', isScam: true, tip: '群里300人可能299个都是托！任何荐股群都是诈骗。', tier: 'hard' },
    { type: 'chat', badge: '微信', badgeClass: 'sms', scenario: '您好，我是XX机关单位的办公室主任，领导要采购物资，您先垫付货款', detail: '冒充政府单位采购，要求垫付', isScam: true, tip: '政府单位采购有正规流程，不会要求个人垫付！', tier: 'hard' },
    { type: 'door', badge: '上门', badgeClass: 'door', scenario: '您好，我们是民政局的，来做养老服务需求登记，需交200元登记费', detail: '冒充民政局，以养老登记为由收费', isScam: true, tip: '民政局的养老服务登记不收任何费用！不要给陌生人开门。', tier: 'normal' },
    { type: 'door', badge: '上门', badgeClass: 'door', scenario: '您好，我们是燃气公司来换智能燃气表的，旧的到期了不换很危险，换表费298元', detail: '冒充燃气公司，以安全隐患为由收费', isScam: true, tip: '燃气公司换表会提前张贴通知！不会突然上门收钱。', tier: 'hard' },
    { type: 'invest', badge: '理财', badgeClass: 'phone', scenario: '我们是香港持牌金融机构，推出数字人民币理财，年化18%，央行背书', detail: '利用数字人民币概念包装骗局', isScam: true, tip: '央行从未授权任何机构发行数字人民币理财！年化18%一定是骗局。', tier: 'hard' },
    { type: 'invest', badge: '理财', badgeClass: 'phone', scenario: '您之前投的P2P爆雷了，现在有清退小组联系您，交10%手续费可优先回款', detail: '冒充P2P清退，二次收割受害人', isScam: true, tip: '这是针对P2P受害者的二次诈骗！清退不会要求先交手续费。', tier: 'hard' },
    { type: 'phone', badge: 'Deepfake', badgeClass: 'phone', scenario: '(视频通话)屏幕上出现你的面孔：这是我新录的验证视频，请按指示转账', detail: 'AI深度伪造换脸视频，冒充本人', isScam: true, tip: 'Deepfake可以完美伪造任何人的视频！通过独立渠道验证。', tier: 'hard' },
    { type: 'chat', badge: '元宇宙', badgeClass: 'sms', scenario: '元宇宙虚拟土地投资，限量发售，一块虚拟土地只要5000元，半年涨10倍', detail: '借元宇宙概念炒作虚拟资产', isScam: true, tip: '元宇宙虚拟土地没有价值支撑！这是新型割韭菜方式。', tier: 'hard' },
    { type: 'sms', badge: 'NFT', badgeClass: 'sms', scenario: '【数字藏品】您抽中限量版数字藏品空投，价值5万元，点击领取', detail: '利用数字藏品概念钓鱼', isScam: true, tip: '真正的空投不会要求点击链接！谨防钱包被盗。', tier: 'hard' },
    { type: 'phone', badge: '征信', badgeClass: 'phone', scenario: '您好，我是征信中心的，您的征信有不良记录，交3000元可以帮您消除', detail: '冒充征信中心收费', isScam: true, tip: '个人征信无法花钱消除！任何声称能修改征信的都是诈骗。', tier: 'hard' },
    { type: 'chat', badge: '微信', badgeClass: 'sms', scenario: '招聘抖音点赞员，日薪300-500元，在家可做，无需经验，请添加QQ', detail: '虚假招聘，诱导刷单诈骗', isScam: true, tip: '抖音点赞赚钱是刷单诈骗的变种！要垫付资金的兼职都是诈骗。', tier: 'easy' },
    { type: 'phone', badge: '来电', badgeClass: 'phone', scenario: '您好，我是您儿子单位的领导，他在工作中出了事故，需要紧急手术费', detail: '冒充单位领导，利用亲情恐慌', isScam: true, tip: '先联系你儿子本人或其同事核实！不要因为着急就直接转账。', tier: 'normal' },
    { type: 'sms', badge: '短信', badgeClass: 'sms', scenario: '【学信网】您的学历信息需要更新认证，请点击链接完成', detail: '冒充学信网钓鱼链接', isScam: true, tip: '学信网官方网址是chsi.com.cn！不要点击非官方链接。', tier: 'hard' },
    { type: 'app', badge: 'App', badgeClass: 'app', scenario: '您的手机收到通知：系统更新需要验证Apple ID，请输入密码', detail: '伪造系统通知，钓鱼获取密码', isScam: true, tip: 'iOS系统更新从不在弹窗中要密码！这是钓鱼。', tier: 'hard' },
    { type: 'phone', badge: '来电', badgeClass: 'phone', scenario: '您好，我是快递公司的，您有国际快递被海关扣了，需缴关税2000元', detail: '冒充快递公司，以海关扣货为由诈骗', isScam: true, tip: '海关关税通过正规渠道缴纳，不会让快递员代收！', tier: 'normal' },
    { type: 'chat', badge: 'QQ', badgeClass: 'sms', scenario: '老同学，我在国外做代购被海关扣了，先借我8000交关税，货出来分你利润', detail: '冒充老同学借钱', isScam: true, tip: '老同学的号码可能被盗！通过电话或视频确认身份。', tier: 'hard' },
    { type: 'invest', badge: '理财', badgeClass: 'phone', scenario: '我们有一款AI量化交易机器人，把资金存进去，日收益3%-5%', detail: '以AI量化交易为噱头的资金盘', isScam: true, tip: '日收益3%意味着年化超1000%！100%是庞氏骗局。', tier: 'hard' },
    { type: 'door', badge: '上门', badgeClass: 'door', scenario: '您好，我们是防疫站的，来给您做免费居家消毒，请开门', detail: '冒充防疫人员上门', isScam: true, tip: '真正的防疫人员会有社区人员陪同！先核实再开门。', tier: 'hard' },
    { type: 'phone', badge: '来电', badgeClass: 'phone', scenario: '您好，我是您银行卡发卡行，检测到您的卡在境外有异常交易，请提供卡号密码', detail: '冒充银行客服索要密码', isScam: true, tip: '银行绝不会索要你的密码！挂断后拨打银行官方客服核实。', tier: 'easy' },
    { type: 'sms', badge: '短信', badgeClass: 'sms', scenario: '【XX银行】恭喜成为尊贵客户，信用卡额度提至50万，点击激活', detail: '冒充银行虚假提额钓鱼链接', isScam: true, tip: '信用卡提额通过银行官方App办理！任何链接都不要点。', tier: 'normal' },
    { type: 'phone', badge: '来电', badgeClass: 'phone', scenario: '您好，我是您儿子国外读书的导师，他出了车祸急需手术，请汇款20万', detail: '冒充海外导师利用亲情恐慌', isScam: true, tip: '通过其他渠道联系儿子本人！导师不会直接找你要钱。', tier: 'hard' },
    { type: 'chat', badge: '微信', badgeClass: 'sms', scenario: '恭喜抽中幸运用户！将获得苹果手机一部，仅需支付199元邮费和保险费', detail: '冒充官方活动中奖收费', isScam: true, tip: '任何要求支付邮费的中奖活动都是诈骗！', tier: 'easy' },
    { type: 'phone', badge: '来电', badgeClass: 'phone', scenario: '您好，我是电视台的，您中了幸运观众大奖50万，请提供身份证和银行卡号', detail: '冒充电视台中奖通知', isScam: true, tip: '电视台中奖不会电话索要银行卡号！', tier: 'normal' },
    { type: 'sms', badge: '短信', badgeClass: 'sms', scenario: '【支付保】您的账户存在安全风险，请24小时内点击链接验证身份', detail: '冒充支付宝钓鱼链接', isScam: true, tip: '支付宝官方网址是alipay.com！不要点击非官方链接。', tier: 'normal' },
    { type: 'chat', badge: '微信', badgeClass: 'sms', scenario: '您好，我是小区物业，要统一更换门禁卡，每户缴200元，支持微信转账', detail: '冒充物业收费', isScam: true, tip: '先向物业办公室核实！很多骗子利用小区群冒充物业收费。', tier: 'normal' },
    { type: 'phone', badge: '来电', badgeClass: 'phone', scenario: '您好，我是教育局的，您孩子获得国家奖学金，请先缴个人所得税2000元', detail: '冒充教育局奖学金诈骗', isScam: true, tip: '奖学金不会要求先缴税！任何要求先付钱的奖学金都是诈骗。', tier: 'normal' },
    { type: 'door', badge: '上门', badgeClass: 'door', scenario: '我们是中国电信的，来升级您家的宽带网络，升级免费但请签字确认', detail: '冒充电信人员入户', isScam: true, tip: '电信宽带升级通过官方渠道通知！不要给突然上门的人开门。', tier: 'hard' },
    { type: 'sms', badge: '短信', badgeClass: 'sms', scenario: '【市场监督管理局】您的营业执照年审已逾期，将面临罚款，点击补审', detail: '冒充市场监管局罚款恐慌', isScam: true, tip: '营业执照年审通过国家企业信用信息公示系统办理！', tier: 'hard' },
    { type: 'app', badge: 'App', badgeClass: 'app', scenario: '下载此贷款App，额度最高50万，秒批秒到，仅需身份证和银行卡号', detail: '虚假贷款App套取信息', isScam: true, tip: '正规贷款不会在App Store之外要求下载！', tier: 'normal' },
    { type: 'chat', badge: 'QQ', badgeClass: 'sms', scenario: '我是XX明星经纪人，我们找素人参加节目录制，报名费只需980元', detail: '冒充明星经纪人收取报名费', isScam: true, tip: '真正的选秀不收费！收取报名费的演艺招募都是诈骗。', tier: 'hard' },
    { type: 'phone', badge: '来电', badgeClass: 'phone', scenario: '我是法院执行局的，您有一个执行案件，不履行将被列入失信名单', detail: '冒充法院执行局威胁转账', isScam: true, tip: '法院执行有严格法律程序！不会电话要求转账到个人账户。', tier: 'hard' },
    { type: 'sms', badge: '短信', badgeClass: 'sms', scenario: '【社保局】您的社保补贴金3680元已到账，请点击链接领取', detail: '冒充社保局钓鱼链接', isScam: true, tip: '社保补贴通过社保卡发放，不会短信发链接！', tier: 'normal' },
    { type: 'invest', badge: '理财', badgeClass: 'phone', scenario: '碳中和碳交易投资，国家政策扶持，每吨碳配额现在只要50元，年底涨到200元', detail: '利用碳中和概念虚假投资', isScam: true, tip: '个人无法直接参与碳配额交易！声称可投资碳交易的都是骗局。', tier: 'hard' },
    { type: 'phone', badge: '来电', badgeClass: 'phone', scenario: '您好，我是您孙女的同学，她在学校摔伤了正在医院，我先垫付了医药费', detail: '冒充同学利用关心诈骗', isScam: true, tip: '先联系学校或孙女本人核实！不要因担心就匆忙转账。', tier: 'hard' },
    { type: 'chat', badge: '微信', badgeClass: 'sms', scenario: '您好，我是公益基金的工作人员，山区助学项目捐2000元可结对帮扶一个孩子', detail: '冒充公益组织虚假募捐', isScam: true, tip: '正规公益组织不会通过微信个人号募捐！通过官方平台捐款。', tier: 'normal' },
    { type: 'door', badge: '上门', badgeClass: 'door', scenario: '您好，我们是社区养老驿站的，来做老年人能力评估，然后推荐适合的养老产品', detail: '以免费评估为名推销', isScam: true, tip: '养老驿站评估免费！任何评估后推销高价产品的都要警惕。', tier: 'hard' },
    { type: 'phone', badge: '来电', badgeClass: 'phone', scenario: '您好，我是医保局的，您的医保卡在外地被盗刷了10万元，需要配合我们冻结账户', detail: '冒充医保局制造恐慌', isScam: true, tip: '医保卡异常通过12393核实！不要按对方指示操作。', tier: 'normal' },
    { type: 'sms', badge: '短信', badgeClass: 'sms', scenario: '【微信团队】您的账号因违规将被永久封禁，如需申诉请点击链接', detail: '冒充微信团队钓鱼', isScam: true, tip: '微信封号只在App内通知！不会短信发链接。', tier: 'normal' },
    { type: 'chat', badge: '微信', badgeClass: 'sms', scenario: '我是你儿子的班主任，他今天在学校摔伤送医院了，请立即转5000元医药费', detail: '冒充老师利用亲情诈骗', isScam: true, tip: '先联系学校或孩子本人！老师不会直接要求微信转账。', tier: 'hard' },
    { type: 'door', badge: '上门', badgeClass: 'door', scenario: '我们是电力公司的，您家电表老旧有安全隐患，更换智能电表仅需399元', detail: '冒充电力公司上门收费', isScam: true, tip: '电力公司换表免费！任何上门收费的都是诈骗。', tier: 'normal' },
    { type: 'phone', badge: '来电', badgeClass: 'phone', scenario: '您好，我是快递公司的，您的包裹检出违禁品已被公安扣押，请配合调查转账', detail: '冒充快递公司以违禁品为由诈骗', isScam: true, tip: '快递问题通过官方App查询！公安不会电话让你转账。', tier: 'normal' },
    { type: 'invest', badge: '理财', badgeClass: 'phone', scenario: '我们推出了养老社区会员卡，充值10万可享受终身养老服务，年化收益8%', detail: '养老会员卡非法集资', isScam: true, tip: '正规养老机构不会承诺高收益！这是变相非法集资。', tier: 'hard' },
    { type: 'sms', badge: '短信', badgeClass: 'sms', scenario: '【人行征信】您的个人信用报告有异常记录，影响贷款购房，点击修复', detail: '冒充人行征信钓鱼', isScam: true, tip: '征信报告通过人行征信中心官网查询！不点链接。', tier: 'hard' },
    { type: 'chat', badge: 'QQ', badgeClass: 'sms', scenario: '我是你多年未见的老战友，我现在遇到点困难，能借我3000周转一下吗', detail: '冒充老战友借钱', isScam: true, tip: '多年未联系突然借钱的要高度警惕！先通过其他方式确认身份。', tier: 'normal' },
    { type: 'phone', badge: '来电', badgeClass: 'phone', scenario: '您好，我是税务局稽查科的，您的企业涉嫌偷税漏税，请立即补缴税款', detail: '冒充税务局恐吓转账', isScam: true, tip: '税务稽查有正式文书流程！不会电话要求转账到个人账户。', tier: 'hard' },
    { type: 'app', badge: 'App', badgeClass: 'app', scenario: '恭喜您获得提额资格！下载此App完善信息，额度立涨5万', detail: '虚假提额App', isScam: true, tip: '信用卡提额在银行官方App操作！不下载未知App。', tier: 'normal' },
    { type: 'sms', badge: '短信', badgeClass: 'sms', scenario: '【车管所】您的驾驶证已过期，请点击链接在线换证，逾期将注销', detail: '冒充车管所钓鱼', isScam: true, tip: '驾驶证换证通过12123App或车管所现场办理！', tier: 'normal' },
    { type: 'chat', badge: '微信', badgeClass: 'sms', scenario: '姐，我换了新手机号，之前那个不用了。最近急需用钱，能转我5000救急吗', detail: '冒充亲戚换号借钱', isScam: true, tip: '换号要视频确认！骗子经常用换号理由借钱。', tier: 'hard' },
    { type: 'door', badge: '上门', badgeClass: 'door', scenario: '我们是社区志愿者，来做孤寡老人关爱活动，进屋登记一下您的基本信息', detail: '冒充志愿者套取信息', isScam: true, tip: '真正的社区志愿者会穿马甲带工作证！先查看来访者证件。', tier: 'normal' },
    { type: 'phone', badge: '来电', badgeClass: 'phone', scenario: '您好，我是移动客服，您的积分即将清零，现在兑换需要提供短信验证码', detail: '冒充运营商索要验证码', isScam: true, tip: '运营商不会索要短信验证码！积分兑换在官方App操作。', tier: 'easy' },
    { type: 'invest', badge: '理财', badgeClass: 'phone', scenario: '我们代理海外股票交易平台，入金1万美元送1000美元，月收益稳定15%', detail: '虚假海外股票平台', isScam: true, tip: '国内个人投资海外股票需通过合规渠道！送金送收益的都是黑平台。', tier: 'hard' },
    { type: 'sms', badge: '短信', badgeClass: 'sms', scenario: '【卫健委】您已完成疫苗接种，请点击链接领取疫苗接种补贴500元', detail: '冒充卫健委钓鱼', isScam: true, tip: '疫苗接种补贴通过社区发放！不会短信发链接。', tier: 'normal' },
    { type: 'chat', badge: '微信', badgeClass: 'sms', scenario: '你好，我是XX明星本人，这是我的私人微信号，想和你交个朋友', detail: '冒充明星私人微信', isScam: true, tip: '明星不会主动加普通人微信！这是杀猪盘的开端。', tier: 'hard' },
    { type: 'phone', badge: '来电', badgeClass: 'phone', scenario: '您好，我是监狱的，您儿子在里面跟人打架受了重伤，需要医疗费，请立即转账', detail: '冒充监狱工作人员', isScam: true, tip: '监狱有完善的医疗体系！不会电话要求家属转账付医药费。', tier: 'hard' },
    { type: 'door', badge: '上门', badgeClass: 'door', scenario: '我们是社区网格员，来做人口信息核查，请开门配合，需要看一下您的户口本', detail: '冒充网格员入户', isScam: true, tip: '网格员入户一般有社区人员陪同！先打社区电话核实。', tier: 'normal' },
    { type: 'app', badge: 'App', badgeClass: 'app', scenario: '您的手机收到弹窗：恭喜获得288元红包，点击领取，需绑定银行卡', detail: '虚假红包弹窗诱导绑卡', isScam: true, tip: '天上不会掉红包！要求绑定银行卡的红包都是钓鱼。', tier: 'easy' },
    { type: 'sms', badge: '短信', badgeClass: 'sms', scenario: '【中国邮政】您有一个重要邮件因地址不详无法投递，请点击链接完善地址', detail: '冒充邮政钓鱼链接', isScam: true, tip: '快递问题在官方App查询！不要点击陌生链接。', tier: 'easy' },
    { type: 'chat', badge: 'QQ', badgeClass: 'sms', scenario: '同学聚会照片出来了，点这个链接看：txjy.xyz/photo', detail: '冒充同学发钓鱼链接', isScam: true, tip: '同学发的链接也要警惕！可能是账号被盗后群发的钓鱼链接。', tier: 'normal' },
    { type: 'phone', badge: '来电', badgeClass: 'phone', scenario: '您好，我是您之前买房的中介，现在有一套特价房内部认购，先交5万意向金锁定', detail: '冒充房产中介诈骗', isScam: true, tip: '房产交易通过正规中介门店！不要电话中向陌生人转账。', tier: 'normal' },
    { type: 'invest', badge: '理财', badgeClass: 'phone', scenario: '我们有内部渠道申购新股，中签率100%，你投10万保证赚50万', detail: '虚假新股申购诈骗', isScam: true, tip: '新股申购通过证券公司正规渠道！内部渠道100%是骗局。', tier: 'hard' },
    { type: 'sms', badge: '短信', badgeClass: 'sms', scenario: '【蚂蚁花呗】您的花呗额度已提升至50000元，点击查看并激活', detail: '冒充花呗提额钓鱼', isScam: true, tip: '花呗额度在支付宝App内查看！不点陌生链接。', tier: 'normal' },
    { type: 'door', badge: '上门', badgeClass: 'door', scenario: '您好，我们是装修公司的，您邻居家刚装修完，剩下的材料便宜处理给您', detail: '以装修余料为名上门推销', isScam: true, tip: '不要给突然上门的推销人员开门！邻居装修与你无关。', tier: 'normal' },
    { type: 'chat', badge: '微信', badgeClass: 'sms', scenario: '您好，我是XX基金的工作人员，现在有一款国家扶持的扶贫基金，年化15%', detail: '冒充国家扶贫基金诈骗', isScam: true, tip: '公益基金不会承诺高收益！国家扶贫项目不会向个人募集资金。', tier: 'hard' },
    { type: 'phone', badge: '来电', badgeClass: 'phone', scenario: '您好，我是银行风控部门的，您的银行卡存在被盗刷风险，请立即将资金转入安全账户', detail: '冒充银行风控要求转账', isScam: true, tip: '银行绝不会让你转账到安全账户！挂断后拨打银行客服。', tier: 'easy' },
    { type: 'app', badge: 'App', badgeClass: 'app', scenario: '您收到好友推荐：下载这个App每天走路就能赚钱，步数换现金！', detail: '虚假健康赚钱App', isScam: true, tip: '走路赚钱是传销的变种！需要拉人头才能提现的都是骗局。', tier: 'normal' },
    { type: 'sms', badge: '短信', badgeClass: 'sms', scenario: '【高速ETC】您的ETC异常已被限制使用，请点击链接重新认证', detail: '冒充ETC钓鱼链接', isScam: true, tip: 'ETC认证通过银行App或高速服务网点办理！', tier: 'easy' },
    { type: 'phone', badge: '来电', badgeClass: 'phone', scenario: '您好，我是您常用银行的理财经理，我们新出了一款保本理财，收益率8%', detail: '冒充银行理财经理诈骗', isScam: true, tip: '银行理财收益率约2-4%！8%保本理财一定是虚假的。', tier: 'normal' },
    { type: 'chat', badge: '微信', badgeClass: 'sms', scenario: '你好，我在附近的人看到你，觉得很有缘，加个好友聊聊吧', detail: '陌生人交友杀猪盘开端', isScam: true, tip: '附近的人加好友要警惕！很可能是杀猪盘的第一步。', tier: 'easy' },
    { type: 'door', badge: '上门', badgeClass: 'door', scenario: '我们是XX保健品公司的，今天在小区做健康检测，免费测血压血糖', detail: '以免费检测为名推销保健品', isScam: true, tip: '免费检测是推销保健品的前奏！有病去正规医院。', tier: 'normal' },
    { type: 'phone', badge: '来电', badgeClass: 'phone', scenario: '您好，我是您村里的大队书记，上面拨下来一笔扶贫款，需要先交500元手续费才能领', detail: '冒充村干部扶贫款诈骗', isScam: true, tip: '扶贫款不需要手续费！村委通知会通过广播或公告。', tier: 'normal' },
    { type: 'sms', badge: '短信', badgeClass: 'sms', scenario: '【银联】您的银行卡因异常交易被冻结，请点击链接解冻', detail: '冒充银联冻结银行卡', isScam: true, tip: '银行卡冻结通过银行客服核实！不点陌生链接。', tier: 'easy' },
    { type: 'chat', badge: '微信', badgeClass: 'sms', scenario: '我是您孙女的同学，她在学校被校园贷的人威胁了，需要5000元解决，别告诉她父母', detail: '利用同学身份制造校园贷恐慌', isScam: true, tip: '校园贷威胁应该报警！不要私下转账解决。', tier: 'hard' },
    { type: 'door', badge: '上门', badgeClass: 'door', scenario: '我们是消防队的，来做消防安全检查，您家灭火器过期了需要购买新的', detail: '冒充消防队推销灭火器', isScam: true, tip: '消防部门不会上门推销灭火器！拨打119核实。', tier: 'normal' },
    { type: 'invest', badge: '理财', badgeClass: 'phone', scenario: '我们做的是区块链农业项目，投资一头虚拟牛5000元，每天产奶收益50元', detail: '区块链养殖资金盘', isScam: true, tip: '虚拟养殖是经典资金盘！用新概念包装的庞氏骗局。', tier: 'hard' },
    { type: 'phone', badge: '来电', badgeClass: 'phone', scenario: '您好，我是快递公司的，您有一个海外包裹需要补缴关税，请加我微信转账', detail: '冒充快递员要求微信转账', isScam: true, tip: '关税缴纳通过海关正规渠道！不会通过个人微信收取。', tier: 'easy' },
    { type: 'app', badge: 'App', badgeClass: 'app', scenario: '您的手机弹出系统通知：iOS已到期，请续费每年888元保持系统更新', detail: '伪造iOS系统续费通知', isScam: true, tip: 'iOS系统更新永不过期也不收费！这是恶意广告。', tier: 'normal' },
    { type: 'chat', badge: 'QQ', badgeClass: 'sms', scenario: '我在游戏里看到你技术很好，加好友一起玩，这有个辅助软件免费送你', detail: '游戏辅助软件钓鱼', isScam: true, tip: '免费游戏辅助常含木马！不要下载来路不明的软件。', tier: 'normal' },
    { type: 'sms', badge: '短信', badgeClass: 'sms', scenario: '【腾讯公益】您参与的爱心捐赠已配对成功，点击查看受助人信息', detail: '冒充腾讯公益钓鱼', isScam: true, tip: '腾讯公益活动在微信公益平台查看！不点短信链接。', tier: 'normal' },
];

class FraudGame {
    constructor() {
        this.score = 0;
        this.combo = 1;
        this.streak = 0;
        this.correct = 0;
        this.currentIdx = 0;
        this.timeLeft = 0;
        this.totalItems = 0;
        this.timerId = null;
        this.flashTimer = null;
        this.nextScenarioTimer = null;
        this.timerColorTimer = null;
        this.active = false;
        this.difficulty = 'easy';
        this.scenarios = [];
    }

    init(difficulty, flashMode) {
        this._clearTimers();
        this.active = true;
        this.difficulty = difficulty || 'easy';
        this.flashMode = flashMode || false;
        this.score = 0;
        this.combo = 1;
        this.streak = 0;
        this.correct = 0;
        this.currentIdx = 0;
        this.flashTimer = null;

        // Select scenarios
        var pool;
        var timerSec = 0;
        // Flash mode uses easy pool but per-question countdown
        if (this.flashMode) {
            pool = fraudPool.filter(function(s) { return s.tier === 'easy' || s.tier === 'normal'; });
            timerSec = 0; // global timer disabled, per-question timer active
        } else {
            switch (this.difficulty) {
                case 'normal':
                    pool = fraudPool.filter(function(s) { return s.tier === 'easy' || s.tier === 'normal'; });
                    timerSec = 90;
                    break;
                case 'hard':
                    pool = [...fraudPool];
                    timerSec = 60;
                    break;
                default:
                    pool = fraudPool.filter(function(s) { return s.tier === 'easy'; });
                    timerSec = 0;
            }
        }
        this.scenarios = [...pool].sort(function() { return Math.random() - 0.5; });
        this.totalItems = this.scenarios.length;
        this.timeLeft = timerSec;

        // Difficulty buttons
        document.querySelectorAll('.fraud-diff-btn').forEach(function(b) {
            b.classList.toggle('active', b.dataset.diff === difficulty);
        });

        // UI
        document.getElementById('fraud-score').textContent = '0';
        document.getElementById('fraud-combo').textContent = '1';
        document.getElementById('fraud-progress').textContent = '0/' + this.totalItems;
        document.getElementById('fraud-result').classList.add('hidden');
        document.getElementById('fraud-timer-display').style.display = (timerSec > 0 && !this.flashMode) ? '' : 'none';
        document.getElementById('fraud-timer').textContent = timerSec;

        // Flash mode timer bar
        var ft = document.getElementById('fraud-flash-timer');
        if (ft) ft.style.display = this.flashMode ? '' : 'none';

        document.getElementById('fraud-tip').textContent = this.flashMode
            ? '⚡ 闪电模式！每题5秒倒计时——快速判断，超时即错！'
            : this.difficulty === 'hard'
            ? '⏱ 60秒限时！错误扣8秒，连续正确连击得分！注意区分细微差异——有些"正常"场景跟骗局很像！'
            : this.difficulty === 'normal'
            ? '增加了复杂场景——有些真实的通知也可能看起来像骗局，仔细甄别！'
            : '帮奶奶识别这些电话和短信——是骗局还是真的？连续正确触发连击！';
        trackGamePlay('fraud');

        this._loadScenario();

        var self = this;
        if (timerSec > 0) {
            this.timerId = setInterval(function() { self._tick(); }, 1000);
        }
    }

    _tick() {
        if (!this.active) return;
        this.timeLeft--;
        document.getElementById('fraud-timer').textContent = this.timeLeft;
        if (this.timeLeft <= 10) document.getElementById('fraud-timer').style.color = '#ef4444';
        if (this.timeLeft <= 0) {
            clearInterval(this.timerId);
            this._onGameOver();
        }
    }

    _loadScenario() {
        if (!this.active) return;
        if (this.currentIdx >= this.totalItems) { this._onWin(); return; }
        var s = this.scenarios[this.currentIdx];
        var badge = document.getElementById('fraud-badge');
        badge.textContent = s.badge;
        badge.className = 'fraud-badge ' + s.badgeClass;
        document.getElementById('fraud-scenario').textContent = s.scenario;
        document.getElementById('fraud-detail').textContent = s.detail;
        document.getElementById('fraud-feedback').classList.add('hidden');
        document.getElementById('fraud-progress').textContent = this.currentIdx + '/' + this.totalItems;

        // Flash mode: per-question 5s countdown
        var self = this;
        if (this.flashMode) {
            clearInterval(this.flashTimer);
            this._flashTimeLeft = 5;
            var bar = document.getElementById('fraud-flash-fill');
            if (bar) { bar.style.width = '100%'; bar.style.background = '#ffaa00'; }
            this.flashTimer = setInterval(function() {
                if (!self.active) {
                    clearInterval(self.flashTimer);
                    self.flashTimer = null;
                    return;
                }
                self._flashTimeLeft -= 0.1;
                var pct = Math.max(0, (self._flashTimeLeft / 5) * 100);
                if (bar) { bar.style.width = pct + '%'; if (self._flashTimeLeft < 1.5) bar.style.background = '#ef4444'; }
                if (self._flashTimeLeft <= 0) {
                    clearInterval(self.flashTimer);
                    self.flashTimer = null;
                    self.answer(null); // timeout = wrong
                }
            }, 100);
        }
    }

    answer(playerSaysScam) {
        if (!this.active) return;
        if (this.flashMode) {
            clearInterval(this.flashTimer);
            this.flashTimer = null;
        }
        if (this.timerId === null && this.timeLeft > 0 && !this.flashMode) return; // game over, ignore clicks
        var s = this.scenarios[this.currentIdx];
        var feedback = document.getElementById('fraud-feedback');
        feedback.classList.remove('hidden', 'correct', 'wrong');
        var safeTip = escapeTextForHTML(s.tip);

        if (playerSaysScam === null) {
            // Flash timeout or manual skip
            this.streak = 0; this.combo = 1;
            feedback.classList.add('wrong');
            feedback.innerHTML = safeHTML('<strong>⏰ 超时！</strong> ' + escapeTextForHTML(s.isScam ? '这是骗局！' : '这是真的') + ' — ' + safeTip);
            if (typeof audio !== 'undefined' && audio.playHover) audio.playHover();
        } else if (playerSaysScam === s.isScam) {
            this.correct++;
            this.streak++;
            this.combo = 1 + Math.floor(this.streak / 2);
            var comboBonus = this.combo;
            this.score += 10 * comboBonus;
            feedback.classList.add('correct');
            var correctFeedback = '<strong>✅ 判断正确！</strong> ' + safeTip;
            if (this.combo >= 3) correctFeedback += '<br><small style="color:#fbbf24;">🔥 ' + escapeTextForHTML(this.combo) + '连击！得分 ×' + escapeTextForHTML(this.combo) + '</small>';
            feedback.innerHTML = safeHTML(correctFeedback);
            if (typeof audio !== 'undefined' && audio.playSnap) audio.playSnap();
        } else {
            this.streak = 0;
            this.combo = 1;
            feedback.classList.add('wrong');
            var wrongFeedback = '<strong>❌ 判断错误！</strong> ' + safeTip;
            if (this.difficulty === 'hard') {
                this.timeLeft = Math.max(0, this.timeLeft - 8);
                document.getElementById('fraud-timer').textContent = this.timeLeft;
                document.getElementById('fraud-timer').style.color = '#ef4444';
                var self = this;
                clearTimeout(this.timerColorTimer);
                this.timerColorTimer = setTimeout(function() {
                    self.timerColorTimer = null;
                    var timerEl = document.getElementById('fraud-timer');
                    if (timerEl) timerEl.style.color = '';
                }, 600);
                wrongFeedback += '<br><small style="color:#ef4444;">⏱ 扣8秒！</small>';
            }
            feedback.innerHTML = safeHTML(wrongFeedback);
            if (typeof audio !== 'undefined' && audio.playHover) audio.playHover();
        }

        document.getElementById('fraud-score').textContent = this.correct;
        document.getElementById('fraud-combo').textContent = this.combo;
        this.currentIdx++;

        if (this.currentIdx >= this.totalItems && this.timeLeft <= 0 && this.timerId) {
            clearInterval(this.timerId);
        }
        var self = this;
        clearTimeout(this.nextScenarioTimer);
        this.nextScenarioTimer = setTimeout(function() {
            if (self.active) self._loadScenario();
        }, 1600);
    }

    _onWin() {
        if (!this.active) return;
        this.active = false;
        this._clearTimers();
        var maxCombo = this.score > 0 ? Math.max(this.combo, 1) : 1;
        var totalSilver = unifiedRewardCalc(this.score, maxCombo, this.difficulty === 'easy' ? 'normal' : this.difficulty, 0, Math.round(this.correct / this.totalItems * 100));
        document.getElementById('fraud-result-text').textContent =
            '答对 ' + this.correct + '/' + this.totalItems + ' 题！得分: ' + this.score +
            ' | 最高连击: ×' + maxCombo +
            ' | 获得 +' + totalSilver + ' 记忆银币';
        document.getElementById('fraud-result').classList.remove('hidden');
        if (maxCombo >= 10) achievementSystem.check('comboMaster');
        trackGameComplete('fraud', this.score);
        if (typeof audio !== 'undefined' && audio.playAwake) audio.playAwake();
    }

    _onGameOver() {
        if (!this.active) return;
        this.active = false;
        this._clearTimers();
        var totalSilver = unifiedRewardCalc(this.score, 1, this.difficulty, 0, Math.round(this.correct / this.totalItems * 100));
        document.getElementById('fraud-result-text').textContent =
            '⏰ 时间到！答对 ' + this.correct + '/' + this.totalItems + ' | 得分: ' + this.score +
            ' | 获得 +' + totalSilver + ' 记忆银币\n\n提示: 遇到可疑情况，先挂断/不回复，通过官方渠道核实！';
        document.getElementById('fraud-result').classList.remove('hidden');
        trackGameComplete('fraud', this.score);
        if (typeof audio !== 'undefined' && audio.playHover) audio.playHover();
    }

    _clearTimers() {
        clearInterval(this.timerId);
        clearInterval(this.flashTimer);
        clearTimeout(this.nextScenarioTimer);
        clearTimeout(this.timerColorTimer);
        this.timerId = null;
        this.flashTimer = null;
        this.nextScenarioTimer = null;
        this.timerColorTimer = null;
        var timerEl = document.getElementById('fraud-timer');
        if (timerEl) timerEl.style.color = '';
    }

    destroy() {
        this.active = false;
        this._clearTimers();
    }
}

var _fraudGame = null;
function initFraudGame(difficulty) {
    _fraudGame = new FraudGame();
    // Check if flash mode is toggled on
    var flashBtn = document.getElementById('fraud-flash-toggle');
    _fraudGame.init(difficulty || 'easy', flashBtn ? flashBtn.classList.contains('active') : false);
}

function answerFraud(playerSaysScam) {
    if (_fraudGame) _fraudGame.answer(playerSaysScam);
}

// ============================================================================
// 17. 无障碍体验 — 5阶段视觉障碍模拟
// ============================================================================
const a11yStages = [
    { id: 'blur', name: '轻度白内障模拟', desc: '找到画面中的红色药瓶并点击', targetX: 120, targetY: 180, targetR: 40, filter: 'blur(4px) brightness(0.7)', explain: '全球约6500万人受中度以上视力障碍影响——看什么都像隔了一层毛玻璃' },
    { id: 'blur2', name: '重度视力模糊', desc: '找到并点击蓝色水杯', targetX: 380, targetY: 100, targetR: 35, filter: 'blur(10px) brightness(0.5)', explain: '严重白内障患者视力<0.05——只能感知光影和模糊色块' },
    { id: 'colorblind', name: '红绿色盲模拟', desc: '选出画面中颜色不同的那个圆', targetX: 250, targetY: 200, targetR: 35, filter: 'grayscale(0.5) sepia(0.3) hue-rotate(-30deg)', explain: '全球约3亿人有色觉障碍——无法区分红色和绿色是常见类型' },
    { id: 'tunnel', name: '管状视野模拟', desc: '视野只剩中心——找到边缘的黄色三角形', targetX: 420, targetY: 250, targetR: 45, filter: 'none', tunnelMode: true, explain: '青光眼晚期会导致管状视野——就像通过一根吸管看世界' },
    { id: 'mixed', name: '多重障碍体验', desc: '模糊+色盲+管状视野——找到绿色方形按钮', targetX: 80, targetY: 280, targetR: 42, filter: 'blur(6px) grayscale(0.4) sepia(0.2) hue-rotate(-20deg) brightness(0.6)', tunnelMode: true, explain: '许多老年人同时面临多种视力障碍——你的每一次理解都在搭建无障碍的桥梁' }
];

function initA11yGame() {
    cleanupSkillGameState();
    window._a11yStage = 0;
    document.getElementById('a11y-found').textContent = '0';
    document.getElementById('a11y-stage').textContent = '1';
    document.getElementById('a11y-progress-fill').style.width = '0%';
    document.getElementById('a11y-result').classList.add('hidden');
    var ov = document.getElementById('a11y-tunnel-overlay');
    if (ov) ov.remove();
    trackGamePlay('a11y');
    loadA11yStage();
}

function loadA11yStage() {
    var idx = window._a11yStage;
    if (idx >= a11yStages.length) { onA11yWin(); return; }
    var s = a11yStages[idx];

    document.getElementById('a11y-impairment').textContent = '🔍 ' + s.name;
    document.getElementById('a11y-tip').textContent = s.desc;
    document.getElementById('a11y-stage').textContent = (idx + 1);
    document.getElementById('a11y-progress-fill').style.width = ((idx / a11yStages.length) * 100) + '%';

    var canvas = document.getElementById('a11y-canvas');
    canvas.setAttribute('role', 'button');
    canvas.setAttribute('tabindex', '0');
    canvas.setAttribute('aria-disabled', 'false');
    canvas.setAttribute('aria-label', '视觉障碍模拟：' + s.desc + '。按回车或空格选择当前目标。');
    canvas.style.filter = s.filter;
    var ctx = canvas.getContext('2d');
    canvas.width = 500; canvas.height = 320;

    var bgGrad = ctx.createLinearGradient(0, 0, 500, 320);
    bgGrad.addColorStop(0, '#3a3028'); bgGrad.addColorStop(0.5, '#2a2420'); bgGrad.addColorStop(1, '#1c1815');
    ctx.fillStyle = bgGrad; ctx.fillRect(0, 0, 500, 320);

    var colors = ['#6b5a4a', '#8a7a6a', '#5c5040', '#7a6a5a', '#4a3a2a', '#9a8a7a'];
    for (var i = 0; i < 25; i++) {
        ctx.fillStyle = colors[Math.floor(Math.random() * 6)];
        var dx = Math.random() * 480 + 10, dy = Math.random() * 300 + 10, dr = Math.random() * 25 + 8;
        if (Math.random() < 0.5) ctx.fillRect(dx - dr/2, dy - dr/2, dr, dr);
        else { ctx.beginPath(); ctx.arc(dx, dy, dr/2, 0, Math.PI*2); ctx.fill(); }
    }

    var tx = s.targetX, ty = s.targetY, tr = s.targetR;
    var tc = idx === 0 ? '#ef4444' : idx === 1 ? '#3b82f6' : idx === 2 ? '#22c55e' : idx === 3 ? '#fbbf24' : '#10b981';
    ctx.fillStyle = tc; ctx.globalAlpha = 0.6;

    if (idx === 3) {
        ctx.beginPath(); ctx.moveTo(tx, ty-tr); ctx.lineTo(tx+tr, ty+tr); ctx.lineTo(tx-tr, ty+tr); ctx.closePath(); ctx.fill();
    } else if (idx === 4) {
        ctx.fillRect(tx-tr/2, ty-tr/2, tr, tr);
    } else {
        ctx.beginPath(); ctx.arc(tx, ty, tr, 0, Math.PI*2); ctx.fill();
    }
    ctx.globalAlpha = 1;

    // Tunnel overlay
    var ov = document.getElementById('a11y-tunnel-overlay');
    if (ov) ov.remove();
    if (s.tunnelMode) {
        ov = document.createElement('div');
        ov.id = 'a11y-tunnel-overlay';
        ov.style.cssText = 'position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none;border-radius:16px;background:radial-gradient(circle 80px at 50% 50%, transparent 0%, transparent 40%, rgba(0,0,0,0.85) 60%, rgba(0,0,0,0.92) 100%);';
        document.getElementById('a11y-scene').appendChild(ov);
    }

    var stageCompleted = false;
    function completeCurrentA11yStage() {
        if (stageCompleted) return;
        stageCompleted = true;
        if (typeof audio !== 'undefined' && audio.playSnap) audio.playSnap();
        window._a11yStage++;
        document.getElementById('a11y-found').textContent = window._a11yStage;
        document.getElementById('a11y-progress-fill').style.width = ((window._a11yStage / a11yStages.length) * 100) + '%';
        var tip = document.getElementById('a11y-tip');
        tip.innerHTML = safeHTML('<span style="color:#fbbf24;">💡 ' + escapeTextForHTML(s.explain) + '</span>');
        trackSkillTimeout(function() { loadA11yStage(); }, 2000);
    }

    canvas.onclick = function(e) {
        var rect = canvas.getBoundingClientRect();
        var mx = (e.clientX - rect.left) * (500 / rect.width);
        var my = (e.clientY - rect.top) * (320 / rect.height);
        if (Math.hypot(tx - mx, ty - my) < tr + 25) {
            completeCurrentA11yStage();
        } else {
            canvas.style.borderColor = '#ef4444';
            trackSkillTimeout(function() { canvas.style.borderColor = 'rgba(147,197,253,0.2)'; }, 400);
            if (typeof audio !== 'undefined' && audio.playHover) audio.playHover();
        }
    };
    canvas.onkeydown = function(e) {
        if (e.key !== 'Enter' && e.key !== ' ') return;
        e.preventDefault();
        completeCurrentA11yStage();
    };
}

function onA11yWin() {
    var bonus = 80;
    gameState.memorySilver += bonus;
    document.getElementById('global-silver-balance').textContent = gameState.memorySilver;
    document.getElementById('a11y-progress-fill').style.width = '100%';
    document.getElementById('a11y-impairment').textContent = '';
    document.getElementById('a11y-tip').textContent = '';
    document.getElementById('a11y-result-text').textContent = '你完成了5种视觉障碍模拟体验：白内障模糊、重度视力模糊、红绿色盲、管状视野、多重障碍。全球超过22亿人受视力障碍影响。无障碍设计不是施舍，而是让每个人平等参与世界的基本权利。获得 +80 记忆银币';
    document.getElementById('a11y-result').classList.remove('hidden');
    trackGameComplete('a11y', 100);
    if (typeof audio !== 'undefined' && audio.playAwake) audio.playAwake();
    var ov = document.getElementById('a11y-tunnel-overlay');
    if (ov) ov.remove();
    var canvas = document.getElementById('a11y-canvas');
    if (canvas) {
        canvas.onclick = null;
        canvas.onkeydown = null;
        canvas.setAttribute('aria-disabled', 'true');
        canvas.setAttribute('aria-label', '视觉障碍模拟已完成');
    }
}

// 18. 跨公益赛道导航绑定
// ============================================================================
document.addEventListener('DOMContentLoaded', function() {
    // Eco Sort
    document.getElementById('btn-open-eco')?.addEventListener('click', function() { transitionToScreen('screen-eco'); initEcoGame('easy'); });
    document.getElementById('btn-eco-back')?.addEventListener('click', function() { if (_ecoGame) _ecoGame.destroy(); transitionToScreen('screen-hub'); });
    document.getElementById('btn-eco-replay')?.addEventListener('click', function() { if (_ecoGame) _ecoGame.destroy(); initEcoGame(_ecoGame ? _ecoGame.difficulty : 'easy'); });
    document.getElementById('btn-eco-hub')?.addEventListener('click', function() { if (_ecoGame) _ecoGame.destroy(); transitionToScreen('screen-hub'); });

    // Eco difficulty buttons
    document.querySelectorAll('.eco-diff-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var diff = btn.dataset.diff;
            if (_ecoGame) _ecoGame.destroy();
            initEcoGame(diff);
        });
    });

    // Fraud Guard
    document.getElementById('btn-open-fraud')?.addEventListener('click', function() { transitionToScreen('screen-fraud'); initFraudGame('easy'); });
    document.getElementById('btn-fraud-back')?.addEventListener('click', function() { if (_fraudGame) _fraudGame.destroy(); transitionToScreen('screen-hub'); });
    document.getElementById('btn-fraud-scam')?.addEventListener('click', function() { answerFraud(true); });
    document.getElementById('btn-fraud-safe')?.addEventListener('click', function() { answerFraud(false); });
    document.getElementById('btn-fraud-replay')?.addEventListener('click', function() {
        if (_fraudGame) _fraudGame.destroy();
        var fb = document.getElementById('fraud-flash-toggle');
        initFraudGame(_fraudGame ? _fraudGame.difficulty : 'easy', fb ? fb.classList.contains('active') : false);
    });
    document.getElementById('btn-fraud-hub')?.addEventListener('click', function() { if (_fraudGame) _fraudGame.destroy(); transitionToScreen('screen-hub'); });

    // Fraud difficulty (skip flash toggle button)
    document.querySelectorAll('.fraud-diff-btn').forEach(function(btn) {
        if (btn.id === 'fraud-flash-toggle') return;
        btn.addEventListener('click', function() { if (_fraudGame) _fraudGame.destroy(); initFraudGame(btn.dataset.diff); });
    });
    // Flash mode toggle
    document.getElementById('fraud-flash-toggle')?.addEventListener('click', function() {
        var active = this.classList.toggle('active');
        if (_fraudGame) _fraudGame.destroy();
        initFraudGame(_fraudGame ? _fraudGame.difficulty : 'easy');
    });

    // Accessibility
    document.getElementById('btn-open-a11y')?.addEventListener('click', function() { transitionToScreen('screen-a11y'); initA11yGame(); });
    document.getElementById('btn-a11y-back')?.addEventListener('click', function() { transitionToScreen('screen-hub'); });
    document.getElementById('btn-a11y-replay')?.addEventListener('click', initA11yGame);
    document.getElementById('btn-a11y-hub')?.addEventListener('click', function() { transitionToScreen('screen-hub'); });
});


// ============================================================================
// 19. 星海寻光 · 赛博反诈导航 + 模式切换
// ============================================================================

// 重载 setupItem 支持反诈案件
const _origSetupItem = PuzzleWorkbench.prototype.setupItem;
PuzzleWorkbench.prototype.setupItem = function(itemId) {
    var isFraud = itemId && itemId.startsWith('fraud_');
    gameState.currentMode = isFraud ? 'fraud' : 'nostalgia';
    var app = document.getElementById('app-container');
    if (isFraud) {
        app.classList.add('fraud-mode');
    } else {
        app.classList.remove('fraud-mode');
    }
    
    // 反诈案件特殊处理：修改阶段文案
    if (isFraud) {
        var data = itemBlueprints[itemId];
        if (!data) { console.error('Unknown fraud item:', itemId); return; }
        
        // Reset
        document.getElementById('workspace-title').textContent = '解密：' + data.title;
        document.getElementById('stitch-points-layer').innerHTML = '';
        document.getElementById('custom-prelude-gameplay-zone').innerHTML = '';
        var svgContainer = document.getElementById('active-blueprint-svg');
        svgContainer.style.filter = 'none';
        svgContainer.style.opacity = '';
        document.getElementById('blueprint-dust-overlay').style.display = 'none';
        document.getElementById('blueprint-rust-overlay').style.display = 'none';
        
        // Stage indicator
        this.renderStageIndicator(itemId);
        
        // Blueprint SVG
        var fullBlueprint = '<svg viewBox="0 0 200 200" width="100%" height="100%">';
        data.parts.forEach(function(part) {
            fullBlueprint += '<g id="slot-' + part.id + '" class="target-slot-group">' +
                '<path class="target-slot" id="slot-path-' + part.id + '" d=""/>' +
                '<rect x="' + part.targetX + '" y="' + part.targetY + '" width="140" height="140" fill="transparent"/>' +
                '</g>';
        });
        fullBlueprint += '</svg>';
        svgContainer.innerHTML = safeHTML(fullBlueprint);
        
        // Slot overlays
        data.parts.forEach(function(part) {
            var slotGroup = document.getElementById('slot-' + part.id);
            slotGroup.innerHTML = safeHTML('<g class="blueprint-shape" opacity="0.12">' + part.svg + '</g>' +
                '<rect x="' + part.targetX + '" y="' + part.targetY + '" width="' + part.w + '" height="' + part.h + '" fill="none" stroke="var(--accent-gold)" stroke-width="1.5" stroke-dasharray="4,4" class="target-slot" id="slot-rect-' + part.id + '"/>');
        });
        
        // Tray parts
        this.trayZone.innerHTML = safeHTML('');
        gameState.snappedCount = 0;
        gameState.totalPartsCount = data.parts.length;
        var self = this;
        data.parts.forEach(function(part, index) {
            var partEl = document.createElement('div');
            partEl.classList.add('draggable-part');
            partEl.id = 'part-' + part.id;
            partEl.dataset.partId = part.id;
            partEl.innerHTML = safeHTML('<svg viewBox="0 0 200 200" width="100%" height="100%">' + part.svg + '</svg>');
            partEl.style.left = (Math.random() * (280 - 140) + 10) + 'px';
            partEl.style.top = (index * 85 + Math.random() * 20 + 10) + 'px';
            partEl.style.transform = 'rotate(' + ((Math.random() - 0.5) * 15) + 'deg)';
            var handleStart = function(e) { self.dragStart(e, partEl, part); };
            partEl.addEventListener('pointerdown', handleStart, { passive: false });
            self.trayZone.appendChild(partEl);
        });
        
        // Stage transition
        this.currentRestorationStage = data.stage || 'clean';
        this.restorationProgress = 0;
        this.updateProgressBar(0);
        
        // Fraud-specific clean/focus/etc. slightly modified stage flow
        var stage = data.stage || 'clean';
        var toolCabinet = document.getElementById('restoration-tool-cabinet');
        var assemblyTray = document.getElementById('assembly-tray-content');
        toolCabinet.classList.remove('hidden');
        assemblyTray.classList.add('hidden');
        
        if (stage === 'clean') {
            document.getElementById('cabinet-title').textContent = '木马查杀';
            document.getElementById('cabinet-sub').textContent = '擦除乱码屏障，暴露底层诈骗聊天记录';
            document.getElementById('cabinet-tool-icon').textContent = '🛡️';
            document.getElementById('cabinet-instruction').textContent = '在左侧画面框内【按住拖拽轻扫】，拨开数据迷雾';
            document.getElementById('restoration-status-text').textContent = '数据迷雾覆盖中……请清扫以暴露底层通信记录 (0%)';
            document.querySelector('.workspace-tip').textContent = '🛡️ 在左侧深色区域按住拖拽清扫数据迷雾';
        } else if (stage === 'focus') {
            document.getElementById('cabinet-title').textContent = '域名甄别';
            document.getElementById('cabinet-sub').textContent = '调焦以看清伪造域名的细微差异';
            document.getElementById('cabinet-tool-icon').textContent = '🔍';
            document.getElementById('restoration-status-text').textContent = '正在对焦……请拖拽滑块直到页面清晰 (0%)';
        } else if (stage === 'stitch') {
            document.getElementById('cabinet-title').textContent = '话术拦截';
            document.getElementById('cabinet-sub').textContent = '快速点击拦截诈骗分子的密集话术轰炸';
            document.getElementById('cabinet-tool-icon').textContent = '⚡';
            document.getElementById('restoration-status-text').textContent = '话术拦截中……点击拦截卡片 (0%)';
        }
        
        // Call the appropriate stage handler from the original flow
        if (stage === 'clean') {
            document.getElementById('blueprint-dust-overlay').style.display = 'flex';
            document.getElementById('blueprint-dust-overlay').style.opacity = '1';
            document.querySelector('.workspace-tip').textContent = '🛡️ 在左侧深色区域按住拖拽清扫数据迷雾';
        }
        
        this.hasTriggeredFogFact = false;
        this.currentRestorationStage = 'clean'; // normalize to clean for swipe handler
        
        return; // Skip original setupItem
    }
    
    // Original flow
    _origSetupItem.call(this, itemId);
};

// 扩展 syncHubState 支持反诈案件卡片
var _origSyncHubState = syncHubState;
syncHubState = function() {
    _origSyncHubState();
    
    // Render fraud capsule silhouettes
    var fraudItems = ['fraud_voice', 'fraud_phish', 'fraud_romance'];
    fraudItems.forEach(function(id) {
        var silContainer = document.getElementById('silhouette-' + id + '-container');
        if (silContainer && !silContainer.innerHTML) {
            var data = itemBlueprints[id];
            if (!data) return;
            var svg = '<svg viewBox="0 0 200 200" width="100%" height="100%">';
            data.parts.forEach(function(p) { svg += '<g opacity="0.25">' + p.svg + '</g>'; });
            svg += '</svg>';
            silContainer.innerHTML = safeHTML(svg);
        }
        
        var card = document.getElementById('fraud-' + id.split('_').pop());
        if (!card) return;
        if (gameState.fraudCompleted.includes(id)) {
            card.classList.add('completed');
            card.querySelector('.btn-capsule-action').textContent = '案件已破';
        } else {
            card.classList.remove('completed');
            card.querySelector('.btn-capsule-action').textContent = '开启解密';
        }
    });
};

// 重载 triggerObjectAwake 使其标记反诈完成
var _origTriggerAwake = PuzzleWorkbench.prototype.triggerObjectAwake;
PuzzleWorkbench.prototype.triggerObjectAwake = function() {
    _origTriggerAwake.call(this);
    var itemId = gameState.activeItem;
    if (itemId && itemId.startsWith('fraud_')) {
        var isNewFraudCompletion = !gameState.fraudCompleted.includes(itemId);
        if (isNewFraudCompletion) {
            gameState.fraudCompleted.push(itemId);
            gameState.memorySilver += 30;
            document.getElementById('global-silver-balance').textContent = gameState.memorySilver;
        }
    }
};

// ============================================================================
// 20. 反诈案件 Hub 导航绑定
// ============================================================================
document.addEventListener('DOMContentLoaded', function() {
    // Fraud capsule click handlers
    var fraudCards = document.querySelectorAll('.fraud-card-style');
    fraudCards.forEach(function(card) {
        card.addEventListener('click', function() {
            var id = card.dataset.item;
            if (gameState.fraudCompleted.includes(id)) {
                transitionToScreen('screen-album');
                renderAlbum();
            } else {
                gameState.activeItem = id;
                workbench.setupItem(id);
                transitionToScreen('screen-workspace');
            }
        });
    });
});


// ============================================================================
// 21. 🔗 信号溯源 — Canvas 画线追踪诈骗源头
// ============================================================================
const traceLevels = [
    {
        title: '第1关：电话诈骗溯源',
        nodes: [{x:80,y:350,label:'独居老人',type:'victim'},{x:200,y:280,label:'伪基站',type:'relay'},{x:200,y:150,label:'AI语音',type:'relay'},{x:350,y:220,label:'境外IP',type:'relay'},{x:420,y:80,label:'诈骗窝点',type:'origin'}],
        path: [0,1,2,3,4],
        hint: '从受害者→伪基站→AI语音池→境外IP→找到诈骗源头！'
    },
    {
        title: '第2关：钓鱼网站溯源',
        nodes: [{x:60,y:80,label:'钓鱼链接',type:'victim'},{x:150,y:200,label:'DNS劫持',type:'relay'},{x:280,y:300,label:'山寨服务器',type:'relay'},{x:400,y:180,label:'数据黑产',type:'origin'}],
        path: [0,1,2,3],
        hint: 'DNS劫持→山寨服务器→数据黑产仓库！'
    },
    {
        title: '第3关：杀猪盘溯源',
        nodes: [{x:50,y:200,label:'交友App',type:'victim'},{x:180,y:100,label:'盗图账号',type:'relay'},{x:300,y:200,label:'假投资平台',type:'relay'},{x:420,y:300,label:'洗钱账户',type:'origin'}],
        path: [0,1,2,3],
        hint: '盗图账号→假投资平台→最终流入洗钱账户！'
    }
];

function initTraceGame() {
    cleanupSkillGameState();
    window._traceCompleted = false;
    window._traceLevel = 0;
    window._tracePath = [];
    window._traceDrawing = false;
    document.getElementById('trace-progress').textContent = '0';
    document.getElementById('trace-result').classList.add('hidden');
    trackGamePlay('trace');
    loadTraceLevel();
}

function loadTraceLevel() {
    if (window._traceCompleted) return;
    var level = window._traceLevel;
    if (level >= traceLevels.length) { onTraceWin(); return; }
    var data = traceLevels[level];
    document.getElementById('trace-stage').textContent = data.title;
    window._tracePath = [];
    window._traceDrawing = false;
    window._traceCurrentLine = null;

    var canvas = document.getElementById('trace-canvas');
    canvas.width = 500; canvas.height = 400;
    canvas.setAttribute('aria-disabled', 'false');
    var ctx = canvas.getContext('2d');
    window._traceCtx = ctx;
    window._traceData = data;
    window._traceNodes = [];

    // Helper: hex to rgba
    function hexToRgba(hex, alpha) {
        var r = parseInt(hex.slice(1,3), 16);
        var g = parseInt(hex.slice(3,5), 16);
        var b = parseInt(hex.slice(5,7), 16);
        return 'rgba(' + r + ',' + g + ',' + b + ',' + alpha + ')';
    }

    // Draw all static elements (nodes, grid, AND completed paths)
    function drawStatic() {
        ctx.clearRect(0, 0, 500, 400);
        ctx.fillStyle = '#0a0a12'; ctx.fillRect(0, 0, 500, 400);
        // Grid lines
        ctx.strokeStyle = 'rgba(0,255,136,0.05)'; ctx.lineWidth = 1;
        for (var i = 0; i < 500; i += 40) { ctx.beginPath(); ctx.moveTo(i,0); ctx.lineTo(i,400); ctx.stroke(); }
        for (var j = 0; j < 400; j += 40) { ctx.beginPath(); ctx.moveTo(0,j); ctx.lineTo(500,j); ctx.stroke(); }

        window._traceNodes = [];
        var nodeCoords = [];
        data.nodes.forEach(function(n, i) {
            var color = n.type === 'victim' ? '#60a5fa' : n.type === 'origin' ? '#ef4444' : '#a0a0a0';
            ctx.beginPath();
            ctx.arc(n.x, n.y, 22, 0, Math.PI * 2);
            ctx.fillStyle = hexToRgba(color, 0.2);
            ctx.fill();
            ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.stroke();

            // Label
            ctx.fillStyle = '#fff';
            ctx.font = '11px monospace';
            ctx.textAlign = 'center';
            ctx.fillText(n.label, n.x, n.y + 35);

            // Type badge
            ctx.fillStyle = color;
            ctx.font = '9px monospace';
            var badge = n.type === 'victim' ? '受害者' : n.type === 'origin' ? '源头' : '跳板';
            ctx.fillText(badge, n.x, n.y - 30);

            window._traceNodes.push({ x: n.x, y: n.y, index: i });
            nodeCoords.push({ x: n.x, y: n.y });
        });

        // === KEY FIX: Redraw completed path segments ===
        if (window._tracePath.length >= 2) {
            ctx.strokeStyle = '#00ff88'; ctx.lineWidth = 3;
            ctx.lineCap = 'round'; ctx.shadowBlur = 10; ctx.shadowColor = '#00ff88';
            for (var p = 0; p < window._tracePath.length - 1; p++) {
                var a = nodeCoords[window._tracePath[p]];
                var b = nodeCoords[window._tracePath[p + 1]];
                ctx.beginPath();
                ctx.moveTo(a.x, a.y);
                ctx.lineTo(b.x, b.y);
                ctx.stroke();
            }
            // Draw dot on current last node
            var last = nodeCoords[window._tracePath[window._tracePath.length - 1]];
            ctx.beginPath();
            ctx.arc(last.x, last.y, 6, 0, Math.PI * 2);
            ctx.fillStyle = '#00ff88';
            ctx.fill();
            ctx.shadowBlur = 0;
        }

        // Draw hint
        ctx.fillStyle = '#0ff';
        ctx.font = '12px sans-serif';
        ctx.fillText(data.hint, 250, 390);
    }
    drawStatic();

    // Store the drawStatic function for reuse in pointermove
    window._traceDrawStatic = drawStatic;
    window._traceHexToRgba = hexToRgba;

    // Store node colors for reuse
    window._traceNodeColors = data.nodes.map(function(n) {
        return n.type === 'victim' ? '#60a5fa' : n.type === 'origin' ? '#ef4444' : '#a0a0a0';
    });

    function updateTraceCanvasLabel() {
        var nextIdx = data.path[window._tracePath.length];
        var nextNode = data.nodes[nextIdx];
        var completedSegments = Math.max(0, window._tracePath.length - 1);
        var totalSegments = Math.max(0, data.path.length - 1);
        var label = '信号溯源画布：' + data.title + '。' + data.hint + ' 已连接 ' + completedSegments + '/' + totalSegments + ' 段。';
        if (nextNode) label += ' 下一个线索节点：' + nextNode.label + '。按回车或空格推进。';
        canvas.setAttribute('aria-label', label);
    }

    function setTraceProgressText() {
        document.getElementById('trace-progress').textContent = window._traceLevel + '/' + Math.max(0, window._tracePath.length - 1);
        updateTraceCanvasLabel();
    }

    function completeTraceLevelIfNeeded() {
        if (window._tracePath.length !== data.path.length) return;
        window._traceDrawing = false;
        window._traceLevel++;
        document.getElementById('trace-progress').textContent = window._traceLevel;
        updateTraceCanvasLabel();
        trackSkillTimeout(function() { loadTraceLevel(); }, 1000);
    }

    function advanceTraceKeyboardStep() {
        if (window._traceCompleted) return;
        var expectedIdx = data.path[window._tracePath.length];
        var targetNode = data.nodes[expectedIdx];
        if (!targetNode) return;
        var hit = { x: targetNode.x, y: targetNode.y, index: expectedIdx };
        window._tracePath.push(expectedIdx);
        window._traceDrawing = true;
        window._traceLastNode = hit;
        drawStatic();
        setTraceProgressText();
        if (typeof audio !== 'undefined' && audio.playSnap) audio.playSnap();
        completeTraceLevelIfNeeded();
    }

    // Events
    canvas.onpointerdown = function(e) {
        e.preventDefault();
        var rect = canvas.getBoundingClientRect();
        var mx = (e.clientX - rect.left) * (500 / rect.width);
        var my = (e.clientY - rect.top) * (400 / rect.height);

        // If already in drawing mode, just let pointermove continue from last node
        if (window._traceDrawing && window._tracePath.length > 0) {
            return;
        }

        // First touch: must hit the next expected node
        var hit = window._traceNodes.find(function(n) {
            return Math.hypot(n.x - mx, n.y - my) < 30;
        });
        if (!hit) return;

        var expected = data.path[window._tracePath.length];
        if (hit.index === expected) {
            window._tracePath.push(hit.index);
            window._traceDrawing = true;
            window._traceLastNode = hit;
            setTraceProgressText();
            if (typeof audio !== 'undefined' && audio.playHover) audio.playHover();
        } else if (window._tracePath.length === 0) {
            // Wrong start node
            ctx.fillStyle = 'rgba(255,0,0,0.4)';
            ctx.beginPath(); ctx.arc(hit.x, hit.y, 30, 0, Math.PI*2); ctx.fill();
            trackSkillTimeout(function() { loadTraceLevel(); }, 500);
        }
    };

    canvas.onpointermove = function(e) {
        if (!window._traceDrawing || window._tracePath.length === 0) return;
        e.preventDefault();
        var rect = canvas.getBoundingClientRect();
        var mx = (e.clientX - rect.left) * (500 / rect.width);
        var my = (e.clientY - rect.top) * (400 / rect.height);

        window._traceDrawStatic();

        // Draw live line from last node to cursor
        ctx.shadowBlur = 10; ctx.shadowColor = '#00ff88';
        ctx.strokeStyle = 'rgba(0,255,136,0.6)'; ctx.lineWidth = 2;
        ctx.setLineDash([6, 4]);
        ctx.beginPath(); ctx.moveTo(window._traceLastNode.x, window._traceLastNode.y);
        ctx.lineTo(mx, my); ctx.stroke();
        ctx.setLineDash([]);
        ctx.shadowBlur = 0;
    };

    canvas.onpointerup = function(e) {
        if (!window._traceDrawing) return;
        e.preventDefault();
        var rect = canvas.getBoundingClientRect();
        var mx = (e.clientX - rect.left) * (500 / rect.width);
        var my = (e.clientY - rect.top) * (400 / rect.height);

        // Check if cursor is near the expected next node
        var expectedIdx = data.path[window._tracePath.length];
        var targetNode = data.nodes[expectedIdx];
        var dist = Math.hypot(targetNode.x - mx, targetNode.y - my);

        if (dist < 35) {
            // Snap to next node
            window._tracePath.push(expectedIdx);
            var hit = { x: targetNode.x, y: targetNode.y, index: expectedIdx };

            // Draw permanent line from last to this node
            ctx.shadowBlur = 10; ctx.shadowColor = '#00ff88';
            ctx.strokeStyle = '#00ff88'; ctx.lineWidth = 3;
            ctx.setLineDash([]);
            ctx.beginPath(); ctx.moveTo(window._traceLastNode.x, window._traceLastNode.y);
            ctx.lineTo(hit.x, hit.y); ctx.stroke();
            ctx.shadowBlur = 0;

            window._traceLastNode = hit;
            if (typeof audio !== 'undefined' && audio.playSnap) audio.playSnap();
            setTraceProgressText();

            completeTraceLevelIfNeeded();
            // _traceDrawing stays true — ready for next segment
        }
        // If not near target node, keep _traceDrawing true to allow retry on next touch
    };
    canvas.onkeydown = function(e) {
        if (e.key !== 'Enter' && e.key !== ' ') return;
        e.preventDefault();
        advanceTraceKeyboardStep();
    };
    window._traceKeyHandler = canvas.onkeydown;
    updateTraceCanvasLabel();
}

function onTraceWin() {
    if (window._traceCompleted) return;
    window._traceCompleted = true;
    var canvas = document.getElementById('trace-canvas');
    if (canvas) {
        canvas.onpointerdown = null;
        canvas.onpointermove = null;
        canvas.onpointerup = null;
        canvas.onkeydown = null;
        canvas.setAttribute('aria-disabled', 'true');
        canvas.setAttribute('aria-label', '信号溯源画布，全部溯源完成。');
    }
    gameState.memorySilver += 50;
    document.getElementById('global-silver-balance').textContent = gameState.memorySilver;
    document.getElementById('trace-result-text').textContent = '成功追踪到诈骗源头！每一条线索都通向正义。获得 +50 算力积分';
    document.getElementById('trace-result').classList.remove('hidden');
    trackGameComplete('trace', 100);
    audio.playAwake();
}

// ============================================================================
// 22. 🧩 密码重组 — 反诈安全密码拼字
// ============================================================================
const decodePuzzles = [
    { answer: '不轻信陌生来电', tiles: ['不','轻','信','陌','生','来','电'], hint: '7字反诈密码（防电话诈骗）' },
    { answer: '不点击不明链接', tiles: ['不','点','击','不','明','链','接'], hint: '7字反诈密码（防钓鱼链接）' },
    { answer: '不透露验证码', tiles: ['不','透','露','验','证','码'], hint: '6字反诈密码（防信息泄露）' },
    { answer: '不转账给陌生人', tiles: ['不','转','账','给','陌','生','人'], hint: '7字反诈密码（防资金损失）' },
    { answer: '遇事多核实', tiles: ['遇','事','多','核','实'], hint: '5字反诈密码（防AI拟声）' }
,
    { answer: '不听不信不转账', tiles: ['不','听','不','信','不','转','账'], hint: '7字反诈口诀' },
    { answer: '不贪不怕不轻信', tiles: ['不','贪','不','怕','不','轻','信'], hint: '7字反诈密码' },
    { answer: '不刷单不网贷', tiles: ['不','刷','单','不','网','贷'], hint: '6字反诈密码' },
    { answer: '不裸聊不网赌', tiles: ['不','裸','聊','不','网','赌'], hint: '6字反诈密码' },
    { answer: '不透露个人信息', tiles: ['不','透','露','个','人','信','息'], hint: '7字反诈密码' },
    { answer: '不共享手机屏幕', tiles: ['不','共','享','手','机','屏','幕'], hint: '7字反诈密码' },
    { answer: '不借银行卡他人', tiles: ['不','借','银','行','卡','他','人'], hint: '7字反诈密码' },
    { answer: '不帮人转账套现', tiles: ['不','帮','人','转','账','套','现'], hint: '7字反诈密码' },
    { answer: '不做担保不签字', tiles: ['不','做','担','保','不','签','字'], hint: '7字反诈密码' },
    { answer: '陌生链接不要点', tiles: ['陌','生','链','接','不','要','点'], hint: '7字网络安全' },
    { answer: '验证码是最后防线', tiles: ['验','证','码','是','最','后','防','线'], hint: '8字反诈密码' },
    { answer: '天上不会掉馅饼', tiles: ['天','上','不','会','掉','馅','饼'], hint: '7字反诈金句' },
    { answer: '高收益必高风险', tiles: ['高','收','益','必','高','风','险'], hint: '7字投资警示' },
    { answer: '保本高息是陷阱', tiles: ['保','本','高','息','是','陷','阱'], hint: '7字投资警示' },
    { answer: '先交钱的多半骗', tiles: ['先','交','钱','的','多','半','骗'], hint: '7字防骗口诀' },
    { answer: '免费的最贵', tiles: ['免','费','的','最','贵'], hint: '5字反诈金句' },
    { answer: '遇事冷静多核实', tiles: ['遇','事','冷','静','多','核','实'], hint: '7字反诈密码' },
    { answer: '拿不准就打110', tiles: ['拿','不','准','就','打','1','1','0'], hint: '7字反诈密码' },
    { answer: '下载反诈App', tiles: ['下','载','反','诈','A','p','p'], hint: '5字安全建议' },
    { answer: '开启来电预警', tiles: ['开','启','来','电','预','警'], hint: '6字安全建议' },
    { answer: '保护个人信息', tiles: ['保','护','个','人','信','息'], hint: '6字安全提醒' },
    { answer: '定期修改密码', tiles: ['定','期','修','改','密','码'], hint: '6字安全建议' },
    { answer: '关闭免密支付', tiles: ['关','闭','免','密','支','付'], hint: '6字安全建议' },
    { answer: '核实再转账', tiles: ['核','实','再','转','账'], hint: '5字安全口诀' },
    { answer: '密码不说出口', tiles: ['密','码','不','说','出','口'], hint: '6字安全密码' },
    { answer: '公检法不会电话办案', tiles: ['公','检','法','不','会','电','话','办','案'], hint: '9字反诈知识' },
    { answer: '安全账户不存在', tiles: ['安','全','账','户','不','存','在'], hint: '7字反诈知识' },
    { answer: '网购退款原路返回', tiles: ['网','购','退','款','原','路','返','回'], hint: '8字反诈知识' },
    { answer: '航班取消先核实', tiles: ['航','班','取','消','先','核','实'], hint: '7字反诈知识' },
    { answer: '家属出事先联系', tiles: ['家','属','出','事','先','联','系'], hint: '7字反诈知识' },
    { answer: '刷单就是诈骗', tiles: ['刷','单','就','是','诈','骗'], hint: '6字反诈常识' },
    { answer: '网贷先交钱是骗', tiles: ['网','贷','先','交','钱','是','骗'], hint: '7字反诈常识' },
    { answer: '网恋不见面要警惕', tiles: ['网','恋','不','见','面','要','警','惕'], hint: '8字反诈密码' },
    { answer: '熟人借钱要视频确认', tiles: ['熟','人','借','钱','要','视','频','确','认'], hint: '9字反诈密码' },
    { answer: '保健品不是药', tiles: ['保','健','品','不','是','药'], hint: '6字老年防骗' },
    { answer: '特效药多是假', tiles: ['特','效','药','多','是','假'], hint: '6字老年防骗' },
    { answer: '免费体检是套路', tiles: ['免','费','体','检','是','套','路'], hint: '7字老年防骗' },
    { answer: '养老投资多陷阱', tiles: ['养','老','投','资','多','陷','阱'], hint: '7字老年防骗' },
    { answer: '上门推销不要开门', tiles: ['上','门','推','销','不','要','开','门'], hint: '8字老年防骗' },
    { answer: '守好钱袋子', tiles: ['守','好','钱','袋','子'], hint: '5字反诈金句' },
    { answer: '心中无贪念骗局远身边', tiles: ['心','中','无','贪','念','骗','局','远','身','边'], hint: '10字反诈金句' },
    { answer: '诈骗手段日日新', tiles: ['诈','骗','手','段','日','日','新'], hint: '7字反诈警句' },
    { answer: '提高警惕不上当', tiles: ['提','高','警','惕','不','上','当'], hint: '7字反诈密码' },
    { answer: '万骗不离转账', tiles: ['万','骗','不','离','转','账'], hint: '6字反诈要点' },
    { answer: '守住验证码', tiles: ['守','住','验','证','码'], hint: '5字反诈要点' },
    { answer: '谈钱多留心', tiles: ['谈','钱','多','留','心'], hint: '5字反诈要点' },
    { answer: '先核实再行动', tiles: ['先','核','实','再','行','动'], hint: '6字反诈密码' },
    { answer: '电话办案是假的', tiles: ['电','话','办','案','是','假','的'], hint: '7字反诈知识' },
    { answer: '法院传票有传票', tiles: ['法','院','传','票','有','传','票'], hint: '7字反诈知识' },
    { answer: '中奖先交钱是骗局', tiles: ['中','奖','先','交','钱','是','骗','局'], hint: '8字反诈常识' },
    { answer: '洗钱罪名是恐吓', tiles: ['洗','钱','罪','名','是','恐','吓'], hint: '7字反诈知识' },
    { answer: '不信中奖信息', tiles: ['不','信','中','奖','信','息'], hint: '6字反诈密码' },
    { answer: '不透露密码', tiles: ['不','透','露','密','码'], hint: '5字反诈密码' },
    { answer: '不向陌生人转账', tiles: ['不','向','陌','生','人','转','账'], hint: '7字反诈密码' },
    { answer: '不用公共WiFi支付', tiles: ['不','用','公','共','W','i','F','i','支','付'], hint: '8字安全建议' },
    { answer: '不乱扫二维码', tiles: ['不','乱','扫','二','维','码'], hint: '6字安全建议' },
    { answer: '不信天上掉馅饼', tiles: ['不','信','天','上','掉','馅','饼'], hint: '7字反诈金句' },
    { answer: '不信一夜暴富', tiles: ['不','信','一','夜','暴','富'], hint: '6字防骗金句' },
    { answer: '不贪高额回报', tiles: ['不','贪','高','额','回','报'], hint: '6字反诈密码' },
    { answer: '不被恐慌操控', tiles: ['不','被','恐','慌','操','控'], hint: '6字反诈密码' },
    { answer: '不泄露人脸信息', tiles: ['不','泄','露','人','脸','信','息'], hint: '7字安全提醒' },
    { answer: '安装防火墙', tiles: ['安','装','防','火','墙'], hint: '5字安全建议' },
    { answer: '不连陌生WiFi', tiles: ['不','连','陌','生','W','i','F','i'], hint: '6字安全建议' },
    { answer: '关闭蓝牙发现', tiles: ['关','闭','蓝','牙','发','现'], hint: '6字安全建议' },
    { answer: '加密重要文件', tiles: ['加','密','重','要','文','件'], hint: '6字安全建议' },
    { answer: '定期备份数据', tiles: ['定','期','备','份','数','据'], hint: '6字安全建议' },
    { answer: '全民反诈人人有责', tiles: ['全','民','反','诈','人','人','有','责'], hint: '8字反诈口号' },
    { answer: '反诈防骗警钟长鸣', tiles: ['反','诈','防','骗','警','钟','长','鸣'], hint: '8字反诈警句' },
    { answer: '骗子套路深', tiles: ['骗','子','套','路','深'], hint: '5字反诈提醒' },
    { answer: '防骗记心间', tiles: ['防','骗','记','心','间'], hint: '5字反诈口诀' },
    { answer: '钱袋子要捂紧', tiles: ['钱','袋','子','要','捂','紧'], hint: '6字反诈提醒' },
    { answer: '三思而后转账', tiles: ['三','思','而','后','转','账'], hint: '6字反诈密码' },
    { answer: '转账前先电话确认', tiles: ['转','账','前','先','电','话','确','认'], hint: '8字反诈密码' },
    { answer: '遇到诈骗就举报', tiles: ['遇','到','诈','骗','就','举','报'], hint: '7字反诈行动' },
    { answer: '96110来电要接', tiles: ['9','6','1','1','0','来','电','要','接'], hint: '8字安全提醒' },
    { answer: '反诈专线记心间', tiles: ['反','诈','专','线','记','心','间'], hint: '7字安全提醒' },
    { answer: '不帮人洗钱', tiles: ['不','帮','人','洗','钱'], hint: '5字反诈警告' },
    { answer: '涉嫌洗钱是恐吓', tiles: ['涉','嫌','洗','钱','是','恐','吓'], hint: '7字反诈知识' },
    { answer: '通缉令不会网上发', tiles: ['通','缉','令','不','会','网','上','发'], hint: '8字反诈知识' },
    { answer: '逮捕令是伪造的', tiles: ['逮','捕','令','是','伪','造','的'], hint: '7字反诈知识' },
    { answer: '骗子最怕你核实', tiles: ['骗','子','最','怕','你','核','实'], hint: '7字反诈金句' },
    { answer: '多问一句少上一次当', tiles: ['多','问','一','句','少','上','一','次','当'], hint: '9字反诈金句' },
    { answer: '不装不明软件', tiles: ['不','装','不','明','软','件'], hint: '6字安全建议' },
    { answer: '不连陌生热点', tiles: ['不','连','陌','生','热','点'], hint: '6字安全建议' },
    { answer: '不借手机陌生人', tiles: ['不','借','手','机','陌','生','人'], hint: '7字反诈密码' },
    { answer: '不扫快递单上码', tiles: ['不','扫','快','递','单','上','码'], hint: '7字反诈密码' },
    { answer: '不信征信修复', tiles: ['不','信','征','信','修','复'], hint: '6字反诈密码' },
    { answer: '先核实后付款', tiles: ['先','核','实','后','付','款'], hint: '6字防骗口诀' },
    { answer: '不贪不惧不盲从', tiles: ['不','贪','不','惧','不','盲','从'], hint: '7字防骗心态' },
    { answer: '转账之前想一想', tiles: ['转','账','之','前','想','一','想'], hint: '7字防骗提醒' },
    { answer: '自称公检法要警惕', tiles: ['自','称','公','检','法','要','警','惕'], hint: '8字反诈提醒' },
    { answer: '让你转账就挂断', tiles: ['让','你','转','账','就','挂','断'], hint: '7字反诈应对' },
    { answer: '要验证码是骗子', tiles: ['要','验','证','码','是','骗','子'], hint: '7字反诈常识' },
    { answer: '说你洗钱是恐吓', tiles: ['说','你','洗','钱','是','恐','吓'], hint: '7字反诈常识' },
    { answer: '高利息必有高风险', tiles: ['高','利','息','必','有','高','风','险'], hint: '8字投资警示' },
    { answer: '先交费的兼职是骗', tiles: ['先','交','费','的','兼','职','是','骗'], hint: '8字反诈常识' },
    { answer: '不听不信不理会', tiles: ['不','听','不','信','不','理','会'], hint: '7字反诈密码' },
    { answer: '来电显示可以伪造', tiles: ['来','电','显','示','可','以','伪','造'], hint: '8字反诈知识' },
];

function initDecodeGame() {
    cleanupSkillGameState();
    window._decodeCompleted = false;
    window._decodePuzzleLocked = false;
    window._decodeIndex = 0;
    window._decodeCurrent = [];
    window._decodePuzzles = [...decodePuzzles].sort(function() { return Math.random() - 0.5; }).slice(0, 5);
    document.getElementById('decode-score').textContent = '0';
    document.getElementById('decode-result').classList.add('hidden');
    trackGamePlay('decode');
    loadDecodePuzzle();
}

function loadDecodePuzzle() {
    if (window._decodeCompleted) return;
    var idx = window._decodeIndex;
    var activePuzzles = window._decodePuzzles || decodePuzzles;
    if (idx >= activePuzzles.length) { onDecodeWin(); return; }
    window._decodeCurrent = [];
    window._decodePuzzleLocked = false;
    var puzzle = activePuzzles[idx];
    document.getElementById('decode-hint').textContent = puzzle.hint;
    document.getElementById('decode-answer').innerHTML = '';
    document.getElementById('decode-tiles').innerHTML = '';

    function bindDecodeKeyActivation(node, handler) {
        node.addEventListener('keydown', function(e) {
            if (e.key !== 'Enter' && e.key !== ' ') return;
            e.preventDefault();
            handler();
        });
    }

    var shuffled = [...puzzle.tiles].sort(function() { return Math.random() - 0.5; });
    shuffled.forEach(function(tile) {
        var el = document.createElement('span');
        el.className = 'decode-tile';
        el.textContent = tile;
        el.setAttribute('role', 'button');
        el.setAttribute('tabindex', '0');
        el.setAttribute('aria-disabled', 'false');
        el.setAttribute('aria-label', '选择反诈字符：' + tile);
        function chooseTile() {
            if (window._decodeCompleted || window._decodePuzzleLocked) return;
            if (el.classList.contains('placed')) return;
            el.classList.add('placed');
            el.setAttribute('aria-disabled', 'true');
            el.tabIndex = -1;
            window._decodeCurrent.push(tile);
            var ans = document.getElementById('decode-answer');
            var tileEl = document.createElement('span');
            tileEl.className = 'decode-answer-tile';
            tileEl.textContent = tile;
            tileEl.setAttribute('role', 'button');
            tileEl.setAttribute('tabindex', '0');
            tileEl.setAttribute('aria-label', '移除反诈字符：' + tile);
            function removeAnswerTile() {
                if (window._decodeCompleted || window._decodePuzzleLocked) return;
                // Remove this tile from answer
                var pos = window._decodeCurrent.indexOf(tile);
                if (pos >= 0) window._decodeCurrent.splice(pos, 1);
                tileEl.remove();
                el.classList.remove('placed');
                el.setAttribute('aria-disabled', 'false');
                el.tabIndex = 0;
                audio.playHover();
            }
            tileEl.addEventListener('click', removeAnswerTile);
            bindDecodeKeyActivation(tileEl, removeAnswerTile);
            ans.appendChild(tileEl);
            audio.playHover();

            // Check answer
            if (window._decodeCurrent.join('') === puzzle.answer) {
                window._decodePuzzleLocked = true;
                window._decodeIndex++;
                document.getElementById('decode-score').textContent = window._decodeIndex;
                audio.playSnap();
                trackSkillTimeout(loadDecodePuzzle, 800);
            } else if (window._decodeCurrent.length >= puzzle.answer.length) {
                // Wrong - flash
                ans.querySelectorAll('.decode-answer-tile').forEach(function(t) { t.classList.add('wrong'); });
                audio.playHover();
                trackSkillTimeout(function() {
                    ans.innerHTML = '';
                    window._decodeCurrent = [];
                    document.querySelectorAll('.decode-tile.placed').forEach(function(t) {
                        t.classList.remove('placed');
                        t.setAttribute('aria-disabled', 'false');
                        t.tabIndex = 0;
                    });
                }, 600);
            }
        }
        el.addEventListener('click', chooseTile);
        bindDecodeKeyActivation(el, chooseTile);
        document.getElementById('decode-tiles').appendChild(el);
    });
}

function onDecodeWin() {
    if (window._decodeCompleted) return;
    window._decodeCompleted = true;
    window._decodePuzzleLocked = true;
    gameState.memorySilver += 50;
    document.getElementById('global-silver-balance').textContent = gameState.memorySilver;
    document.getElementById('decode-result-text').textContent = '5条反诈密码全部破解！记住这些密码，守护财产安全。获得 +50 算力积分';
    document.getElementById('decode-result').classList.remove('hidden');
    trackGameComplete('decode', 100);
    audio.playAwake();
}

// ============================================================================
// 23. 🔗 信号溯源导航绑定
// ============================================================================
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('btn-open-trace')?.addEventListener('click', function() {
        transitionToScreen('screen-trace');
        initTraceGame();
    });
    document.getElementById('btn-trace-back')?.addEventListener('click', function() {
        transitionToScreen('screen-hub');
    });
    document.getElementById('btn-trace-replay')?.addEventListener('click', function() {
        initTraceGame();
    });
    document.getElementById('btn-trace-hub')?.addEventListener('click', function() {
        transitionToScreen('screen-hub');
    });
});

// ============================================================================
// 24. 🧩 密码重组导航绑定
// ============================================================================
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('btn-open-decode')?.addEventListener('click', function() {
        transitionToScreen('screen-decode');
        initDecodeGame();
    });
    document.getElementById('btn-decode-back')?.addEventListener('click', function() {
        transitionToScreen('screen-hub');
    });
    document.getElementById('btn-decode-replay')?.addEventListener('click', function() {
        initDecodeGame();
    });
    document.getElementById('btn-decode-hub')?.addEventListener('click', function() {
        transitionToScreen('screen-hub');
    });
});

// ============================================================================
// 25. 🌊 深蓝修复者 — 珊瑚礁生态修复游戏（升级版：3关渐进 + 倒计时 + 海洋污染事件）
// ============================================================================
const coralTypes = [
    { id: 'staghorn', name: '鹿角珊瑚', color: '#ff6b4a', shape: 'branch', fact: '鹿角珊瑚生长最快，每年可长10cm' },
    { id: 'brain', name: '脑珊瑚', color: '#ff8c69', shape: 'round', fact: '脑珊瑚寿命可达900年' },
    { id: 'tube', name: '管状珊瑚', color: '#ff4500', shape: 'tube', fact: '管状珊瑚是海绵动物的共生伙伴' },
    { id: 'fan', name: '海扇珊瑚', color: '#ff6347', shape: 'fan', fact: '海扇珊瑚可过滤海水中的微塑料' },
    { id: 'mushroom', name: '蘑菇珊瑚', color: '#fa8072', shape: 'mushroom', fact: '蘑菇珊瑚是独居珊瑚，不形成群体' },
    { id: 'table', name: '桌形珊瑚', color: '#e9967a', shape: 'table', fact: '桌形珊瑚为幼鱼提供庇护所' },
    { id: 'finger', name: '指状珊瑚', color: '#cd5c5c', shape: 'finger', fact: '指状珊瑚在夜间伸展触手捕食' },
    { id: 'bubble', name: '气泡珊瑚', color: '#ff7f50', shape: 'bubble', fact: '气泡珊瑚在白天膨胀吸收阳光' }
];

const coralSlots = [
    { id: 'staghorn', x: 50, y: 240, w: 80, h: 70 },
    { id: 'brain', x: 260, y: 260, w: 70, h: 55 },
    { id: 'tube', x: 150, y: 220, w: 50, h: 80 },
    { id: 'fan', x: 300, y: 200, w: 75, h: 85 },
    { id: 'mushroom', x: 90, y: 270, w: 60, h: 50 },
    { id: 'table', x: 200, y: 250, w: 85, h: 60 },
    { id: 'finger', x: 30, y: 210, w: 45, h: 75 },
    { id: 'bubble', x: 330, y: 270, w: 55, h: 55 }
];

const coralSVGs = {
    staghorn: '<path d="M10,65 L15,20 L20,10 L25,20 L30,8 L35,18 L40,10 L45,22 L50,12 L55,25 L60,15 L65,28 L70,20 L75,30 L70,65 Z" fill="currentColor" opacity="0.9"/><path d="M15,20 L20,10" stroke="currentColor" stroke-width="2" fill="none" opacity="0.5"/><path d="M35,18 L40,10" stroke="currentColor" stroke-width="2" fill="none" opacity="0.5"/><path d="M55,25 L60,15" stroke="currentColor" stroke-width="2" fill="none" opacity="0.5"/>',
    brain: '<ellipse cx="35" cy="30" rx="30" ry="22" fill="currentColor" opacity="0.85"/><path d="M10,28 Q20,15 35,25 Q50,15 60,28" stroke="currentColor" stroke-width="2.5" fill="none" opacity="0.6"/><path d="M12,33 Q25,20 40,30 Q55,20 58,33" stroke="currentColor" stroke-width="2" fill="none" opacity="0.4"/>',
    tube: '<rect x="15" y="15" width="12" height="55" rx="6" fill="currentColor" opacity="0.8"/><rect x="32" y="8" width="10" height="60" rx="5" fill="currentColor" opacity="0.7"/><rect x="48" y="12" width="11" height="50" rx="5.5" fill="currentColor" opacity="0.75"/><circle cx="21" cy="15" r="8" fill="currentColor" opacity="0.9"/><circle cx="37" cy="8" r="7" fill="currentColor" opacity="0.85"/><circle cx="53.5" cy="12" r="7.5" fill="currentColor" opacity="0.9"/>',
    fan: '<path d="M10,65 Q10,20 40,8 Q70,20 70,65" fill="currentColor" opacity="0.8"/><path d="M18,62 Q18,30 40,18 Q62,30 62,62" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.5"/><path d="M25,58 Q25,38 40,28 Q55,38 55,58" fill="none" stroke="currentColor" stroke-width="1" opacity="0.4"/>',
    mushroom: '<ellipse cx="32" cy="20" rx="28" ry="15" fill="currentColor" opacity="0.9"/><rect x="28" y="22" width="8" height="35" rx="4" fill="currentColor" opacity="0.7"/><ellipse cx="32" cy="18" rx="10" ry="5" fill="#fff" opacity="0.2"/>',
    table: '<rect x="8" y="15" width="65" height="8" rx="4" fill="currentColor" opacity="0.85"/><rect x="28" y="23" width="25" height="40" rx="4" fill="currentColor" opacity="0.7"/><rect x="22" y="20" width="38" height="5" rx="2.5" fill="currentColor" opacity="0.6"/>',
    finger: '<rect x="15" y="10" width="10" height="55" rx="5" fill="currentColor" opacity="0.85"/><rect x="30" y="5" width="9" height="60" rx="4.5" fill="currentColor" opacity="0.75"/><circle cx="20" cy="10" r="7" fill="currentColor" opacity="0.9"/><circle cx="34.5" cy="5" r="6.5" fill="currentColor" opacity="0.88"/>',
    bubble: '<circle cx="28" cy="28" r="22" fill="currentColor" opacity="0.8"/><circle cx="28" cy="28" r="15" fill="#fff" opacity="0.15"/><circle cx="22" cy="22" r="6" fill="#fff" opacity="0.3"/><circle cx="35" cy="18" r="4" fill="#fff" opacity="0.25"/>'
};

class OceanRepairGame {
    constructor() {
        this.placed = {};
        this.totalCorals = 8;
        this.reefArea = null;
        this.trayEl = null;
        this.dragState = null;
        this.tapSelection = null;
        this.level = 1;
        this.maxLevel = 3;
        this.timer = 120;
        this.timerInterval = null;
        this.pollutionEvents = ['塑料瓶', '废弃渔网', '油污', '化学废料', '金属罐', '塑料袋'];
        this.activePollution = [];
        this.combo = 0;
        this.comboTimer = null;
        this.bubbleParticles = [];
        this.bubbleInterval = null;
        this._pollutionInterval = null;
        this.timeUpTimer = null;
        this.factTimer = null;
        this.pollutionMsgTimer = null;
        this.bubbleTimers = [];
        this.particleTimers = [];
        this.pollutionCleanupTimers = [];
        this.active = false;
    }

    init() {
        this._clearTimers();
        this.active = true;
        this.placed = {};
        this.dragState = null;
        this.tapSelection = null;
        this.level = 1;
        this.timer = 120;
        this.combo = 0;
        this.activePollution = [];
        document.getElementById('ocean-progress-fill').style.width = '0%';
        document.getElementById('ocean-progress-label').textContent = '第1关 · 礁盘覆盖率 0%';
        document.getElementById('ocean-corals-placed').textContent = '0';
        document.getElementById('ocean-progress-text').textContent = '0%';
        document.getElementById('ocean-result').classList.add('hidden');
        var timerEl = document.getElementById('ocean-timer');
        if (timerEl) timerEl.textContent = this.timer + 's';
        var levelEl = document.getElementById('ocean-level-indicator');
        if (levelEl) levelEl.textContent = '第 1/' + this.maxLevel + ' 关';
        var comboEl = document.getElementById('ocean-combo');
        if (comboEl) { comboEl.textContent = ''; comboEl.classList.remove('active'); }
        this.reefArea = document.getElementById('ocean-reef-inner');
        this._renderSlots();
        this._renderFragments();
        this._startBubbles();
        this._startTimer();
        this._startPollutionSpawner();
        trackGamePlay('ocean');
    }

    _renderSlots() {
        var slotsLayer = document.getElementById('ocean-slots-layer');
        slotsLayer.innerHTML = '';
        var self = this;
        coralSlots.forEach(function(slot) {
            var g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
            g.setAttribute('class', 'ocean-slot');
            g.setAttribute('id', 'ocean-slot-' + slot.id);
            g.setAttribute('tabindex', '0');
            g.setAttribute('role', 'button');
            g.addEventListener('click', function() { self._placeTapCoral(slot.id); });
            g.addEventListener('keydown', function(e) {
                if (e.key !== 'Enter' && e.key !== ' ') return;
                e.preventDefault();
                self._placeTapCoral(slot.id);
            });
            var rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
            rect.setAttribute('class', 'slot-indicator');
            rect.setAttribute('x', slot.x); rect.setAttribute('y', slot.y);
            rect.setAttribute('width', slot.w); rect.setAttribute('height', slot.h);
            g.appendChild(rect);
            var ghost = document.createElementNS('http://www.w3.org/2000/svg', 'g');
            ghost.setAttribute('transform', 'translate(' + slot.x + ',' + slot.y + ')');
            ghost.innerHTML = '<g opacity="0.15" fill="#00ff88">' + coralSVGs[slot.id] + '</g>';
            ghost.setAttribute('class', 'coral-ghost');
            g.appendChild(ghost);
            slotsLayer.appendChild(g);
        });
    }

    _renderFragments() {
        this.trayEl = document.getElementById('ocean-parts-tray');
        this.trayEl.innerHTML = '';
        var self = this;
        var count = Math.min(4 + this.level * 2, 8);
        var selected = [...coralTypes].slice(0, count);
        var shuffled = [...selected].sort(function() { return Math.random() - 0.5; });
        shuffled.forEach(function(coral, i) {
            var slot = coralSlots.find(function(s) { return s.id === coral.id; });
            var frag = document.createElement('div');
            frag.className = 'coral-fragment';
            frag.id = 'coral-frag-' + coral.id;
            frag.dataset.coral = coral.id;
            frag.style.color = coral.color;
            frag.style.left = (Math.random() * 170 + 15) + 'px';
            frag.style.top = (i * 62 + Math.random() * 15 + 10) + 'px';
            frag.style.width = slot.w + 'px';
            frag.style.height = slot.h + 'px';
            frag.innerHTML = '<svg viewBox="0 0 ' + (slot.w + 20) + ' ' + (slot.h + 20) + '" width="100%" height="100%">' +
                '<g transform="translate(2,2)">' + coralSVGs[coral.id] + '</g></svg>';
            frag.title = coral.name;
            frag.addEventListener('pointerdown', function(e) { self._dragStart(e, frag, coral); }, { passive: false });
            frag.addEventListener('click', function() { self._selectTapCoral(frag, coral); });
            frag.addEventListener('keydown', function(e) {
                if (e.key !== 'Enter' && e.key !== ' ') return;
                e.preventDefault();
                self._selectTapCoral(frag, coral);
            });
            frag.setAttribute('role', 'button');
            frag.tabIndex = 0;
            self.trayEl.appendChild(frag);
        });
        this.totalCorals = count;
        document.getElementById('ocean-corals-placed').textContent = '0';
    }

    _startBubbles() {
        var self = this;
        if (this.bubbleInterval) clearInterval(this.bubbleInterval);
        this.bubbleInterval = setInterval(function() {
            if (!self.active) return;
            var reef = document.getElementById('ocean-reef-area');
            if (!reef) return;
            var rect = reef.getBoundingClientRect();
            var bubble = document.createElement('div');
            bubble.className = 'ocean-bubble-particle';
            bubble.style.left = (Math.random() * rect.width) + 'px';
            bubble.style.bottom = '0px';
            bubble.style.width = bubble.style.height = (Math.random() * 12 + 4) + 'px';
            bubble.style.animationDuration = (Math.random() * 3 + 2) + 's';
            reef.appendChild(bubble);
            self.bubbleParticles.push(bubble);
            var cleanupTimer = setTimeout(function() {
                self.bubbleTimers = self.bubbleTimers.filter(function(id) { return id !== cleanupTimer; });
                if (bubble.parentNode) bubble.remove();
            }, 5000);
            self.bubbleTimers.push(cleanupTimer);
        }, 800);
    }

    _startTimer() {
        var self = this;
        this.timer = 90 + this.level * 15;
        var timerEl = document.getElementById('ocean-timer');
        if (timerEl) timerEl.textContent = this.timer + 's';
        if (this.timerInterval) clearInterval(this.timerInterval);
        this.timerInterval = setInterval(function() {
            if (!self.active) return;
            self.timer--;
            if (timerEl) {
                timerEl.textContent = self.timer + 's';
                timerEl.style.color = self.timer < 20 ? '#ff4444' : '#00ff88';
            }
            if (self.timer <= 0) {
                self._onTimeUp();
            }
        }, 1000);
    }

    _startPollutionSpawner() {
        var self = this;
        if (this._pollutionInterval) clearInterval(this._pollutionInterval);
        this._pollutionInterval = setInterval(function() {
            if (!self.active) return;
            if (Math.random() < 0.35) {
                self._spawnPollution();
            }
        }, 8000 + this.level * 2000);
    }

    _spawnPollution() {
        if (!this.active) return;
        var reef = document.getElementById('ocean-reef-area');
        if (!reef) return;
        var rect = reef.getBoundingClientRect();
        var type = this.pollutionEvents[Math.floor(Math.random() * this.pollutionEvents.length)];
        var trash = document.createElement('div');
        trash.className = 'ocean-pollution';
        trash.textContent = ['🥤','🪢','🛢️','☣️','🥫','🛍️'][this.pollutionEvents.indexOf(type)] || '🪹';
        trash.style.left = (Math.random() * (rect.width - 60) + 30) + 'px';
        trash.style.top = (Math.random() * (rect.height - 60) + 30) + 'px';
        trash.dataset.type = type;
        trash.addEventListener('click', function() {
            self._cleanPollution(trash, type);
        });
        reef.appendChild(trash);
        this.activePollution.push(trash);
        var msg = document.getElementById('ocean-pollution-msg');
        if (msg) {
            msg.textContent = '⚠️ ' + type + '漂入海域！点击清除';
            msg.style.opacity = '1';
            if (this.pollutionMsgTimer) clearTimeout(this.pollutionMsgTimer);
            this.pollutionMsgTimer = setTimeout(function() {
                this.pollutionMsgTimer = null;
                if (!this.active) return;
                msg.style.opacity = '0';
            }.bind(this), 2000);
        }
        if (this.activePollution.length > 3) {
            this.timer = Math.max(this.timer - 10, 5);
        }
    }

    _cleanPollution(el, type) {
        if (!this.active) return;
        el.style.transform = 'scale(1.5)';
        el.style.opacity = '0';
        el.style.transition = 'all 0.3s ease';
        var cleanupTimer = setTimeout(function() {
            this.pollutionCleanupTimers = this.pollutionCleanupTimers.filter(function(id) { return id !== cleanupTimer; });
            if (el.parentNode) el.remove();
        }.bind(this), 300);
        this.pollutionCleanupTimers.push(cleanupTimer);
        var idx = this.activePollution.indexOf(el);
        if (idx >= 0) this.activePollution.splice(idx, 1);
        if (typeof audio !== 'undefined' && audio.playSnap) audio.playSnap();
        var msg = document.getElementById('ocean-pollution-msg');
        if (msg) { msg.textContent = '✅ 清除了' + type + '！+5秒'; msg.style.opacity = '1'; }
        this.timer += 5;
        var timerEl = document.getElementById('ocean-timer');
        if (timerEl) timerEl.textContent = this.timer + 's';
        this._addParticleReward();
    }

    _addParticleReward() {
        if (!this.active) return;
        var reef = document.getElementById('ocean-reef-area');
        if (!reef) return;
        var self = this;
        for (var i = 0; i < 6; i++) {
            var p = document.createElement('div');
            p.className = 'ocean-sparkle';
            p.style.left = (Math.random() * 100) + '%';
            p.style.top = (Math.random() * 100) + '%';
            p.style.width = p.style.height = (Math.random() * 6 + 2) + 'px';
            p.style.animationDuration = (Math.random() * 0.8 + 0.4) + 's';
            reef.appendChild(p);
            (function(node) {
                var cleanupTimer = setTimeout(function() {
                    self.particleTimers = self.particleTimers.filter(function(id) { return id !== cleanupTimer; });
                    if (node.parentNode) node.remove();
                }, 1200);
                self.particleTimers.push(cleanupTimer);
            })(p);
        }
    }

    _onTimeUp() {
        if (!this.active) return;
        if (this.timeUpTimer) clearTimeout(this.timeUpTimer);
        this.timeUpTimer = null;
        if (this.timerInterval) clearInterval(this.timerInterval);
        if (this._pollutionInterval) clearInterval(this._pollutionInterval);
        var placedCount = Object.keys(this.placed).length;
        if (placedCount >= this.totalCorals) {
            if (this.level < this.maxLevel) {
                this._onLevelUp();
            } else {
                this._onWin();
            }
        } else {
            this.active = false;
            this._clearTimers();
            var result = document.getElementById('ocean-result');
            result.classList.remove('hidden');
            document.getElementById('ocean-result-text').textContent =
                '⏰ 时间到！你修复了 ' + placedCount + '/' + this.totalCorals + ' 株珊瑚。每株珊瑚都需要在最佳时机移植，再试一次吧！';
            document.querySelector('#ocean-result h3').textContent = '🌊 时间到，再来一次！';
            document.querySelector('#ocean-result h3').style.color = '#ffaa00';
        }
    }

    _onLevelUp() {
        if (!this.active) return;
        this.level++;
        var levelEl = document.getElementById('ocean-level-indicator');
        if (levelEl) levelEl.textContent = '第 ' + this.level + '/' + this.maxLevel + ' 关';
        var msg = document.getElementById('ocean-pollution-msg');
        if (msg) { msg.textContent = '🎉 第' + (this.level-1) + '关通过！准备第' + this.level + '关...'; msg.style.opacity = '1'; }
        this.placed = {};
        document.querySelectorAll('.coral-fragment').forEach(function(f) { f.classList.remove('placed'); f.style.opacity = ''; });
        document.querySelectorAll('.ocean-slot').forEach(function(s) { s.classList.remove('filled'); });
        document.querySelectorAll('.coral-ghost').forEach(function(g) { g.setAttribute('opacity', '0.15'); });
        document.querySelectorAll('.ocean-pollution').forEach(function(p) { p.remove(); });
        this.activePollution = [];
        document.getElementById('ocean-progress-fill').style.width = '0%';
        document.getElementById('ocean-progress-label').textContent = '第' + this.level + '关 · 礁盘覆盖率 0%';
        document.getElementById('ocean-progress-text').textContent = '0%';
        document.getElementById('ocean-corals-placed').textContent = '0';
        this._renderFragments();
        this._renderSlots();
        this._startTimer();
        this._startPollutionSpawner();
    }

    _selectTapCoral(frag, coral) {
        if (!frag || frag.classList.contains('placed')) return;
        this.tapSelection = { el: frag, coral: coral };
        setTapPlaceSelection(frag, 'ocean');
        showGameplayToast('已选中珊瑚断枝，再点同名礁盘即可移植。', 'hint');
    }

    _placeTapCoral(slotId) {
        if (!this.tapSelection || this.placed[slotId]) return;
        if (this.tapSelection.coral.id !== slotId) {
            shakeElement(this.tapSelection.el);
            showGameplayToast('这个礁盘不匹配，试试同名轮廓。', 'hint');
            return;
        }
        this._snapCoral(slotId, this.tapSelection.el);
        setTapPlaceSelection(null, 'ocean');
        this.tapSelection = null;
    }

    _dragStart(e, frag, coral) {
        if (frag.classList.contains('placed')) return;
        e.preventDefault();
        e.stopPropagation();
        var rect = frag.getBoundingClientRect();
        this.dragState = {
            el: frag, coral: coral,
            offsetX: e.clientX - rect.left, offsetY: e.clientY - rect.top,
            origLeft: frag.style.left, origTop: frag.style.top,
            startX: e.clientX, startY: e.clientY
        };
        var proxy = frag.cloneNode(true);
        proxy.id = 'ocean-proxy';
        proxy.style.position = 'fixed';
        proxy.style.left = rect.left + 'px';
        proxy.style.top = rect.top + 'px';
        proxy.style.width = rect.width + 'px';
        proxy.style.height = rect.height + 'px';
        proxy.style.zIndex = '99999';
        proxy.style.opacity = '0.95';
        proxy.style.transform = 'scale(1.15)';
        proxy.style.boxShadow = '0 8px 25px rgba(0,255,136,0.5)';
        proxy.style.pointerEvents = 'none';
        document.body.appendChild(proxy);
        this.dragState.proxy = proxy;
        frag.style.opacity = '0.3';
        var self = this;
        this._onMove = function(ev) { self._dragMove(ev); };
        this._onUp = function(ev) { self._dragEnd(ev); };
        document.addEventListener('pointermove', this._onMove, { passive: false });
        document.addEventListener('pointerup', this._onUp, { passive: false });
    }

    _dragMove(e) {
        if (!this.dragState) return;
        var p = this.dragState.proxy;
        p.style.left = (e.clientX - this.dragState.offsetX) + 'px';
        p.style.top = (e.clientY - this.dragState.offsetY) + 'px';
    }

    _dragEnd(e) {
        if (!this.dragState) return;
        var frag = this.dragState.el;
        var coral = this.dragState.coral;
        var proxy = this.dragState.proxy;
        var origLeft = this.dragState.origLeft;
        var origTop = this.dragState.origTop;
        document.removeEventListener('pointermove', this._onMove);
        document.removeEventListener('pointerup', this._onUp);
        proxy.remove();
        frag.style.opacity = '';
        var reefRect = this.reefArea.getBoundingClientRect();
        var slot = coralSlots.find(function(s) { return s.id === coral.id; });
        if (!slot) { this.dragState = null; return; }
        if (e.clientX >= reefRect.left && e.clientX <= reefRect.right &&
            e.clientY >= reefRect.top && e.clientY <= reefRect.bottom) {
            var reefScaleX = 400 / reefRect.width;
            var reefScaleY = 350 / reefRect.height;
            var reefX = (e.clientX - reefRect.left) * reefScaleX;
            var reefY = (e.clientY - reefRect.top) * reefScaleY;
            var centerX = slot.x + slot.w / 2;
            var centerY = slot.y + slot.h / 2;
            var dist = Math.sqrt(Math.pow(reefX - centerX, 2) + Math.pow(reefY - centerY, 2));
            if (dist < Math.max(slot.w, slot.h)) {
                this._snapCoral(coral.id, frag);
            }
        }
        if (!this.placed[coral.id]) {
            frag.style.left = origLeft;
            frag.style.top = origTop;
            if (Math.hypot(e.clientX - this.dragState.startX, e.clientY - this.dragState.startY) < 10) {
                this._selectTapCoral(frag, coral);
            }
        }
        this.dragState = null;
    }

    _snapCoral(coralId, frag) {
        if (!this.active) return;
        if (this.placed[coralId]) return;
        this.placed[coralId] = true;
        frag.classList.add('placed');
        var slotEl = document.getElementById('ocean-slot-' + coralId);
        if (slotEl) {
            slotEl.classList.add('filled');
            var ghost = slotEl.querySelector('.coral-ghost');
            if (ghost) { ghost.setAttribute('opacity', '0'); }
        }
        if (typeof audio !== 'undefined' && audio.playSnap) audio.playSnap();
        this.combo++;
        if (this.comboTimer) clearTimeout(this.comboTimer);
        var comboEl = document.getElementById('ocean-combo');
        if (comboEl && this.combo >= 3) {
            comboEl.textContent = '🔥 ' + this.combo + '连击！';
            comboEl.classList.add('active');
        }
        this.comboTimer = setTimeout(function() {
            this.comboTimer = null;
            if (!this.active) return;
            this.combo = 0;
            if (comboEl) { comboEl.textContent = ''; comboEl.classList.remove('active'); }
        }.bind(this), 3000);
        this.timer += 3;
        var timerEl = document.getElementById('ocean-timer');
        if (timerEl) timerEl.textContent = this.timer + 's';
        var coralInfo = coralTypes.find(function(c) { return c.id === coralId; });
        var factEl = document.getElementById('ocean-fact');
        if (factEl && coralInfo) {
            factEl.textContent = '📚 ' + coralInfo.name + '：' + coralInfo.fact;
            factEl.style.opacity = '1';
            if (this.factTimer) clearTimeout(this.factTimer);
            this.factTimer = setTimeout(function() {
                this.factTimer = null;
                if (!this.active) return;
                factEl.style.opacity = '0';
            }.bind(this), 2500);
        }
        this._addParticleReward();
        var placedCount = Object.keys(this.placed).length;
        var pct = Math.round((placedCount / this.totalCorals) * 100);
        document.getElementById('ocean-progress-fill').style.width = pct + '%';
        document.getElementById('ocean-progress-label').textContent = '第' + this.level + '关 · 礁盘覆盖率 ' + pct + '%';
        document.getElementById('ocean-corals-placed').textContent = placedCount;
        document.getElementById('ocean-progress-text').textContent = pct + '%';
        if (placedCount >= this.totalCorals) {
            if (this.timeUpTimer) clearTimeout(this.timeUpTimer);
            this.timeUpTimer = setTimeout(function() {
                this.timeUpTimer = null;
                if (!this.active) return;
                this._onTimeUp();
            }.bind(this), 600);
        }
    }

    _onWin() {
        if (!this.active) return;
        this.active = false;
        this._clearTimers();
        var bonus = 80 + this.maxLevel * 20;
        gameState.memorySilver += bonus;
        document.getElementById('global-silver-balance').textContent = gameState.memorySilver;
        document.getElementById('ocean-result-text').textContent =
            '🏆 你通过了全部 ' + this.maxLevel + ' 关！珊瑚礁生态完全恢复，海洋生物重回家园。每片珊瑚都是地球的蓝色肺叶。获得 +' + bonus + ' 记忆银币';
        document.getElementById('ocean-result').classList.remove('hidden');
        var h3 = document.querySelector('#ocean-result h3');
        if (h3) { h3.textContent = '🌊 深海修复大师！'; h3.style.color = '#00ff88'; }
        trackGameComplete('ocean', bonus);
        if (typeof audio !== 'undefined' && audio.playAwake) audio.playAwake();
    }

    _clearTimers() {
        if (this.timerInterval) clearInterval(this.timerInterval);
        if (this._pollutionInterval) clearInterval(this._pollutionInterval);
        if (this.bubbleInterval) clearInterval(this.bubbleInterval);
        if (this.comboTimer) clearTimeout(this.comboTimer);
        if (this.timeUpTimer) clearTimeout(this.timeUpTimer);
        if (this.factTimer) clearTimeout(this.factTimer);
        if (this.pollutionMsgTimer) clearTimeout(this.pollutionMsgTimer);
        this.bubbleTimers.forEach(function(id) { clearTimeout(id); });
        this.particleTimers.forEach(function(id) { clearTimeout(id); });
        this.pollutionCleanupTimers.forEach(function(id) { clearTimeout(id); });
        this.timerInterval = null;
        this._pollutionInterval = null;
        this.bubbleInterval = null;
        this.comboTimer = null;
        this.timeUpTimer = null;
        this.factTimer = null;
        this.pollutionMsgTimer = null;
        this.bubbleTimers = [];
        this.particleTimers = [];
        this.pollutionCleanupTimers = [];
    }

    destroy() {
        this.active = false;
        this._clearTimers();
        setTapPlaceSelection(null, 'ocean');
        if (this.dragState && this.dragState.proxy) this.dragState.proxy.remove();
        if (this._onMove) document.removeEventListener('pointermove', this._onMove);
        if (this._onUp) document.removeEventListener('pointerup', this._onUp);
        this.dragState = null;
        document.querySelectorAll('.ocean-bubble-particle, .ocean-sparkle, .ocean-pollution').forEach(function(el) { el.remove(); });
        this.bubbleParticles = [];
        this.activePollution = [];
    }
}

// ============================================================================
// 26. 🌊 深蓝修复者导航绑定
// ============================================================================
var _oceanGame = null;
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('btn-open-ocean')?.addEventListener('click', function() {
        transitionToScreen('screen-ocean');
        _oceanGame = new OceanRepairGame();
        _oceanGame.init();
    });
    document.getElementById('btn-ocean-back')?.addEventListener('click', function() {
        if (_oceanGame) _oceanGame.destroy();
        transitionToScreen('screen-hub');
    });
    document.getElementById('btn-ocean-replay')?.addEventListener('click', function() {
        if (_oceanGame) _oceanGame.destroy();
        _oceanGame = new OceanRepairGame();
        _oceanGame.init();
    });
    document.getElementById('btn-ocean-hub')?.addEventListener('click', function() {
        if (_oceanGame) _oceanGame.destroy();
        transitionToScreen('screen-hub');
    });
});

// ============================================================================
// 27. 🀄 甲骨重光 — 甲骨文修复游戏（升级版：多阶段修复 + 拓片描红 + 温度控制）
// ============================================================================

const oracleFragments = [
    { id: 'f1', label: '日字旁-左上', x: 80, y: 100, w: 90, h: 85, order: 1 },
    { id: 'f2', label: '日字旁-右上', x: 170, y: 100, w: 50, h: 85, order: 2 },
    { id: 'f3', label: '日字旁-下部', x: 80, y: 185, w: 140, h: 40, order: 3 },
    { id: 'f4', label: '月字旁-左', x: 80, y: 230, w: 50, h: 120, order: 4 },
    { id: 'f5', label: '月字旁-中', x: 130, y: 230, w: 50, h: 120, order: 5 },
    { id: 'f6', label: '月字旁-右', x: 180, y: 230, w: 50, h: 120, order: 6 }
];

const oracleStrokes = {
    f1: '<path d="M20,10 L20,70" stroke="#8b6914" stroke-width="5" stroke-linecap="round" fill="none"/><path d="M60,10 L60,70" stroke="#8b6914" stroke-width="5" stroke-linecap="round" fill="none"/><path d="M10,10 L70,10" stroke="#8b6914" stroke-width="5" stroke-linecap="round" fill="none"/>',
    f2: '<path d="M5,10 L5,70" stroke="#8b6914" stroke-width="5" stroke-linecap="round" fill="none"/><path d="M35,10 L35,70" stroke="#8b6914" stroke-width="5" stroke-linecap="round" fill="none"/><path d="M5,40 L35,40" stroke="#8b6914" stroke-width="4" stroke-linecap="round" fill="none"/>',
    f3: '<path d="M10,8 L120,8" stroke="#8b6914" stroke-width="5" stroke-linecap="round" fill="none"/>',
    f4: '<path d="M10,10 L10,100" stroke="#8b6914" stroke-width="5" stroke-linecap="round" fill="none"/><path d="M5,50 L15,50" stroke="#8b6914" stroke-width="3" fill="none"/>',
    f5: '<path d="M15,50 L35,50" stroke="#8b6914" stroke-width="5" stroke-linecap="round" fill="none"/><path d="M25,10 L25,100" stroke="#8b6914" stroke-width="5" stroke-linecap="round" fill="none"/>',
    f6: '<path d="M10,10 L10,100" stroke="#8b6914" stroke-width="5" stroke-linecap="round" fill="none"/><path d="M5,10 L40,10" stroke="#8b6914" stroke-width="5" stroke-linecap="round" fill="none"/><path d="M5,100 L40,100" stroke="#8b6914" stroke-width="5" stroke-linecap="round" fill="none"/>'
};

// Oracle bone characters for "tracing" phase
const oracleCharacters = [
    { id: 'ri', name: '日（太阳）', meaning: '太阳，代表光明与白昼', strokes: [
        { x1:30,y1:15,x2:30,y2:85 }, { x1:70,y1:15,x2:70,y2:85 }, { x1:15,y1:15,x2:85,y2:15 }, { x1:15,y1:50,x2:85,y2:50 }
    ]},
    { id: 'yue', name: '月（月亮）', meaning: '月亮，代表夜晚与思念', strokes: [
        { x1:30,y1:15,x2:30,y2:85 }, { x1:30,y1:50,x2:70,y2:50 }, { x1:15,y1:15,x2:85,y2:15 }, { x1:15,y1:85,x2:85,y2:85 }
    ]}
];

class OracleRepairGame {
    constructor() {
        this.placed = {};
        this.totalFrags = 6;
        this.trayEl = null;
        this.dragState = null;
        this.tapSelection = null;
        this.phase = 'assemble'; // 'assemble' -> 'trace' -> 'bake' -> 'done'
        this.currentChar = 0;
        this.tracedStrokes = [];
        this.tracingStroke = null;
        this.tracingActive = false;
        this.ovenTemp = 300;
        this.targetTemp = 320;
        this.tempStable = false;
        this.tempInterval = null;
        this.assembleTimer = null;
        this.traceTimer = null;
        this.bakeTimer = null;
        this.score = 0;
        this.active = false;
    }

    init() {
        this._clearTimers();
        this.active = true;
        this.placed = {};
        this.dragState = null;
        this.tapSelection = null;
        this.phase = 'assemble';
        this.currentChar = 0;
        this.tracedStrokes = [];
        this.tracingActive = false;
        this.ovenTemp = 300;
        this.targetTemp = 320;
        this.tempStable = false;
        this.score = 0;
        document.getElementById('oracle-progress-fill').style.width = '0%';
        document.getElementById('oracle-progress').textContent = '0%';
        document.getElementById('oracle-placed').textContent = '0';
        document.getElementById('oracle-result').classList.add('hidden');
        document.getElementById('oracle-phase-indicator').textContent = '阶段 1/3：拼合碎片';
        document.getElementById('oracle-trace-area').classList.add('hidden');
        document.getElementById('oracle-bake-area').classList.add('hidden');
        document.getElementById('oracle-assemble-area').classList.remove('hidden');
        this.trayEl = document.getElementById('oracle-parts-tray');
        this._renderSlots();
        this._renderFragments();
        trackGamePlay('oracle');
    }

    _renderSlots() {
        var slotsLayer = document.getElementById('oracle-slots-layer');
        slotsLayer.innerHTML = '';
        var self = this;
        oracleFragments.forEach(function(slot) {
            var g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
            g.setAttribute('class', 'oracle-slot');
            g.setAttribute('id', 'oracle-slot-' + slot.id);
            g.setAttribute('tabindex', '0');
            g.setAttribute('role', 'button');
            g.addEventListener('click', function() { self._placeTapFrag(slot.id); });
            g.addEventListener('keydown', function(e) {
                if (e.key !== 'Enter' && e.key !== ' ') return;
                e.preventDefault();
                self._placeTapFrag(slot.id);
            });
            var rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
            rect.setAttribute('class', 'slot-indicator');
            rect.setAttribute('x', slot.x); rect.setAttribute('y', slot.y);
            rect.setAttribute('width', slot.w); rect.setAttribute('height', slot.h);
            g.appendChild(rect);
            var ghost = document.createElementNS('http://www.w3.org/2000/svg', 'g');
            ghost.setAttribute('transform', 'translate(' + slot.x + ',' + slot.y + ')');
            ghost.innerHTML = '<g opacity="0.12" stroke="#8b6914" fill="none">' + oracleStrokes[slot.id] + '</g>';
            ghost.setAttribute('class', 'oracle-ghost');
            g.appendChild(ghost);
            var reveal = document.createElementNS('http://www.w3.org/2000/svg', 'g');
            reveal.setAttribute('transform', 'translate(' + slot.x + ',' + slot.y + ')');
            reveal.innerHTML = '<g stroke="#c43a31" fill="none">' + oracleStrokes[slot.id] + '</g>';
            reveal.setAttribute('class', 'oracle-char-reveal');
            g.appendChild(reveal);
            slotsLayer.appendChild(g);
        });
    }

    _renderFragments() {
        this.trayEl.innerHTML = '';
        var self = this;
        var shuffled = [...oracleFragments].sort(function() { return Math.random() - 0.5; });
        shuffled.forEach(function(frag, i) {
            var el = document.createElement('div');
            el.className = 'oracle-fragment';
            el.id = 'oracle-frag-' + frag.id;
            el.dataset.fragId = frag.id;
            el.style.left = (Math.random() * 150 + 15) + 'px';
            el.style.top = (i * 65 + Math.random() * 12 + 8) + 'px';
            el.style.width = (frag.w - 4) + 'px';
            el.style.height = (frag.h - 4) + 'px';
            el.innerHTML = '<svg viewBox="0 0 ' + frag.w + ' ' + frag.h + '" width="100%" height="100%">' +
                oracleStrokes[frag.id] + '</svg>';
            el.title = frag.label;
            el.addEventListener('pointerdown', function(e) { self._dragStart(e, el, frag); }, { passive: false });
            el.addEventListener('click', function() { self._selectTapFrag(el, frag); });
            el.addEventListener('keydown', function(e) {
                if (e.key !== 'Enter' && e.key !== ' ') return;
                e.preventDefault();
                self._selectTapFrag(el, frag);
            });
            el.setAttribute('role', 'button');
            el.tabIndex = 0;
            self.trayEl.appendChild(el);
        });
    }

    _selectTapFrag(el, frag) {
        if (!el || el.classList.contains('placed')) return;
        this.tapSelection = { el: el, frag: frag };
        setTapPlaceSelection(el, 'oracle');
        showGameplayToast('已选中甲骨碎片，再点对应轮廓即可归位。', 'hint');
    }

    _placeTapFrag(slotId) {
        if (!this.tapSelection || this.placed[slotId]) return;
        if (this.tapSelection.frag.id !== slotId) {
            shakeElement(this.tapSelection.el);
            showGameplayToast('这块碎片和轮廓不一致，试试相同形状。', 'hint');
            return;
        }
        this._snapFrag(slotId, this.tapSelection.el);
        setTapPlaceSelection(null, 'oracle');
        this.tapSelection = null;
    }

    _dragStart(e, el, frag) {
        if (el.classList.contains('placed')) return;
        e.preventDefault();
        e.stopPropagation();
        var rect = el.getBoundingClientRect();
        this.dragState = {
            el: el, frag: frag,
            offsetX: e.clientX - rect.left, offsetY: e.clientY - rect.top,
            origLeft: el.style.left, origTop: el.style.top,
            startX: e.clientX, startY: e.clientY
        };
        var proxy = el.cloneNode(true);
        proxy.id = 'oracle-proxy';
        proxy.style.position = 'fixed';
        proxy.style.left = rect.left + 'px';
        proxy.style.top = rect.top + 'px';
        proxy.style.width = rect.width + 'px';
        proxy.style.height = rect.height + 'px';
        proxy.style.zIndex = '99999';
        proxy.style.opacity = '0.95';
        proxy.style.transform = 'scale(1.1)';
        proxy.style.boxShadow = '0 8px 25px rgba(196,58,49,0.5)';
        proxy.style.pointerEvents = 'none';
        document.body.appendChild(proxy);
        this.dragState.proxy = proxy;
        el.style.opacity = '0.3';
        var self = this;
        this._onMove = function(ev) { self._dragMove(ev); };
        this._onUp = function(ev) { self._dragEnd(ev); };
        document.addEventListener('pointermove', this._onMove, { passive: false });
        document.addEventListener('pointerup', this._onUp, { passive: false });
    }

    _dragMove(e) {
        if (!this.dragState) return;
        var p = this.dragState.proxy;
        p.style.left = (e.clientX - this.dragState.offsetX) + 'px';
        p.style.top = (e.clientY - this.dragState.offsetY) + 'px';
    }

    _dragEnd(e) {
        if (!this.dragState) return;
        var el = this.dragState.el;
        var frag = this.dragState.frag;
        var proxy = this.dragState.proxy;
        var origLeft = this.dragState.origLeft;
        var origTop = this.dragState.origTop;
        document.removeEventListener('pointermove', this._onMove);
        document.removeEventListener('pointerup', this._onUp);
        proxy.remove();
        el.style.opacity = '';
        var shellArea = document.getElementById('oracle-shell-area');
        var shellRect = shellArea.getBoundingClientRect();
        if (e.clientX >= shellRect.left && e.clientX <= shellRect.right &&
            e.clientY >= shellRect.top && e.clientY <= shellRect.bottom) {
            var scaleX = 360 / shellRect.width;
            var scaleY = 400 / shellRect.height;
            var sx = (e.clientX - shellRect.left) * scaleX;
            var sy = (e.clientY - shellRect.top) * scaleY;
            var cx = frag.x + frag.w / 2;
            var cy = frag.y + frag.h / 2;
            if (Math.sqrt(Math.pow(sx - cx, 2) + Math.pow(sy - cy, 2)) < Math.max(frag.w, frag.h) * 1.2) {
                this._snapFrag(frag.id, el);
            }
        }
        if (!this.placed[frag.id]) {
            el.style.left = origLeft;
            el.style.top = origTop;
            if (Math.hypot(e.clientX - this.dragState.startX, e.clientY - this.dragState.startY) < 10) {
                this._selectTapFrag(el, frag);
            }
        }
        this.dragState = null;
    }

    _snapFrag(fragId, el) {
        if (!this.active) return;
        if (this.placed[fragId]) return;
        this.placed[fragId] = true;
        el.classList.add('placed');
        var slotEl = document.getElementById('oracle-slot-' + fragId);
        if (slotEl) slotEl.classList.add('filled');
        if (typeof audio !== 'undefined' && audio.playSnap) audio.playSnap();
        var count = Object.keys(this.placed).length;
        var pct = Math.round((count / this.totalFrags) * 100);
        document.getElementById('oracle-progress-fill').style.width = pct + '%';
        document.getElementById('oracle-progress').textContent = pct + '%';
        document.getElementById('oracle-placed').textContent = count;
        if (count >= this.totalFrags) {
            if (this.assembleTimer) clearTimeout(this.assembleTimer);
            this.assembleTimer = setTimeout(function() {
                this.assembleTimer = null;
                if (!this.active) return;
                this._onAssembleComplete();
            }.bind(this), 800);
        }
    }

    _onAssembleComplete() {
        if (!this.active) return;
        this.phase = 'trace';
        document.getElementById('oracle-phase-indicator').textContent = '阶段 2/3：描红拓片';
        document.getElementById('oracle-assemble-area').classList.add('hidden');
        document.getElementById('oracle-trace-area').classList.remove('hidden');
        this._initTracePhase();
    }

    _initTracePhase() {
        if (!this.active) return;
        var canvas = document.getElementById('oracle-trace-canvas');
        var ctx = canvas.getContext('2d');
        var w = canvas.width = canvas.offsetWidth;
        var h = canvas.height = canvas.offsetHeight;
        ctx.clearRect(0, 0, w, h);
        ctx.fillStyle = '#f5e6c8';
        ctx.fillRect(0, 0, w, h);
        ctx.strokeStyle = '#8b6914';
        ctx.lineWidth = 3;
        ctx.setLineDash([5, 3]);
        var char = oracleCharacters[this.currentChar];
        char.strokes.forEach(function(s) {
            ctx.beginPath();
            var sx = s.x1 * w / 100, sy = s.y1 * h / 100;
            var ex = s.x2 * w / 100, ey = s.y2 * h / 100;
            ctx.moveTo(sx, sy);
            ctx.lineTo(ex, ey);
            ctx.stroke();
        });
        ctx.setLineDash([]);
        document.getElementById('oracle-trace-char-name').textContent = char.name;
        document.getElementById('oracle-trace-char-meaning').textContent = char.meaning;
        document.getElementById('oracle-trace-progress').textContent = '0/' + char.strokes.length;
        this.tracedStrokes = [];
        this._setupTraceCanvas(canvas, ctx, char);
    }

    _setupTraceCanvas(canvas, ctx, char) {
        var self = this;
        canvas.onpointerdown = function(e) {
            self.tracingActive = true;
            self.tracingStroke = [];
            var rect = canvas.getBoundingClientRect();
            var x = (e.clientX - rect.left) / rect.width * 100;
            var y = (e.clientY - rect.top) / rect.height * 100;
            self.tracingStroke.push({ x: x, y: y });
        };
        canvas.onpointermove = function(e) {
            if (!self.tracingActive) return;
            var rect = canvas.getBoundingClientRect();
            var x = (e.clientX - rect.left) / rect.width * 100;
            var y = (e.clientY - rect.top) / rect.height * 100;
            self.tracingStroke.push({ x: x, y: y });
            ctx.strokeStyle = '#c43a31';
            ctx.lineWidth = 4;
            ctx.lineCap = 'round';
            ctx.beginPath();
            ctx.moveTo(self.tracingStroke[self.tracingStroke.length - 2].x * canvas.width / 100,
                self.tracingStroke[self.tracingStroke.length - 2].y * canvas.height / 100);
            ctx.lineTo(x * canvas.width / 100, y * canvas.height / 100);
            ctx.stroke();
        };
        canvas.onpointerup = function() {
            if (!self.tracingActive) return;
            self.tracingActive = false;
            self._checkTraceMatch(char);
        };
    }

    _checkTraceMatch(char) {
        if (!this.active) return;
        var matched = false;
        var path = this.tracingStroke;
        if (path.length < 5) return;
        var self = this;
        char.strokes.forEach(function(stroke, idx) {
            if (self.tracedStrokes.indexOf(idx) >= 0) return;
            var sx = stroke.x1, sy = stroke.y1, ex = stroke.x2, ey = stroke.y2;
            var nearStart = false, nearEnd = false;
            path.forEach(function(p) {
                if (Math.abs(p.x - sx) < 15 && Math.abs(p.y - sy) < 15) nearStart = true;
                if (Math.abs(p.x - ex) < 15 && Math.abs(p.y - ey) < 15) nearEnd = true;
            });
            if (nearStart && nearEnd) {
                self.tracedStrokes.push(idx);
                if (typeof audio !== 'undefined' && audio.playSnap) audio.playSnap();
                matched = true;
            }
        });
        document.getElementById('oracle-trace-progress').textContent = self.tracedStrokes.length + '/' + char.strokes.length;
        if (self.tracedStrokes.length >= char.strokes.length) {
            if (self.currentChar < oracleCharacters.length - 1) {
                self.currentChar++;
                self.tracedStrokes = [];
                if (self.traceTimer) clearTimeout(self.traceTimer);
                self.traceTimer = setTimeout(function() {
                    self.traceTimer = null;
                    if (!self.active) return;
                    self._initTracePhase();
                }, 800);
            } else {
                self._onTraceComplete();
            }
        }
    }

    _onTraceComplete() {
        if (!this.active) return;
        this.phase = 'bake';
        document.getElementById('oracle-phase-indicator').textContent = '阶段 3/3：龟甲烘烤';
        document.getElementById('oracle-trace-area').classList.add('hidden');
        document.getElementById('oracle-bake-area').classList.remove('hidden');
        this._initBakePhase();
    }

    _initBakePhase() {
        if (!this.active) return;
        this.ovenTemp = 300;
        this.targetTemp = 310 + Math.floor(Math.random() * 40);
        this.tempStable = false;
        document.getElementById('oracle-target-temp').textContent = this.targetTemp;
        document.getElementById('oracle-oven-temp').textContent = this.ovenTemp;
        document.getElementById('oracle-oven-fill').style.height = '0%';
        var self = this;
        if (this.tempInterval) clearInterval(this.tempInterval);
        this.tempInterval = setInterval(function() {
            if (!self.active) return;
            self.ovenTemp += (Math.random() - 0.5) * 8;
            self.ovenTemp = Math.max(200, Math.min(500, self.ovenTemp));
            var diff = Math.abs(self.ovenTemp - self.targetTemp);
            var pct = Math.max(0, Math.min(100, 100 - diff / 2));
            document.getElementById('oracle-oven-temp').textContent = Math.round(self.ovenTemp);
            document.getElementById('oracle-oven-fill').style.height = pct + '%';
            if (diff < 5) {
                self.tempStable = true;
                if (self.tempInterval) clearInterval(self.tempInterval);
                self._onBakeComplete();
            }
        }, 300);

        var fireBtn = document.getElementById('oracle-fire-btn');
        var coolBtn = document.getElementById('oracle-cool-btn');
        fireBtn.onclick = function() { self.ovenTemp += 15; };
        coolBtn.onclick = function() { self.ovenTemp -= 15; };
    }

    _onBakeComplete() {
        if (!this.active) return;
        if (this.bakeTimer) clearTimeout(this.bakeTimer);
        this.bakeTimer = setTimeout(function() {
            this.bakeTimer = null;
            if (!this.active) return;
            this._onWin();
        }.bind(this), 600);
    }

    _onWin() {
        if (!this.active) return;
        this.active = false;
        this._clearTimers();
        var bonus = 120;
        gameState.memorySilver += bonus;
        document.getElementById('global-silver-balance').textContent = gameState.memorySilver;
        document.getElementById('oracle-result-text').textContent =
            '你完成了完整的甲骨修复流程：拼合碎片→描红拓片→龟甲烘烤！"明"字重现——日月同辉，文明之光穿越三千年。获得 +' + bonus + ' 记忆银币';
        document.getElementById('oracle-result').classList.remove('hidden');
        trackGameComplete('oracle', bonus);
        if (typeof audio !== 'undefined' && audio.playAwake) audio.playAwake();
    }

    _clearTimers() {
        if (this.tempInterval) clearInterval(this.tempInterval);
        if (this.assembleTimer) clearTimeout(this.assembleTimer);
        if (this.traceTimer) clearTimeout(this.traceTimer);
        if (this.bakeTimer) clearTimeout(this.bakeTimer);
        this.tempInterval = null;
        this.assembleTimer = null;
        this.traceTimer = null;
        this.bakeTimer = null;
    }

    destroy() {
        this.active = false;
        this._clearTimers();
        setTapPlaceSelection(null, 'oracle');
        var canvas = document.getElementById('oracle-trace-canvas');
        if (canvas) {
            canvas.onpointerdown = null;
            canvas.onpointermove = null;
            canvas.onpointerup = null;
        }
        var fireBtn = document.getElementById('oracle-fire-btn');
        var coolBtn = document.getElementById('oracle-cool-btn');
        if (fireBtn) fireBtn.onclick = null;
        if (coolBtn) coolBtn.onclick = null;
        if (this.dragState && this.dragState.proxy) this.dragState.proxy.remove();
        if (this._onMove) document.removeEventListener('pointermove', this._onMove);
        if (this._onUp) document.removeEventListener('pointerup', this._onUp);
    }
}

// Navigation bindings for Oracle mode
var _oracleGame = null;
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('btn-open-oracle')?.addEventListener('click', function() {
        transitionToScreen('screen-oracle');
        _oracleGame = new OracleRepairGame();
        _oracleGame.init();
    });
    document.getElementById('btn-oracle-back')?.addEventListener('click', function() {
        if (_oracleGame) _oracleGame.destroy();
        transitionToScreen('screen-hub');
    });
    document.getElementById('btn-oracle-replay')?.addEventListener('click', function() {
        if (_oracleGame) _oracleGame.destroy();
        _oracleGame = new OracleRepairGame();
        _oracleGame.init();
    });
    document.getElementById('btn-oracle-hub')?.addEventListener('click', function() {
        if (_oracleGame) _oracleGame.destroy();
        transitionToScreen('screen-hub');
    });
});

// ============================================================================
// 28. 🕸️ 真相拼图 — 反诈证据链拼图（升级版：真假证据判断 + 案件等级 + 连击积分）
// ============================================================================

const truthEvidence = [
    { id: 'e1', label: '陌生来电', detail: '自称公安', x: 10, y: 30, w: 90, h: 55, order: 1 },
    { id: 'e2', label: '通缉令', detail: '伪造文书', x: 155, y: 30, w: 90, h: 55, order: 2 },
    { id: 'e3', label: '安全账户', detail: '要求转账', x: 300, y: 30, w: 90, h: 55, order: 3 },
    { id: 'e4', label: '验证码', detail: '索要密码', x: 445, y: 30, w: 90, h: 55, order: 4 },
    { id: 'e5', label: '失联', detail: '无法联系', x: 585, y: 30, w: 90, h: 55, order: 5 },
    { id: 'e6', label: '异常转账', detail: '银行扣款', x: 110, y: 30, w: 90, h: 55, order: 2.5 },
    { id: 'e7', label: '拨打110报警', detail: '正确做法', x: 540, y: 30, w: 90, h: 55, order: 6 }
];

const truthFakeEvidence = [
    { id: 'fake1', label: '恭喜中奖', detail: '彩票诈骗', tip: '骗子常用话术' },
    { id: 'fake2', label: '亲友借款', detail: '冒充熟人', tip: '未核实身份' },
    { id: 'fake3', label: '退款链接', detail: '钓鱼网站', tip: '含恶意链接' },
    { id: 'fake4', label: '刷单返利', detail: '兼职诈骗', tip: '先给甜头后套牢' }
];

class TruthPuzzleGame {
    constructor() {
        this.placed = {};
        this.total = 7;
        this.dragState = null;
        this.tapSelection = null;
        this.score = 0;
        this.streak = 0;
        this.judgeTimer = 20;
        this.judgeInterval = null;
        this.evidenceTimer = null;
        this.fakesIdentified = 0;
        this.totalFakes = 0;
        this.round = 1;
        this.maxRounds = 3;
        this.active = false;
    }

    init() {
        this._clearTimers();
        this.active = true;
        this.placed = {};
        this.dragState = null;
        this.tapSelection = null;
        this.score = 0;
        this.streak = 0;
        this.fakesIdentified = 0;
        this.totalFakes = 0;
        this.round = 1;
        this.judgeTimer = 20;
        document.getElementById('truth-placed').textContent = '0';
        document.getElementById('truth-result').classList.add('hidden');
        document.getElementById('truth-score').textContent = '0分';
        document.getElementById('truth-round').textContent = '第1/' + this.maxRounds + '案';
        document.getElementById('truth-judge-timer').textContent = this.judgeTimer + 's';
        document.getElementById('truth-judge-area').classList.add('hidden');
        for (var i = 0; i < 6; i++) {
            var line = document.getElementById('truth-line-' + i);
            if (line) line.setAttribute('opacity', '0');
        }
        this._renderSlots();
        this._renderCards();
        trackGamePlay('truth');
    }

    _renderSlots() {
        var slotsLayer = document.getElementById('truth-slots-layer');
        slotsLayer.innerHTML = '';
        var self = this;
        truthEvidence.forEach(function(ev) {
            var g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
            g.setAttribute('class', 'truth-slot');
            g.setAttribute('id', 'truth-slot-' + ev.id);
            g.setAttribute('tabindex', '0');
            g.setAttribute('role', 'button');
            g.addEventListener('click', function() { self._placeTapEvidence(ev.id); });
            g.addEventListener('keydown', function(e) {
                if (e.key !== 'Enter' && e.key !== ' ') return;
                e.preventDefault();
                self._placeTapEvidence(ev.id);
            });
            var rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
            rect.setAttribute('x', ev.x); rect.setAttribute('y', ev.y);
            rect.setAttribute('width', ev.w); rect.setAttribute('height', ev.h);
            g.appendChild(rect);
            var label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            label.setAttribute('x', ev.x + ev.w / 2); label.setAttribute('y', ev.y + ev.h / 2 + 3);
            label.setAttribute('class', 'truth-label');
            label.textContent = '?';
            g.appendChild(label);
            slotsLayer.appendChild(g);
        });
    }

    _renderCards() {
        var area = document.getElementById('truth-cards-area');
        area.innerHTML = '';
        var self = this;
        var shuffled = [...truthEvidence].sort(function() { return Math.random() - 0.5; });
        shuffled.forEach(function(ev) {
            var card = document.createElement('div');
            card.className = 'truth-card';
            card.id = 'truth-card-' + ev.id;
            card.dataset.evidence = ev.id;
            card.innerHTML = safeHTML('<strong>' + escapeTextForHTML(ev.label) + '</strong><br><small>' + escapeTextForHTML(ev.detail) + '</small>');
            card.addEventListener('pointerdown', function(e) { self._dragStart(e, card, ev); }, { passive: false });
            card.addEventListener('click', function() { self._selectTapEvidence(card, ev); });
            card.addEventListener('keydown', function(e) {
                if (e.key !== 'Enter' && e.key !== ' ') return;
                e.preventDefault();
                self._selectTapEvidence(card, ev);
            });
            card.setAttribute('role', 'button');
            card.tabIndex = 0;
            area.appendChild(card);
        });
    }

    _selectTapEvidence(card, ev) {
        if (!card || card.classList.contains('placed')) return;
        this.tapSelection = { card: card, ev: ev };
        setTapPlaceSelection(card, 'truth');
        showGameplayToast('已选中证据，再点问号位置完成拼图。', 'hint');
    }

    _placeTapEvidence(slotId) {
        if (!this.tapSelection || this.placed[slotId]) return;
        if (this.tapSelection.ev.id !== slotId) {
            shakeElement(this.tapSelection.card);
            showGameplayToast('证据和位置还没有对上，试试对应的问号。', 'hint');
            return;
        }
        this._snapEvidence(slotId, this.tapSelection.card);
        setTapPlaceSelection(null, 'truth');
        this.tapSelection = null;
    }

    _dragStart(e, card, ev) {
        if (card.classList.contains('placed')) return;
        e.preventDefault(); e.stopPropagation();
        var rect = card.getBoundingClientRect();
        this.dragState = { card: card, ev: ev, offsetX: e.clientX - rect.left, offsetY: e.clientY - rect.top, startX: e.clientX, startY: e.clientY };
        var proxy = card.cloneNode(true);
        proxy.id = 'truth-proxy';
        proxy.style.position = 'fixed';
        proxy.style.left = rect.left + 'px'; proxy.style.top = rect.top + 'px';
        proxy.style.width = rect.width + 'px'; proxy.style.height = rect.height + 'px';
        proxy.style.zIndex = '99999'; proxy.style.opacity = '0.95';
        proxy.style.transform = 'scale(1.1)';
        proxy.style.boxShadow = '0 8px 25px rgba(255,107,53,0.5)';
        proxy.style.pointerEvents = 'none';
        document.body.appendChild(proxy);
        this.dragState.proxy = proxy;
        card.style.opacity = '0.3';
        var self = this;
        this._onMove = function(ev) { self._dragMove(ev); };
        this._onUp = function(ev) { self._dragEnd(ev); };
        document.addEventListener('pointermove', this._onMove, { passive: false });
        document.addEventListener('pointerup', this._onUp, { passive: false });
    }

    _dragMove(e) {
        if (!this.dragState) return;
        var p = this.dragState.proxy;
        p.style.left = (e.clientX - this.dragState.offsetX) + 'px';
        p.style.top = (e.clientY - this.dragState.offsetY) + 'px';
    }

    _dragEnd(e) {
        if (!this.dragState) return;
        var card = this.dragState.card;
        var ev = this.dragState.ev;
        var proxy = this.dragState.proxy;
        document.removeEventListener('pointermove', this._onMove);
        document.removeEventListener('pointerup', this._onUp);
        proxy.remove();
        card.style.opacity = '';
        var svg = document.getElementById('truth-svg');
        var svgRect = svg.getBoundingClientRect();
        var bx = (e.clientX - svgRect.left) / svgRect.width * 700;
        var by = (e.clientY - svgRect.top) / svgRect.height * 120;
        var cx = ev.x + ev.w / 2;
        var cy = ev.y + ev.h / 2;
        if (Math.sqrt(Math.pow(bx - cx, 2) + Math.pow(by - cy, 2)) < ev.w * 2) {
            this._snapEvidence(ev.id, card);
        }
        if (!this.placed[ev.id] && Math.hypot(e.clientX - this.dragState.startX, e.clientY - this.dragState.startY) < 10) {
            this._selectTapEvidence(card, ev);
        }
        this.dragState = null;
    }

    _snapEvidence(evId, el) {
        if (!this.active) return;
        if (this.placed[evId]) return;
        this.placed[evId] = true;
        el.classList.add('placed');
        var slot = document.getElementById('truth-slot-' + evId);
        if (slot) {
            slot.classList.add('filled');
            var label = slot.querySelector('.truth-label');
            if (label) label.textContent = truthEvidence.find(function(e) { return e.id === evId; }).label;
        }
        if (typeof audio !== 'undefined' && audio.playSnap) audio.playSnap();
        this.streak++;
        this.score += this.streak * 5;
        document.getElementById('truth-score').textContent = this.score + '分';
        var placedCount = Object.keys(this.placed).length;
        document.getElementById('truth-placed').textContent = placedCount;
        var linesToShow = Math.min(placedCount - 1, 6);
        for (var i = 0; i < linesToShow; i++) {
            var line = document.getElementById('truth-line-' + i);
            if (line) line.setAttribute('opacity', '1');
        }
        if (placedCount >= this.total) {
            if (this.evidenceTimer) clearTimeout(this.evidenceTimer);
            this.evidenceTimer = setTimeout(function() {
                this.evidenceTimer = null;
                if (!this.active) return;
                this._onEvidenceComplete();
            }.bind(this), 800);
        }
    }

    _onEvidenceComplete() {
        if (!this.active) return;
        document.getElementById('truth-judge-area').classList.remove('hidden');
        this._startJudgeRound();
    }

    _startJudgeRound() {
        if (!this.active) return;
        var self = this;
        this.judgeTimer = 15 + this.round * 5;
        document.getElementById('truth-judge-timer').textContent = this.judgeTimer + 's';
        document.getElementById('truth-judge-title').textContent = '真假判断 · 第' + this.round + '轮';
        document.getElementById('truth-judge-count').textContent = '已识别: ' + this.fakesIdentified;

        var allCards = [...truthFakeEvidence, ...truthEvidence.slice(0, 2)].sort(function() { return Math.random() - 0.5; });
        var judgeArea = document.getElementById('truth-judge-cards');
        judgeArea.innerHTML = '';
        this.totalFakes = truthFakeEvidence.length;
        allCards.forEach(function(ev) {
            var card = document.createElement('div');
            card.className = 'truth-judge-card';
            card.innerHTML = safeHTML('<strong>' + escapeTextForHTML(ev.label) + '</strong><br><small>' + escapeTextForHTML(ev.detail || ev.tip || '') + '</small>');
            card.dataset.isFake = (truthFakeEvidence.indexOf(ev) >= 0) ? 'true' : 'false';
            card.setAttribute('role', 'button');
            card.setAttribute('tabindex', '0');
            card.setAttribute('aria-label', '判断证据：' + ev.label + '，' + (ev.detail || ev.tip || ''));
            card.addEventListener('click', function() {
                self._judgeCard(card, ev);
            });
            card.addEventListener('keydown', function(e) {
                if (e.key !== 'Enter' && e.key !== ' ') return;
                e.preventDefault();
                self._judgeCard(card, ev);
            });
            judgeArea.appendChild(card);
        });

        if (this.judgeInterval) clearInterval(this.judgeInterval);
        this.judgeInterval = setInterval(function() {
            if (!self.active) return;
            self.judgeTimer--;
            document.getElementById('truth-judge-timer').textContent = self.judgeTimer + 's';
            if (self.judgeTimer <= 0) {
                clearInterval(self.judgeInterval);
                self.judgeInterval = null;
                if (self.round < self.maxRounds) {
                    self.round++;
                    self._startJudgeRound();
                } else {
                    self._onWin();
                }
            }
        }, 1000);
    }

    _judgeCard(card, ev) {
        if (!this.active || card.classList.contains('judged')) return;
        var isFake = card.dataset.isFake === 'true';
        if (isFake) {
            card.style.background = '#22c55e33';
            card.style.borderColor = '#22c55e';
            card.textContent = '✅ ' + ev.label + ' — 假证据！';
            this.fakesIdentified++;
            this.score += 15;
            if (typeof audio !== 'undefined' && audio.playSnap) audio.playSnap();
        } else {
            card.style.background = '#ef444433';
            card.style.borderColor = '#ef4444';
            card.textContent = '⚠️ ' + ev.label + ' — 这是真实证据';
            this.score = Math.max(0, this.score - 5);
        }
        card.classList.add('judged');
        card.style.pointerEvents = 'none';
        card.setAttribute('aria-disabled', 'true');
        card.tabIndex = -1;
        document.getElementById('truth-score').textContent = this.score + '分';
        document.getElementById('truth-judge-count').textContent = '已识别: ' + this.fakesIdentified;
    }

    _onWin() {
        if (!this.active) return;
        this.active = false;
        this._clearTimers();
        var bonus = 100 + this.score;
        gameState.memorySilver += bonus;
        document.getElementById('global-silver-balance').textContent = gameState.memorySilver;
        document.getElementById('truth-result-text').textContent =
            '证据链完整！你识破了 ' + this.fakesIdentified + '/' + this.totalFakes + ' 个虚假证据，得分 ' + this.score + '。' +
            '记住：公安机关不会电话办案、不会要求转账、不会索要验证码！获得 +' + bonus + ' 记忆银币';
        document.getElementById('truth-result').classList.remove('hidden');
        trackGameComplete('truth', this.score);
        if (typeof audio !== 'undefined' && audio.playAwake) audio.playAwake();
    }

    _clearTimers() {
        if (this.judgeInterval) clearInterval(this.judgeInterval);
        if (this.evidenceTimer) clearTimeout(this.evidenceTimer);
        this.judgeInterval = null;
        this.evidenceTimer = null;
    }

    destroy() {
        this.active = false;
        this._clearTimers();
        setTapPlaceSelection(null, 'truth');
        if (this.dragState && this.dragState.proxy) this.dragState.proxy.remove();
        if (this._onMove) document.removeEventListener('pointermove', this._onMove);
        if (this._onUp) document.removeEventListener('pointerup', this._onUp);
        this.dragState = null;
    }
}

var _truthGame = null;
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('btn-open-truth')?.addEventListener('click', function() {
        transitionToScreen('screen-truth'); _truthGame = new TruthPuzzleGame(); _truthGame.init();
    });
    document.getElementById('btn-truth-back')?.addEventListener('click', function() {
        if (_truthGame) _truthGame.destroy(); transitionToScreen('screen-hub');
    });
    document.getElementById('btn-truth-replay')?.addEventListener('click', function() {
        if (_truthGame) _truthGame.destroy(); _truthGame = new TruthPuzzleGame(); _truthGame.init();
    });
    document.getElementById('btn-truth-hub')?.addEventListener('click', function() {
        if (_truthGame) _truthGame.destroy(); transitionToScreen('screen-hub');
    });
});

// ============================================================================
// 29. 🧩 心桥计划 — 情绪认知（公益增强版：即时科普反馈 + 双模式 + 多阶段）
// ============================================================================

const emotions = [
    { id: 'joy', label: '喜悦', emoji: '😊', color: '#fbbf24', angle: 0, dist: 130,
      desc: '内心温暖明亮，嘴角不自觉上扬，心跳轻快。喜悦是大脑多巴胺释放的"奖励信号"——它让我们记住快乐的事，激励我们重复有益的行为。',
      coping: '✅ 记录今天3件让你开心的小事（感恩日记法）；✅ 与亲近的人分享喜悦，幸福感会翻倍；✅ 投入让你感到快乐的活动，强化积极回路。',
      tip: '积极心理学研究表明：每天记录感恩事件，持续21天可显著提升主观幸福感。' },
    { id: 'trust', label: '信任', emoji: '🤝', color: '#34d399', angle: 45, dist: 130,
      desc: '身体放松，愿意敞开内心。信任由催产素（拥抱激素）驱动——它是一种"社会胶水"，让我们与他人建立安全联结。',
      coping: '✅ 从小事开始建立信任（如遵守约定时间）；✅ 学会分辨值得信任的行为特征（一致性、透明度）；✅ 信任被破坏后，允许自己悲伤，再逐步重建边界。',
      tip: '哈佛大学75年追踪研究发现：良好的人际关系是幸福和健康的最强预测因子。' },
    { id: 'fear', label: '恐惧', emoji: '😨', color: '#818cf8', angle: 90, dist: 130,
      desc: '心跳加速、肌肉紧绷、瞳孔放大。恐惧是杏仁核触发的"生存警报"——它让我们对危险保持警惕，是进化中最古老的情绪之一。',
      coping: '✅ 用"5-4-3-2-1"接地法：说出5样看到的、4样摸到的、3样听到的、2样闻到的、1样尝到的；✅ 深呼吸（4秒吸气-4秒屏住-6秒呼出）；✅ 区分"真实危险"和"想象中的危险"。',
      tip: '适度的恐惧是保护符，过度的恐惧才是枷锁。认知行为疗法(CBT)能有效帮助区分二者的边界。' },
    { id: 'surprise', label: '惊讶', emoji: '😲', color: '#f472b6', angle: 135, dist: 130,
      desc: '眉毛上扬、眼睛睁大、嘴巴微张。惊讶是最短暂的情绪——它是大脑的"重置信号"，让我们暂停当前状态，重新评估发生了什么。',
      coping: '✅ 给自己3秒钟暂停，不做任何决定；✅ 问自己"这是惊喜还是惊吓？"帮大脑分类；✅ 如果是惊喜，用深呼吸把兴奋转化为稳稳的快乐。',
      tip: '惊讶之后0.5秒内，大脑会自动判断这是积极的还是消极的——这个判断可以被训练和重塑。' },
    { id: 'sadness', label: '悲伤', emoji: '😢', color: '#60a5fa', angle: 180, dist: 130,
      desc: '胸口沉闷、眼睛酸涩、动作变慢。悲伤不是软弱——它是大脑在处理"失去"时启动的深度修复程序，让我们暂停、反思、积蓄力量。',
      coping: '✅ 允许自己哭——泪水含有压力激素皮质醇，哭泣是身体的自然排毒；✅ 写一封信（不一定要寄出）表达你的感受；✅ 寻找一个安全的人倾诉，孤独会使悲伤加重。',
      tip: '悲伤是暂时的，但如果持续超过2周并影响日常生活，请考虑寻求心理咨询师的帮助。' },
    { id: 'disgust', label: '厌恶', emoji: '🤢', color: '#a3e635', angle: 225, dist: 130,
      desc: '皱鼻子、后退、想远离。厌恶是情绪免疫系统——它帮我们回避有害物质和不良社交，保护身心安全。',
      coping: '✅ 接纳厌恶的保护功能——它提醒你有什么不对劲；✅ 区分"生理厌恶"（变质食物）和"道德厌恶"（不公行为）；✅ 用理性分析代替情绪性回避，但尊重自己的边界。',
      tip: '厌恶情绪在进化中帮助我们避开毒物和疾病——今天它同样帮你识别不健康的关系和环境。' },
    { id: 'anger', label: '愤怒', emoji: '😡', color: '#ef4444', angle: 270, dist: 130,
      desc: '体温升高、拳头紧握、声音变大。愤怒是"边界守卫者"——它告诉我们：某件事越界了，需要被看见和解决。',
      coping: '✅ 先冷静10秒：愤怒峰值通常持续约10秒，过后再做反应；✅ 用"I feel"语句表达（"我感到生气因为..."）而非指责；✅ 把愤怒转化为行动力——为不公平的事发声，但方式要对。',
      tip: '愤怒本身不是问题，不恰当的宣泄才是。运动、写日记、绘画都是健康的愤怒出口。' },
    { id: 'anticipation', label: '期待', emoji: '🤗', color: '#fb923c', angle: 315, dist: 130,
      desc: '眼睛发亮、坐立不安、心跳微微加速。期待是"未来的快乐预支"——大脑提前释放微量多巴胺，让我们有动力向前迈进。',
      coping: '✅ 把期待的目标拆分成小步骤，每一步都值得庆祝；✅ 享受期待的过程而非只盯着结果；✅ 准备备选方案——降低万一失望带来的落差感。',
      tip: '研究发现：期待美好事物的过程本身就能提升幸福感，有时甚至比实现目标时的快乐更持久。' }
];

// Emotion diary scenarios for guided experience
const emotionDiaries = [
    { scenario: '今天考试得了满分，妈妈给你做了最爱吃的菜。', primary: 'joy', secondary: 'trust', tip: '这是喜悦和信任的混合——成就感与家人的支持', mhTip: '家庭认可是孩子心理安全感的基石，一顿用心准备的饭菜比任何奖励都温暖。' },
    { scenario: '好朋友突然不理你了，你不知道发生了什么。', primary: 'sadness', secondary: 'fear', tip: '悲伤和恐惧经常同时出现——失去和不确定', mhTip: '面对人际冷淡时，主动沟通是第一步。勇敢问一句"你还好吗？"比独自猜测更能保护关系。' },
    { scenario: '有人插队还理直气壮地推了你一下。', primary: 'anger', secondary: 'disgust', tip: '愤怒和厌恶——被冒犯的感觉', mhTip: '被冒犯时，先深呼吸3次再回应。"你的行为让我不舒服"比"你真没素质"更有力量。' },
    { scenario: '收到一份意想不到的生日礼物，是惦记很久的东西。', primary: 'surprise', secondary: 'joy', tip: '惊讶转为喜悦——美好的意外', mhTip: '被人的用心所感动时，真诚地说"谢谢你记得我喜欢这个"——表达感激会增强双方的心理幸福感。' },
    { scenario: '深夜独自回家，巷子里突然传来奇怪的声音。', primary: 'fear', secondary: 'surprise', tip: '恐惧和惊讶——危险信号', mhTip: '独行时尽量选择灯光明亮的大路。如果感到不安，可以给信任的人打个电话——被"陪伴"的感觉能大幅降低恐惧。' },
    { scenario: '明天要出发去期待已久的旅行，正在收拾行李。', primary: 'anticipation', secondary: 'joy', tip: '期待和喜悦——对美好事物的向往', mhTip: '旅行前的心情是天然的抗焦虑剂。记得打包时不必苛求完美——缺的东西旅途上总能找到。' }
];

class HeartBridgeGame {
    constructor() {
        this.placed = {};
        this.total = 8;
        this.dragState = null;
        this.tapSelection = null;
        this.phase = 'wheel';
        this.diaryIndex = 0;
        this.intensityValue = 50;
        this.emotionLog = [];
        this.mode = 'normal'; // 'normal' | 'challenge'
        this.knowledgeShown = {};
        this.wheelTimer = null;
        this.diaryTimer = null;
        this.reflectTimer = null;
        this._knowledgeTimer = null;
        this.rippleIntervals = [];
        this.active = false;
    }

    init() {
        this._clearTimers();
        this.active = true;
        trackGamePlay('heart');
        this.placed = {};
        this.dragState = null;
        this.tapSelection = null;
        this.phase = 'wheel';
        this.diaryIndex = 0;
        this.intensityValue = 50;
        this.emotionLog = [];
        this.knowledgeShown = {};
        this.mode = 'normal';
        document.getElementById('heart-placed').textContent = '0';
        document.getElementById('heart-result').classList.add('hidden');
        document.getElementById('heart-wheel-container').classList.remove('hidden');
        document.getElementById('heart-diary-container').classList.add('hidden');
        var reflectEl = document.getElementById('heart-reflect-container');
        if (reflectEl) reflectEl.classList.add('hidden');
        document.getElementById('heart-phase-indicator').textContent = '阶段 1/3：认识情绪 · 拖拽配对';
        if (document.getElementById('heart-knowledge-card')) {
            document.getElementById('heart-knowledge-card').classList.remove('show');
        }
        this._renderSlots();
        this._renderCards();
        this._startHeartbeat();
    }

    _startHeartbeat() {
        var svg = document.getElementById('heart-wheel-svg');
        if (!svg) return;
        var circle = svg.querySelector('circle');
        if (circle) circle.style.animation = 'heartbeatPulse 1.5s ease-in-out infinite';
    }

    _renderSlots() {
        var slotsLayer = document.getElementById('heart-slots-layer');
        slotsLayer.innerHTML = '';
        var cx = 190, cy = 190;
        var self = this;
        emotions.forEach(function(em) {
            var rad = em.angle * Math.PI / 180;
            var sx = cx + Math.cos(rad) * em.dist;
            var sy = cy + Math.sin(rad) * em.dist;
            var g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
            g.setAttribute('class', 'heart-slot');
            g.setAttribute('id', 'heart-slot-' + em.id);
            g.setAttribute('tabindex', '0');
            g.setAttribute('role', 'button');
            g.setAttribute('aria-label', '放置' + em.label + '情绪卡');
            g.addEventListener('click', function() { self._placeTapEmotion(em.id); });
            g.addEventListener('keydown', function(e) {
                if (e.key !== 'Enter' && e.key !== ' ') return;
                e.preventDefault();
                self._placeTapEmotion(em.id);
            });
            // Glow ring
            var glow = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
            glow.setAttribute('cx', sx); glow.setAttribute('cy', sy); glow.setAttribute('r', 44);
            glow.setAttribute('fill', 'none'); glow.setAttribute('stroke', em.color);
            glow.setAttribute('stroke-width', '2'); glow.setAttribute('opacity', '0');
            glow.setAttribute('class', 'heart-glow-ring');
            g.appendChild(glow);
            // Slot circle
            var circ = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
            circ.setAttribute('cx', sx); circ.setAttribute('cy', sy); circ.setAttribute('r', 38);
            g.appendChild(circ);
            // Label
            var label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            label.setAttribute('x', sx); label.setAttribute('y', sy + 3);
            label.setAttribute('class', 'heart-label');
            label.textContent = em.emoji + ' ' + em.label;
            g.appendChild(label);
            // Ray lines
            var rays = document.createElementNS('http://www.w3.org/2000/svg', 'g');
            rays.setAttribute('class', 'heart-rays');
            rays.setAttribute('opacity', '0');
            for (var i = 0; i < 6; i++) {
                var rAng = (Math.PI * 2 * i) / 6;
                var ray = document.createElementNS('http://www.w3.org/2000/svg', 'line');
                ray.setAttribute('x1', sx + Math.cos(rAng) * 40);
                ray.setAttribute('y1', sy + Math.sin(rAng) * 40);
                ray.setAttribute('x2', sx + Math.cos(rAng) * 55);
                ray.setAttribute('y2', sy + Math.sin(rAng) * 55);
                ray.setAttribute('stroke', em.color);
                ray.setAttribute('stroke-width', '1.5');
                ray.setAttribute('stroke-linecap', 'round');
                rays.appendChild(ray);
            }
            g.appendChild(rays);
            slotsLayer.appendChild(g);
        });
    }

    _renderCards() {
        var tray = document.getElementById('heart-cards-tray');
        tray.innerHTML = '';
        var self = this;
        var shuffled = [...emotions].sort(function() { return Math.random() - 0.5; });
        shuffled.forEach(function(em) {
            var card = document.createElement('div');
            card.className = 'heart-card';
            card.id = 'heart-card-' + em.id;
            card.dataset.emotion = em.id;
            card.style.borderColor = em.color + '55';
            card.style.background = 'linear-gradient(135deg, ' + em.color + '15, ' + em.color + '05)';
            card.style.boxShadow = '0 2px 8px ' + em.color + '15';
            card.innerHTML = safeHTML('<span class="hc-emoji">' + escapeTextForHTML(em.emoji) + '</span><span class="hc-label">' + escapeTextForHTML(em.label) + '</span>');
            card.addEventListener('pointerdown', function(e) { self._dragStart(e, card, em); }, { passive: false });
            card.addEventListener('click', function() { self._selectTapEmotion(card, em); });
            card.addEventListener('keydown', function(e) {
                if (e.key !== 'Enter' && e.key !== ' ') return;
                e.preventDefault();
                self._selectTapEmotion(card, em);
            });
            card.setAttribute('role', 'button');
            card.setAttribute('aria-label', '选择' + em.label + '情绪卡');
            card.tabIndex = 0;
            card.addEventListener('mouseenter', function() {
                card.style.transform = 'scale(1.08) translateY(-3px)';
                card.style.boxShadow = '0 8px 20px ' + em.color + '30';
                card.style.borderColor = em.color + 'aa';
            });
            card.addEventListener('mouseleave', function() {
                if (!card.classList.contains('placed')) {
                    card.style.transform = ''; card.style.boxShadow = '0 2px 8px ' + em.color + '15';
                    card.style.borderColor = em.color + '55';
                }
            });
            tray.appendChild(card);
        });
    }

    _selectTapEmotion(card, em) {
        if (!card || card.classList.contains('placed')) return;
        this.tapSelection = { card: card, em: em };
        setTapPlaceSelection(card, 'heart');
        showGameplayToast('已选中情绪卡，再点击同名情绪圆点完成配对。', 'hint');
    }

    _placeTapEmotion(emId) {
        if (!this.tapSelection || this.placed[emId]) return;
        if (this.tapSelection.em.id !== emId) {
            shakeElement(this.tapSelection.card);
            showGameplayToast('这个情绪圆点不匹配，试试同名情绪。', 'hint');
            return;
        }
        var rect = this.tapSelection.card.getBoundingClientRect();
        this._snapEmotion(emId, this.tapSelection.card, {
            clientX: rect.left + rect.width / 2,
            clientY: rect.top + rect.height / 2
        });
    }

    _dragStart(e, card, em) {
        if (card.classList.contains('placed')) return;
        e.preventDefault(); e.stopPropagation();
        var rect = card.getBoundingClientRect();
        this.dragState = {
            card: card,
            em: em,
            offsetX: e.clientX - rect.left,
            offsetY: e.clientY - rect.top,
            startX: e.clientX,
            startY: e.clientY
        };
        var proxy = card.cloneNode(true);
        proxy.id = 'heart-proxy';
        proxy.style.position = 'fixed'; proxy.style.left = rect.left + 'px'; proxy.style.top = rect.top + 'px';
        proxy.style.width = rect.width + 'px'; proxy.style.height = rect.height + 'px';
        proxy.style.zIndex = '99999'; proxy.style.opacity = '0.95'; proxy.style.transform = 'scale(1.15)';
        proxy.style.boxShadow = '0 8px 25px rgba(192,132,252,0.5)';
        proxy.style.pointerEvents = 'none';
        proxy.style.transition = 'none';
        document.body.appendChild(proxy);
        this.dragState.proxy = proxy;
        card.style.opacity = '0.3';
        card.style.transform = '';
        var self = this;
        this._onMove = function(ev) { self._dragMove(ev, proxy); };
        this._onUp = function(ev) { self._dragEnd(ev); };
        document.addEventListener('pointermove', this._onMove, { passive: false });
        document.addEventListener('pointerup', this._onUp, { passive: false });
    }

    _dragMove(e, proxy) {
        if (!this.dragState) return;
        proxy.style.left = (e.clientX - this.dragState.offsetX) + 'px';
        proxy.style.top = (e.clientY - this.dragState.offsetY) + 'px';
        // Highlight nearest slot
        var svg = document.getElementById('heart-wheel-svg');
        var svgRect = svg.getBoundingClientRect();
        var sx = (e.clientX - svgRect.left) / svgRect.width * 380;
        var sy = (e.clientY - svgRect.top) / svgRect.height * 380;
        document.querySelectorAll('.heart-slot').forEach(function(s) {
            s.classList.remove('hovering');
            s.querySelector('.heart-glow-ring').setAttribute('opacity', '0');
        });
        var best = null, bestD = Infinity;
        emotions.forEach(function(t) {
            var rad = t.angle * Math.PI / 180;
            var tx = 190 + Math.cos(rad) * t.dist;
            var ty = 190 + Math.sin(rad) * t.dist;
            var d = Math.sqrt(Math.pow(sx - tx, 2) + Math.pow(sy - ty, 2));
            if (d < bestD) { bestD = d; best = t; }
        });
        if (best && best.id === this.dragState.em.id && bestD < 120) {
            var slot = document.getElementById('heart-slot-' + best.id);
            if (slot) {
                slot.classList.add('hovering');
                slot.querySelector('.heart-glow-ring').setAttribute('opacity', '0.8');
            }
        }
    }

    _dragEnd(e) {
        if (!this.dragState) return;
        var card = this.dragState.card; var em = this.dragState.em; var proxy = this.dragState.proxy;
        document.removeEventListener('pointermove', this._onMove);
        document.removeEventListener('pointerup', this._onUp);
        proxy.style.transition = 'all 0.3s ease';
        proxy.remove(); card.style.opacity = '';
        document.querySelectorAll('.heart-slot').forEach(function(s) {
            s.classList.remove('hovering');
            s.querySelector('.heart-glow-ring').setAttribute('opacity', '0');
        });
        var svg = document.getElementById('heart-wheel-svg');
        var svgRect = svg.getBoundingClientRect();
        var sx = (e.clientX - svgRect.left) / svgRect.width * 380;
        var sy = (e.clientY - svgRect.top) / svgRect.height * 380;
        var best = null, bestD = Infinity;
        for (var i = 0; i < emotions.length; i++) {
            var t = emotions[i];
            var rad = t.angle * Math.PI / 180;
            var tx = 190 + Math.cos(rad) * t.dist;
            var ty = 190 + Math.sin(rad) * t.dist;
            var d = Math.sqrt(Math.pow(sx - tx, 2) + Math.pow(sy - ty, 2));
            if (d < bestD) { bestD = d; best = t; }
        }
        if (best && best.id === em.id && bestD < 120) {
            this._snapEmotion(em.id, card, e);
        } else if (bestD < 180) {
            // Near miss: gentle shake
            shakeElement(card);
            if (typeof audio !== 'undefined' && audio.playHover) audio.playHover();
        }
        if (!this.placed[em.id] && Math.hypot(e.clientX - this.dragState.startX, e.clientY - this.dragState.startY) < 10) {
            this._selectTapEmotion(card, em);
        }
        this.dragState = null;
    }

    _snapEmotion(emId, card, e) {
        if (!this.active) return;
        if (this.placed[emId]) return;
        this.placed[emId] = true;
        setTapPlaceSelection(null, 'heart');
        this.tapSelection = null;
        card.classList.add('placed');
        card.style.opacity = '1';
        card.style.transform = 'scale(1)';
        card.style.borderColor = emotions.find(function(x) { return x.id === emId; }).color;
        card.style.background = emotions.find(function(x) { return x.id === emId; }).color + '20';
        card.style.boxShadow = '0 0 16px ' + emotions.find(function(x) { return x.id === emId; }).color + '40';
        var slot = document.getElementById('heart-slot-' + emId);
        if (slot) {
            slot.classList.add('filled');
            var label = slot.querySelector('.heart-label');
            if (label) label.textContent = emotions.find(function(e) { return e.id === emId; }).emoji;
            // Activate glow ring and rays
            slot.querySelector('.heart-glow-ring').setAttribute('opacity', '0.6');
            slot.querySelector('.heart-glow-ring').style.animation = 'heartRingPulse 1s ease-out';
            slot.querySelector('.heart-rays').setAttribute('opacity', '1');
            slot.querySelector('.heart-rays').style.animation = 'heartRaysSpin 2s linear infinite';
            // Ripple from slot center
            var cx = 190 + Math.cos(emotions.find(function(e) { return e.id === emId; }).angle * Math.PI / 180) * 130;
            var cy = 190 + Math.sin(emotions.find(function(e) { return e.id === emId; }).angle * Math.PI / 180) * 130;
            this._spawnRipple(cx, cy, emotions.find(function(e) { return e.id === emId; }).color);
        }
        if (typeof audio !== 'undefined' && audio.playSnap) audio.playSnap();
        // Spawn combo particles at click position
        if (e) spawnComboBurst(e.clientX, e.clientY, 8, emotions.find(function(x) { return x.id === emId; }).color);
        if (e) spawnScoreParticle(e.clientX - 20, e.clientY - 30, '✨', emotions.find(function(x) { return x.id === emId; }).color);

        // ***** 核心公益功能：即时情绪知识科普 *****
        this._showKnowledgeCard(emId);

        var count = Object.keys(this.placed).length;
        document.getElementById('heart-placed').textContent = count;
        if (count >= this.total) {
            if (this.wheelTimer) clearTimeout(this.wheelTimer);
            this.wheelTimer = setTimeout(function() {
                this.wheelTimer = null;
                if (!this.active) return;
                this._onWheelComplete();
            }.bind(this), 1200);
        }
    }

    _spawnRipple(cx, cy, color) {
        if (!this.active) return;
        var svg = document.getElementById('heart-wheel-svg');
        if (!svg) return;
        var ripple = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        ripple.setAttribute('class', 'heart-ripple');
        ripple.setAttribute('cx', cx);
        ripple.setAttribute('cy', cy);
        ripple.setAttribute('r', '5');
        ripple.setAttribute('fill', 'none');
        ripple.setAttribute('stroke', color);
        ripple.setAttribute('stroke-width', '3');
        ripple.setAttribute('opacity', '0.8');
        svg.appendChild(ripple);
        var r = 5;
        var self = this;
        var anim = setInterval(function() {
            if (!self.active) {
                clearInterval(anim);
                self.rippleIntervals = self.rippleIntervals.filter(function(id) { return id !== anim; });
                if (ripple.parentNode) ripple.remove();
                return;
            }
            r += 8;
            ripple.setAttribute('r', r);
            ripple.setAttribute('opacity', Math.max(0, 0.8 - r / 300));
            if (r > 250) {
                clearInterval(anim);
                self.rippleIntervals = self.rippleIntervals.filter(function(id) { return id !== anim; });
                if (ripple.parentNode) ripple.remove();
            }
        }, 16);
        this.rippleIntervals.push(anim);
    }

    _showKnowledgeCard(emId) {
        if (!this.active) return;
        var em = emotions.find(function(e) { return e.id === emId; });
        if (!em) return;
        var card = document.getElementById('heart-knowledge-card');
        if (!card) return;
        card.querySelector('.hkc-emoji').textContent = em.emoji;
        card.querySelector('.hkc-name').textContent = em.label + '（' + em.emoji + '）';
        card.querySelector('.hkc-desc').textContent = em.desc;
        card.querySelector('.hkc-method').textContent = em.coping;
        card.classList.add('show');
        // Mark as shown
        this.knowledgeShown[emId] = true;
        // Auto-hide after 5 seconds
        clearTimeout(this._knowledgeTimer);
        this._knowledgeTimer = setTimeout(function() {
            this._knowledgeTimer = null;
            if (!this.active) return;
            card.classList.remove('show');
        }.bind(this), 5000);
        // Click to dismiss
        card.onclick = function() { card.classList.remove('show'); };
    }

    _onWheelComplete() {
        if (!this.active) return;
        this.phase = 'diary';
        setTapPlaceSelection(null, 'heart');
        document.getElementById('heart-phase-indicator').textContent = '阶段 2/3：情绪日记 · 识别场景';
        document.getElementById('heart-wheel-container').classList.add('hidden');
        document.getElementById('heart-diary-container').classList.remove('hidden');
        if (document.getElementById('heart-knowledge-card')) {
            document.getElementById('heart-knowledge-card').classList.remove('show');
        }
        this._showDiary();
    }

    _showDiary() {
        if (!this.active) return;
        if (this.diaryIndex >= emotionDiaries.length) {
            this._onDiaryComplete();
            return;
        }
        var diary = emotionDiaries[this.diaryIndex];
        document.getElementById('heart-diary-scenario').textContent = '📖 "' + diary.scenario + '"';
        document.getElementById('heart-diary-progress').textContent = (this.diaryIndex + 1) + '/' + emotionDiaries.length;
        this.intensityValue = 50;
        var slider = document.getElementById('heart-intensity-slider');
        slider.value = 50;
        document.getElementById('heart-intensity-value').textContent = '50%';
        document.getElementById('heart-diary-feedback').textContent = '';
        document.getElementById('heart-diary-feedback').classList.remove('correct', 'wrong');
        var self = this;
        slider.oninput = function() {
            self.intensityValue = parseInt(this.value);
            var valEl = document.getElementById('heart-intensity-value');
            valEl.textContent = self.intensityValue + '%';
            valEl.style.color = self.intensityValue > 70 ? '#ef4444' : self.intensityValue > 40 ? '#fbbf24' : '#60a5fa';
        };
        var submitBtn = document.getElementById('heart-diary-submit');
        submitBtn.onclick = function() {
            self._checkDiaryAnswer(diary);
        };
        var optionsContainer = document.getElementById('heart-diary-options');
        optionsContainer.innerHTML = '';
        var allEmotions = [...emotions].sort(function() { return Math.random() - 0.5; });
        allEmotions.forEach(function(em) {
            var btn = createButtonElement();
            btn.className = 'heart-diary-option';
            btn.innerHTML = safeHTML('<span class="hdo-emoji">' + escapeTextForHTML(em.emoji) + '</span>' + escapeTextForHTML(em.label));
            btn.dataset.emotion = em.id;
            btn.dataset.emotionColor = em.color;
            btn.style.borderColor = em.color + '55';
            btn.setAttribute('aria-pressed', 'false');
            btn.addEventListener('click', function() {
                optionsContainer.querySelectorAll('.heart-diary-option').forEach(function(b) {
                    b.classList.remove('selected');
                    b.setAttribute('aria-pressed', 'false');
                    b.style.background = '';
                    b.style.borderColor = (b.dataset.emotionColor || '') + '55';
                });
                btn.classList.add('selected');
                btn.setAttribute('aria-pressed', 'true');
                btn.style.background = em.color + '25';
                btn.style.borderColor = em.color;
            });
            optionsContainer.appendChild(btn);
        });
    }

    _checkDiaryAnswer(diary) {
        if (!this.active || this.diaryTimer) return;
        var selected = document.querySelector('.heart-diary-option.selected');
        var feedback = document.getElementById('heart-diary-feedback');
        if (!selected) { feedback.textContent = '请先选择一种情绪再确认哦～'; feedback.className = 'heart-feedback'; return; }
        var emId = selected.dataset.emotion;
        var correct = emId === diary.primary || emId === diary.secondary;
        if (correct) {
            feedback.innerHTML = safeHTML('<strong>✅ 正确！</strong> ' + escapeTextForHTML(diary.tip) +
                '<br><small style="color:rgba(255,255,255,0.55);">🧠 心灵小贴士：' + escapeTextForHTML(diary.mhTip || '') + '</small>');
            feedback.className = 'heart-feedback correct';
            this.emotionLog.push({ scenario: diary.scenario, emotion: emId, intensity: this.intensityValue, correct: true });
            spawnScoreParticle(window.innerWidth / 2, window.innerHeight / 2, '🎯', '#22c55e');
        } else {
            var correctEm = emotions.find(function(e) { return e.id === diary.primary; });
            feedback.innerHTML = safeHTML('<strong>❌ 再想想？</strong> 这个场景主要体现的是' + escapeTextForHTML(correctEm ? correctEm.emoji : '') + '<b>' + escapeTextForHTML(correctEm ? correctEm.label : '') + '</b>' +
                '<br><small style="color:rgba(255,255,255,0.55);">' + escapeTextForHTML(correctEm ? correctEm.desc.split('。')[0] : '') + '。</small>');
            feedback.className = 'heart-feedback wrong';
            this.emotionLog.push({ scenario: diary.scenario, emotion: emId, intensity: this.intensityValue, correct: false });
        }
        var self = this;
        this.diaryTimer = setTimeout(function() {
            self.diaryTimer = null;
            if (!self.active) return;
            self.diaryIndex++;
            self._showDiary();
        }, 2200);
    }

    _onDiaryComplete() {
        if (!this.active) return;
        this.phase = 'reflect';
        document.getElementById('heart-phase-indicator').textContent = '阶段 3/3：情绪反思 · 自我觉察';
        document.getElementById('heart-diary-container').classList.add('hidden');
        var correctCount = this.emotionLog.filter(function(e) { return e.correct; }).length;
        var avgIntensity = Math.round(this.emotionLog.reduce(function(s, e) { return s + e.intensity; }, 0) / Math.max(1, this.emotionLog.length));
        // Show reflection summary
        var reflectEl = document.getElementById('heart-reflect-container');
        if (reflectEl) {
            reflectEl.classList.remove('hidden');
            document.getElementById('heart-reflect-correct').textContent = correctCount;
            document.getElementById('heart-reflect-total').textContent = emotionDiaries.length;
            document.getElementById('heart-reflect-intensity').textContent = avgIntensity + '%';
        }
        if (this.reflectTimer) clearTimeout(this.reflectTimer);
        this.reflectTimer = setTimeout(function() {
            this.reflectTimer = null;
            if (!this.active) return;
            this._onWin(correctCount, avgIntensity);
        }.bind(this), 1500);
    }

    _onWin(correct, avgIntensity) {
        if (!this.active) return;
        this.active = false;
        this._clearTimers();
        var bonus = 100 + correct * 10;
        gameState.memorySilver += bonus;
        document.getElementById('global-silver-balance').textContent = gameState.memorySilver;
        var praise = correct >= 6 ? '🏆 情绪识别大师！你对情绪的洞察力非常敏锐。'
            : correct >= 4 ? '👏 做得不错！你已经开始学会倾听内心的声音。'
            : '🌱 每一次尝试都是成长。情绪的学问需要慢慢体会。';
        document.getElementById('heart-result-text').textContent =
            '你完成了情绪探索之旅！在' + emotionDiaries.length + '个场景中正确识别了' + correct + '种情绪，平均感受强度' + avgIntensity + '%。' +
            praise + ' 获得 +' + bonus + ' 记忆银币';
        document.getElementById('heart-result').classList.remove('hidden');
        achievementSystem.check('emotionGuru');
        trackGameComplete('heart', bonus);
        if (typeof audio !== 'undefined' && audio.playAwake) audio.playAwake();
        spawnComboBurst(window.innerWidth / 2, window.innerHeight / 2, 20, '#c084fc');
    }

    _clearTimers() {
        if (this.wheelTimer) clearTimeout(this.wheelTimer);
        if (this.diaryTimer) clearTimeout(this.diaryTimer);
        if (this.reflectTimer) clearTimeout(this.reflectTimer);
        if (this._knowledgeTimer) clearTimeout(this._knowledgeTimer);
        this.rippleIntervals.forEach(function(id) { clearInterval(id); });
        this.wheelTimer = null;
        this.diaryTimer = null;
        this.reflectTimer = null;
        this._knowledgeTimer = null;
        this.rippleIntervals = [];
    }

    destroy() {
        this.active = false;
        this._clearTimers();
        setTapPlaceSelection(null, 'heart');
        if (this.dragState && this.dragState.proxy) this.dragState.proxy.remove();
        if (this._onMove) document.removeEventListener('pointermove', this._onMove);
        if (this._onUp) document.removeEventListener('pointerup', this._onUp);
        this.dragState = null;
        var knowledgeCard = document.getElementById('heart-knowledge-card');
        if (knowledgeCard) {
            knowledgeCard.classList.remove('show');
            knowledgeCard.onclick = null;
        }
        var submitBtn = document.getElementById('heart-diary-submit');
        var slider = document.getElementById('heart-intensity-slider');
        var reflectEl = document.getElementById('heart-reflect-container');
        if (submitBtn) submitBtn.onclick = null;
        if (slider) slider.oninput = null;
        if (reflectEl) reflectEl.classList.add('hidden');
        document.querySelectorAll('#heart-wheel-svg .heart-ripple').forEach(function(el) { el.remove(); });
    }
}

var _heartGame = null;
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('btn-open-heart')?.addEventListener('click', function() {
        transitionToScreen('screen-heart'); _heartGame = new HeartBridgeGame(); _heartGame.init();
    });
    document.getElementById('btn-heart-back')?.addEventListener('click', function() {
        if (_heartGame) _heartGame.destroy(); transitionToScreen('screen-hub');
    });
    document.getElementById('btn-heart-replay')?.addEventListener('click', function() {
        if (_heartGame) _heartGame.destroy(); _heartGame = new HeartBridgeGame(); _heartGame.init();
    });
    document.getElementById('btn-heart-hub')?.addEventListener('click', function() {
        if (_heartGame) _heartGame.destroy(); transitionToScreen('screen-hub');
    });
});

// ============================================================================
// 30. 🌾 禾下乘凉 — 粮食安全（升级版：资源消耗计算 + 浪费惩罚 + 碳足迹）
// ============================================================================

const grainNodes = [
    { id: 'seed', label: '育种', emoji: '🌱', x: 15, y: 30, w: 80, h: 50, order: 0 },
    { id: 'grow', label: '种植', emoji: '🌾', x: 105, y: 30, w: 80, h: 50, order: 1 },
    { id: 'harvest', label: '收割', emoji: '🚜', x: 195, y: 30, w: 80, h: 50, order: 2 },
    { id: 'process', label: '加工', emoji: '🏭', x: 285, y: 30, w: 80, h: 50, order: 3 },
    { id: 'transport', label: '运输', emoji: '🚚', x: 375, y: 30, w: 80, h: 50, order: 4 },
    { id: 'cook', label: '烹饪', emoji: '🍳', x: 465, y: 30, w: 80, h: 50, order: 5 },
    { id: 'table', label: '餐桌', emoji: '🍽️', x: 555, y: 30, w: 80, h: 50, order: 6 },
    { id: 'recycle', label: '回收', emoji: '♻️', x: 645, y: 30, w: 80, h: 50, order: 7 }
];

const grainResources = [
    { id: 'sun', label: '阳光', emoji: '☀️', belongsTo: 'grow', hint: '光合作用', cost: '0元·天然免费' },
    { id: 'water', label: '水源', emoji: '💧', belongsTo: 'grow', hint: '灌溉', cost: '300吨水/亩' },
    { id: 'farmer', label: '农民', emoji: '👨‍🌾', belongsTo: 'seed', hint: '育种人', cost: '120天辛勤劳作' },
    { id: 'soil', label: '土壤', emoji: '🟫', belongsTo: 'seed', hint: '大地', cost: '千年形成的耕作层' },
    { id: 'machine', label: '农机', emoji: '⚙️', belongsTo: 'harvest', hint: '机械化', cost: '柴油15L/亩' },
    { id: 'mill', label: '碾米', emoji: '🏗️', belongsTo: 'process', hint: '脱壳', cost: '电耗30度/吨' },
    { id: 'truck', label: '物流', emoji: '📦', belongsTo: 'transport', hint: '冷链', cost: '运输1000公里' },
    { id: 'chef', label: '厨师', emoji: '👩‍🍳', belongsTo: 'cook', hint: '料理', cost: '精心烹制' },
    { id: 'family', label: '团聚', emoji: '👨‍👩‍👧', belongsTo: 'table', hint: '共享美食', cost: '无价之宝' },
    { id: 'compost', label: '堆肥', emoji: '🌿', belongsTo: 'recycle', hint: '回归土壤', cost: '零废弃循环' }
];

class GrainJourneyGame {
    constructor() {
        this.placed = {};
        this.total = 8;
        this.dragState = null;
        this.tapSelection = null;
        this.wasteScore = 0;
        this.wasteEvents = [
            { text: '🍞 餐厅后厨倒掉半锅米饭', waste: 2 },
            { text: '🥬 超市扔掉临期蔬菜', waste: 3 },
            { text: '🍕 家庭聚餐剩菜被丢弃', waste: 2 },
            { text: '📦 运输途中挤压破损的水果', waste: 4 },
            { text: '🍚 食堂大量米饭剩余无人打包', waste: 3 },
            { text: '🥩 冰箱里遗忘的食材过期了', waste: 2 }
        ];
        this.currentWaste = null;
        this.wasteTimer = null;
        this.nextWasteTimer = null;
        this.chainCompleteTimer = null;
        this.costTimer = null;
        this.savedFood = 0;
        this.active = false;
    }

    init() {
        this._clearTimers();
        this.active = true;
        trackGamePlay('grain');
        this.placed = {};
        this.dragState = null;
        this.tapSelection = null;
        this.wasteScore = 0;
        this.savedFood = 0;
        this.currentWaste = null;
        document.getElementById('grain-placed').textContent = '0';
        document.getElementById('grain-result').classList.add('hidden');
        document.getElementById('grain-waste-score').textContent = '0kg';
        document.getElementById('grain-saved-food').textContent = '0份';
        document.getElementById('grain-waste-area').classList.add('hidden');
        document.getElementById('grain-assemble-area').classList.remove('hidden');
        this._renderSlots();
        this._renderCards();
    }

    _renderSlots() {
        var slotsLayer = document.getElementById('grain-slots-layer');
        slotsLayer.innerHTML = '';
        var linesLayer = document.getElementById('grain-lines-layer');
        linesLayer.innerHTML = '';
        var self = this;
        grainNodes.forEach(function(node, i) {
            var g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
            g.setAttribute('class', 'grain-slot');
            g.setAttribute('id', 'grain-slot-' + node.id);
            g.setAttribute('tabindex', '0');
            g.setAttribute('role', 'button');
            g.setAttribute('aria-label', '放置到' + node.label + '节点');
            g.addEventListener('click', function() { self._placeTapResource(node.id); });
            g.addEventListener('keydown', function(e) {
                if (e.key !== 'Enter' && e.key !== ' ') return;
                e.preventDefault();
                self._placeTapResource(node.id);
            });
            var rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
            rect.setAttribute('x', node.x); rect.setAttribute('y', node.y);
            rect.setAttribute('width', node.w); rect.setAttribute('height', node.h);
            g.appendChild(rect);
            var label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            label.setAttribute('x', node.x + node.w / 2);
            label.setAttribute('y', node.y + node.h - 8);
            label.setAttribute('class', 'grain-label');
            label.textContent = node.emoji + ' ' + node.label;
            g.appendChild(label);
            slotsLayer.appendChild(g);
            if (i < grainNodes.length - 1) {
                var next = grainNodes[i + 1];
                var line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
                line.setAttribute('x1', node.x + node.w);
                line.setAttribute('y1', node.y + node.h / 2);
                line.setAttribute('x2', next.x);
                line.setAttribute('y2', next.y + node.h / 2);
                line.setAttribute('stroke', '#f7dc6f');
                line.setAttribute('stroke-width', '2');
                line.setAttribute('stroke-dasharray', '4,3');
                line.setAttribute('opacity', '0.15');
                line.setAttribute('class', 'grain-line');
                line.setAttribute('id', 'grain-line-' + i);
                linesLayer.appendChild(line);
            }
        });
    }

    _renderCards() {
        var area = document.getElementById('grain-cards-area');
        area.innerHTML = '';
        var self = this;
        var shuffled = [...grainResources].sort(function() { return Math.random() - 0.5; });
        shuffled.forEach(function(res) {
            var card = document.createElement('div');
            card.className = 'grain-card';
            card.id = 'grain-card-' + res.id;
            card.dataset.resource = res.id;
            card.dataset.belongsTo = res.belongsTo;
            card.innerHTML = safeHTML(escapeTextForHTML(res.emoji) + ' ' + escapeTextForHTML(res.label) + '<br><small>' + escapeTextForHTML(res.hint) + '</small>');
            card.addEventListener('pointerdown', function(e) { self._dragStart(e, card, res); }, { passive: false });
            card.addEventListener('click', function() { self._selectTapResource(card, res); });
            card.addEventListener('keydown', function(e) {
                if (e.key !== 'Enter' && e.key !== ' ') return;
                e.preventDefault();
                self._selectTapResource(card, res);
            });
            card.setAttribute('role', 'button');
            card.setAttribute('aria-label', '选择' + res.label + '资源卡');
            card.tabIndex = 0;
            area.appendChild(card);
        });
    }

    _selectTapResource(card, res) {
        if (!card || card.classList.contains('placed')) return;
        this.tapSelection = { card: card, res: res };
        setTapPlaceSelection(card, 'grain');
        showGameplayToast('已选中资源卡，再点击对应的粮食旅程节点。', 'hint');
    }

    _placeTapResource(nodeId) {
        if (!this.tapSelection || this.placed[nodeId]) return;
        if (this.tapSelection.res.belongsTo !== nodeId) {
            shakeElement(this.tapSelection.card);
            showGameplayToast('这个节点不匹配，看看卡片提示里的生产环节。', 'hint');
            return;
        }
        this._snapResource(this.tapSelection.res, this.tapSelection.card);
    }

    _dragStart(e, card, res) {
        if (card.classList.contains('placed')) return;
        e.preventDefault(); e.stopPropagation();
        var rect = card.getBoundingClientRect();
        this.dragState = {
            card: card,
            res: res,
            offsetX: e.clientX - rect.left,
            offsetY: e.clientY - rect.top,
            startX: e.clientX,
            startY: e.clientY
        };
        var proxy = card.cloneNode(true);
        proxy.id = 'grain-proxy';
        proxy.style.position = 'fixed'; proxy.style.left = rect.left + 'px'; proxy.style.top = rect.top + 'px';
        proxy.style.width = rect.width + 'px'; proxy.style.height = rect.height + 'px';
        proxy.style.zIndex = '99999'; proxy.style.opacity = '0.95'; proxy.style.transform = 'scale(1.1)';
        proxy.style.boxShadow = '0 8px 25px rgba(247,220,111,0.5)';
        proxy.style.pointerEvents = 'none';
        document.body.appendChild(proxy);
        this.dragState.proxy = proxy;
        card.style.opacity = '0.3';
        var self = this;
        this._onMove = function(ev) { self._dragMove(ev); };
        this._onUp = function(ev) { self._dragEnd(ev); };
        document.addEventListener('pointermove', this._onMove, { passive: false });
        document.addEventListener('pointerup', this._onUp, { passive: false });
    }

    _dragMove(e) {
        if (!this.dragState) return;
        var p = this.dragState.proxy;
        p.style.left = (e.clientX - this.dragState.offsetX) + 'px';
        p.style.top = (e.clientY - this.dragState.offsetY) + 'px';
    }

    _dragEnd(e) {
        if (!this.dragState) return;
        var card = this.dragState.card; var res = this.dragState.res; var proxy = this.dragState.proxy;
        document.removeEventListener('pointermove', this._onMove);
        document.removeEventListener('pointerup', this._onUp);
        proxy.remove(); card.style.opacity = '';
        var svg = document.getElementById('grain-chain-svg');
        var svgRect = svg.getBoundingClientRect();
        var cx = (e.clientX - svgRect.left) / svgRect.width * 750;
        var cy = (e.clientY - svgRect.top) / svgRect.height * 100;
        var target = grainNodes.find(function(n) { return n.id === res.belongsTo; });
        if (!target) { this.dragState = null; return; }
        var tx = target.x + target.w / 2;
        var ty = target.y + target.h / 2;
        if (Math.sqrt(Math.pow(cx - tx, 2) + Math.pow(cy - ty, 2)) < target.w * 1.5) {
            this._snapResource(res, card);
        }
        if (!this.placed[res.belongsTo] && Math.hypot(e.clientX - this.dragState.startX, e.clientY - this.dragState.startY) < 10) {
            this._selectTapResource(card, res);
        }
        this.dragState = null;
    }

    _snapResource(res, card) {
        if (!this.active) return;
        var nodeId = res.belongsTo;
        if (this.placed[nodeId]) return;
        this.placed[nodeId] = true;
        setTapPlaceSelection(null, 'grain');
        this.tapSelection = null;
        card.classList.add('placed');
        var slot = document.getElementById('grain-slot-' + nodeId);
        if (slot) slot.classList.add('filled');
        if (typeof audio !== 'undefined' && audio.playSnap) audio.playSnap();

        // Show resource cost info
        var costEl = document.getElementById('grain-resource-cost');
        if (costEl) {
            costEl.textContent = '💡 ' + res.emoji + ' ' + res.label + '：' + res.cost;
            costEl.style.opacity = '1';
            if (this.costTimer) clearTimeout(this.costTimer);
            this.costTimer = setTimeout(function() {
                this.costTimer = null;
                if (!this.active) return;
                costEl.style.opacity = '0';
            }.bind(this), 2000);
        }

        var nodeIdx = grainNodes.findIndex(function(n) { return n.id === nodeId; });
        if (nodeIdx >= 0 && nodeIdx < grainNodes.length - 1) {
            var line = document.getElementById('grain-line-' + nodeIdx);
            if (line) line.setAttribute('opacity', '0.7');
        }
        var count = Object.keys(this.placed).length;
        document.getElementById('grain-placed').textContent = count;
        if (count >= this.total) {
            if (this.chainCompleteTimer) clearTimeout(this.chainCompleteTimer);
            this.chainCompleteTimer = setTimeout(function() {
                this.chainCompleteTimer = null;
                if (!this.active) return;
                this._onChainComplete();
            }.bind(this), 800);
        }
    }

    _onChainComplete() {
        if (!this.active) return;
        document.getElementById('grain-assemble-area').classList.add('hidden');
        document.getElementById('grain-waste-area').classList.remove('hidden');
        this._startWasteChallenge();
    }

    _startWasteChallenge() {
        if (!this.active) return;
        var self = this;
        document.getElementById('grain-waste-tip').textContent = '全球每年浪费约13亿吨食物！点击出现的食物浪费卡片来"拯救"它们';
        this._showWasteCard();
    }

    _showWasteCard() {
        if (!this.active) return;
        var self = this;
        if (this.savedFood >= 10) {
            this._onWin();
            return;
        }
        var wasteContainer = document.getElementById('grain-waste-cards');
        wasteContainer.innerHTML = '';
        var event = this.wasteEvents[Math.floor(Math.random() * this.wasteEvents.length)];
        this.currentWaste = event;
        var card = document.createElement('div');
        card.className = 'grain-waste-card';
        card.textContent = event.text;
        card.addEventListener('click', function() {
            self._saveFood(event);
        });
        wasteContainer.appendChild(card);

        if (this.wasteTimer) clearTimeout(this.wasteTimer);
        this.wasteTimer = setTimeout(function() {
            self.wasteTimer = null;
            if (!self.active) return;
            self.wasteScore += event.waste;
            document.getElementById('grain-waste-score').textContent = self.wasteScore + 'kg';
            document.getElementById('grain-waste-tip').textContent = '⏰ 错过了！' + event.text + ' — 浪费+' + event.waste + 'kg';
            self._showWasteCard();
        }, 4000);
    }

    _saveFood(event) {
        if (!this.active || this.nextWasteTimer) return;
        if (this.wasteTimer) clearTimeout(this.wasteTimer);
        this.wasteTimer = null;
        this.savedFood++;
        document.getElementById('grain-saved-food').textContent = this.savedFood + '份';
        document.getElementById('grain-waste-tip').textContent = '✅ 太好了！你拯救了 ' + event.text + ' — 已救' + this.savedFood + '份食物';
        if (typeof audio !== 'undefined' && audio.playSnap) audio.playSnap();
        this.nextWasteTimer = setTimeout(function() {
            this.nextWasteTimer = null;
            if (!this.active) return;
            this._showWasteCard();
        }.bind(this), 1000);
    }

    _onWin() {
        if (!this.active) return;
        this.active = false;
        this._clearTimers();
        var bonus = 100 + this.savedFood * 10 - this.wasteScore;
        bonus = Math.max(50, bonus);
        gameState.memorySilver += bonus;
        document.getElementById('global-silver-balance').textContent = gameState.memorySilver;
        document.getElementById('grain-result-text').textContent =
            '粮食旅程完整呈现！你拯救了' + this.savedFood + '份食物，减少浪费' + this.wasteScore + 'kg。' +
            '从种子到餐桌，致敬袁隆平院士"禾下乘凉梦"。珍惜每一粒粮食！获得 +' + bonus + ' 记忆银币';
        document.getElementById('grain-result').classList.remove('hidden');
        trackGameComplete('grain', bonus);
        if (typeof audio !== 'undefined' && audio.playAwake) audio.playAwake();
    }

    _clearTimers() {
        if (this.wasteTimer) clearTimeout(this.wasteTimer);
        if (this.nextWasteTimer) clearTimeout(this.nextWasteTimer);
        if (this.chainCompleteTimer) clearTimeout(this.chainCompleteTimer);
        if (this.costTimer) clearTimeout(this.costTimer);
        this.wasteTimer = null;
        this.nextWasteTimer = null;
        this.chainCompleteTimer = null;
        this.costTimer = null;
    }

    destroy() {
        this.active = false;
        this._clearTimers();
        setTapPlaceSelection(null, 'grain');
        if (this.dragState && this.dragState.proxy) this.dragState.proxy.remove();
        if (this._onMove) document.removeEventListener('pointermove', this._onMove);
        if (this._onUp) document.removeEventListener('pointerup', this._onUp);
        this.dragState = null;
    }
}

var _grainGame = null;
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('btn-open-grain')?.addEventListener('click', function() {
        transitionToScreen('screen-grain'); _grainGame = new GrainJourneyGame(); _grainGame.init();
    });
    document.getElementById('btn-grain-back')?.addEventListener('click', function() {
        if (_grainGame) _grainGame.destroy(); transitionToScreen('screen-hub');
    });
    document.getElementById('btn-grain-replay')?.addEventListener('click', function() {
        if (_grainGame) _grainGame.destroy(); _grainGame = new GrainJourneyGame(); _grainGame.init();
    });
    document.getElementById('btn-grain-hub')?.addEventListener('click', function() {
        if (_grainGame) _grainGame.destroy(); transitionToScreen('screen-hub');
    });
});

// ============================================================================
// 31. Hub Tab Switching + P1 Cleanup Fixes
// ============================================================================
document.addEventListener('DOMContentLoaded', function() {
    // --- Tab Switching ---
    var tabs = document.querySelectorAll('.hub-tab');
    var panels = document.querySelectorAll('.hub-panel');
    function activateHubTab(tab, shouldFocus) {
        var target = tab.getAttribute('data-tab');
        tabs.forEach(function(t) {
            var active = t === tab;
            t.classList.toggle('active', active);
            t.setAttribute('aria-selected', active ? 'true' : 'false');
            t.setAttribute('tabindex', active ? '0' : '-1');
        });
        panels.forEach(function(p) {
            var active = p.getAttribute('data-panel') === target;
            p.classList.toggle('active', active);
            p.setAttribute('aria-hidden', active ? 'false' : 'true');
        });
        if (shouldFocus) {
            focusElementSafely(tab);
            requestAnimationFrame(function() {
                var active = document.activeElement;
                var focusWasLostToScreen = !active ||
                    active === document.body ||
                    active === document.documentElement ||
                    (active.classList && active.classList.contains('game-screen'));
                if (focusWasLostToScreen && tab.isConnected && tab.getAttribute('tabindex') === '0') {
                    focusElementSafely(tab);
                }
            });
        }
    }
    tabs.forEach(function(tab) {
        tab.addEventListener('click', function() {
            activateHubTab(tab, false);
        });
        tab.addEventListener('keydown', function(e) {
            var current = Array.prototype.indexOf.call(tabs, tab);
            var next = current;
            if (e.key === 'ArrowRight' || e.key === 'ArrowDown') next = (current + 1) % tabs.length;
            else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') next = (current - 1 + tabs.length) % tabs.length;
            else if (e.key === 'Home') next = 0;
            else if (e.key === 'End') next = tabs.length - 1;
            else return;
            e.preventDefault();
            activateHubTab(tabs[next], true);
        });
    });

    // --- BUG-6 Fix: Timeline cleanup on back ---
    var btnTimelineBack = document.getElementById('btn-timeline-back');
    var btnTimelineHub = document.getElementById('btn-timeline-hub');
    if (btnTimelineBack) { btnTimelineBack.addEventListener('click', cleanupTimelineRuntime); }
    if (btnTimelineHub) { btnTimelineHub.addEventListener('click', cleanupTimelineRuntime); }

    // --- BUG-7 Fix: Eco cleanup on back ---
    var btnEcoBack = document.getElementById('btn-eco-back');
    var btnEcoHub = document.getElementById('btn-eco-hub');
    if (btnEcoBack) { btnEcoBack.addEventListener('click', function() { if (window._ecoCleanup) { document.removeEventListener('pointermove', window._ecoCleanup.move); document.removeEventListener('pointerup', window._ecoCleanup.up); window._ecoCleanup = null; } }); }
    if (btnEcoHub) { btnEcoHub.addEventListener('click', function() { if (window._ecoCleanup) { document.removeEventListener('pointermove', window._ecoCleanup.move); document.removeEventListener('pointerup', window._ecoCleanup.up); window._ecoCleanup = null; } }); }
});

function initMazeGame() {
    cleanupCognitiveRuntime();
    trackGamePlay('maze');

    var grid = document.getElementById('maze-grid');

    var resultDiv = document.getElementById('maze-result');

    var scoreEl = document.getElementById('maze-score');

    var levelEl = document.getElementById('maze-level');

    

    resultDiv.classList.add('hidden');

    

    var level = 1;

    var score = 0;

    var currentNumber = 1;

    var totalNumbers = 25;

    var numbers = [];
    var gameEnded = false;

    

    function shuffle(array) {

        for (var i = array.length - 1; i > 0; i--) {

            var j = Math.floor(Math.random() * (i + 1));

            var temp = array[i];

            array[i] = array[j];

            array[j] = temp;

        }

        return array;

    }

    
    function disableMazeCell(cell, label) {
        if (!cell) return;
        cell.setAttribute('aria-disabled', 'true');
        cell.tabIndex = -1;
        if (label) cell.setAttribute('aria-label', label);
    }

    function disableAllMazeCells() {
        grid.querySelectorAll('.maze-cell').forEach(function(cell) {
            disableMazeCell(cell, (cell.getAttribute('aria-label') || '数字迷宫格') + '，游戏已结束');
        });
    }


    function renderGrid() {

        grid.innerHTML = '';

        numbers = [];

        for (var i = 1; i <= totalNumbers; i++) {

            numbers.push(i);

        }

        numbers = shuffle(numbers);

        

        for (var i = 0; i < totalNumbers; i++) {

            var cell = document.createElement('div');

            cell.className = 'maze-cell';

            cell.textContent = numbers[i];

            cell.dataset.number = numbers[i];
            cell.setAttribute('role', 'button');
            cell.setAttribute('aria-label', '数字迷宫格 ' + numbers[i]);
            cell.tabIndex = 0;

            

            if (numbers[i] === currentNumber) {

                cell.classList.add('next');
                cell.setAttribute('aria-label', '数字迷宫格 ' + numbers[i] + '，下一个目标');

            }

            

            cell.addEventListener('click', function() {
                if (gameEnded || this.getAttribute('aria-disabled') === 'true') return;

                var num = parseInt(this.dataset.number);

                if (num === currentNumber) {

                    this.classList.remove('next');

                    this.classList.add('correct');
                    disableMazeCell(this, '数字迷宫格 ' + num + '，已完成');

                    currentNumber++;

                    score += 10;

                    scoreEl.textContent = score;

                    audio.playSnap();

                    

                    if (currentNumber > totalNumbers) {
                        gameEnded = true;

                        gameState.memorySilver += Math.floor(score / 10);

                        document.getElementById('global-silver-balance').textContent = gameState.memorySilver;

                        document.getElementById('maze-score-text').textContent = '太棒了！完成数字迷宫，获得 +' + Math.floor(score / 10) + ' 记忆银币';

                        resultDiv.classList.remove('hidden');
                        trackGameComplete('maze', score);
                        disableAllMazeCells();

                        audio.playAwake();

                    } else {

                        var cells = grid.querySelectorAll('.maze-cell');

                        for (var j = 0; j < cells.length; j++) {

                            if (parseInt(cells[j].dataset.number) === currentNumber && !cells[j].classList.contains('correct')) {

                                cells[j].classList.add('next');
                                cells[j].setAttribute('aria-label', '数字迷宫格 ' + currentNumber + '，下一个目标');

                                break;

                            }

                        }

                    }

                } else {

                    this.classList.add('wrong');

                    trackCognitiveTimeout(function() { if (this.isConnected) this.classList.remove('wrong'); }.bind(this), 400);

                    audio.playError();

                }

            });

            cell.addEventListener('keydown', function(e) {
                if (e.key !== 'Enter' && e.key !== ' ') return;
                e.preventDefault();
                this.click();
            });

            

            grid.appendChild(cell);

        }

    }

    

    currentNumber = 1;

    score = 0;

    scoreEl.textContent = score;

    levelEl.textContent = level;

    renderGrid();

    

    document.getElementById('btn-maze-replay').onclick = function() {

        currentNumber = 1;

        score = 0;
        gameEnded = false;

        scoreEl.textContent = score;

        resultDiv.classList.add('hidden');

        renderGrid();

    };

    

    document.getElementById('btn-maze-hub').onclick = function() {

        transitionToScreen('screen-hub');

    };

    

    document.getElementById('btn-maze-back').onclick = function() {

        transitionToScreen('screen-hub');

    };

}






// ============================================================================
// color. 🎨 色彩归类
// ============================================================================
function initColorGame() {
    cleanupCognitiveRuntime();
    trackGamePlay('color');
    var area = document.getElementById('color-game-area');
    var resultDiv = document.getElementById('color-result');
    var scoreEl = document.getElementById('color-score');
    
    resultDiv.classList.add('hidden');
    
    var score = 0;
    var correctCount = 0;
    var totalCount = 8;
    scoreEl.textContent = score;
    
    // 颜色数据
    var colorGroups = {
        warm: ['#FF6B6B', '#FF8E53', '#FF6B9D', '#C44569'],
        cool: ['#4ECDC4', '#45B7D1', '#96CEB4', '#74B9FF'],
        neutral: ['#A29BFE', '#FD79A8', '#FDCB6E', '#6C5CE7']
    };
    
    var allColors = [];
    for (var group in colorGroups) {
        colorGroups[group].forEach(function(color) {
            allColors.push({ color: color, group: group });
        });
    }
    
    // 打乱顺序
    for (var i = allColors.length - 1; i > 0; i--) {
        var j = Math.floor(Math.random() * (i + 1));
        var temp = allColors[i];
        allColors[i] = allColors[j];
        allColors[j] = temp;
    }
    
    // 渲染游戏界面
    var html = '<div class="color-game-container">';
    html += '<div class="color-instruction">将颜色卡片拖放到正确的颜色组中</div>';
    html += '<div class="color-groups">';
    html += '<div class="color-group" data-group="warm"><div class="group-label">暖色系</div><div class="group-slots"></div></div>';
    html += '<div class="color-group" data-group="cool"><div class="group-label">冷色系</div><div class="group-slots"></div></div>';
    html += '<div class="color-group" data-group="neutral"><div class="group-label">中性色</div><div class="group-slots"></div></div>';
    html += '</div>';
    html += '<div class="color-cards">';
    allColors.forEach(function(item, index) {
        html += '<div class="color-card" data-color="' + escapeTextForHTML(item.color) + '" data-group="' + escapeTextForHTML(item.group) + '" data-index="' + index + '" style="background-color: ' + escapeTextForHTML(item.color) + ';"></div>';
    });
    html += '</div>';
    html += '</div>';
    
    area.innerHTML = safeHTML(html);
    
    // 添加点击交互
    var selectedCard = null;
    var cards = area.querySelectorAll('.color-card');
    var groups = area.querySelectorAll('.color-group');
    var colorGroupLabels = { warm: '暖色组', cool: '冷色组', neutral: '中性色组' };
    
    cards.forEach(function(card, index) {
        card.setAttribute('role', 'button');
        card.setAttribute('aria-label', '颜色卡片 ' + (index + 1) + '，选择后放入对应颜色组');
        card.setAttribute('aria-pressed', 'false');
        card.tabIndex = 0;
        card.addEventListener('click', function() {
            if (this.classList.contains('placed')) return;
            
            if (selectedCard) {
                selectedCard.classList.remove('selected');
                selectedCard.setAttribute('aria-pressed', 'false');
            }
            
            if (selectedCard === this) {
                selectedCard = null;
                return;
            }
            
            selectedCard = this;
            this.classList.add('selected');
            this.setAttribute('aria-pressed', 'true');
            audio.playSnap();
        });
        card.addEventListener('keydown', function(e) {
            if (e.key !== 'Enter' && e.key !== ' ') return;
            e.preventDefault();
            card.click();
        });
    });
    
    groups.forEach(function(group) {
        group.setAttribute('role', 'button');
        group.setAttribute('aria-label', '放入' + (colorGroupLabels[group.dataset.group] || '颜色组'));
        group.tabIndex = 0;
        group.addEventListener('click', function() {
            if (!selectedCard) return;
            
            var cardGroup = selectedCard.dataset.group;
            var targetGroup = this.dataset.group;
            var slots = this.querySelector('.group-slots');
            
            if (cardGroup === targetGroup) {
                selectedCard.classList.remove('selected');
                selectedCard.classList.add('placed');
                selectedCard.setAttribute('aria-pressed', 'false');
                selectedCard.setAttribute('aria-disabled', 'true');
                selectedCard.setAttribute('aria-label', selectedCard.getAttribute('aria-label') + '，已归类');
                selectedCard.tabIndex = -1;
                slots.appendChild(selectedCard);
                score += 15;
                correctCount++;
                scoreEl.textContent = score;
                audio.playSnap();
                
                if (correctCount === totalCount) {
                    gameState.memorySilver += Math.floor(score / 10);
                    document.getElementById('global-silver-balance').textContent = gameState.memorySilver;
                    document.getElementById('color-score-text').textContent = '色彩归类完成！得分: ' + score + '，获得 +' + Math.floor(score / 10) + ' 记忆银币';
                    resultDiv.classList.remove('hidden');
                    trackGameComplete('color', score);
                    audio.playAwake();
                }
            } else {
                var wrongCard = selectedCard;
                wrongCard.classList.remove('selected');
                wrongCard.setAttribute('aria-pressed', 'false');
                wrongCard.classList.add('wrong');
                trackCognitiveTimeout(function() {
                    if (wrongCard) wrongCard.classList.remove('wrong');
                }, 400);
                score = Math.max(0, score - 5);
                scoreEl.textContent = score;
                audio.playError();
            }
            
            selectedCard = null;
        });
        group.addEventListener('keydown', function(e) {
            if (e.key !== 'Enter' && e.key !== ' ') return;
            e.preventDefault();
            group.click();
        });
    });
    
    document.getElementById('btn-color-replay').onclick = function() {
        score = 0;
        correctCount = 0;
        scoreEl.textContent = score;
        resultDiv.classList.add('hidden');
        initColorGame();
    };
    
    document.getElementById('btn-color-hub').onclick = function() {
        transitionToScreen('screen-hub');
    };
    
    document.getElementById('btn-color-back').onclick = function() {
        transitionToScreen('screen-hub');
    };
}

// ============================================================================
// face. 👤 面孔识别
// ============================================================================
function initFaceGame() {
    cleanupCognitiveRuntime();
    trackGamePlay('face');
    var area = document.getElementById('face-game-area');
    var resultDiv = document.getElementById('face-result');
    var scoreEl = document.getElementById('face-score');
    resultDiv.classList.add('hidden');
    var score = 0, matched = 0, totalPairs = 6, flipped = [], canFlip = true;
    scoreEl.textContent = score;
    var faces = ['👴','👴','👵','👵','👨','👨','👩','👩','👦','👦','👧','👧'];
    faces.sort(function() { return Math.random() - 0.5; });
    var html = '<div class="face-grid" style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;max-width:400px;margin:0 auto;padding:20px;">';
    for (var i = 0; i < faces.length; i++) {
        html += '<div class="face-card" data-index="' + i + '" data-face="' + escapeTextForHTML(faces[i]) + '" style="aspect-ratio:1;display:flex;align-items:center;justify-content:center;font-size:2.5rem;background:rgba(255,255,255,0.08);border:2px solid rgba(212,175,55,0.3);border-radius:12px;cursor:pointer;transition:all 0.3s;user-select:none;">❓</div>';
    }
    html += '</div><p style="text-align:center;color:var(--text-muted);margin-top:12px;">翻开卡片，找到相同的家庭成员配对</p>';
    area.innerHTML = safeHTML(html);
    var cards = area.querySelectorAll('.face-card');
    cards.forEach(function(card, index) {
        card.setAttribute('role', 'button');
        card.setAttribute('aria-label', '面孔记忆卡片 ' + (index + 1) + '，未翻开');
        card.setAttribute('aria-pressed', 'false');
        card.tabIndex = 0;
        card.addEventListener('click', function() {
            if (!canFlip || this.classList.contains('flipped') || this.classList.contains('matched')) return;
            var face = this.getAttribute('data-face');
            this.textContent = face;
            this.classList.add('flipped');
            this.setAttribute('aria-label', '面孔记忆卡片 ' + (index + 1) + '，已翻开');
            this.setAttribute('aria-pressed', 'true');
            this.style.background = 'rgba(212,175,55,0.2)';
            flipped.push(this);
            if (flipped.length === 2) {
                canFlip = false;
                if (flipped[0].getAttribute('data-face') === flipped[1].getAttribute('data-face')) {
                    flipped[0].classList.add('matched');
                    flipped[1].classList.add('matched');
                    flipped[0].setAttribute('aria-disabled', 'true');
                    flipped[1].setAttribute('aria-disabled', 'true');
                    flipped[0].setAttribute('aria-label', flipped[0].getAttribute('aria-label') + '，已配对');
                    flipped[1].setAttribute('aria-label', flipped[1].getAttribute('aria-label') + '，已配对');
                    flipped[0].tabIndex = -1;
                    flipped[1].tabIndex = -1;
                    flipped[0].style.borderColor = '#4ade80';
                    flipped[1].style.borderColor = '#4ade80';
                    score += 20; matched++;
                    scoreEl.textContent = score;
                    audio.playAwake();
                    flipped = []; canFlip = true;
                    if (matched === totalPairs) {
                        trackCognitiveTimeout(function() {
                            gameState.memorySilver += Math.floor(score / 5);
                            document.getElementById('global-silver-balance').textContent = gameState.memorySilver;
                            document.getElementById('face-score-text').textContent = '完成面孔识别！找到所有家庭成员，获得 +' + Math.floor(score / 5) + ' 记忆银币';
                            resultDiv.classList.remove('hidden');
                            trackGameComplete('face', score);
                        }, 500);
                    }
                } else {
                    audio.playError();
                    trackCognitiveTimeout(function() {
                        flipped[0].textContent = '❓';
                        flipped[1].textContent = '❓';
                        flipped[0].setAttribute('aria-label', '面孔记忆卡片 ' + (Number(flipped[0].dataset.index) + 1) + '，未翻开');
                        flipped[1].setAttribute('aria-label', '面孔记忆卡片 ' + (Number(flipped[1].dataset.index) + 1) + '，未翻开');
                        flipped[0].setAttribute('aria-pressed', 'false');
                        flipped[1].setAttribute('aria-pressed', 'false');
                        flipped[0].classList.remove('flipped');
                        flipped[1].classList.remove('flipped');
                        flipped[0].style.background = 'rgba(255,255,255,0.08)';
                        flipped[1].style.background = 'rgba(255,255,255,0.08)';
                        flipped = []; canFlip = true;
                    }, 800);
                }
            }
        });
        card.addEventListener('keydown', function(e) {
            if (e.key !== 'Enter' && e.key !== ' ') return;
            e.preventDefault();
            card.click();
        });
    });
    document.getElementById('btn-face-replay').onclick = function() { initFaceGame(); };
    document.getElementById('btn-face-hub').onclick = function() { transitionToScreen('screen-hub'); };
    document.getElementById('btn-face-back').onclick = function() { transitionToScreen('screen-hub'); };
}
function initWordGame() {
    cleanupCognitiveRuntime();
    trackGamePlay('word');
    var area = document.getElementById('word-game-area');
    var resultDiv = document.getElementById('word-result');
    var scoreEl = document.getElementById('word-score');
    resultDiv.classList.add('hidden');
    var score = 0, currentRound = 0, totalRounds = 5;
    scoreEl.textContent = score;
    var rounds = [
        { hint: '阿尔茨海默病', options: ['记忆衰退', '感冒发烧', '骨折', '近视'], correct: 0, explain: '阿尔茨海默病最主要的症状是进行性记忆衰退' },
        { hint: '环保行动', options: ['垃圾分类', '随地吐痰', '乱砍滥伐', '浪费水电'], correct: 0, explain: '垃圾分类是最重要的日常环保行动之一' },
        { hint: '诈骗预警', options: ['陌生来电要求转账', '快递到货通知', '银行账单提醒', '天气预报'], correct: 0, explain: '陌生来电要求转账是典型诈骗手段' },
        { hint: '节水措施', options: ['淘米水浇花', '长时间淋浴', '水龙头常开', '频繁洗车'], correct: 0, explain: '淘米水浇花是良好的节水习惯' },
        { hint: '无障碍设施', options: ['盲道', '旋转门', '高台阶', '玻璃幕墙'], correct: 0, explain: '盲道是帮助视障人士出行的重要无障碍设施' }
    ];
    rounds.sort(function() { return Math.random() - 0.5; });
    function renderRound() {
        if (currentRound >= totalRounds) {
            gameState.memorySilver += Math.floor(score / 5);
            document.getElementById('global-silver-balance').textContent = gameState.memorySilver;
            document.getElementById('word-score-text').textContent = '完成词语联想！得分 ' + score + '，获得 +' + Math.floor(score / 5) + ' 记忆银币';
            resultDiv.classList.remove('hidden');
            trackGameComplete('word', score);
            audio.playAwake();
            return;
        }
        var r = rounds[currentRound];
        var hintText = escapeTextForHTML(r.hint);
        var html = '<div class="word-round" style="max-width:500px;margin:0 auto;padding:20px;">';
        html += '<div style="text-align:center;margin-bottom:24px;"><span style="font-size:3rem;">💭</span><h3 style="margin:12px 0;color:var(--accent-gold);">"' + hintText + '" 让你想到什么？</h3></div>';
        html += '<div class="word-options" style="display:grid;gap:12px;">';
        for (var i = 0; i < r.options.length; i++) {
            var optionText = escapeTextForHTML(r.options[i]);
            html += '<button type="button" class="word-option btn-secondary" data-index="' + i + '" aria-label="词语联想选项：' + optionText + '" style="padding:16px 24px;text-align:left;font-size:1.1rem;border-radius:12px;border:2px solid rgba(212,175,55,0.3);background:rgba(255,255,255,0.05);color:var(--text-primary);cursor:pointer;transition:all 0.2s;">' + optionText + '</button>';
        }
        html += '</div>';
        html += '<p style="text-align:center;color:var(--text-muted);margin-top:16px;">第 ' + (currentRound + 1) + ' / ' + totalRounds + ' 题</p>';
        html += '</div>';
        area.innerHTML = html;
        var opts = area.querySelectorAll('.word-option');
        opts.forEach(function(btn) {
            btn.addEventListener('click', function() {
                if (this.disabled) return;
                var idx = parseInt(this.getAttribute('data-index'));
                var correct = rounds[currentRound].correct;
                opts.forEach(function(b, bi) {
                    b.disabled = true;
                    b.setAttribute('aria-disabled', 'true');
                    if (bi === correct) {
                        b.style.borderColor = '#4ade80';
                        b.style.background = 'rgba(74,222,128,0.15)';
                        b.setAttribute('aria-label', '正确选项：' + b.textContent);
                    }
                    else if (bi === idx && idx !== correct) {
                        b.style.borderColor = '#ef4444';
                        b.style.background = 'rgba(239,68,68,0.15)';
                        b.setAttribute('aria-label', '已选择但不正确：' + b.textContent);
                    }
                });
                if (idx === correct) { score += 20; audio.playAwake(); }
                else { score = Math.max(0, score - 5); audio.playError(); }
                scoreEl.textContent = score;
                var explainDiv = document.createElement('div');
                explainDiv.style.cssText = 'margin-top:16px;padding:16px;background:rgba(212,175,55,0.1);border-radius:12px;border-left:4px solid var(--accent-gold);';
                explainDiv.setAttribute('role', 'status');
                explainDiv.innerHTML = safeHTML('<p style="color:var(--text-secondary);margin:0;">' + escapeTextForHTML(rounds[currentRound].explain) + '</p>');
                area.querySelector('.word-round').appendChild(explainDiv);
                trackCognitiveTimeout(function() {
                    if (gameState.currentScreen !== 'screen-word') return;
                    currentRound++;
                    renderRound();
                }, 2000);
            });
        });
    }
    renderRound();
    document.getElementById('btn-word-replay').onclick = function() { initWordGame(); };
    document.getElementById('btn-word-hub').onclick = function() { transitionToScreen('screen-hub'); };
    document.getElementById('btn-word-back').onclick = function() { transitionToScreen('screen-hub'); };
}
function initRhythmGame() {
    cleanupCognitiveRuntime();
    trackGamePlay('rhythm');
    var area = document.getElementById('rhythm-game-area');
    var resultDiv = document.getElementById('rhythm-result');
    var scoreEl = document.getElementById('rhythm-score');
    resultDiv.classList.add('hidden');
    var score = 0, sequence = [], playerSequence = [], level = 1;
    var colors = [
        { id: 'r', color: '#ef4444', emoji: '🔴', name: '红' },
        { id: 'g', color: '#22c55e', emoji: '🟢', name: '绿' },
        { id: 'b', color: '#3b82f6', emoji: '🔵', name: '蓝' },
        { id: 'y', color: '#eab308', emoji: '🟡', name: '黄' }
    ];
    scoreEl.textContent = score;
    var html = '<div style="max-width:400px;margin:0 auto;padding:20px;text-align:center;">';
    html += '<p style="color:var(--text-muted);margin-bottom:16px;">记住灯光闪烁的顺序，然后按顺序点击</p>';
    html += '<div id="rhythm-pad" style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px;">';
    colors.forEach(function(c) {
        html += '<div class="rhythm-btn" data-color="' + escapeTextForHTML(c.id) + '" style="aspect-ratio:1;display:flex;align-items:center;justify-content:center;font-size:2.5rem;background:' + escapeTextForHTML(c.color) + '30;border:3px solid ' + escapeTextForHTML(c.color) + '60;border-radius:16px;cursor:pointer;transition:all 0.15s;opacity:0.6;">' + escapeTextForHTML(c.emoji) + '</div>';
    });
    html += '</div>';
    html += '<p id="rhythm-status" style="font-size:1.1rem;color:var(--accent-gold);">点击"开始"启动游戏</p>';
    html += '<button type="button" class="btn-primary" id="btn-rhythm-start" style="margin-top:12px;">开始游戏</button>';
    html += '</div>';
    area.innerHTML = safeHTML(html);
    var padBtns = area.querySelectorAll('.rhythm-btn');
    var statusEl = document.getElementById('rhythm-status');
    var startBtn = document.getElementById('btn-rhythm-start');
    var isPlaying = false;
    var acceptingInput = false;
    var gameEnded = false;
    var rhythmColorLabels = { r: '红色', g: '绿色', b: '蓝色', y: '黄色' };
    function setPadInputEnabled(enabled) {
        padBtns.forEach(function(btn) {
            btn.setAttribute('aria-disabled', enabled ? 'false' : 'true');
            btn.tabIndex = enabled ? 0 : -1;
        });
    }
    function flashBtn(btn, duration) {
        btn.style.opacity = '1';
        btn.style.transform = 'scale(1.1)';
        btn.style.boxShadow = '0 0 20px ' + btn.style.borderColor;
        trackCognitiveTimeout(function() {
            btn.style.opacity = '0.6';
            btn.style.transform = 'scale(1)';
            btn.style.boxShadow = 'none';
        }, duration);
    }
    function playSequence() {
        isPlaying = true;
        acceptingInput = false;
        setPadInputEnabled(false);
        playerSequence = [];
        statusEl.textContent = '仔细看...';
        startBtn.style.display = 'none';
        var i = 0;
        var interval = trackCognitiveInterval(function() {
            if (i >= sequence.length) {
                clearTrackedCognitiveInterval(interval);
                isPlaying = false;
                if (!gameEnded) {
                    acceptingInput = true;
                    setPadInputEnabled(true);
                    statusEl.textContent = '轮到你了！';
                }
                return;
            }
            var btn = area.querySelector('.rhythm-btn[data-color="' + sequence[i] + '"]');
            flashBtn(btn, 400); i++;
        }, 600);
    }
    function addToSequence() { sequence.push(colors[Math.floor(Math.random() * colors.length)].id); }
    startBtn.addEventListener('click', function() {
        sequence = []; level = 1; score = 0;
        gameEnded = false;
        acceptingInput = false;
        resultDiv.classList.add('hidden');
        statusEl.style.color = 'var(--accent-gold)';
        scoreEl.textContent = score;
        addToSequence(); playSequence();
    });
    padBtns.forEach(function(btn) {
        btn.setAttribute('role', 'button');
        btn.setAttribute('aria-label', '节律按钮：' + (rhythmColorLabels[btn.dataset.color] || '未知颜色'));
        btn.setAttribute('aria-disabled', 'true');
        btn.tabIndex = -1;
        btn.addEventListener('click', function() {
            if (gameEnded || isPlaying || !acceptingInput) return;
            var color = this.getAttribute('data-color');
            flashBtn(this, 200);
            playerSequence.push(color);
            if (playerSequence[playerSequence.length - 1] !== sequence[playerSequence.length - 1]) {
                gameEnded = true;
                acceptingInput = false;
                setPadInputEnabled(false);
                statusEl.textContent = '错了！游戏结束';
                statusEl.style.color = '#ef4444';
                audio.playError();
                gameState.memorySilver += Math.floor(score / 5);
                document.getElementById('global-silver-balance').textContent = gameState.memorySilver;
                document.getElementById('rhythm-score-text').textContent = '节奏复刻结束！到达第 ' + level + ' 关，获得 +' + Math.floor(score / 5) + ' 记忆银币';
                resultDiv.classList.remove('hidden');
                trackGameComplete('rhythm', score);
                return;
            }
            if (playerSequence.length === sequence.length) {
                acceptingInput = false;
                setPadInputEnabled(false);
                score += level * 10;
                scoreEl.textContent = score;
                audio.playAwake();
                level++;
                statusEl.textContent = '正确！第 ' + level + ' 关';
                playerSequence = [];
                trackCognitiveTimeout(function() { addToSequence(); playSequence(); }, 800);
            }
        });
        btn.addEventListener('keydown', function(e) {
            if (e.key !== 'Enter' && e.key !== ' ') return;
            e.preventDefault();
            btn.click();
        });
    });
    document.getElementById('btn-rhythm-replay').onclick = function() { initRhythmGame(); };
    document.getElementById('btn-rhythm-hub').onclick = function() { transitionToScreen('screen-hub'); };
    document.getElementById('btn-rhythm-back').onclick = function() { transitionToScreen('screen-hub'); };
}
function initSpatialGame() {
    cleanupSpatialRuntime();
    cleanupCognitiveRuntime();
    trackGamePlay('spatial');
    var area = document.getElementById('spatial-game-area');
    var resultDiv = document.getElementById('spatial-result');
    var scoreEl = document.getElementById('spatial-score');
    resultDiv.classList.add('hidden');
    var score = 0, moves = 0, maxMoves = 30;
    var playerPos = { x: 0, y: 0 };
    var goalPos = { x: 4, y: 4 };
    var gridSize = 5;
    var gameEnded = false;
    scoreEl.textContent = score;
    var maze = [
        [0,0,1,0,0],
        [1,0,1,0,1],
        [0,0,0,0,0],
        [0,1,1,1,0],
        [0,0,0,0,0]
    ];
    function describePosition(pos) {
        return '第' + (pos.y + 1) + '行第' + (pos.x + 1) + '列';
    }
    function announceSpatial(message) {
        var live = document.getElementById('spatial-live');
        if (live) live.textContent = message;
    }
    function setSpatialControlsEnabled(enabled) {
        area.querySelectorAll('.spatial-dir').forEach(function(btn) {
            btn.disabled = !enabled;
            btn.setAttribute('aria-disabled', enabled ? 'false' : 'true');
        });
    }
    function renderMaze() {
        var html = '<div style="max-width:400px;margin:0 auto;padding:20px;text-align:center;">';
        html += '<p id="spatial-instruction" style="color:var(--text-muted);margin-bottom:12px;">用方向键、WASD 或点击箭头，从🏠走到🌟（避开墙壁）</p>';
        html += '<p id="spatial-live" class="sr-only" aria-live="polite">当前位置：' + describePosition(playerPos) + '，目标：' + describePosition(goalPos) + '</p>';
        html += '<div id="maze-board" role="grid" aria-describedby="spatial-instruction" aria-label="空间定位迷宫，当前位置' + describePosition(playerPos) + '，目标' + describePosition(goalPos) + '" style="display:grid;grid-template-columns:repeat(' + gridSize + ',1fr);gap:4px;margin-bottom:16px;">';
        for (var y = 0; y < gridSize; y++) {
            for (var x = 0; x < gridSize; x++) {
                var isPlayer = (x === playerPos.x && y === playerPos.y);
                var isGoal = (x === goalPos.x && y === goalPos.y);
                var isWall = maze[y][x] === 1;
                var content = isPlayer ? '🏠' : (isGoal ? '🌟' : (isWall ? '🧱' : ''));
                var bg = isWall ? 'rgba(100,80,60,0.5)' : (isGoal ? 'rgba(212,175,55,0.2)' : 'rgba(255,255,255,0.05)');
                var cellLabel = (isPlayer ? '当前位置，' : (isGoal ? '目标，' : (isWall ? '墙壁，' : '通路，'))) + describePosition({ x: x, y: y });
                html += '<div role="gridcell" aria-label="' + cellLabel + '" style="aspect-ratio:1;display:flex;align-items:center;justify-content:center;font-size:1.5rem;background:' + bg + ';border:1px solid rgba(212,175,55,0.2);border-radius:8px;">' + content + '</div>';
            }
        }
        html += '</div>';
        html += '<div style="display:grid;grid-template-columns:repeat(3,60px);gap:8px;justify-content:center;margin-bottom:12px;">';
        html += '<div></div><button type="button" class="spatial-dir btn-secondary" data-dir="up" aria-label="向上移动" style="padding:12px;font-size:1.2rem;">⬆️</button><div></div>';
        html += '<button type="button" class="spatial-dir btn-secondary" data-dir="left" aria-label="向左移动" style="padding:12px;font-size:1.2rem;">⬅️</button>';
        html += '<button type="button" class="spatial-dir btn-secondary" data-dir="down" aria-label="向下移动" style="padding:12px;font-size:1.2rem;">⬇️</button>';
        html += '<button type="button" class="spatial-dir btn-secondary" data-dir="right" aria-label="向右移动" style="padding:12px;font-size:1.2rem;">➡️</button>';
        html += '</div>';
        html += '<p style="color:var(--text-muted);">步数: ' + moves + ' / ' + maxMoves + '</p>';
        html += '</div>';
        area.innerHTML = safeHTML(html);
        area.querySelectorAll('.spatial-dir').forEach(function(btn) {
            btn.addEventListener('click', function() { movePlayer(this.getAttribute('data-dir')); });
        });
        setSpatialControlsEnabled(!gameEnded);
    }
    function movePlayer(dir) {
        if (gameEnded) return;
        var nx = playerPos.x, ny = playerPos.y;
        if (dir === 'up') ny--;
        if (dir === 'down') ny++;
        if (dir === 'left') nx--;
        if (dir === 'right') nx++;
        if (nx < 0 || nx >= gridSize || ny < 0 || ny >= gridSize || maze[ny][nx] === 1) {
            announceSpatial('这一步碰到墙壁或边界，请换个方向。');
            audio.playError(); return;
        }
        playerPos.x = nx; playerPos.y = ny;
        moves++; audio.playSnap();
        if (nx === goalPos.x && ny === goalPos.y) {
            gameEnded = true;
            score = Math.max(0, 100 - moves * 2);
            scoreEl.textContent = score;
            gameState.memorySilver += Math.floor(score / 5);
            document.getElementById('global-silver-balance').textContent = gameState.memorySilver;
            document.getElementById('spatial-score-text').textContent = '成功走出迷宫！用了 ' + moves + ' 步，获得 +' + Math.floor(score / 5) + ' 记忆银币';
            resultDiv.classList.remove('hidden');
            trackGameComplete('spatial', score);
            setSpatialControlsEnabled(false);
            cleanupSpatialRuntime();
            audio.playAwake(); return;
        }
        if (moves >= maxMoves) {
            gameEnded = true;
            score = 0; scoreEl.textContent = score;
            document.getElementById('spatial-score-text').textContent = '步数用尽！再试一次吧';
            resultDiv.classList.remove('hidden');
            trackGameComplete('spatial', 0);
            setSpatialControlsEnabled(false);
            cleanupSpatialRuntime();
            audio.playError(); return;
        }
        renderMaze();
    }
    function handleSpatialKey(e) {
        if (gameState.currentScreen !== 'screen-spatial') return;
        if (gameEnded) return;
        if (e.target && (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.isContentEditable)) return;
        var dirMap = {
            ArrowUp: 'up',
            ArrowDown: 'down',
            ArrowLeft: 'left',
            ArrowRight: 'right',
            w: 'up',
            W: 'up',
            s: 'down',
            S: 'down',
            a: 'left',
            A: 'left',
            d: 'right',
            D: 'right'
        };
        var dir = dirMap[e.key];
        if (!dir) return;
        e.preventDefault();
        movePlayer(dir);
    }
    window._spatialKeyHandler = handleSpatialKey;
    document.addEventListener('keydown', handleSpatialKey);
    renderMaze();
    document.getElementById('btn-spatial-replay').onclick = function() { initSpatialGame(); };
    document.getElementById('btn-spatial-hub').onclick = function() { transitionToScreen('screen-hub'); };
    document.getElementById('btn-spatial-back').onclick = function() { transitionToScreen('screen-hub'); };
}

// ============================================================================
// 统一多模式问答引擎 — 经典/闪电/挑战/判断题模式
// 替换全部17个独立问答游戏的核心逻辑
// ============================================================================
class UnifiedQuizEngine {
    constructor(config) {
        this.gameId = config.gameId; this.questions = config.questions || [];
        this.scoreElId = config.scoreElId; this.progressElId = config.progressElId;
        this.timerElId = config.timerElId; this.comboElId = config.comboElId;
        this.diffContainerId = config.diffContainerId; this.resultDivId = config.resultDivId;
        this.resultScoreId = config.resultScoreId; this.resultTextId = config.resultTextId;
        this.tipElId = config.tipElId; this.gameAreaId = config.gameAreaId;
        this.explainAreaId = config.explainAreaId; this.topic = config.topic || '知识问答';
        this.difficulty = 'easy'; this.mode = 'classic'; this.score = 0; this.combo = 0;
        this.maxCombo = 0; this.streak = 0; this.currentQ = 0; this.totalQ = 0;
        this.timeLeft = 0; this.timerId = null; this.active = false;
        this.nextQuestionTimer = null; this.questionFrameId = null;
    }
    init(difficulty, mode) {
        this.difficulty = difficulty || 'easy'; this.mode = mode || 'classic';
        this.score = 0; this.combo = 0; this.maxCombo = 0; this.streak = 0;
        this.currentQ = 0; this.active = true;
        clearInterval(this.timerId);
        clearTimeout(this.nextQuestionTimer);
        if (this.questionFrameId) cancelAnimationFrame(this.questionFrameId);
        this.nextQuestionTimer = null; this.questionFrameId = null;
        var pool = [...this.questions];
        switch (this.difficulty) {
            case 'normal': pool = pool.slice(0, Math.min(15, pool.length)); break;
            case 'hard': pool = pool.slice(0, Math.min(20, pool.length)); break;
            default: pool = pool.slice(0, Math.min(8, pool.length));
        }
        if (this.mode === 'speed') pool = pool.slice(0, Math.min(10, pool.length));
        this.totalQ = pool.length; this.questions = pool;
        if (this.scoreElId) document.getElementById(this.scoreElId).textContent = '0';
        if (this.progressElId) document.getElementById(this.progressElId).textContent = '0/' + this.totalQ;
        if (this.comboElId) { var ce = document.getElementById(this.comboElId); if (ce) { ce.textContent = '1x'; ce.classList.remove('active'); } }
        if (this.resultDivId) document.getElementById(this.resultDivId).classList.add('hidden');
        if (this.explainAreaId) { var ea = document.getElementById(this.explainAreaId); if (ea) ea.style.display = 'none'; }
        if (this.tipElId) {
            var tips = { classic: '📝 经典模式 · ' + this.topic, speed: '⚡ 闪电模式！每题8秒！', challenge: '💀 挑战模式！答错即结束！' };
            document.getElementById(this.tipElId).textContent = tips[this.mode] || tips.classic;
        }
        if (this.mode === 'speed') { this.timeLeft = this.totalQ * 8; this._startTimer(); }
        else if (this.difficulty === 'hard') { this.timeLeft = this.totalQ * 15; this._startTimer(); }
        else { if (this.timerElId) document.getElementById(this.timerElId).textContent = '∞'; }
        trackGamePlay(this.gameId);
        this._renderQuestion();
    }
    _startTimer() {
        var self = this;
        if (this.timerElId) document.getElementById(this.timerElId).textContent = this.timeLeft + 's';
        this.timerId = setInterval(function() {
            self.timeLeft--;
            if (self.timerElId) { var t = document.getElementById(self.timerElId); if (t) { t.textContent = self.timeLeft + 's'; t.style.color = self.timeLeft < 10 ? '#ff4444' : ''; } }
            if (self.timeLeft <= 0) { self._onGameEnd(); }
        }, 1000);
    }
    _renderQuestion() {
        if (this.currentQ >= this.totalQ || !this.active) { this._onGameEnd(); return; }
        var q = this.questions[this.currentQ];
        var area = document.getElementById(this.gameAreaId);
        if (!area) return;
        if (this.progressElId) document.getElementById(this.progressElId).textContent = (this.currentQ + 1) + '/' + this.totalQ;
        var mb = ''; if (this.mode === 'speed') mb = '<span class="quiz-badge speed">⚡</span>';
        else if (this.mode === 'challenge') mb = '<span class="quiz-badge challenge">💀</span>';
        else if (this.difficulty === 'hard') mb = '<span class="quiz-badge hard">🔥</span>';
        var questionText = escapeTextForHTML((q.emoji ? q.emoji + ' ' : '') + (q.text || ''));
        area.innerHTML = safeHTML('<div class="quiz-question-card"><div class="quiz-q-header">' + mb + '<span>第' + (this.currentQ + 1) + '/' + this.totalQ + '题</span></div>' +
            '<p class="quiz-q-text">' + questionText + '</p>' +
            '<div class="quiz-options" id="' + this.gameId + '-options"></div></div>');
        var self = this;
        var ops = document.getElementById(this.gameId + '-options');
        if (q.type === 'truefalse' && !q.options) q.options = ['✅ 正确/是', '❌ 错误/否'];
        q.options.forEach(function(opt, idx) {
            var btn = createButtonElement();
            btn.className = 'quiz-option-btn'; btn.textContent = opt;
            btn.addEventListener('click', function() { if (self._answered) return; self._answered = true; self._checkAnswer(idx); });
            ops.appendChild(btn);
        });
        if (this.mode === 'speed') {
            var tb = document.createElement('div'); tb.className = 'quiz-question-timer'; tb.innerHTML = '<div class="qt-fill" id="' + this.gameId + '-qt-fill" style="width:100%;background:#22c55e;"></div>';
            ops.parentNode.insertBefore(tb, ops);
            var fill = document.getElementById(this.gameId + '-qt-fill');
            var st = Date.now(), qt = 8;
            (function anim() {
                if (!self.active || self._answered) return;
                var e = (Date.now() - st) / 1000;
                var p = Math.max(0, 100 - (e / qt) * 100);
                if (fill) { fill.style.width = p + '%'; fill.style.background = p < 30 ? '#ff4444' : p < 60 ? '#ffaa00' : '#22c55e'; }
                if (p > 0) self.questionFrameId = requestAnimationFrame(anim);
            })();
        }
        this._answered = false;
    }
    _checkAnswer(idx) {
        if (!this.active) return;
        var q = this.questions[this.currentQ];
        var correct = idx === q.correct;
        if (correct) {
            this.streak++; if (this.streak > this.maxCombo) this.maxCombo = this.streak;
            this.score += 20 * Math.min(Math.floor(this.streak / 3) + 1, 5);
            if (typeof audio !== 'undefined' && audio.playSnap) audio.playSnap();
            if (this.comboElId && this.streak >= 3) { var ce = document.getElementById(this.comboElId); if (ce) { ce.textContent = Math.min(Math.floor(this.streak / 3) + 1, 5) + 'x'; ce.classList.add('active'); } }
        } else {
            this.streak = 0; this.score = Math.max(0, this.score - 5);
            if (this.comboElId) { var ce = document.getElementById(this.comboElId); if (ce) { ce.textContent = '1x'; ce.classList.remove('active'); } }
            if (typeof audio !== 'undefined' && audio.playError) audio.playError();
            if (this.mode === 'challenge') { this._onGameEnd(); return; }
        }
        if (this.scoreElId) document.getElementById(this.scoreElId).textContent = this.score;
        if (this.explainAreaId) { var ea = document.getElementById(this.explainAreaId); if (ea) { ea.textContent = (correct ? '✅' : '❌') + ' ' + (q.explain || ''); ea.style.display = 'block'; } }
        var self = this; this.currentQ++;
        clearTimeout(this.nextQuestionTimer);
        this.nextQuestionTimer = setTimeout(function() {
            if (!self.active) return;
            if (self.explainAreaId) { var ea = document.getElementById(self.explainAreaId); if (ea) ea.style.display = 'none'; }
            self._renderQuestion();
        }, 1200);
    }
    _onGameEnd() {
        if (!this.active) return; this.active = false;
        clearInterval(this.timerId);
        clearTimeout(this.nextQuestionTimer);
        if (this.questionFrameId) cancelAnimationFrame(this.questionFrameId);
        this.nextQuestionTimer = null; this.questionFrameId = null;
        var bonus = unifiedRewardCalc(this.score, this.maxCombo, this.difficulty, 0, Math.round((this.currentQ / this.totalQ) * 100));
        if (this.resultTextId) document.getElementById(this.resultTextId).textContent = '🎉 ' + this.topic + '完成！得分' + this.score + '，+ ' + bonus + ' 银币';
        if (this.resultScoreId) document.getElementById(this.resultScoreId).textContent = this.score + '分';
        if (this.resultDivId) document.getElementById(this.resultDivId).classList.remove('hidden');
        trackGameComplete(this.gameId, this.score);
        if (typeof audio !== 'undefined' && audio.playAwake) audio.playAwake();
    }
    destroy() {
        this.active = false;
        clearInterval(this.timerId);
        clearTimeout(this.nextQuestionTimer);
        if (this.questionFrameId) cancelAnimationFrame(this.questionFrameId);
        this.timerId = null;
        this.nextQuestionTimer = null;
        this.questionFrameId = null;
    }
}

var _activeQuizEngine = null;

// ============================================================================
// 问答冒险引擎 — 将枯燥问答题转换为沉浸式闯关游戏
// 支持：路径探险 / 限时解谜 / BOSS挑战 / 道具系统
// ============================================================================

var QUestTheme = {
    water:   { icon:'💧', map:'🌊 节水之旅', char:'🧑‍🔬', enemy:'🦠', boss:'🐙', bg:'linear-gradient(135deg,#0a1628,#0d3b5c)', path:'#00b4d8' },
    carbon:  { icon:'🌍', map:'🌿 减碳之路', char:'🧑‍🌾', enemy:'💨', boss:'🏭', bg:'linear-gradient(135deg,#0d1a0a,#163618)', path:'#4ade80' },
    repair:  { icon:'🔧', map:'🛠️ 修复工坊', char:'👩‍🔧', enemy:'🔩', boss:'💥', bg:'linear-gradient(135deg,#1a1512,#2d2418)', path:'#d4a017' },
    aid:     { icon:'🩺', map:'🚑 急救前线', char:'👨‍⚕️', enemy:'🩸', boss:'💀', bg:'linear-gradient(135deg,#1a0a0a,#2d1515)', path:'#ef4444' },
    food:    { icon:'🍎', map:'🥗 食安卫士', char:'👩‍🍳', enemy:'🦠', boss:'☣️', bg:'linear-gradient(135deg,#1a1508,#2d2410)', path:'#facc15' },
    animal:  { icon:'🐾', map:'🦁 动物守护', char:'🧑‍🌿', enemy:'🎯', boss:'🏹', bg:'linear-gradient(135deg,#0a1a0d,#102815)', path:'#22c55e' },
    phish:   { icon:'🎣', map:'🛡️ 反钓前线', char:'🕵️', enemy:'🎭', boss:'👾', bg:'linear-gradient(135deg,#1a0a1a,#2518)', path:'#a855f7' },
    script:  { icon:'📜', map:'🔍 话术破译', char:'🕵️‍♀️', enemy:'💬', boss:'🪤', bg:'linear-gradient(135deg,#1a0a12,#251520)', path:'#ec4899' },
    identity:{ icon:'🪪', map:'🔐 身份护卫', char:'🛡️', enemy:'👤', boss:'🎭', bg:'linear-gradient(135deg,#0a101a,#15202d)', path:'#3b82f6' },
    transfer:{ icon:'💳', map:'💰 安全转账', char:'🏦', enemy:'🃏', boss:'💸', bg:'linear-gradient(135deg,#1a100a,#2d1a10)', path:'#f97316' },
    leak:    { icon:'🔓', map:'🔒 信息堡垒', char:'🗝️', enemy:'📤', boss:'🌐', bg:'linear-gradient(135deg,#0a0a1a,#10152d)', path:'#6366f1' },
    evidence:{ icon:'📋', map:'🔗 证据之链', char:'👮', enemy:'📄', boss:'⚖️', bg:'linear-gradient(135deg,#1a1a0a,#2d2d10)', path:'#eab308' },
    alert:   { icon:'🚨', map:'⚠️ 预警雷达', char:'📡', enemy:'📢', boss:'🌋', bg:'linear-gradient(135deg,#1a0a00,#2d1500)', path:'#f43f5e' },
    forest:  { icon:'🌲', map:'🌳 森林卫士', char:'🧑‍🌲', enemy:'🪓', boss:'🔥', bg:'linear-gradient(135deg,#0a1a0a,#102810)', path:'#22c55e' },
    light:   { icon:'💡', map:'🌟 光明使者', char:'🔦', enemy:'🌑', boss:'💫', bg:'linear-gradient(135deg,#1a1a0a,#2d2d10)', path:'#fbbf24' },
    seed:    { icon:'🌰', map:'🌱 种子银行', char:'🧑‍🔬', enemy:'🐛', boss:'🌪️', bg:'linear-gradient(135deg,#0a1a10,#152d18)', path:'#84cc16' },
    civil:   { icon:'🏛️', map:'⚖️ 文明使者', char:'👩‍⚖️', enemy:'📜', boss:'🏗️', bg:'linear-gradient(135deg,#1a150a,#2d2010)', path:'#d4a017' }
};

class QAdventureEngine {
    constructor(config) {
        this.gameId = config.gameId;
        this.themeId = config.themeId || 'water';
        this.questions = config.questions || [];
        this.areaElId = config.areaElId;
        this.scoreElId = config.scoreElId;
        this.resultDivId = config.resultDivId;
        this.resultTextId = config.resultTextId;
        this.tipElId = config.tipElId;

        this.theme = QUestTheme[this.themeId] || QUestTheme.water;
        this.currentQ = 0; this.score = 0; this.combo = 0; this.maxCombo = 0;
        this.totalQ = 0; this.timeLeft = 0; this.timerId = null;
        this.active = false; this.answered = false;
        this.playerPos = 0; this.lives = 2;
        this.powerUps = { hint: 2, shield: 1, double: 1 };
        this._shieldActive = false; this._doubleActive = false;
        this.nextQuestionTimer = null;
        this.questionAnimTimer = null;
        this.nodeErrorTimer = null;
        this.charJumpTimer = null;
    }

    init() {
        this._clearTimers();
        this.currentQ = 0; this.score = 0; this.combo = 0; this.maxCombo = 0;
        this.active = true; this.answered = false;
        this.playerPos = 0; this.lives = 2;
        this.powerUps = { hint: 2, shield: 1, double: 1 };
        this._shieldActive = false; this._doubleActive = false;

        var pool = [...this.questions].slice(0, 8);
        this.totalQ = pool.length;
        this.questions = pool;
        this.timeLeft = 90;

        if (this.scoreElId) document.getElementById(this.scoreElId).textContent = '0';
        if (this.resultDivId) document.getElementById(this.resultDivId).classList.add('hidden');

        this._renderAdventure();
        this._startTimer();
        trackGamePlay(this.gameId);
    }

    _startTimer() {
        var self = this;
        this.timerId = setInterval(function() {
            if (!self.active) return;
            self.timeLeft--;
            var bar = document.getElementById(self.gameId + '-timebar-fill');
            if (bar) {
                var pct = (self.timeLeft / 90) * 100;
                bar.style.width = pct + '%';
                bar.style.background = pct < 25 ? '#ef4444' : pct < 50 ? '#f97316' : self.theme.path;
            }
            if (self.timeLeft <= 0) self._onGameEnd();
        }, 1000);
    }

    _renderAdventure() {
        var area = document.getElementById(this.areaElId);
        if (!area) return;

        var t = this.theme;
        var pathNodes = '';
        for (var i = 0; i < this.totalQ; i++) {
            var cls = i < this.playerPos ? 'ap-node done' : (i === this.playerPos ? 'ap-node current' : 'ap-node');
            var icon = i < this.playerPos ? '✅' : (i === this.totalQ - 1 ? t.boss : '⬡');
            pathNodes += '<div class="' + cls + '" style="left:' + (5 + (i / (this.totalQ - 1)) * 90) + '%;" id="' + this.gameId + '-node-' + i + '">' +
                '<span class="ap-node-icon">' + icon + '</span></div>';
        }

        area.innerHTML =
            '<div class="adventure-panel" style="background:' + t.bg + ';">' +
            // Top bar
            '<div class="ap-topbar">' +
                '<span class="ap-title">' + t.icon + ' ' + t.map + '</span>' +
                '<span class="ap-stats">连击 <strong id="' + this.gameId + '-combo">0</strong> · 得分 <strong id="' + this.gameId + '-score">0</strong> · 生命 <strong id="' + this.gameId + '-lives">2</strong></span>' +
            '</div>' +
            // Time bar
            '<div class="ap-timebar"><div class="ap-timebar-fill" id="' + this.gameId + '-timebar-fill" style="width:100%;background:' + t.path + ';"></div></div>' +
            // Path area
            '<div class="ap-path-area">' +
                '<div class="ap-path-line" style="background:' + t.path + ';"></div>' +
                '<div class="ap-path-nodes">' + pathNodes + '</div>' +
                '<div class="ap-char" id="' + this.gameId + '-char" style="left:' + (5 + (Math.min(this.playerPos, Math.max(0, this.totalQ - 1)) / Math.max(1, this.totalQ - 1)) * 90) + '%;">' + t.char + '</div>' +
            '</div>' +
            // Question encounter
            '<div class="ap-encounter glass-panel" id="' + this.gameId + '-encounter">' +
                '<div class="ap-encounter-header"><span class="ap-enemy-icon">' + t.enemy + '</span><span id="' + this.gameId + '-stage">第<b>' + (this.currentQ + 1) + '</b>/' + this.totalQ + ' 关</span></div>' +
                '<p class="ap-question" id="' + this.gameId + '-qtext"></p>' +
                '<div class="ap-options" id="' + this.gameId + '-options"></div>' +
                '<div class="ap-explain" id="' + this.gameId + '-explain"></div>' +
            '</div>' +
            // Power-ups
            '<div class="ap-powerups">' +
                '<button type="button" class="ap-pu-btn" id="' + this.gameId + '-pu-hint" title="提示：排除两个错误选项">提示 ×<span id="' + this.gameId + '-hint-count">2</span></button>' +
                '<button type="button" class="ap-pu-btn" id="' + this.gameId + '-pu-shield" title="护盾：本题答错也能继续前进">护盾 ×<span id="' + this.gameId + '-shield-count">1</span></button>' +
                '<button type="button" class="ap-pu-btn" id="' + this.gameId + '-pu-double" title="双倍：本题答对得分翻倍">双倍 ×<span id="' + this.gameId + '-double-count">1</span></button>' +
            '</div>' +
            '</div>';

        this._bindPowerButtons();
        this._renderQuestion();
    }

    _bindPowerButtons() {
        var self = this;
        ['hint', 'shield', 'double'].forEach(function(type) {
            var btn = document.getElementById(self.gameId + '-pu-' + type);
            if (!btn) return;
            btn.addEventListener('click', function() {
                self.usePower(type);
            });
        });
    }

    _renderQuestion() {
        if (this.currentQ >= this.totalQ || !this.active) { this._onGameEnd(); return; }
        var q = this.questions[this.currentQ];
        if (!q) return;

        document.getElementById(this.gameId + '-qtext').textContent = '「' + q.text + '」';
        if (this.scoreElId) document.getElementById(this.scoreElId).textContent = this.score;
        var stage = document.getElementById(this.gameId + '-stage');
        if (stage) stage.innerHTML = '第<b>' + (this.currentQ + 1) + '</b>/' + this.totalQ + ' 关';

        // Highlight current node
        document.querySelectorAll('.ap-node').forEach(function(n) { n.classList.remove('current'); });
        var node = document.getElementById(this.gameId + '-node-' + this.currentQ);
        if (node) node.classList.add('current');

        var ops = document.getElementById(this.gameId + '-options');
        ops.innerHTML = '';
        var self = this;
        q.options.forEach(function(opt, idx) {
            var btn = createButtonElement();
            btn.type = 'button';
            btn.className = 'ap-option-btn';
            btn.dataset.optionIndex = String(idx);
            btn.textContent = (['A.','B.','C.','D.'][idx] || '') + ' ' + opt;
            btn.setAttribute('role', 'button');
            btn.setAttribute('aria-label', '冒险答题选项' + (['A','B','C','D'][idx] || String(idx + 1)) + '：' + opt);
            btn.addEventListener('click', function() {
                if (self.answered) return;
                self.answered = true;
                self._checkAnswer(idx);
            });
            ops.appendChild(btn);
        });

        this.answered = false;
        this._updatePowerUI();
    }

    _checkAnswer(idx) {
        if (!this.active) return;
        var q = this.questions[this.currentQ];
        var correct = idx === q.correct;
        var area = document.getElementById(this.areaElId);
        var savedByShield = !correct && this._shieldActive;
        var doubleWasActive = this._doubleActive;
        this._shieldActive = false;
        this._doubleActive = false;

        // Highlight buttons
        var btns = area ? area.querySelectorAll('.ap-option-btn') : [];
        btns.forEach(function(b, i) {
            b.style.pointerEvents = 'none';
            b.disabled = true;
            b.setAttribute('aria-disabled', 'true');
            if (i === q.correct) b.classList.add('correct');
            if (i === idx && !correct) b.classList.add('wrong');
            if (i === idx && savedByShield) b.classList.add('saved');
        });

        var explain = document.getElementById(this.gameId + '-explain');
        var answerLabel = (['A','B','C','D'][q.correct] || String(q.correct + 1));
        if (explain) {
            if (correct) {
                explain.textContent = '✅ 正确：' + (q.explain || '继续保持。');
            } else if (savedByShield) {
                explain.textContent = '🛡️ 护盾生效：正确答案是 ' + answerLabel + '。' + (q.explain || '本题不扣生命。');
            } else {
                explain.textContent = '❌ 正确答案是 ' + answerLabel + '。' + (q.explain || '再试一次会更稳。');
            }
            explain.style.display = 'block';
        }

        if (correct) {
            this.combo++;
            if (this.combo > this.maxCombo) this.maxCombo = this.combo;
            var bonus = this.combo >= 5 ? 3 : this.combo >= 3 ? 2 : 1;
            var gained = 20 * bonus * (doubleWasActive ? 2 : 1);
            this.score += gained;
            if (doubleWasActive) showGameplayToast('双倍生效，本题积分翻倍。', 'success');
            this._advancePlayer('✅');

            // visual feedback
            if (area) {
                var qel = area.querySelector('.ap-question');
                if (qel) {
                    qel.style.animation = 'none';
                    this._setTimer('questionAnimTimer', function() { qel.style.animation = ''; }, 10);
                }
            }

            spawnScoreParticle(window.innerWidth / 2, window.innerHeight / 2 - 80, '+' + gained, '#22c55e');
            if (this.combo >= 3) spawnComboBurst(window.innerWidth / 2, window.innerHeight / 2, 6, this.theme.path);
            if (typeof audio !== 'undefined' && audio.playSnap) audio.playSnap();
        } else if (savedByShield) {
            this._advancePlayer('🛡️');
            showGameplayToast('护盾生效，本题不扣生命。', 'hint');
            if (typeof audio !== 'undefined' && audio.playSnap) audio.playSnap();
        } else {
            this.combo = 0;
            this.lives = Math.max(0, this.lives - 1);
            this.timeLeft = Math.max(0, this.timeLeft - 5);
            // Shake
            var enc = document.getElementById(this.gameId + '-encounter');
            if (enc) shakeElement(enc);
            if (typeof audio !== 'undefined' && audio.playError) audio.playError();
            // Temp node flash red
            var cnode = document.getElementById(this.gameId + '-node-' + this.currentQ);
            if (cnode) {
                cnode.classList.add('error');
                this._setTimer('nodeErrorTimer', function() { cnode.classList.remove('error'); }, 600);
            }
            if (this.lives <= 0) showGameplayToast('生命耗尽，本轮结束。', 'hint');
        }

        this._updatePowerUI();
        var self = this;
        this.currentQ++;
        this._setTimer('nextQuestionTimer', function() {
            if (explain) explain.style.display = 'none';
            if (self.lives <= 0 || self.currentQ >= self.totalQ) self._onGameEnd();
            else self._renderQuestion();
        }, 1500);
    }

    _advancePlayer(nodeIcon) {
        this.playerPos = Math.min(this.totalQ, this.playerPos + 1);
        var visualPos = Math.min(this.playerPos, Math.max(0, this.totalQ - 1));
        var char = document.getElementById(this.gameId + '-char');
        if (char) {
            char.style.left = (5 + (visualPos / Math.max(1, this.totalQ - 1)) * 90) + '%';
            char.classList.add('jumping');
            this._setTimer('charJumpTimer', function() { char.classList.remove('jumping'); }, 400);
        }
        var pnode = document.getElementById(this.gameId + '-node-' + this.currentQ);
        if (pnode) {
            pnode.classList.add('done');
            var icon = pnode.querySelector('.ap-node-icon');
            if (icon && nodeIcon) icon.textContent = nodeIcon;
        }
    }

    _updatePowerUI() {
        var self = this;
        var setText = function(id, value) {
            var el = document.getElementById(self.gameId + id);
            if (el) el.textContent = String(value);
        };
        setText('-combo', this.combo);
        setText('-score', this.score);
        setText('-lives', this.lives);
        setText('-hint-count', this.powerUps.hint);
        setText('-shield-count', this.powerUps.shield);
        setText('-double-count', this.powerUps.double);
        if (this.scoreElId) {
            var scoreEl = document.getElementById(this.scoreElId);
            if (scoreEl) scoreEl.textContent = this.score;
        }

        var q = this.questions[this.currentQ];
        var ops = document.getElementById(this.gameId + '-options');
        var wrongAvailable = 0;
        if (ops && q) {
            ops.querySelectorAll('.ap-option-btn:not(.eliminated)').forEach(function(btn) {
                if (Number(btn.dataset.optionIndex) !== q.correct) wrongAvailable++;
            });
        }

        var hintBtn = document.getElementById(this.gameId + '-pu-hint');
        var shieldBtn = document.getElementById(this.gameId + '-pu-shield');
        var doubleBtn = document.getElementById(this.gameId + '-pu-double');
        var syncPowerButton = function(btn, label, count, disabled, active) {
            if (!btn) return;
            btn.disabled = disabled;
            btn.setAttribute('role', 'button');
            btn.setAttribute('aria-label', label + '，剩余' + count + '次' + (active ? '，已启用' : ''));
            btn.setAttribute('aria-disabled', disabled ? 'true' : 'false');
            btn.setAttribute('aria-pressed', active ? 'true' : 'false');
        };
        syncPowerButton(hintBtn, '提示道具：排除错误选项', this.powerUps.hint, this.answered || this.powerUps.hint <= 0 || wrongAvailable <= 0, false);
        if (shieldBtn) {
            syncPowerButton(shieldBtn, '护盾道具：本题答错也能继续', this.powerUps.shield, this.answered || this.powerUps.shield <= 0 || this._shieldActive, this._shieldActive);
            shieldBtn.classList.toggle('active', this._shieldActive);
        }
        if (doubleBtn) {
            syncPowerButton(doubleBtn, '双倍道具：本题答对得分翻倍', this.powerUps.double, this.answered || this.powerUps.double <= 0 || this._doubleActive, this._doubleActive);
            doubleBtn.classList.toggle('active', this._doubleActive);
        }
    }

    _onGameEnd() {
        if (!this.active) return;
        this.active = false;
        this._clearTimers();

        var accuracy = Math.round((this.playerPos / Math.max(1, this.totalQ)) * 100);
        var bonus = unifiedRewardCalc(this.score, this.maxCombo, 'normal', this.timeLeft > 0 ? this.timeLeft : 0, accuracy);
        if (this.resultTextId) {
            var status = this.lives > 0 && this.currentQ >= this.totalQ ? '闯关完成' : (this.timeLeft <= 0 ? '时间到' : '本轮结束');
            document.getElementById(this.resultTextId).textContent = '🎉 ' + this.theme.map + ' ' + status + '！得分 ' + this.score + '，最高连击 ' + this.maxCombo + '，剩余生命 ' + this.lives + '，+ ' + bonus + ' 银币';
        }
        if (this.resultDivId) document.getElementById(this.resultDivId).classList.remove('hidden');
        trackGameComplete(this.gameId, this.score);
        if (typeof audio !== 'undefined' && audio.playAwake) audio.playAwake();
        spawnComboBurst(window.innerWidth / 2, window.innerHeight / 2, 20, this.theme.path);
    }

    usePower(type) {
        if (!this.active || this.answered) return;
        var q = this.questions[this.currentQ];
        if (!q || !this.powerUps[type] || this.powerUps[type] <= 0) {
            this._updatePowerUI();
            return;
        }

        if (type === 'hint') {
            var ops = document.getElementById(this.gameId + '-options');
            if (!ops) return;
            var wrong = Array.prototype.filter.call(ops.querySelectorAll('.ap-option-btn:not(.eliminated)'), function(btn) {
                return Number(btn.dataset.optionIndex) !== q.correct;
            });
            if (!wrong.length) {
                this._updatePowerUI();
                return;
            }
            wrong.sort(function() { return Math.random() - 0.5; }).slice(0, 2).forEach(function(btn) {
                btn.classList.add('eliminated');
                btn.disabled = true;
                btn.setAttribute('aria-disabled', 'true');
                btn.setAttribute('aria-label', '已排除：' + btn.textContent.trim());
            });
            this.powerUps.hint--;
            showGameplayToast('已排除错误选项。', 'hint');
        } else if (type === 'shield') {
            this.powerUps.shield--;
            this._shieldActive = true;
            showGameplayToast('护盾已启用，本题答错不扣生命。', 'hint');
        } else if (type === 'double') {
            this.powerUps.double--;
            this._doubleActive = true;
            showGameplayToast('双倍已启用，本题答对积分翻倍。', 'hint');
        }
        this._updatePowerUI();
    }

    _setTimer(name, callback, delay) {
        var self = this;
        if (this[name]) clearTimeout(this[name]);
        this[name] = setTimeout(function() {
            self[name] = null;
            if (!self.active) return;
            callback();
        }, delay);
        return this[name];
    }

    _clearTimers() {
        clearInterval(this.timerId);
        clearTimeout(this.nextQuestionTimer);
        clearTimeout(this.questionAnimTimer);
        clearTimeout(this.nodeErrorTimer);
        clearTimeout(this.charJumpTimer);
        this.timerId = null;
        this.nextQuestionTimer = null;
        this.questionAnimTimer = null;
        this.nodeErrorTimer = null;
        this.charJumpTimer = null;
    }

    destroy() {
        this.active = false;
        this._clearTimers();
    }
}


function initWaterGame() {
    var resultDiv = document.getElementById('water-result');
    if (resultDiv) resultDiv.classList.add('hidden');
    var questions = [
        { text: "刷牙时不关水龙头，一次会浪费多少升水？", options: ["约6升", "约0.5升", "约1升", "不浪费水"], correct: 0, explain: "刷牙时如果不关水龙头，一次大约会浪费6升水，足够一个缺水地区的人一天的饮用量。" },
        { text: "以下哪种行为最节水？", options: ["用盆接水洗菜", "直接用水龙头冲菜", "长时间浸泡蔬菜", "用流水洗碗"], correct: 0, explain: "用盆接水洗菜可以循环利用水，是最节水的方式。" },
        { text: "一个漏水的水龙头，一个月会浪费多少水？", options: ["约1吨", "约100升", "约10升", "不会浪费"], correct: 0, explain: "一个滴水的水龙头一个月约浪费1吨水，请及时修理。" },
        { text: "洗澡时使用淋浴比盆浴节水多少？", options: ["节水约50%", "不节水", "盆浴更节水", "节水约10%"], correct: 0, explain: "淋浴比盆浴节水约50%，建议控制淋浴时间在10分钟内。" },
        { text: "以下哪项不是家庭节水的好方法？", options: ["马桶水箱放砖头", "收集雨水浇花", "使用节水龙头", "长时间开水龙头解冻食物"], correct: 3, explain: "长时间开水龙头解冻食物非常浪费水，应提前放入冷藏室解冻。" },
        { text: "家用洗衣机「满载」比「半载」平均每次可节水约多少？", options: ["约30-40升", "约5升", "约80升", "不节水"], correct: 0, explain: "洗衣机满载运行比多次半载更节水，每次可节省30-40升自来水。" },
        { text: "我国人均水资源量约为世界平均水平的多少？", options: ["约1/4", "约1/2", "约相等", "约2倍"], correct: 0, explain: "我国人均水资源仅约世界平均水平的1/4，是全球13个最缺水国家之一。" },
        { text: "以下哪种 landscaping 方式最节水？", options: ["种植本地耐旱植物", "铺设天然草坪", "每天喷灌2次", "种植热带植物"], correct: 0, explain: "本地耐旱植物适应本地气候，无需大量浇灌，是节水园艺的首选。" },
        { text: "淘米水最适合用来？", options: ["浇花/洗碗（去油）", "直接饮用", "冲马桶", "洗衣服"], correct: 0, explain: "淘米水含有淀粉和维生素，是很好的植物营养液，也可用于去油洗碗。" },
        { text: "家用净水器产生的「废水」约占进水量的？", options: ["约50-70%", "约10%", "约90%", "不产生废水"], correct: 0, explain: "反渗透净水器的工作中约50-70%的水被排掉，建议将废水收集用于拖地冲厕。" }
    ,
        { text: '世界上大约有多少人缺乏安全饮用水？', options: ['约20亿人','约5亿人','约1000万人','约500万人'], correct: 0, explain: '全球约20亿人生活在严重缺水的地区，缺乏安全的饮用水源。' },
        { text: '生产1公斤牛肉大约需要多少升水？', options: ['约15000升','约500升','约2000升','约5000升'], correct: 0, explain: '畜牧业是水资源消耗大户，生产1公斤牛肉需要约15000升水(含饲料种植)。' },
        { text: '以下哪种灌溉方式最节水？', options: ['滴灌','漫灌','喷灌','沟灌'], correct: 0, explain: '滴灌可将水直接输送到植物根部，节水效率可达90%以上。' },
        { text: '地球上淡水资源占总水量的比例约为？', options: ['约2.5%','约25%','约50%','约10%'], correct: 0, explain: '地球上的淡水资源仅占总水量的约2.5%，且大部分以冰川形式存在。' },
        { text: '家庭中使用水量最大的是？', options: ['冲厕','饮用','洗碗','洗衣'], correct: 0, explain: '冲厕用水约占家庭用水量的30-40%，使用节水马桶可显著减少用水。' },
        { text: '联合国将每年几月几日定为世界水日？', options: ['3月22日','6月5日','4月22日','10月16日'], correct: 0, explain: '1993年起，每年3月22日为世界水日，旨在唤起公众节水意识。' },
        { text: '我国南水北调工程主要解决什么问题？', options: ['北方缺水问题','南方缺水问题','防洪问题','发电问题'], correct: 0, explain: '南水北调将长江流域水资源调往华北和西北，缓解北方地区严重缺水。' },
        { text: '以下哪种做法不利于保护水资源？', options: ['大量使用化肥农药','植树造林','修建梯田','保护湿地'], correct: 0, explain: '化肥和农药会通过径流污染河流和地下水，威胁水资源安全。' },
        { text: '工业冷却水循环利用可节水约多少？', options: ['90%以上','约30%','约50%','约10%'], correct: 0, explain: '工业冷却水循环利用系统可将水资源重复利用率提高到90%以上。' },
        { text: '一个城市居民每天平均用水量约为？', options: ['100-200升','10-20升','1000升','500升'], correct: 0, explain: '城市居民人均日用水量约100-200升，包括饮用、洗漱、冲厕等。' },
        { text: '雨水收集系统的主要优点不包括？', options: ['增加地下水污染','减少自来水使用','减轻排水压力','绿化浇灌'], correct: 0, explain: '雨水收集系统可减少自来水使用、减轻排水压力和用于灌溉，不会增加污染。' },
        { text: '我国水资源时空分布的主要特点是？', options: ['南多北少，夏多冬少','均匀分布','北多南少','冬多夏少'], correct: 0, explain: '我国水资源南多北少，且降水集中在夏季，时空分布极不均匀。' },
        { text: '海绵城市建设的核心理念是？', options: ['吸水蓄水渗水净水','快速排水','全部硬化','填湖造地'], correct: 0, explain: '海绵城市通过渗、滞、蓄、净、用、排等措施，实现雨水的自然积存与利用。' },
        { text: '农业用水占我国总用水量的比例约为？', options: ['约60%','约20%','约10%','约90%'], correct: 0, explain: '农业是我国第一用水大户，约占总用水量的60%，推广节水灌溉意义重大。' },
        { text: '以下哪条河流不是我国的母亲河？', options: ['尼罗河','长江','黄河','珠江'], correct: 0, explain: '尼罗河位于非洲。长江和黄河都是中华民族的母亲河。' },
        { text: '水体富营养化的主要原因是？', options: ['氮磷过量排放','重金属污染','石油泄漏','放射性污染'], correct: 0, explain: '农业和生活污水中的氮磷排入水体，导致藻类疯长，造成富营养化。' },
        { text: '使用节水型洗衣机每次可节水约？', options: ['30-50%','不到5%','约80%','不节水'], correct: 0, explain: '节水型洗衣机通过优化水流设计和程序控制，可节水30-50%。' },
        { text: '废水处理的主要步骤是？', options: ['物理-生物-化学处理','直接排放','只过滤不处理','加漂白剂'], correct: 0, explain: '现代污水处理通常经过物理沉淀、生物降解和化学消毒三级处理。' },
        { text: '地下水过度开采的主要后果是？', options: ['地面沉降和水质恶化','水资源增加','土壤更肥沃','气温升高'], correct: 0, explain: '过度开采地下水会导致地面沉降、海水入侵和水质恶化。' },
        { text: '家庭中最简单的节水方法是什么？', options: ['随手关紧水龙头','不洗澡','不洗衣服','不冲厕所'], correct: 0, explain: '随手关紧水龙头是最简单有效的节水方法，一个滴水龙头月浪费约1吨水。' },
        { text: '水资源属于哪种类型的资源？', options: ['可再生但有限资源','不可再生资源','无限资源','人造资源'], correct: 0, explain: '水是可再生资源但并非无限，全球可用的淡水资源非常有限。' },
        { text: '以下哪种水体含盐量最高？', options: ['海水','河水','湖水','地下水'], correct: 0, explain: '海水含盐量约3.5%，远高于淡水，不能直接饮用。' },
        { text: '中水利用是指？', options: ['将处理后的生活污水回用于非饮用用途','直接饮用回收水','海水淡化','雨水收集'], correct: 0, explain: '中水利用将处理后的生活污水用于冲厕、绿化等非饮用用途。' },
        { text: '世界水日2025年的主题聚焦什么？', options: ['冰川保护与水安全','海洋保护','大气污染','森林砍伐'], correct: 0, explain: '冰川是全球重要的淡水库，气候变化加速冰川融化威胁水安全。' },
        { text: '洗车时采用哪种方式最节水？', options: ['微水洗车或蒸汽洗车','高压水枪冲洗','水管直接冲洗','桶装水泼洗'], correct: 0, explain: '微水洗车或蒸汽洗车每次仅需3-5升水，传统方式需100升以上。' },
        { text: '农业中推广覆膜技术主要为了？', options: ['减少蒸发保墒节水','增加美观','防止鸟害','增加产量'], correct: 0, explain: '地膜覆盖可减少土壤水分蒸发，在干旱地区可节水30-50%。' },
        { text: '雨水和污水分别排放的好处是？', options: ['减轻污水处理负担和回收雨水','增加成本','没有区别','方便排放'], correct: 0, explain: '雨污分流可减轻污水处理压力，并有利于雨水回收利用。' },
        { text: '泳池一次换水大约需要多少吨水？', options: ['数百至上千吨','约10吨','约1吨','约50吨'], correct: 0, explain: '标准泳池换一次水需数百吨甚至上千吨水，应循环过滤使用。' },
        { text: '以下哪项是保护水资源的正确做法？', options: ['参与河流清洁志愿活动','向河中倾倒垃圾','过度使用洗洁精','随意排放污水'], correct: 0, explain: '参与河流清洁保护志愿活动是每个公民都能做的护水行动。' },
        { text: '海水淡化目前最大的挑战是？', options: ['高能耗和高成本','技术不成熟','水质不好','设备太大'], correct: 0, explain: '海水淡化能耗高、成本大，目前主要在中东等能源便宜的地区使用。' },

        { text: '世界上大约有多少人缺乏安全饮用水？', options: ['约20亿人','约5亿人','约1000万人','约500万人'], correct: 0, explain: '全球约20亿人生活在严重缺水的地区，缺乏安全的饮用水源。' },
        { text: '生产1公斤牛肉大约需要多少升水？', options: ['约15000升','约500升','约2000升','约5000升'], correct: 0, explain: '畜牧业是水资源消耗大户，生产1公斤牛肉需要约15000升水(含饲料种植)。' },
        { text: '以下哪种灌溉方式最节水？', options: ['滴灌','漫灌','喷灌','沟灌'], correct: 0, explain: '滴灌可将水直接输送到植物根部，节水效率可达90%以上。' },
        { text: '地球上淡水资源占总水量的比例约为？', options: ['约2.5%','约25%','约50%','约10%'], correct: 0, explain: '地球上的淡水资源仅占总水量的约2.5%，且大部分以冰川形式存在。' },
        { text: '家庭中使用水量最大的是？', options: ['冲厕','饮用','洗碗','洗衣'], correct: 0, explain: '冲厕用水约占家庭用水量的30-40%，使用节水马桶可显著减少用水。' },
        { text: '联合国将每年几月几日定为世界水日？', options: ['3月22日','6月5日','4月22日','10月16日'], correct: 0, explain: '1993年起，每年3月22日为世界水日，旨在唤起公众节水意识。' },
        { text: '我国南水北调工程主要解决什么问题？', options: ['北方缺水问题','南方缺水问题','防洪问题','发电问题'], correct: 0, explain: '南水北调将长江流域水资源调往华北和西北，缓解北方地区严重缺水。' },
        { text: '以下哪种做法不利于保护水资源？', options: ['大量使用化肥农药','植树造林','修建梯田','保护湿地'], correct: 0, explain: '化肥和农药会通过径流污染河流和地下水，威胁水资源安全。' },
        { text: '工业冷却水循环利用可节水约多少？', options: ['90%以上','约30%','约50%','约10%'], correct: 0, explain: '工业冷却水循环利用系统可将水资源重复利用率提高到90%以上。' },
        { text: '一个城市居民每天平均用水量约为？', options: ['100-200升','10-20升','1000升','500升'], correct: 0, explain: '城市居民人均日用水量约100-200升，包括饮用、洗漱、冲厕等。' },
        { text: '雨水收集系统的主要优点不包括？', options: ['增加地下水污染','减少自来水使用','减轻排水压力','绿化浇灌'], correct: 0, explain: '雨水收集系统可减少自来水使用、减轻排水压力和用于灌溉，不会增加污染。' },
        { text: '我国水资源时空分布的主要特点是？', options: ['南多北少，夏多冬少','均匀分布','北多南少','冬多夏少'], correct: 0, explain: '我国水资源南多北少，且降水集中在夏季，时空分布极不均匀。' },
        { text: '海绵城市建设的核心理念是？', options: ['吸水蓄水渗水净水','快速排水','全部硬化','填湖造地'], correct: 0, explain: '海绵城市通过渗、滞、蓄、净、用、排等措施，实现雨水的自然积存与利用。' },
        { text: '农业用水占我国总用水量的比例约为？', options: ['约60%','约20%','约10%','约90%'], correct: 0, explain: '农业是我国第一用水大户，约占总用水量的60%，推广节水灌溉意义重大。' },
        { text: '以下哪条河流不是我国的母亲河？', options: ['尼罗河','长江','黄河','珠江'], correct: 0, explain: '尼罗河位于非洲。长江和黄河都是中华民族的母亲河。' },
        { text: '水体富营养化的主要原因是？', options: ['氮磷过量排放','重金属污染','石油泄漏','放射性污染'], correct: 0, explain: '农业和生活污水中的氮磷排入水体，导致藻类疯长，造成富营养化。' },
        { text: '使用节水型洗衣机每次可节水约？', options: ['30-50%','不到5%','约80%','不节水'], correct: 0, explain: '节水型洗衣机通过优化水流设计和程序控制，可节水30-50%。' },
        { text: '废水处理的主要步骤是？', options: ['物理-生物-化学处理','直接排放','只过滤不处理','加漂白剂'], correct: 0, explain: '现代污水处理通常经过物理沉淀、生物降解和化学消毒三级处理。' },
        { text: '地下水过度开采的主要后果是？', options: ['地面沉降和水质恶化','水资源增加','土壤更肥沃','气温升高'], correct: 0, explain: '过度开采地下水会导致地面沉降、海水入侵和水质恶化。' },
        { text: '家庭中最简单的节水方法是什么？', options: ['随手关紧水龙头','不洗澡','不洗衣服','不冲厕所'], correct: 0, explain: '随手关紧水龙头是最简单有效的节水方法，一个滴水龙头月浪费约1吨水。' },
        { text: '水资源属于哪种类型的资源？', options: ['可再生但有限资源','不可再生资源','无限资源','人造资源'], correct: 0, explain: '水是可再生资源但并非无限，全球可用的淡水资源非常有限。' },
        { text: '以下哪种水体含盐量最高？', options: ['海水','河水','湖水','地下水'], correct: 0, explain: '海水含盐量约3.5%，远高于淡水，不能直接饮用。' },
        { text: '中水利用是指？', options: ['将处理后的生活污水回用于非饮用用途','直接饮用回收水','海水淡化','雨水收集'], correct: 0, explain: '中水利用将处理后的生活污水用于冲厕、绿化等非饮用用途。' },
        { text: '世界水日2025年的主题聚焦什么？', options: ['冰川保护与水安全','海洋保护','大气污染','森林砍伐'], correct: 0, explain: '冰川是全球重要的淡水库，气候变化加速冰川融化威胁水安全。' },
        { text: '洗车时采用哪种方式最节水？', options: ['微水洗车或蒸汽洗车','高压水枪冲洗','水管直接冲洗','桶装水泼洗'], correct: 0, explain: '微水洗车或蒸汽洗车每次仅需3-5升水，传统方式需100升以上。' },
        { text: '农业中推广覆膜技术主要为了？', options: ['减少蒸发保墒节水','增加美观','防止鸟害','增加产量'], correct: 0, explain: '地膜覆盖可减少土壤水分蒸发，在干旱地区可节水30-50%。' },
        { text: '雨水和污水分别排放的好处是？', options: ['减轻污水处理负担和回收雨水','增加成本','没有区别','方便排放'], correct: 0, explain: '雨污分流可减轻污水处理压力，并有利于雨水回收利用。' },
        { text: '泳池一次换水大约需要多少吨水？', options: ['数百至上千吨','约10吨','约1吨','约50吨'], correct: 0, explain: '标准泳池换一次水需数百吨甚至上千吨水，应循环过滤使用。' },
        { text: '以下哪项是保护水资源的正确做法？', options: ['参与河流清洁志愿活动','向河中倾倒垃圾','过度使用洗洁精','随意排放污水'], correct: 0, explain: '参与河流清洁保护志愿活动是每个公民都能做的护水行动。' },
        { text: '海水淡化目前最大的挑战是？', options: ['高能耗和高成本','技术不成熟','水质不好','设备太大'], correct: 0, explain: '海水淡化能耗高、成本大，目前主要在中东等能源便宜的地区使用。' },

        { text: '安全知识测试题1：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题2：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题3：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题4：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题5：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题6：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题7：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题8：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题9：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题10：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题11：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题12：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题13：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题14：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题15：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题16：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题17：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题18：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题19：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题20：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题21：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题22：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题23：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题24：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题25：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题26：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题27：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题28：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题29：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题30：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
];
    if (window._qadventure) window._qadventure.destroy();
    window._qadventure = new QAdventureEngine({
        gameId: 'water',
        themeId: 'water',
        questions: questions,
        areaElId: 'water-game-area',
        scoreElId: 'water-score',
        resultDivId: 'water-result',
        resultTextId: 'water-score-text'
    });
    window._qadventure.init();
}
function initCarbonGame() {
    var resultDiv = document.getElementById('carbon-result');
    if (resultDiv) resultDiv.classList.add('hidden');
    var questions = [
        { text: "乘坐飞机飞行1000公里，约产生多少公斤碳排放？", options: ["约150-250kg", "约10kg", "约50kg", "约500kg"], correct: 0, explain: "飞机是碳排放最高的交通工具，1000公里飞行约产生150-250kg二氧化碳。" },
        { text: "以下哪种食物碳足迹最低？", options: ["本地当季蔬菜", "进口牛肉", "温室种植草莓", "空运海鲜"], correct: 0, explain: "本地当季蔬菜运输距离短、无需温室，碳足迹最低。牛肉养殖产生大量甲烷。" },
        { text: "一台空调开一夜（8小时）约排放多少二氧化碳？", options: ["约2-4kg", "约0.1kg", "约10kg", "不排放"], correct: 0, explain: "空调是家庭耗电大户，一夜约耗电2-4度，相当于2-4kg二氧化碳。" },
        { text: "哪种出行方式每公里碳排放最低？", options: ["骑自行车", "电动汽车", "公交车", "摩托车"], correct: 0, explain: "骑自行车零直接排放，是最环保的出行方式。" },
        { text: "一件棉T恤从生产到废弃，约产生多少碳排放？", options: ["约5-7kg", "约0.5kg", "约20kg", "约1kg"], correct: 0, explain: "一件棉T恤全生命周期约产生5-7kg二氧化碳，快时尚加剧了这一问题。" },
        { text: "全球温室气体排放中，食品系统的贡献约占多少？", options: ["约25-30%", "约5%", "约50%", "约80%"], correct: 0, explain: "全球食品系统（生产、加工、运输、废弃）贡献了约25-30%的人为温室气体排放。" },
        { text: "将肉类消费减少一半，个人碳足迹可减少约多少？", options: ["约20-30%", "约5%", "约50%", "约1%"], correct: 0, explain: "畜牧业是甲烷（温室效应是CO₂的28倍）主要来源，减少肉类消费是降低个人碳足迹最有效的方法之一。" },
        { text: "以下哪类电力来源全生命周期碳排放最低？", options: ["风能/核能", "天然气发电", "燃煤发电", "柴油发电"], correct: 0, explain: "风能、太阳能和核能发电几乎零碳排放，而燃煤发电每度约排放0.8-1kg CO₂。" },
        { text: "一棵树平均每年可吸收多少二氧化碳？", options: ["约10-20kg", "约1kg", "约100kg", "约500kg"], correct: 0, explain: "一棵成年树每年约吸收10-20kg CO₂，但要抵消一个人一年的排放需要约20-30棵树的吸收量。" },
        { text: "「碳补偿（Carbon Offset）」的核心逻辑是？", options: ["在其他地方减排来抵消自身排放", "直接消除大气中的CO₂", "购买碳排放权", "减少个人消费"], correct: 0, explain: "碳补偿是通过资助减排项目（如植树、风电）来抵消自身无法避免的碳排放，但不能替代直接减排。" }
    ,
        { text: '以下哪种出行方式碳足迹最低？', options: ['步行或骑行','私家车','出租车','公交车'], correct: 0, explain: '步行和骑行是零碳排放的出行方式，既环保又健康。' },
        { text: '生产1公斤牛肉的碳排放量约为？', options: ['约60公斤CO2','约5公斤CO2','约1公斤CO2','约10公斤CO2'], correct: 0, explain: '牛肉生产碳排放远高于其他肉类，是羊肉的2倍、鸡肉的10倍。' },
        { text: '碳达峰是指？', options: ['碳排放达到峰值后下降','碳排放为零','碳排放持续增长','碳交易价格最高点'], correct: 0, explain: '碳达峰是指一个国家或地区的碳排放达到历史最高值后进入下降通道。' },
        { text: '碳中和是指？', options: ['碳排放与碳吸收平衡','完全不排放碳','只吸收不排放','排放可以忽略'], correct: 0, explain: '碳中和是使排放的碳与通过植树等方式吸收的碳达到平衡。' },
        { text: '中国承诺在哪一年前实现碳达峰？', options: ['2030年前','2025年前','2050年前','2040年前'], correct: 0, explain: '中国承诺2030年前实现碳达峰，2060年前实现碳中和。' },
        { text: '中国承诺在哪一年前实现碳中和？', options: ['2060年前','2030年前','2040年前','2050年前'], correct: 0, explain: '中国承诺2060年前实现碳中和，这是应对全球气候变化的重要承诺。' },
        { text: '一棵成年大树每年大约吸收多少CO2？', options: ['约10-20公斤','约1000公斤','约1公斤','约500公斤'], correct: 0, explain: '一棵成年大树每年约吸收10-20公斤CO2，植树造林是最自然固碳方式。' },
        { text: '以下哪种能源碳排放最低？', options: ['太阳能和风能','煤炭','石油','天然气'], correct: 0, explain: '太阳能和风能是清洁可再生能源，运行过程几乎不产生碳排放。' },
        { text: '衣服晾干 vs 烘干机，哪个碳足迹更低？', options: ['晾干更低','烘干机更低','一样','不确定'], correct: 0, explain: '晾干利用太阳能和风能，碳足迹几乎为零；烘干机耗电量大。' },
        { text: '新能源汽车比燃油车减少碳排放约？', options: ['30-50%','不到5%','约80%','完全相同'], correct: 0, explain: '新能源车在使用阶段的碳排放比燃油车少30-50%(取决于电力来源)。' },
        { text: '夏季空调温度每提高1度可节能约？', options: ['约7-10%','约1%','约30%','约50%'], correct: 0, explain: '夏季空调温度适度提高可显著节能，建议设置在26℃左右。' },
        { text: '垃圾分类对减碳的作用是？', options: ['提高回收率减少原材料开采','没有作用','只美化环境','增加碳排放'], correct: 0, explain: '回收利用可大幅减少原材料开采和加工过程中的碳排放。' },
        { text: '全球变暖1.5℃和2℃的主要区别？', options: ['2℃将导致更严重的极端天气和生态崩溃','没有区别','1.5℃更严重','只影响南北极'], correct: 0, explain: '每增加0.5℃都会显著增加极端天气、物种灭绝和海平面上升风险。' },
        { text: '以下哪种食物碳足迹最高？', options: ['牛肉','鸡肉','大米','蔬菜'], correct: 0, explain: '牛肉生产涉及饲料种植、牲畜反刍甲烷排放等，碳足迹远超其他食物。' },
        { text: '冰箱门开关频率对能耗的影响？', options: ['频繁开关增加能耗约10%','没有影响','反而省电','能耗减半'], correct: 0, explain: '频繁开关冰箱门导致冷气流失，压缩机频繁启动，增加能耗。' },
        { text: '碳排放权交易的基本原理是？', options: ['通过市场机制控制排放总量','免费排放','按需排放','限制经济发展'], correct: 0, explain: '碳交易通过设定排放上限和分配配额，用市场手段激励企业减排。' },
        { text: '绿色建筑评价标准中哪项不是重点？', options: ['使用大理石装修','节能设计','节水措施','环保材料'], correct: 0, explain: '绿色建筑关注节能、节水、节材和室内环境质量，不鼓励奢侈装修。' },
        { text: '共享单车对碳减排的贡献是？', options: ['替代短途私家车出行','增加了碳排放','只适合年轻人','不够安全'], correct: 0, explain: '共享单车替代短途私家车出行，每骑行1公里可减少约0.2kg碳排放。' },
        { text: '家庭中待机电器耗电占比约为？', options: ['5-10%','约50%','不到1%','约30%'], correct: 0, explain: '家中待机电器(电视、空调、充电器等)耗电占总用电的5-10%。' },
        { text: '以下哪种行为不利于碳减排？', options: ['使用一次性餐具','自带购物袋','乘坐公共交通','节约用纸'], correct: 0, explain: '一次性餐具生产和处理都会产生碳排放，应尽量使用可重复餐具。' },
        { text: '光伏发电板的原理是？', options: ['将光能直接转化为电能','将热能转化为电能','需要燃烧燃料','核反应'], correct: 0, explain: '光伏板利用半导体材料的光伏效应，直接将太阳光转化为直流电。' },
        { text: '一个家庭安装太阳能热水器年减碳约？', options: ['约500-1000kg','约10kg','约5000kg','不减排'], correct: 0, explain: '太阳能热水器替代电或燃气加热，一个家庭年减排约500-1000kg CO2。' },
        { text: '包装减量化的环保意义是？', options: ['减少资源消耗和运输碳排放','不影响','只减少成本','只为了美观'], correct: 0, explain: '减少过度包装可节约原材料和减少运输重量，从而减少碳排放。' },
        { text: '碳捕集与封存(CCS)技术主要作用？', options: ['将工业排放的CO2捕集并储存地下','制造更多CO2','直接排放','净化空气'], correct: 0, explain: 'CCS技术捕集工业排放的CO2并封存在地下岩层中，是重要的减排技术。' },
        { text: '我国碳市场目前覆盖的主要行业是？', options: ['电力行业','房地产业','农业','服务业'], correct: 0, explain: '2021年全国碳市场启动，首批覆盖发电行业，未来将扩展至钢铁等行业。' },
        { text: '纸张双面使用相比单面使用的碳减排效果？', options: ['减少约50%的用纸碳足迹','没有作用','减碳约1%','反而更耗能'], correct: 0, explain: '双面用纸可直接减半纸张消耗，从而减少木材采伐和造纸过程中的碳排放。' },
        { text: '以下哪种做法是碳补偿？', options: ['购买碳信用支持植树造林','多开空调','多开车','使用更多塑料'], correct: 0, explain: '碳补偿是通过投资减排项目来抵消自身碳排放，如购买碳信用支持植树。' },
        { text: '飞机和高铁哪个碳排放更高？', options: ['飞机约为高铁的3-5倍','高铁更高','一样','高铁是飞机的10倍'], correct: 0, explain: '短途出行高铁人均碳排放约为飞机的1/3到1/5，长途飞机排放更高。' },
        { text: '家庭节能灯比白炽灯节能约？', options: ['约80%','约10%','约30%','完全相同'], correct: 0, explain: 'LED节能灯比白炽灯节能约80%，使用寿命也更长，是家庭减碳好选择。' },
        { text: '有机食品的碳足迹一定更低吗？', options: ['不一定，取决于生产方式','一定更低','一定更高','完全相同'], correct: 0, explain: '有机食品碳足迹取决于具体生产方式，部分有机产品的碳足迹可能更高。' },

        { text: '以下哪种出行方式碳足迹最低？', options: ['步行或骑行','私家车','出租车','公交车'], correct: 0, explain: '步行和骑行是零碳排放的出行方式，既环保又健康。' },
        { text: '生产1公斤牛肉的碳排放量约为？', options: ['约60公斤CO2','约5公斤CO2','约1公斤CO2','约10公斤CO2'], correct: 0, explain: '牛肉生产碳排放远高于其他肉类，是羊肉的2倍、鸡肉的10倍。' },
        { text: '碳达峰是指？', options: ['碳排放达到峰值后下降','碳排放为零','碳排放持续增长','碳交易价格最高点'], correct: 0, explain: '碳达峰是指一个国家或地区的碳排放达到历史最高值后进入下降通道。' },
        { text: '碳中和是指？', options: ['碳排放与碳吸收平衡','完全不排放碳','只吸收不排放','排放可以忽略'], correct: 0, explain: '碳中和是使排放的碳与通过植树等方式吸收的碳达到平衡。' },
        { text: '中国承诺在哪一年前实现碳达峰？', options: ['2030年前','2025年前','2050年前','2040年前'], correct: 0, explain: '中国承诺2030年前实现碳达峰，2060年前实现碳中和。' },
        { text: '中国承诺在哪一年前实现碳中和？', options: ['2060年前','2030年前','2040年前','2050年前'], correct: 0, explain: '中国承诺2060年前实现碳中和，这是应对全球气候变化的重要承诺。' },
        { text: '一棵成年大树每年大约吸收多少CO2？', options: ['约10-20公斤','约1000公斤','约1公斤','约500公斤'], correct: 0, explain: '一棵成年大树每年约吸收10-20公斤CO2，植树造林是最自然固碳方式。' },
        { text: '以下哪种能源碳排放最低？', options: ['太阳能和风能','煤炭','石油','天然气'], correct: 0, explain: '太阳能和风能是清洁可再生能源，运行过程几乎不产生碳排放。' },
        { text: '衣服晾干 vs 烘干机，哪个碳足迹更低？', options: ['晾干更低','烘干机更低','一样','不确定'], correct: 0, explain: '晾干利用太阳能和风能，碳足迹几乎为零；烘干机耗电量大。' },
        { text: '新能源汽车比燃油车减少碳排放约？', options: ['30-50%','不到5%','约80%','完全相同'], correct: 0, explain: '新能源车在使用阶段的碳排放比燃油车少30-50%(取决于电力来源)。' },
        { text: '夏季空调温度每提高1度可节能约？', options: ['约7-10%','约1%','约30%','约50%'], correct: 0, explain: '夏季空调温度适度提高可显著节能，建议设置在26℃左右。' },
        { text: '垃圾分类对减碳的作用是？', options: ['提高回收率减少原材料开采','没有作用','只美化环境','增加碳排放'], correct: 0, explain: '回收利用可大幅减少原材料开采和加工过程中的碳排放。' },
        { text: '全球变暖1.5℃和2℃的主要区别？', options: ['2℃将导致更严重的极端天气和生态崩溃','没有区别','1.5℃更严重','只影响南北极'], correct: 0, explain: '每增加0.5℃都会显著增加极端天气、物种灭绝和海平面上升风险。' },
        { text: '以下哪种食物碳足迹最高？', options: ['牛肉','鸡肉','大米','蔬菜'], correct: 0, explain: '牛肉生产涉及饲料种植、牲畜反刍甲烷排放等，碳足迹远超其他食物。' },
        { text: '冰箱门开关频率对能耗的影响？', options: ['频繁开关增加能耗约10%','没有影响','反而省电','能耗减半'], correct: 0, explain: '频繁开关冰箱门导致冷气流失，压缩机频繁启动，增加能耗。' },
        { text: '碳排放权交易的基本原理是？', options: ['通过市场机制控制排放总量','免费排放','按需排放','限制经济发展'], correct: 0, explain: '碳交易通过设定排放上限和分配配额，用市场手段激励企业减排。' },
        { text: '绿色建筑评价标准中哪项不是重点？', options: ['使用大理石装修','节能设计','节水措施','环保材料'], correct: 0, explain: '绿色建筑关注节能、节水、节材和室内环境质量，不鼓励奢侈装修。' },
        { text: '共享单车对碳减排的贡献是？', options: ['替代短途私家车出行','增加了碳排放','只适合年轻人','不够安全'], correct: 0, explain: '共享单车替代短途私家车出行，每骑行1公里可减少约0.2kg碳排放。' },
        { text: '家庭中待机电器耗电占比约为？', options: ['5-10%','约50%','不到1%','约30%'], correct: 0, explain: '家中待机电器(电视、空调、充电器等)耗电占总用电的5-10%。' },
        { text: '以下哪种行为不利于碳减排？', options: ['使用一次性餐具','自带购物袋','乘坐公共交通','节约用纸'], correct: 0, explain: '一次性餐具生产和处理都会产生碳排放，应尽量使用可重复餐具。' },
        { text: '光伏发电板的原理是？', options: ['将光能直接转化为电能','将热能转化为电能','需要燃烧燃料','核反应'], correct: 0, explain: '光伏板利用半导体材料的光伏效应，直接将太阳光转化为直流电。' },
        { text: '一个家庭安装太阳能热水器年减碳约？', options: ['约500-1000kg','约10kg','约5000kg','不减排'], correct: 0, explain: '太阳能热水器替代电或燃气加热，一个家庭年减排约500-1000kg CO2。' },
        { text: '包装减量化的环保意义是？', options: ['减少资源消耗和运输碳排放','不影响','只减少成本','只为了美观'], correct: 0, explain: '减少过度包装可节约原材料和减少运输重量，从而减少碳排放。' },
        { text: '碳捕集与封存(CCS)技术主要作用？', options: ['将工业排放的CO2捕集并储存地下','制造更多CO2','直接排放','净化空气'], correct: 0, explain: 'CCS技术捕集工业排放的CO2并封存在地下岩层中，是重要的减排技术。' },
        { text: '我国碳市场目前覆盖的主要行业是？', options: ['电力行业','房地产业','农业','服务业'], correct: 0, explain: '2021年全国碳市场启动，首批覆盖发电行业，未来将扩展至钢铁等行业。' },
        { text: '纸张双面使用相比单面使用的碳减排效果？', options: ['减少约50%的用纸碳足迹','没有作用','减碳约1%','反而更耗能'], correct: 0, explain: '双面用纸可直接减半纸张消耗，从而减少木材采伐和造纸过程中的碳排放。' },
        { text: '以下哪种做法是碳补偿？', options: ['购买碳信用支持植树造林','多开空调','多开车','使用更多塑料'], correct: 0, explain: '碳补偿是通过投资减排项目来抵消自身碳排放，如购买碳信用支持植树。' },
        { text: '飞机和高铁哪个碳排放更高？', options: ['飞机约为高铁的3-5倍','高铁更高','一样','高铁是飞机的10倍'], correct: 0, explain: '短途出行高铁人均碳排放约为飞机的1/3到1/5，长途飞机排放更高。' },
        { text: '家庭节能灯比白炽灯节能约？', options: ['约80%','约10%','约30%','完全相同'], correct: 0, explain: 'LED节能灯比白炽灯节能约80%，使用寿命也更长，是家庭减碳好选择。' },
        { text: '有机食品的碳足迹一定更低吗？', options: ['不一定，取决于生产方式','一定更低','一定更高','完全相同'], correct: 0, explain: '有机食品碳足迹取决于具体生产方式，部分有机产品的碳足迹可能更高。' },
        { text: '碳标签是什么？', options: ['印在产品上标示碳排放量的标签','食品保质期标签','价格标签','品牌标签'], correct: 0, explain: '碳标签标示产品从原料到废弃的全生命周期碳排放，帮助消费者低碳选择。' },
        { text: '人均碳排放最高的国家在？', options: ['中东产油国和发达国家','非洲国家','东南亚','南美洲'], correct: 0, explain: '中东产油国如卡塔尔人均碳排全球最高；发达国家人均碳排也远超发展中国家。' },
        { text: '碳中和认证对企业意味着？', options: ['通过减排和补偿实现净零排放','随意排放','只是花钱买证','不重要'], correct: 0, explain: '碳中和认证表明企业已通过节能减排和碳补偿方式实现温室气体净零排放。' },
        { text: '网上购物 vs 实体店购物哪个碳足迹更低？', options: ['取决于配送方式和包装','网购一定更低','实体店一定更低','完全相同'], correct: 0, explain: '碳足迹取决于物流效率、包装量和退货率，不能简单对比。' },
        { text: '碳普惠是什么？', options: ['鼓励公众低碳行为的激励机制','碳税','一个App','名人代言'], correct: 0, explain: '碳普惠通过量化公众低碳行为并给予奖励，激励全民参与减排。' },
        { text: '以下哪种饮食碳足迹最低？', options: ['以植物为主的膳食','以牛肉为主的膳食','海鲜为主','乳制品为主'], correct: 0, explain: '植物性膳食碳排放远低于肉类为主膳食，多吃菜少吃肉也是减排行动。' },
        { text: '节能家电能效等级数字越小代表？', options: ['越省电','越耗电','价格越高','寿命越长'], correct: 0, explain: '我国能效等级1级最省电，5级最耗电。优先选购1-2级节能家电。' },
        { text: '闲置电子产品回收的环保意义？', options: ['减少电子垃圾和资源浪费','只值几块钱','没有意义','太麻烦'], correct: 0, explain: '回收电子产品可提取贵金属、减少矿山开采和电子垃圾填埋污染。' },
        { text: '外卖不使用一次性餐具可减排约？', options: ['每单约减排50-100gCO2','没有作用','约1kg','约10g'], correct: 0, explain: '拒绝一次性餐具、选择无需餐具配送，是简单易行的日常减碳行动。' },
        { text: '植树造林固碳的局限是？', options: ['树木长大后固碳效率降低且有火灾风险','没有局限','固碳量无限','所有地方都能种'], correct: 0, explain: '森林固碳是重要的碳汇，但需考虑树种选择、火灾风险和土地竞争。' },
        { text: '碳标签上数字越小代表？', options: ['产品碳排放越低','产品价格越低','产品质量越差','生产越慢'], correct: 0, explain: '碳标签数字越小说明该产品碳排放越低，是选购环保商品的参考指标。' },
        { text: '极地冰盖融化的直接后果是？', options: ['海平面上升和全球气候失调','只是风景变了','不关我们的事','只影响企鹅'], correct: 0, explain: '极地冰盖融化导致海平面上升威胁沿海城市，并影响全球洋流和气候系统。' },
        { text: '碳税和碳交易哪个更有效？', options: ['各有优劣，需要配合使用','碳税更好','碳交易更好','都不好'], correct: 0, explain: '碳税设定价格、碳交易控制总量，两者配合使用效果最佳。' },
        { text: '日常办公中哪种做法最减排？', options: ['无纸化办公和视频会议替代出差','打印所有文件','每天出差开会','大量使用传真'], correct: 0, explain: '无纸化减少造纸排放，视频会议减少差旅碳排放，是现代办公减排的关键。' },
        { text: '饮食中最大的碳足迹来源通常是？', options: ['红肉和乳制品','蔬菜水果','米饭面包','豆制品'], correct: 0, explain: '红肉和乳制品生产产生大量甲烷和碳排放，是饮食碳足迹的最大来源。' },
        { text: '一度绿电减少多少碳排放？', options: ['取决于当地电力结构约0.3-1kg','没有任何减少','约10kg','约0.01kg'], correct: 0, explain: '绿电取代火电可减少碳排放，具体减排量取决于当地电力碳排放因子。' },
        { text: '普通人最容易实践的减排行为？', options: ['减少食物浪费和选择公共交通','买碳信用','不管','等政府政策'], correct: 0, explain: '减少食物浪费(约占全球8%的碳排放)和少开车是最简单的个人减排行动。' },
        { text: 'CCER是什么？', options: ['中国核证自愿减排量','国际碳汇','一种减排技术','环保组织名称'], correct: 0, explain: 'CCER是中国碳市场的自愿减排信用，企业可购买以抵消自身碳排放。' },
        { text: '以下哪项是正确的碳减排排序？', options: ['避免排放>减少排放>碳补偿','碳补偿>减少排放>避免排放','都一样的','不用排序'], correct: 0, explain: '优先避免不必要的排放，其次减少必要排放，最后用碳补偿抵消无法减少的排放。' },
        { text: '为什么少吃牛肉是有效的减排行动？', options: ['牛肉碳排放是鸡肉的10倍以上','没有效果','牛太少了','与其他减排矛盾'], correct: 0, explain: '牛肉生产碳排放极高(约60kgCO2/kg)，用鸡肉或植物蛋白替代可大幅减碳。' },
        { text: '中国碳排放峰值大约在哪一年？', options: ['预计在2025-2030年间','已经过了','2090年','2020年前'], correct: 0, explain: '中国二氧化碳排放预计在2025-2030年间达峰，此后开始下降。' },
        { text: '企业范围3碳排放是指？', options: ['供应链上下游间接排放','公司直接运营排放','外购电力排放','员工通勤排放'], correct: 0, explain: '范围3包括供应链、产品使用等全价值链间接排放，通常是企业最大排放源。' },
        { text: '碳捕集技术CCUS中U代表？', options: ['利用与封存(Utilisation)','地下(Underground)','紧急(Urgent)','无条件(Unconditional)'], correct: 0, explain: 'CCUS=Carbon Capture Utilisation and Storage，即碳捕集利用与封存技术。' },
        { text: '什么温度下空调最节能？', options: ['制冷26℃制热20℃','制冷16℃制热30℃','制冷22℃制热26℃','没有标准'], correct: 0, explain: '夏季空调制冷26℃、冬季制热20℃兼顾舒适与节能，是国家推荐温度。' },
        { text: '购买碳信用等于？', options: ['资助等量减排项目抵消自身排放','获得排放许可','交税','捐款给环保组织'], correct: 0, explain: '购买碳信用是通过资助植树或可再生能源等项目，抵消自身产生的碳排放。' },
        { text: '绿色工厂认证的核心标准是？', options: ['节能节水减碳和资源循环利用','只要绿化好','只要产品是绿色的','只要员工穿绿衣'], correct: 0, explain: '绿色工厂需满足用地集约化、原料无害化、生产洁净化、废物资源化等标准。' },
        { text: '天然气是清洁能源吗？', options: ['比煤炭清洁但仍产生碳排放','零碳排放','比煤炭排放更多','完全清洁'], correct: 0, explain: '天然气燃烧碳排放比煤少约50%但仍有排放，是过渡性能源不是零碳能源。' },
        { text: '新能源汽车哪种最减排？', options: ['具体取决于电力结构','纯电动车一定最减排','插混一定最减排','都一样的'], correct: 0, explain: '纯电动车在清洁电力占比高的地区减排效果最好；在火电为主的地区减排有限。' },
        { text: '全球气候变暖已经升高了约？', options: ['约1.1°C','约5°C','约0.1°C','约10°C'], correct: 0, explain: '工业革命以来全球平均气温已上升约1.1°C，导致冰川消融和极端天气频发。' },

        { text: '安全知识测试题1：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
];
    if (window._qadventure) window._qadventure.destroy();
    window._qadventure = new QAdventureEngine({
        gameId: 'carbon',
        themeId: 'carbon',
        questions: questions,
        areaElId: 'carbon-game-area',
        scoreElId: 'carbon-score',
        resultDivId: 'carbon-result',
        resultTextId: 'carbon-score-text'
    });
    window._qadventure.init();
}
function initRepairGame() {
    var resultDiv = document.getElementById('repair-result');
    if (resultDiv) resultDiv.classList.add('hidden');
    var questions = [
        { text: "旧T恤最适合改造成什么？", options: ["环保购物袋", "直接丢弃", "焚烧处理", "填埋"], correct: 0, explain: "旧T恤可以剪开缝制成环保购物袋，减少塑料袋使用。" },
        { text: "玻璃瓶洗净后最适合？", options: ["储物罐/花瓶", "直接扔其他垃圾", "打碎填埋", "焚烧"], correct: 0, explain: "玻璃瓶清洗后可反复用作储物罐或花瓶，是最环保的选择。" },
        { text: "废旧电池属于什么垃圾？", options: ["有害垃圾", "可回收物", "厨余垃圾", "其他垃圾"], correct: 0, explain: "废旧电池含有重金属，必须作为有害垃圾专门回收处理。" },
        { text: "破损的陶瓷碗属于？", options: ["其他垃圾", "可回收物", "有害垃圾", "厨余垃圾"], correct: 0, explain: "陶瓷不可回收，也不属于有害垃圾，应放入其他垃圾。" },
        { text: "以下哪种旧物改造最有创意？", options: ["轮胎改花盆", "直接丢弃", "焚烧", "填埋"], correct: 0, explain: "轮胎改花盆既减少了废弃物，又美化了环境，是典型的旧物新生。" },
        { text: "一颗纽扣电池可污染多少升水？", options: ["约60万升", "约1000升", "约1万升", "不污染水"], correct: 0, explain: "一颗纽扣电池可污染60万升水，相当于一个人一生的饮水量，切勿随意丢弃。" },
        { text: "废弃食用油最适合如何处理？", options: ["冷却后倒入专用回收桶", "直接倒入下水道", "冲入马桶", "倒入花园"], correct: 0, explain: "废弃食用油应冷却凝固后投入专用回收桶，可用于制作生物柴油，切勿倒入下水道。" },
        { text: "废纸回收再利用1吨，可节约多少棵大树？", options: ["约17棵", "约2棵", "约50棵", "不节约树木"], correct: 0, explain: "回收1吨废纸可节约约17棵大树，减少约30%的空气污染和50%的水污染。" },
        { text: "旧牛仔裤改造成拖把前，最重要的处理步骤是？", options: ["拆掉金属铆钉和拉链", "直接缝合", "先染色", "先剪碎"], correct: 0, explain: "牛仔裤上的金属部件在洗涤过程中可能划伤衣物或损坏洗衣机，改造前必须拆除。" },
        { text: "以下哪种材料的降解时间最长？", options: ["塑料瓶（约450年）", "铝罐（约200年）", "羊毛袜子（约5年）", "香蕉皮（约2-10周）"], correct: 0, explain: "塑料瓶在自然环境中约需450年才能降解，有些塑料永远无法完全降解，只会碎裂成微塑料。" }
    ,
        { text: '旧物修复最大的环保意义是？', options: ['减少资源开采和垃圾填埋','省钱','好玩','消磨时间'], correct: 0, explain: '修复旧物可直接减少新产品制造所需的资源开采，并减少废弃物填埋。' },
        { text: '电子废弃物中可回收的贵金属包括？', options: ['金、银、铜、钯','铝、铁、锌','塑料、橡胶','石头、沙子'], correct: 0, explain: '废弃手机和电脑中含有金、银等贵金属，1吨旧手机可提取约300克黄金。' },
        { text: '家具修复常用的传统工艺叫？', options: ['榫卯修复','焊接','胶水粘合','钉子固定'], correct: 0, explain: '榫卯是中国传统木工连接方式，无需钉子即可牢固连接木构件。' },
        { text: '旧衣服改造为购物袋的意义是？', options: ['减少塑料袋使用和纺织品废弃','只是为了好看','没有意义','浪费布料'], correct: 0, explain: '将旧衣改造为购物袋可同时减少塑料袋使用和纺织品垃圾。' },
        { text: '修复一台旧手机相当于减少约多少碳排放？', options: ['约50-80kg CO2','不到1kg','约500kg','没有减少'], correct: 0, explain: '修复一台手机可避免生产新手机的碳排放，约相当于减排50-80kg CO2。' },
        { text: '以下哪种物品最不适合填埋处理？', options: ['废旧电池和电子产品','厨余垃圾','建筑废料','木材'], correct: 0, explain: '电池和电子产品含有害重金属，填埋后会污染土壤和地下水。' },
        { text: '循环经济3R原则不包括？', options: ['拒绝(Refuse)','减量(Reduce)','再利用(Reuse)','回收(Recycle)'], correct: 0, explain: '3R为Reduce、Reuse、Recycle；Refuse(拒绝)是更高级的环保行为。' },
        { text: '我国每年废弃手机数量约为？', options: ['约2-4亿部','约100万部','约10亿部','约50万部'], correct: 0, explain: '中国每年产生约2-4亿部废弃手机，其中大部分未得到正规回收处理。' },
        { text: '陶瓷修复中使用金粉修复的技术叫？', options: ['金缮(Kintsugi)','镀金','涂金','熔金'], correct: 0, explain: '金缮是日本传统修复技术，用金粉混合漆料修复破损陶瓷，将残缺变为独特美学。' },
        { text: '旧书捐赠的环保价值是？', options: ['延长书籍使用寿命减少造纸','没有价值','占用空间','浪费精力'], correct: 0, explain: '每本旧书的再利用可减少约2-3公斤的木材消耗和造纸污染。' },
        { text: '塑料瓶回收后可以做成什么？', options: ['衣服、地毯、新瓶子等','食物','纸','玻璃'], correct: 0, explain: '回收的PET塑料瓶可以制成聚酯纤维，用于制作衣服、地毯等产品。' },
        { text: '哪种材料的降解时间最长？', options: ['玻璃瓶(约100万年)','纸张(数月)','棉布(数年)','木材(数十年)'], correct: 0, explain: '玻璃瓶在自然环境中几乎永久存在，降解时间超过100万年。' },
        { text: '修理咖啡馆(Repair Cafe)是什么？', options: ['免费互助修理物品的社区活动','卖咖啡的地方','自行车修理店','手机维修店'], correct: 0, explain: '起源于荷兰的修理咖啡馆是社区志愿者免费帮助居民修理物品的公益活动。' },
        { text: '旧家具翻新刷漆应注意什么？', options: ['使用环保水性漆','随便用漆','多用油漆','不处理直接刷'], correct: 0, explain: '环保水性漆VOC含量低，对环境和健康影响小，是旧家具翻新的更好选择。' },
        { text: '修复一把旧椅子相当于减少了多少木材消耗？', options: ['约0.02-0.05立方米','约1立方米','没有减少','约0.5立方米'], correct: 0, explain: '修复旧椅子可避免购买新椅子所需的木材，约节省0.02-0.05立方米木材。' },
        { text: '以下哪种损坏最容易家庭修复？', options: ['松动的螺丝或脱胶的桌腿','屏幕碎裂','芯片损坏','发动机故障'], correct: 0, explain: '松动螺丝和脱胶问题只需简单工具即可修复，是最适合家庭DIY的修复项目。' },
        { text: '电子产品的计划性报废是指？', options: ['厂家设计产品寿命有限迫使换新','产品自然老化','用户不爱惜','技术进步太快'], correct: 0, explain: '计划性报废是厂商故意设计产品寿命有限以促进持续消费的商业策略。' },
        { text: '旧物市集(跳蚤市场)的环保意义？', options: ['促进物品循环利用减少垃圾','只是好玩','浪费资源','扰乱市场'], correct: 0, explain: '旧物市集让闲置物品找到新主人，延长其使用寿命并减少废弃物产生。' },
        { text: '自行车修理中最常见的易损件是？', options: ['刹车片和链条','车架','坐垫','铃铛'], correct: 0, explain: '刹车片和链条是自行车使用频率最高的部件，定期保养可显著延长寿命。' },
        { text: '修理权(Right to Repair)运动主张什么？', options: ['消费者有权自行或选择第三方维修产品','只有厂家能修','禁止维修','必须买新的'], correct: 0, explain: '修理权运动主张消费者应拥有维修自己购买的产品的权利，包括获取零件和维修手册。' },
        { text: '金属回收相比采矿冶炼节能约？', options: ['60-95%','不到10%','约20%','完全相同'], correct: 0, explain: '回收铝比从矿石冶炼节能95%，回收铜节能85%，回收钢铁节能60%以上。' },
        { text: '旧轮胎可以回收利用做什么？', options: ['橡胶跑道、沥青改性剂等','食品容器','新衣服','纸'], correct: 0, explain: '废旧轮胎可加工成胶粉用于铺设运动跑道、改性沥青等用途。' },
        { text: '你扔掉的旧手机去了哪里最可能是？', options: ['被非正规拆解造成污染','直接销毁','全部回收','堆在仓库'], correct: 0, explain: '全球大量电子垃圾流入非正规拆解渠道，用火烧酸洗等原始方式提取金属。' },
        { text: '旧物修复需要哪些基本心态？', options: ['耐心、创造力、珍惜物品','着急、随便、无所谓','完美主义','买新的更方便'], correct: 0, explain: '修复需要耐心和创造力，更重要的是对物品的珍惜和爱护之心。' },
        { text: '衣服破了先想到什么？', options: ['尝试缝补而非丢弃','扔掉买新','不管继续穿','送人'], correct: 0, explain: '衣服破损可以缝补、改造或用作抹布，减少纺织品浪费。' },

        { text: '旧物修复最大的环保意义是？', options: ['减少资源开采和垃圾填埋','省钱','好玩','消磨时间'], correct: 0, explain: '修复旧物可直接减少新产品制造所需的资源开采，并减少废弃物填埋。' },
        { text: '电子废弃物中可回收的贵金属包括？', options: ['金、银、铜、钯','铝、铁、锌','塑料、橡胶','石头、沙子'], correct: 0, explain: '废弃手机和电脑中含有金、银等贵金属，1吨旧手机可提取约300克黄金。' },
        { text: '家具修复常用的传统工艺叫？', options: ['榫卯修复','焊接','胶水粘合','钉子固定'], correct: 0, explain: '榫卯是中国传统木工连接方式，无需钉子即可牢固连接木构件。' },
        { text: '旧衣服改造为购物袋的意义是？', options: ['减少塑料袋使用和纺织品废弃','只是为了好看','没有意义','浪费布料'], correct: 0, explain: '将旧衣改造为购物袋可同时减少塑料袋使用和纺织品垃圾。' },
        { text: '修复一台旧手机相当于减少约多少碳排放？', options: ['约50-80kg CO2','不到1kg','约500kg','没有减少'], correct: 0, explain: '修复一台手机可避免生产新手机的碳排放，约相当于减排50-80kg CO2。' },
        { text: '以下哪种物品最不适合填埋处理？', options: ['废旧电池和电子产品','厨余垃圾','建筑废料','木材'], correct: 0, explain: '电池和电子产品含有害重金属，填埋后会污染土壤和地下水。' },
        { text: '循环经济3R原则不包括？', options: ['拒绝(Refuse)','减量(Reduce)','再利用(Reuse)','回收(Recycle)'], correct: 0, explain: '3R为Reduce、Reuse、Recycle；Refuse(拒绝)是更高级的环保行为。' },
        { text: '我国每年废弃手机数量约为？', options: ['约2-4亿部','约100万部','约10亿部','约50万部'], correct: 0, explain: '中国每年产生约2-4亿部废弃手机，其中大部分未得到正规回收处理。' },
        { text: '陶瓷修复中使用金粉修复的技术叫？', options: ['金缮(Kintsugi)','镀金','涂金','熔金'], correct: 0, explain: '金缮是日本传统修复技术，用金粉混合漆料修复破损陶瓷，将残缺变为独特美学。' },
        { text: '旧书捐赠的环保价值是？', options: ['延长书籍使用寿命减少造纸','没有价值','占用空间','浪费精力'], correct: 0, explain: '每本旧书的再利用可减少约2-3公斤的木材消耗和造纸污染。' },
        { text: '塑料瓶回收后可以做成什么？', options: ['衣服、地毯、新瓶子等','食物','纸','玻璃'], correct: 0, explain: '回收的PET塑料瓶可以制成聚酯纤维，用于制作衣服、地毯等产品。' },
        { text: '哪种材料的降解时间最长？', options: ['玻璃瓶(约100万年)','纸张(数月)','棉布(数年)','木材(数十年)'], correct: 0, explain: '玻璃瓶在自然环境中几乎永久存在，降解时间超过100万年。' },
        { text: '修理咖啡馆(Repair Cafe)是什么？', options: ['免费互助修理物品的社区活动','卖咖啡的地方','自行车修理店','手机维修店'], correct: 0, explain: '起源于荷兰的修理咖啡馆是社区志愿者免费帮助居民修理物品的公益活动。' },
        { text: '旧家具翻新刷漆应注意什么？', options: ['使用环保水性漆','随便用漆','多用油漆','不处理直接刷'], correct: 0, explain: '环保水性漆VOC含量低，对环境和健康影响小，是旧家具翻新的更好选择。' },
        { text: '修复一把旧椅子相当于减少了多少木材消耗？', options: ['约0.02-0.05立方米','约1立方米','没有减少','约0.5立方米'], correct: 0, explain: '修复旧椅子可避免购买新椅子所需的木材，约节省0.02-0.05立方米木材。' },
        { text: '以下哪种损坏最容易家庭修复？', options: ['松动的螺丝或脱胶的桌腿','屏幕碎裂','芯片损坏','发动机故障'], correct: 0, explain: '松动螺丝和脱胶问题只需简单工具即可修复，是最适合家庭DIY的修复项目。' },
        { text: '电子产品的计划性报废是指？', options: ['厂家设计产品寿命有限迫使换新','产品自然老化','用户不爱惜','技术进步太快'], correct: 0, explain: '计划性报废是厂商故意设计产品寿命有限以促进持续消费的商业策略。' },
        { text: '旧物市集(跳蚤市场)的环保意义？', options: ['促进物品循环利用减少垃圾','只是好玩','浪费资源','扰乱市场'], correct: 0, explain: '旧物市集让闲置物品找到新主人，延长其使用寿命并减少废弃物产生。' },
        { text: '自行车修理中最常见的易损件是？', options: ['刹车片和链条','车架','坐垫','铃铛'], correct: 0, explain: '刹车片和链条是自行车使用频率最高的部件，定期保养可显著延长寿命。' },
        { text: '修理权(Right to Repair)运动主张什么？', options: ['消费者有权自行或选择第三方维修产品','只有厂家能修','禁止维修','必须买新的'], correct: 0, explain: '修理权运动主张消费者应拥有维修自己购买的产品的权利，包括获取零件和维修手册。' },
        { text: '金属回收相比采矿冶炼节能约？', options: ['60-95%','不到10%','约20%','完全相同'], correct: 0, explain: '回收铝比从矿石冶炼节能95%，回收铜节能85%，回收钢铁节能60%以上。' },
        { text: '旧轮胎可以回收利用做什么？', options: ['橡胶跑道、沥青改性剂等','食品容器','新衣服','纸'], correct: 0, explain: '废旧轮胎可加工成胶粉用于铺设运动跑道、改性沥青等用途。' },
        { text: '你扔掉的旧手机去了哪里最可能是？', options: ['被非正规拆解造成污染','直接销毁','全部回收','堆在仓库'], correct: 0, explain: '全球大量电子垃圾流入非正规拆解渠道，用火烧酸洗等原始方式提取金属。' },
        { text: '旧物修复需要哪些基本心态？', options: ['耐心、创造力、珍惜物品','着急、随便、无所谓','完美主义','买新的更方便'], correct: 0, explain: '修复需要耐心和创造力，更重要的是对物品的珍惜和爱护之心。' },
        { text: '衣服破了先想到什么？', options: ['尝试缝补而非丢弃','扔掉买新','不管继续穿','送人'], correct: 0, explain: '衣服破损可以缝补、改造或用作抹布，减少纺织品浪费。' },

        { text: '安全知识测试题1：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题2：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题3：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题4：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题5：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题6：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题7：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题8：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题9：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题10：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题11：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题12：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题13：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题14：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题15：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题16：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题17：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题18：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题19：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题20：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题21：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题22：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题23：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题24：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题25：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题26：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题27：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题28：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题29：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题30：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题31：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题32：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题33：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题34：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题35：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题36：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题37：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题38：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题39：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题40：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
];
    if (window._qadventure) window._qadventure.destroy();
    window._qadventure = new QAdventureEngine({
        gameId: 'repair',
        themeId: 'repair',
        questions: questions,
        areaElId: 'repair-game-area',
        scoreElId: 'repair-score',
        resultDivId: 'repair-result',
        resultTextId: 'repair-score-text'
    });
    window._qadventure.init();
}
function initAidGame() {
    var resultDiv = document.getElementById('aid-result');
    if (resultDiv) resultDiv.classList.add('hidden');
    var questions = [
        { text: "发现有人心脏骤停，第一步应该？", options: ["呼叫急救并心肺复苏", "喂水", "扶起来走动", "等待自然恢复"], correct: 0, explain: "心脏骤停后4-6分钟脑细胞开始死亡，必须立即呼叫急救并开始心肺复苏。" },
        { text: "烫伤后正确的处理方式是？", options: ["流动冷水冲15-20分钟", "涂牙膏", "涂酱油", "戳破水泡"], correct: 0, explain: "烫伤后立即用流动冷水冲15-20分钟，可有效降温减轻损伤。切勿涂牙膏酱油。" },
        { text: "海姆立克急救法用于？", options: ["气道异物梗阻", "心脏骤停", "骨折", "中暑"], correct: 0, explain: "海姆立克急救法专门用于气道异物梗阻，通过腹部冲击排出异物。" },
        { text: "有人溺水救上岸后，首先应该？", options: ["清理口鼻异物，检查呼吸", "倒立控水", "猛烈摇晃", "喂热水"], correct: 0, explain: "先清理口鼻异物确保气道通畅，然后检查呼吸，必要时进行人工呼吸。" },
        { text: "流鼻血时正确的做法是？", options: ["身体前倾，捏住鼻翼", "仰头止血", "平躺", "塞纸巾深处"], correct: 0, explain: "身体前倾、捏住鼻翼压迫止血是正确的，仰头会让血液流入咽喉。" },
        { text: "成人心肺复苏（CPR）的按压频率应为每分钟多少次？", options: ["100-120次", "60-80次", "140-160次", "随意频率"], correct: 0, explain: "CPR标准按压频率为每分钟100-120次，深度5-6厘米，每次按压后让胸廓完全回弹。" },
        { text: "被蜜蜂蜇伤后，正确的处理方式是？", options: ["用卡片刮出毒刺，不捏挤", "用嘴吸出毒液", "用指甲掐出毒刺", "立即切开伤口"], correct: 0, explain: "用硬卡片（如银行卡）向侧方刮出毒刺，切勿用指甲或镊子捏挤毒囊，以免释放更多毒液。" },
        { text: "低血糖昏迷的患者，应该？", options: ["让其侧卧，不要喂食", "喂糖水", "注射胰岛素", "剧烈摇晃唤醒"], correct: 0, explain: "昏迷患者无法吞咽，喂食会导致窒息。应让其侧卧保持气道通畅，立即呼叫急救。" },
        { text: "骨折现场急救的首要原则是？", options: ["避免移动伤处，固定后送医", "立即复位", "按摩活血", "让患者行走测试"], correct: 0, explain: "骨折后错误移动可能导致骨刺伤血管神经，应先利用夹板等固定再送医。" },
        { text: "中暑最严重的阶段（热射病）体温可达多少度？", options: ["超过40℃", "约37℃", "约38℃", "约35℃"], correct: 0, explain: "热射病是最严重的中暑类型，体温可超过40℃，伴有意识障碍，死亡率高达50%，需立即降温并送医。" }
    ,
        { text: '心肺复苏(CPR)的按压频率应为每分钟多少次？', options: ['100-120次','60-80次','150-180次','30-50次'], correct: 0, explain: '成人CPR按压频率应为每分钟100-120次，按压深度5-6厘米。' },
        { text: '海姆立克急救法用于处理什么情况？', options: ['气道异物梗阻','心脏病发作','骨折','中暑'], correct: 0, explain: '海姆立克法通过腹部冲击排出气道异物，是窒息急救的首选方法。' },
        { text: '烫伤后第一步正确处理是？', options: ['流动凉水冲洗至少15分钟','涂牙膏','涂酱油','冰敷'], correct: 0, explain: '烫伤后立即用流动凉水冲洗降温，不要涂抹牙膏酱油等偏方！' },
        { text: '发现有人倒地首先应做什么？', options: ['确认环境安全后判断意识','立即做CPR','立即搬动患者','不管直接离开'], correct: 0, explain: '急救第一步永远是确保环境安全，然后判断患者意识和呼吸。' },
        { text: '正确的止血方法是？', options: ['用干净布料直接按压伤口','用嘴吸','用泥土敷','用酒精冲洗'], correct: 0, explain: '直接按压法是标准止血方法：用干净布料按压伤口并抬高患处。' },
        { text: '鼻出血的正确处理是？', options: ['头前倾捏住鼻翼','仰头','塞纸巾不管','用力擤鼻子'], correct: 0, explain: '鼻出血应头前倾、捏住鼻翼10-15分钟，仰头可能使血液流入咽喉。' },
        { text: '骨折的临时固定原则是？', options: ['固定骨折上下两个关节','只固定骨折处','随意搬动','热敷'], correct: 0, explain: '骨折固定应超出上下两个关节，用夹板和绷带固定后尽快就医。' },
        { text: '中暑急救的第一步是？', options: ['移至阴凉通风处降温','喝热水','盖被子','运动出汗'], correct: 0, explain: '中暑后应立即移至阴凉通风处，解开衣物散热，补充水分。' },
        { text: '糖尿病人低血糖时应？', options: ['立即补充糖分(糖果/果汁)','注射胰岛素','喝水','运动'], correct: 0, explain: '低血糖可危及生命，应迅速补充含糖食物如果汁、糖果等快速升糖。' },
        { text: '胸痛可能是哪种疾病的信号？', options: ['心肌梗死(心脏病发作)','感冒','胃痛','疲劳'], correct: 0, explain: '突发胸痛特别是伴有出汗、呼吸困难的，要高度警惕心肌梗死。' },
        { text: '遇到有人癫痫发作应？', options: ['保护头部移开危险物品不约束','往嘴里塞东西','强行按住','泼冷水'], correct: 0, explain: '癫痫发作时不往嘴里塞东西！保护头部、移开危险物、记录发作时间。' },
        { text: '急救电话120拨通后应先说什么？', options: ['准确地址和患者情况','先哭再说话','只说快来','先挂断再准备'], correct: 0, explain: '拨打120应冷静说清地址、患者情况、联系方式，不要先挂电话。' },
        { text: '动物咬伤后首要处理是？', options: ['肥皂水冲洗15分钟以上','包扎不管','用嘴吸','涂红花油'], correct: 0, explain: '动物咬伤用大量肥皂水冲洗伤口15分钟以上，然后尽快就医评估狂犬病风险。' },
        { text: 'AED(自动体外除颤器)是什么？', options: ['用于心脏骤停急救的便携设备','测血压的仪器','血糖仪','体温计'], correct: 0, explain: 'AED是用于心脏骤停的自动体外除颤器，普通人按语音提示即可使用。' },
        { text: '溺水者救上岸后首先？', options: ['检查意识和呼吸','立即做人工呼吸','控水','不管'], correct: 0, explain: '先判断意识和呼吸，如无呼吸立即开始CPR，不要浪费时间控水。' },
        { text: '烧伤水泡应该？', options: ['保持完整不要挑破','立即挑破','涂酱油','敷冰块'], correct: 0, explain: '水泡是天然的保护层，保持完整可防感染，小水泡会自行吸收。' },
        { text: '踝关节扭伤后急救原则缩写是？', options: ['RICE(休息冰敷加压抬高)','CPR','ABC','AED'], correct: 0, explain: 'RICE：Rest休息、Ice冰敷、Compression加压、Elevation抬高。' },
        { text: '食物中毒后应该？', options: ['补充水分及时就医','吃止泻药','喝牛奶解毒','不管等自愈'], correct: 0, explain: '食物中毒后最重要的是防止脱水，多喝水并及时就医。' },
        { text: '户外被蛇咬伤的正确处理？', options: ['保持冷静制动并立即就医','用嘴吸毒','切开伤口','绑紧伤口上方'], correct: 0, explain: '被蛇咬应保持冷静减少活动以减缓毒素扩散，迅速就医注射抗蛇毒血清。' },
        { text: '过敏性休克的首选急救药物是？', options: ['肾上腺素(肾上腺素笔)','抗生素','止痛药','维生素'], correct: 0, explain: '肾上腺素是过敏性休克的一线急救药物，严重过敏者应随身携带肾上腺素笔。' },
        { text: '一岁以下婴儿窒息急救方法？', options: ['背部拍击和胸部按压交替','海姆立克法','倒吊拍打','用力摇晃'], correct: 0, explain: '婴儿窒息采用5次背部拍击+5次胸部按压交替，不要倒吊或摇晃。' },
        { text: '户外失温(低体温)的表现不包括？', options: ['面色潮红发热','发抖','意识模糊','言语不清'], correct: 0, explain: '失温表现为发抖→意识模糊→失去知觉，面色潮红发热是相反的。' },
        { text: '被蜜蜂蜇伤后应该？', options: ['用卡片刮除毒刺不要挤压','用手挤毒刺','涂酒','不管'], correct: 0, explain: '用硬卡片刮除毒刺，不要挤压以免更多毒液注入，然后冰敷消肿。' },
        { text: '厨房油锅起火正确灭火方式？', options: ['盖上锅盖或用灭火毯','用水浇','用面粉','用嘴吹'], correct: 0, explain: '油锅起火盖锅盖隔绝氧气或用灭火毯覆盖，绝对不可以用水！' },
        { text: '高处坠落伤者应如何搬运？', options: ['固定脊柱用硬质担架搬运','随意搬动','扶起来走','背起来跑'], correct: 0, explain: '高处坠落可能伤及脊柱，必须用硬质担架固定后搬运，避免二次伤害。' },

        { text: '心肺复苏(CPR)的按压频率应为每分钟多少次？', options: ['100-120次','60-80次','150-180次','30-50次'], correct: 0, explain: '成人CPR按压频率应为每分钟100-120次，按压深度5-6厘米。' },
        { text: '海姆立克急救法用于处理什么情况？', options: ['气道异物梗阻','心脏病发作','骨折','中暑'], correct: 0, explain: '海姆立克法通过腹部冲击排出气道异物，是窒息急救的首选方法。' },
        { text: '烫伤后第一步正确处理是？', options: ['流动凉水冲洗至少15分钟','涂牙膏','涂酱油','冰敷'], correct: 0, explain: '烫伤后立即用流动凉水冲洗降温，不要涂抹牙膏酱油等偏方！' },
        { text: '发现有人倒地首先应做什么？', options: ['确认环境安全后判断意识','立即做CPR','立即搬动患者','不管直接离开'], correct: 0, explain: '急救第一步永远是确保环境安全，然后判断患者意识和呼吸。' },
        { text: '正确的止血方法是？', options: ['用干净布料直接按压伤口','用嘴吸','用泥土敷','用酒精冲洗'], correct: 0, explain: '直接按压法是标准止血方法：用干净布料按压伤口并抬高患处。' },
        { text: '鼻出血的正确处理是？', options: ['头前倾捏住鼻翼','仰头','塞纸巾不管','用力擤鼻子'], correct: 0, explain: '鼻出血应头前倾、捏住鼻翼10-15分钟，仰头可能使血液流入咽喉。' },
        { text: '骨折的临时固定原则是？', options: ['固定骨折上下两个关节','只固定骨折处','随意搬动','热敷'], correct: 0, explain: '骨折固定应超出上下两个关节，用夹板和绷带固定后尽快就医。' },
        { text: '中暑急救的第一步是？', options: ['移至阴凉通风处降温','喝热水','盖被子','运动出汗'], correct: 0, explain: '中暑后应立即移至阴凉通风处，解开衣物散热，补充水分。' },
        { text: '糖尿病人低血糖时应？', options: ['立即补充糖分(糖果/果汁)','注射胰岛素','喝水','运动'], correct: 0, explain: '低血糖可危及生命，应迅速补充含糖食物如果汁、糖果等快速升糖。' },
        { text: '胸痛可能是哪种疾病的信号？', options: ['心肌梗死(心脏病发作)','感冒','胃痛','疲劳'], correct: 0, explain: '突发胸痛特别是伴有出汗、呼吸困难的，要高度警惕心肌梗死。' },
        { text: '遇到有人癫痫发作应？', options: ['保护头部移开危险物品不约束','往嘴里塞东西','强行按住','泼冷水'], correct: 0, explain: '癫痫发作时不往嘴里塞东西！保护头部、移开危险物、记录发作时间。' },
        { text: '急救电话120拨通后应先说什么？', options: ['准确地址和患者情况','先哭再说话','只说快来','先挂断再准备'], correct: 0, explain: '拨打120应冷静说清地址、患者情况、联系方式，不要先挂电话。' },
        { text: '动物咬伤后首要处理是？', options: ['肥皂水冲洗15分钟以上','包扎不管','用嘴吸','涂红花油'], correct: 0, explain: '动物咬伤用大量肥皂水冲洗伤口15分钟以上，然后尽快就医评估狂犬病风险。' },
        { text: 'AED(自动体外除颤器)是什么？', options: ['用于心脏骤停急救的便携设备','测血压的仪器','血糖仪','体温计'], correct: 0, explain: 'AED是用于心脏骤停的自动体外除颤器，普通人按语音提示即可使用。' },
        { text: '溺水者救上岸后首先？', options: ['检查意识和呼吸','立即做人工呼吸','控水','不管'], correct: 0, explain: '先判断意识和呼吸，如无呼吸立即开始CPR，不要浪费时间控水。' },
        { text: '烧伤水泡应该？', options: ['保持完整不要挑破','立即挑破','涂酱油','敷冰块'], correct: 0, explain: '水泡是天然的保护层，保持完整可防感染，小水泡会自行吸收。' },
        { text: '踝关节扭伤后急救原则缩写是？', options: ['RICE(休息冰敷加压抬高)','CPR','ABC','AED'], correct: 0, explain: 'RICE：Rest休息、Ice冰敷、Compression加压、Elevation抬高。' },
        { text: '食物中毒后应该？', options: ['补充水分及时就医','吃止泻药','喝牛奶解毒','不管等自愈'], correct: 0, explain: '食物中毒后最重要的是防止脱水，多喝水并及时就医。' },
        { text: '户外被蛇咬伤的正确处理？', options: ['保持冷静制动并立即就医','用嘴吸毒','切开伤口','绑紧伤口上方'], correct: 0, explain: '被蛇咬应保持冷静减少活动以减缓毒素扩散，迅速就医注射抗蛇毒血清。' },
        { text: '过敏性休克的首选急救药物是？', options: ['肾上腺素(肾上腺素笔)','抗生素','止痛药','维生素'], correct: 0, explain: '肾上腺素是过敏性休克的一线急救药物，严重过敏者应随身携带肾上腺素笔。' },
        { text: '一岁以下婴儿窒息急救方法？', options: ['背部拍击和胸部按压交替','海姆立克法','倒吊拍打','用力摇晃'], correct: 0, explain: '婴儿窒息采用5次背部拍击+5次胸部按压交替，不要倒吊或摇晃。' },
        { text: '户外失温(低体温)的表现不包括？', options: ['面色潮红发热','发抖','意识模糊','言语不清'], correct: 0, explain: '失温表现为发抖→意识模糊→失去知觉，面色潮红发热是相反的。' },
        { text: '被蜜蜂蜇伤后应该？', options: ['用卡片刮除毒刺不要挤压','用手挤毒刺','涂酒','不管'], correct: 0, explain: '用硬卡片刮除毒刺，不要挤压以免更多毒液注入，然后冰敷消肿。' },
        { text: '厨房油锅起火正确灭火方式？', options: ['盖上锅盖或用灭火毯','用水浇','用面粉','用嘴吹'], correct: 0, explain: '油锅起火盖锅盖隔绝氧气或用灭火毯覆盖，绝对不可以用水！' },
        { text: '高处坠落伤者应如何搬运？', options: ['固定脊柱用硬质担架搬运','随意搬动','扶起来走','背起来跑'], correct: 0, explain: '高处坠落可能伤及脊柱，必须用硬质担架固定后搬运，避免二次伤害。' },

        { text: '安全知识测试题1：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题2：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题3：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题4：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题5：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题6：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题7：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题8：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题9：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题10：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题11：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题12：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题13：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题14：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题15：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题16：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题17：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题18：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题19：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题20：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题21：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题22：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题23：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题24：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题25：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题26：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题27：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题28：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题29：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题30：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题31：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题32：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题33：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题34：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题35：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题36：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题37：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题38：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题39：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题40：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
];
    if (window._qadventure) window._qadventure.destroy();
    window._qadventure = new QAdventureEngine({
        gameId: 'aid',
        themeId: 'aid',
        questions: questions,
        areaElId: 'aid-game-area',
        scoreElId: 'aid-score',
        resultDivId: 'aid-result',
        resultTextId: 'aid-score-text'
    });
    window._qadventure.init();
}
function initFoodGame() {
    var resultDiv = document.getElementById('food-result');
    if (resultDiv) resultDiv.classList.add('hidden');
    var questions = [
        { text: "以下哪种食物变质后会产生黄曲霉素（强致癌物）？", options: ["发霉的花生/玉米", "过期的牛奶", "变软的苹果", "隔夜的米饭"], correct: 0, explain: "黄曲霉素主要由黄曲霉菌产生，常见于发霉的花生、玉米、坚果中，是强致癌物。" },
        { text: "冰箱中熟食和生食的正确存放方式是？", options: ["熟食放上，生食放下", "混放没关系", "生食放上，熟食放下", "全部放冷冻"], correct: 0, explain: "熟食放上层，生食放下层，防止生食汁液滴落污染熟食。" },
        { text: "以下哪种情况说明鸡蛋可能已经变质？", options: ["摇晃时有明显水声", "蛋壳有斑点", "蛋壳较白", "鸡蛋较小"], correct: 0, explain: "摇晃鸡蛋有明显水声说明蛋白蛋黄已分离变质，新鲜鸡蛋摇晃无声。" },
        { text: "剩菜在室温下放置多久后不宜食用？", options: ["超过2小时", "超过30分钟", "超过6小时", "超过12小时"], correct: 0, explain: "室温下细菌繁殖迅速，剩菜超过2小时应冷藏，超过4小时建议丢弃。" },
        { text: "以下哪种食品标签日期表示最佳食用期（过期仍可食用但品质下降）？", options: ["保质期", "生产日期", "保存期", "上市日期"], correct: 0, explain: "保质期是最佳食用期，过期后品质可能下降但不一定有害；保存期是安全食用期限。" },
        { text: "四季豆（扁豆）未煮熟食用可能导致？", options: ["皂素中毒（恶心呕吐）", "维生素中毒", "蛋白质中毒", "无害，口感差而已"], correct: 0, explain: "四季豆含有皂素和植物血凝素，未充分加热食用会导致中毒，表现为恶心、呕吐、腹泻，必须彻底煮熟。" },
        { text: "发芽的土豆含有哪种有毒物质？", options: ["龙葵素", "黄曲霉素", "亚硝酸盐", "甲醛"], correct: 0, explain: "发芽或变绿的土豆含有大量龙葵素，食用后可引起咽喉麻痒、呕吐，严重可致死，应整个丢弃。" },
        { text: "微波炉加热食物的下列做法中，哪个是正确的？", options: ["使用微波专用容器，不密封", "使用密封塑料盒", "用铝箔纸包裹加热", "用泡沫餐盒直接加热"], correct: 0, explain: "微波加热应使用标注「微波适用」的容器，且不能密封（会爆炸）。金属容器和泡沫塑料均不适用。" },
        { text: "食品添加剂「亚硝酸盐」在腌肉中的主要作用是？", options: ["发色抑菌（但过量致癌）", "增加甜味", "防腐漂白", "增加脆嫩口感"], correct: 0, explain: "亚硝酸盐可使肉制品呈现粉红色并抑制肉毒杆菌，但过量摄入会在体内转化为致癌物亚硝胺，须严格控制用量。" },
        { text: "野生蘑菇中毒后，以下哪项是错误做法？", options: ["自行服用解药/催吐自救", "立即就医并保留蘑菇样本", "告知医生蘑菇形态", "大量饮水稀释"], correct: 0, explain: "野生蘑菇中毒没有通用解药，自行催吐可能误吸导致窒息，立即就医并告知蘑菇特征是最正确的做法。" }
    ,
        { text: '以下哪种食物最容易滋生黄曲霉素？', options: ['发霉的花生和玉米','新鲜蔬菜','鲜肉','冷藏水果'], correct: 0, explain: '发霉花生和玉米中的黄曲霉素是强致癌物，霉变食物一定不能食用。' },
        { text: '冰箱冷藏室的建议温度是多少？', options: ['0-4°C','-18°C','10-15°C','20°C'], correct: 0, explain: '冷藏室建议设置在0-4°C，可有效抑制大多数细菌生长。' },
        { text: '食物在危险温度带最容易滋生细菌，这个范围是？', options: ['5-60°C','-18-0°C','60-100°C','100°C以上'], correct: 0, explain: '5-60°C是食品安全危险温度带，食物在此温度超过2小时即有风险。' },
        { text: '以下哪种做法最容易导致食物交叉污染？', options: ['生熟共用砧板刀具','分用砧板','洗手','分装保存'], correct: 0, explain: '生熟共用砧板刀具极易导致交叉污染，应分开使用或先切熟后切生。' },
        { text: '隔夜菜在室温下放置多久就会有变质风险？', options: ['超过2小时','超过8小时','超过24小时','永远不会'], correct: 0, explain: '煮熟的饭菜在室温下放置超过2小时就进入危险温度带，应尽快冷藏。' },
        { text: '野生蘑菇中毒的主要原因是？', options: ['误食有毒品种','烹饪时间不够','没洗干净','调味太重'], correct: 0, explain: '我国有400多种毒蘑菇，很多与食用菌相似，切勿采摘食用不认识的野生菌。' },
        { text: '发芽的土豆为什么不能吃？', options: ['含有龙葵素可致中毒','太苦了','太老了','太硬了'], correct: 0, explain: '发芽土豆中龙葵素含量剧增，食用后可导致恶心呕吐甚至死亡。' },
        { text: '以下哪种是正确的解冻方式？', options: ['提前放入冷藏室解冻','室温解冻','热水浸泡解冻','不解冻直接烹饪'], correct: 0, explain: '冷藏室解冻最安全，室温解冻使食物进入危险温度带。急需解冻可用微波炉。' },
        { text: '食品保质期和保存期的区别？', options: ['保存期过后不可食用保质期是质量保证','完全一样','保质期可延后','保存期无所谓'], correct: 0, explain: '保质期是质量保证期，保存期是安全期限，超过保存期的食品绝对不能吃。' },
        { text: '亚硝酸盐中毒最常见的原因是？', options: ['误食工业盐或过量腌制食品','吃太多水果','喝太多水','吃太多米饭'], correct: 0, explain: '亚硝酸盐中毒常见于误将工业盐当食盐或短期腌菜亚硝酸盐高峰期食用。' },
        { text: '冰箱食物存放原则正确的是？', options: ['生食放下层熟食放上层','随意放','生食放上层','全部堆一起'], correct: 0, explain: '熟食放上层生食放下层，防止生食汁水滴落污染熟食。' },
        { text: '有机食品是指？', options: ['生产中不使用化学合成农药化肥','不洗的食品','野生的食品','进口食品'], correct: 0, explain: '有机食品在生产过程中不使用化学合成农药、化肥、转基因技术等。' },
        { text: '食物中毒最常见的症状是？', options: ['恶心呕吐腹泻腹痛','发烧咳嗽','皮肤瘙痒','失眠'], correct: 0, explain: '食物中毒典型表现为胃肠道症状：恶心、呕吐、腹痛、腹泻。' },
        { text: '以下哪种食物天然含有毒素必须彻底煮熟？', options: ['四季豆','黄瓜','生菜','番茄'], correct: 0, explain: '四季豆含皂苷和血球凝集素，不彻底煮熟可导致中毒。' },
        { text: '转基因食品是否安全？', options: ['经安全评估上市的与传统食品一样安全','绝对有害','绝对安全','不能食用'], correct: 0, explain: '世界卫生组织和各国科学机构共识：经安全评估上市的转基因食品与传统食品一样安全。' },
        { text: '剩菜保存超过几天不建议食用？', options: ['冷藏超过3天','超过1天','超过7天','超过1个月'], correct: 0, explain: '冰箱剩菜冷藏超过3天细菌繁殖风险大幅增加，建议3天内食用完毕。' },
        { text: '预包装食品的SC编码代表什么？', options: ['食品生产许可证编号','食品等级','食品价格','食品产地'], correct: 0, explain: 'SC编码是食品生产许可证编号，代表该产品由获证企业合法生产。' },
        { text: '以下哪种添加剂是国家允许使用的防腐剂？', options: ['山梨酸钾','甲醛','硼砂','吊白块'], correct: 0, explain: '山梨酸钾是法定食品防腐剂；甲醛、硼砂、吊白块是非法添加物。' },
        { text: '食品安全五大要点不包括？', options: ['使用漂白剂清洗','保持清洁','生熟分开','彻底煮熟'], correct: 0, explain: 'WHO食品安全五要点：保持清洁、生熟分开、彻底煮熟、安全温度、安全原料。' },
        { text: '重金属污染最可能来源于？', options: ['工业废水灌溉的农作物','深海鱼','有机蔬菜','纯净水'], correct: 0, explain: '工业废水灌溉的农作物可能富集铅、镉、汞等重金属，长期食用危害健康。' },
        { text: '新鲜的肉类应该呈现什么状态？', options: ['有光泽弹性好无异味','发黏','发绿','有臭味'], correct: 0, explain: '新鲜肉应有光泽、指压后凹陷立即恢复、具有正常肉味无异味。' },
        { text: '塑化剂事件中受影响最大的是？', options: ['饮料和油脂食品','蔬菜水果','大米白面','海鲜'], correct: 0, explain: '塑化剂易溶于油脂，在含油脂食品和饮料中最容易被非法添加。' },
        { text: '鸡蛋是否应该清洗后再储存？', options: ['不应清洗，会破坏保护膜','应该洗干净','无所谓','应该泡水'], correct: 0, explain: '鸡蛋表面有天然保护膜，清洗会破坏保护膜使细菌更容易侵入。' },
        { text: '哪种烹饪方式产生的致癌物最少？', options: ['蒸煮','烧烤','油炸','烟熏'], correct: 0, explain: '蒸煮温度较低不产生油烟，产生的致癌物质(如苯并芘)最少。' },
        { text: '食物中检测出农药残留就一定不安全吗？', options: ['低于国标限值是安全的','一定不安全','绝对安全','无所谓'], correct: 0, explain: '农药残留低于国家标准限值的食品是安全的，标准已留足安全空间。' },

        { text: '以下哪种食物最容易滋生黄曲霉素？', options: ['发霉的花生和玉米','新鲜蔬菜','鲜肉','冷藏水果'], correct: 0, explain: '发霉花生和玉米中的黄曲霉素是强致癌物，霉变食物一定不能食用。' },
        { text: '冰箱冷藏室的建议温度是多少？', options: ['0-4°C','-18°C','10-15°C','20°C'], correct: 0, explain: '冷藏室建议设置在0-4°C，可有效抑制大多数细菌生长。' },
        { text: '食物在危险温度带最容易滋生细菌，这个范围是？', options: ['5-60°C','-18-0°C','60-100°C','100°C以上'], correct: 0, explain: '5-60°C是食品安全危险温度带，食物在此温度超过2小时即有风险。' },
        { text: '以下哪种做法最容易导致食物交叉污染？', options: ['生熟共用砧板刀具','分用砧板','洗手','分装保存'], correct: 0, explain: '生熟共用砧板刀具极易导致交叉污染，应分开使用或先切熟后切生。' },
        { text: '隔夜菜在室温下放置多久就会有变质风险？', options: ['超过2小时','超过8小时','超过24小时','永远不会'], correct: 0, explain: '煮熟的饭菜在室温下放置超过2小时就进入危险温度带，应尽快冷藏。' },
        { text: '野生蘑菇中毒的主要原因是？', options: ['误食有毒品种','烹饪时间不够','没洗干净','调味太重'], correct: 0, explain: '我国有400多种毒蘑菇，很多与食用菌相似，切勿采摘食用不认识的野生菌。' },
        { text: '发芽的土豆为什么不能吃？', options: ['含有龙葵素可致中毒','太苦了','太老了','太硬了'], correct: 0, explain: '发芽土豆中龙葵素含量剧增，食用后可导致恶心呕吐甚至死亡。' },
        { text: '以下哪种是正确的解冻方式？', options: ['提前放入冷藏室解冻','室温解冻','热水浸泡解冻','不解冻直接烹饪'], correct: 0, explain: '冷藏室解冻最安全，室温解冻使食物进入危险温度带。急需解冻可用微波炉。' },
        { text: '食品保质期和保存期的区别？', options: ['保存期过后不可食用保质期是质量保证','完全一样','保质期可延后','保存期无所谓'], correct: 0, explain: '保质期是质量保证期，保存期是安全期限，超过保存期的食品绝对不能吃。' },
        { text: '亚硝酸盐中毒最常见的原因是？', options: ['误食工业盐或过量腌制食品','吃太多水果','喝太多水','吃太多米饭'], correct: 0, explain: '亚硝酸盐中毒常见于误将工业盐当食盐或短期腌菜亚硝酸盐高峰期食用。' },
        { text: '冰箱食物存放原则正确的是？', options: ['生食放下层熟食放上层','随意放','生食放上层','全部堆一起'], correct: 0, explain: '熟食放上层生食放下层，防止生食汁水滴落污染熟食。' },
        { text: '有机食品是指？', options: ['生产中不使用化学合成农药化肥','不洗的食品','野生的食品','进口食品'], correct: 0, explain: '有机食品在生产过程中不使用化学合成农药、化肥、转基因技术等。' },
        { text: '食物中毒最常见的症状是？', options: ['恶心呕吐腹泻腹痛','发烧咳嗽','皮肤瘙痒','失眠'], correct: 0, explain: '食物中毒典型表现为胃肠道症状：恶心、呕吐、腹痛、腹泻。' },
        { text: '以下哪种食物天然含有毒素必须彻底煮熟？', options: ['四季豆','黄瓜','生菜','番茄'], correct: 0, explain: '四季豆含皂苷和血球凝集素，不彻底煮熟可导致中毒。' },
        { text: '转基因食品是否安全？', options: ['经安全评估上市的与传统食品一样安全','绝对有害','绝对安全','不能食用'], correct: 0, explain: '世界卫生组织和各国科学机构共识：经安全评估上市的转基因食品与传统食品一样安全。' },
        { text: '剩菜保存超过几天不建议食用？', options: ['冷藏超过3天','超过1天','超过7天','超过1个月'], correct: 0, explain: '冰箱剩菜冷藏超过3天细菌繁殖风险大幅增加，建议3天内食用完毕。' },
        { text: '预包装食品的SC编码代表什么？', options: ['食品生产许可证编号','食品等级','食品价格','食品产地'], correct: 0, explain: 'SC编码是食品生产许可证编号，代表该产品由获证企业合法生产。' },
        { text: '以下哪种添加剂是国家允许使用的防腐剂？', options: ['山梨酸钾','甲醛','硼砂','吊白块'], correct: 0, explain: '山梨酸钾是法定食品防腐剂；甲醛、硼砂、吊白块是非法添加物。' },
        { text: '食品安全五大要点不包括？', options: ['使用漂白剂清洗','保持清洁','生熟分开','彻底煮熟'], correct: 0, explain: 'WHO食品安全五要点：保持清洁、生熟分开、彻底煮熟、安全温度、安全原料。' },
        { text: '重金属污染最可能来源于？', options: ['工业废水灌溉的农作物','深海鱼','有机蔬菜','纯净水'], correct: 0, explain: '工业废水灌溉的农作物可能富集铅、镉、汞等重金属，长期食用危害健康。' },
        { text: '新鲜的肉类应该呈现什么状态？', options: ['有光泽弹性好无异味','发黏','发绿','有臭味'], correct: 0, explain: '新鲜肉应有光泽、指压后凹陷立即恢复、具有正常肉味无异味。' },
        { text: '塑化剂事件中受影响最大的是？', options: ['饮料和油脂食品','蔬菜水果','大米白面','海鲜'], correct: 0, explain: '塑化剂易溶于油脂，在含油脂食品和饮料中最容易被非法添加。' },
        { text: '鸡蛋是否应该清洗后再储存？', options: ['不应清洗，会破坏保护膜','应该洗干净','无所谓','应该泡水'], correct: 0, explain: '鸡蛋表面有天然保护膜，清洗会破坏保护膜使细菌更容易侵入。' },
        { text: '哪种烹饪方式产生的致癌物最少？', options: ['蒸煮','烧烤','油炸','烟熏'], correct: 0, explain: '蒸煮温度较低不产生油烟，产生的致癌物质(如苯并芘)最少。' },
        { text: '食物中检测出农药残留就一定不安全吗？', options: ['低于国标限值是安全的','一定不安全','绝对安全','无所谓'], correct: 0, explain: '农药残留低于国家标准限值的食品是安全的，标准已留足安全空间。' },

        { text: '安全知识测试题1：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题2：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题3：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题4：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题5：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题6：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题7：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题8：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题9：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题10：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题11：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题12：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题13：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题14：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题15：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题16：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题17：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题18：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题19：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题20：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题21：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题22：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题23：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题24：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题25：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题26：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题27：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题28：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题29：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题30：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题31：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题32：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题33：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题34：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题35：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题36：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题37：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题38：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题39：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题40：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
];
    if (window._qadventure) window._qadventure.destroy();
    window._qadventure = new QAdventureEngine({
        gameId: 'food',
        themeId: 'food',
        questions: questions,
        areaElId: 'food-game-area',
        scoreElId: 'food-score',
        resultDivId: 'food-result',
        resultTextId: 'food-score-text'
    });
    window._qadventure.init();
}
function initAnimalGame() {
    var resultDiv = document.getElementById('animal-result');
    if (resultDiv) resultDiv.classList.add('hidden');
    var questions = [
        { text: "遇到受伤的野生动物，正确的做法是？", options: ["联系林业部门/野生动物救助站", "带回家饲养", "直接放生", "喂人类食物"], correct: 0, explain: "应联系专业救助机构，私自饲养可能违法且对动物不利。" },
        { text: "以下哪种动物是国家一级保护动物？", options: ["大熊猫", "麻雀", "家鸽", "流浪猫"], correct: 0, explain: "大熊猫是国家一级保护动物，也是世界自然基金会的标志物种。" },
        { text: "发现非法野生动物交易，应该拨打？", options: ["12315或110", "120", "114", "119"], correct: 0, explain: "发现非法野生动物交易可拨打12315（市场监管）或110报警。" },
        { text: "以下哪种行为会威胁海洋生物生存？", options: ["随意丢弃塑料垃圾", "海边捡贝壳", "观赏海豚表演", "食用养殖海鱼"], correct: 0, explain: "塑料垃圾被海洋生物误食会导致死亡，每年约100万只海鸟因此丧生。" },
        { text: "候鸟迁徙途中最重要的需求是？", options: ["安全的停歇地（湿地）", "人类投喂", "温暖的天气", "高大的树木"], correct: 0, explain: "湿地为候鸟提供食物和休息场所，湿地破坏是候鸟面临的最大威胁。" },
        { text: "穿山甲被猎捕的主要原因是？", options: ["鳞片被误认为可入药", "肉质鲜美", "皮毛值钱", "作为宠物贸易"], correct: 0, explain: "穿山甲鳞片主要成分是角蛋白（与人类指甲相同），并无特殊药效，但因误信传言而被大量猎杀，现已极度濒危。" },
        { text: "蜜蜂减少（蜂群崩溃综合征）对人类最大的威胁是？", options: ["粮食减产（授粉不足）", "蜂蜜价格上涨", "蚊子增多", "花朵不再鲜艳"], correct: 0, explain: "约75%的全球主要粮食作物依赖动物授粉，蜜蜂减少将直接导致粮食减产和营养不良加剧。" },
        { text: "以下哪种做法对流浪动物最负责？", options: ["TNR（捕捉-绝育-放归）", "随意投喂不绝育", "全部捕捉安乐死", "驱赶出社区"], correct: 0, explain: "TNR是目前国际公认最人道的流浪猫管理方案，通过绝育控制种群数量，同时维持群落稳定。" },
        { text: "我国《野生动物保护法》最新修订于哪一年？", options: ["2022年", "2010年", "2025年", "尚未立法"], correct: 0, explain: "《中华人民共和国野生动物保护法》于2022年完成最新修订，加大了对野生动物保护的力度，2023年5月1日起施行。" },
        { text: "以下哪种海洋动物因「幽灵渔具」缠绕而受害最深？", options: ["海龟/鲸类", "小丑鱼", "海豚（被圈养）", "珊瑚虫"], correct: 0, explain: "被遗弃的渔网（幽灵渔具）会在海洋中持续缠绕海洋生物数十年，海龟、鲸类和海鸟是最大受害者。" }
    ,
        { text: '我国一级保护动物不包括？', options: ['麻雀','大熊猫','朱鹮','扬子鳄'], correct: 0, explain: '麻雀是常见鸟类不属于保护动物。大熊猫、朱鹮、扬子鳄都是国家一级保护动物。' },
        { text: '遇到受伤的野生动物首先应该？', options: ['联系当地野生动物救助机构','自己带回家养','不管离开','拍照发朋友圈'], correct: 0, explain: '遇到受伤的野生动物应联系专业救助机构，不要自行捕捉或饲养。' },
        { text: '穿山甲的主要威胁是什么？', options: ['非法捕猎和栖息地丧失','自然灾害','天敌太多','不会繁殖'], correct: 0, explain: '穿山甲因鳞片和肉被大量捕猎，加上栖息地破坏，所有8种穿山甲都濒临灭绝。' },
        { text: '非法购买野生动物制品会？', options: ['触犯法律面临刑罚','没事','只是罚款','警告一下'], correct: 0, explain: '收购、运输、出售珍贵濒危野生动物制品构成犯罪，可处有期徒刑和罚金。' },
        { text: '流浪猫对生态环境的影响？', options: ['捕杀大量鸟类和小型野生动物','没有影响','有益','只影响老鼠'], correct: 0, explain: '流浪猫每年捕杀数十亿只鸟类和小动物，是入侵性捕食者对本土生态造成严重威胁。' },
        { text: '以下哪个是野生动物友好行为？', options: ['远距离观察不投喂不打扰','投喂食物','追逐拍照','捕捉回家'], correct: 0, explain: '观察野生动物应保持距离、不投喂、不惊扰，让它们在自然状态下生活。' },
        { text: '象牙贸易为什么被禁止？', options: ['导致大象被大量偷猎濒临灭绝','象牙太贵','不好看','没有用'], correct: 0, explain: '每年约2万头大象因象牙被猎杀，2018年起中国全面禁止国内象牙商业性贸易。' },
        { text: '鱼翅消费导致什么问题？', options: ['每年约7300万条鲨鱼被割鳍后丢弃','没有影响','鲨鱼太多了','有益'], correct: 0, explain: '为取鱼翅每年约7300万条鲨鱼被割鳍后扔回海里等死，许多鲨鱼种类已濒危。' },
        { text: '遇到搁浅的海洋动物应该？', options: ['保持距离降温保湿并报警','推回海里','围观拍照','触摸玩耍'], correct: 0, explain: '搁浅鲸豚等海洋动物应保持距离、泼水降温保湿，立即报告渔政或救助机构。' },
        { text: '小区里发现刺猬应该？', options: ['不打扰让它自行离开','带回家养','给牛奶喝','赶走'], correct: 0, explain: '城市中的刺猬是野生动物，不要捕捉或投喂（尤其是牛奶会致腹泻），让它自行离去。' },
        { text: '以下哪项不是野生动物走私的常见目标？', options: ['家猫','象牙','穿山甲','犀牛角'], correct: 0, explain: '家猫是宠物不属于野生动物走私目标。象牙、穿山甲、犀牛角是常见走私品。' },
        { text: '候鸟迁徙途中最大的威胁是？', options: ['栖息地丧失和非法捕猎','不会飞','天气','年龄'], correct: 0, explain: '湿地减少和非法捕鸟网是候鸟迁徙的主要威胁，中国是东亚-澳大利西亚迁徙路线的重要节点。' },
        { text: '购买和饲养野生保护动物？', options: ['违法','合法','看情况','无所谓'], correct: 0, explain: '私自购买和饲养国家重点保护野生动物是违法行为，可被追究刑事责任。' },
        { text: '中华白海豚主要分布在？', options: ['珠江口和厦门海域','长江上游','黄河','青海湖'], correct: 0, explain: '中华白海豚是国家一级保护动物，主要栖息在珠江口、厦门等近岸海域。' },
        { text: '看到售卖野生动物应该？', options: ['拨打12315或110举报','购买','不管','拍照发朋友圈'], correct: 0, explain: '发现非法出售野生动物请拨打12315(市监)或110(公安)举报。' },
        { text: '救助幼鸟的正确做法？', options: ['放回附近安全高处让亲鸟找回','带回家养','喂食','不管'], correct: 0, explain: '落地幼鸟通常亲鸟就在附近，将其放回附近安全树枝或高处即可。' },
        { text: '为什么不能随意放生动物？', options: ['可能造成生物入侵威胁本土物种','太贵了','影响美观','无所谓'], correct: 0, explain: '随意放生外来物种可能造成生态灾难，如巴西龟已严重威胁本土龟类生存。' },
        { text: '藏羚羊保护的转折点是？', options: ['青藏铁路修建动物通道和严厉打击盗猎','自然恢复','数量太多','没有转折'], correct: 0, explain: '通过青藏铁路动物通道建设和反盗猎行动，藏羚羊数量从2万恢复到20万+。' },
        { text: '昆虫多样性的重要性是？', options: ['传粉、分解、食物链基石','没用的虫子','只对科学家有意义','只有蜜蜂重要'], correct: 0, explain: '昆虫承担着传粉、分解有机物、维持食物链等关键生态功能，是生态系统的基石。' },

        { text: '我国一级保护动物不包括？', options: ['麻雀','大熊猫','朱鹮','扬子鳄'], correct: 0, explain: '麻雀是常见鸟类不属于保护动物。大熊猫、朱鹮、扬子鳄都是国家一级保护动物。' },
        { text: '遇到受伤的野生动物首先应该？', options: ['联系当地野生动物救助机构','自己带回家养','不管离开','拍照发朋友圈'], correct: 0, explain: '遇到受伤的野生动物应联系专业救助机构，不要自行捕捉或饲养。' },
        { text: '穿山甲的主要威胁是什么？', options: ['非法捕猎和栖息地丧失','自然灾害','天敌太多','不会繁殖'], correct: 0, explain: '穿山甲因鳞片和肉被大量捕猎，加上栖息地破坏，所有8种穿山甲都濒临灭绝。' },
        { text: '非法购买野生动物制品会？', options: ['触犯法律面临刑罚','没事','只是罚款','警告一下'], correct: 0, explain: '收购、运输、出售珍贵濒危野生动物制品构成犯罪，可处有期徒刑和罚金。' },
        { text: '流浪猫对生态环境的影响？', options: ['捕杀大量鸟类和小型野生动物','没有影响','有益','只影响老鼠'], correct: 0, explain: '流浪猫每年捕杀数十亿只鸟类和小动物，是入侵性捕食者对本土生态造成严重威胁。' },
        { text: '以下哪个是野生动物友好行为？', options: ['远距离观察不投喂不打扰','投喂食物','追逐拍照','捕捉回家'], correct: 0, explain: '观察野生动物应保持距离、不投喂、不惊扰，让它们在自然状态下生活。' },
        { text: '象牙贸易为什么被禁止？', options: ['导致大象被大量偷猎濒临灭绝','象牙太贵','不好看','没有用'], correct: 0, explain: '每年约2万头大象因象牙被猎杀，2018年起中国全面禁止国内象牙商业性贸易。' },
        { text: '鱼翅消费导致什么问题？', options: ['每年约7300万条鲨鱼被割鳍后丢弃','没有影响','鲨鱼太多了','有益'], correct: 0, explain: '为取鱼翅每年约7300万条鲨鱼被割鳍后扔回海里等死，许多鲨鱼种类已濒危。' },
        { text: '遇到搁浅的海洋动物应该？', options: ['保持距离降温保湿并报警','推回海里','围观拍照','触摸玩耍'], correct: 0, explain: '搁浅鲸豚等海洋动物应保持距离、泼水降温保湿，立即报告渔政或救助机构。' },
        { text: '小区里发现刺猬应该？', options: ['不打扰让它自行离开','带回家养','给牛奶喝','赶走'], correct: 0, explain: '城市中的刺猬是野生动物，不要捕捉或投喂（尤其是牛奶会致腹泻），让它自行离去。' },
        { text: '以下哪项不是野生动物走私的常见目标？', options: ['家猫','象牙','穿山甲','犀牛角'], correct: 0, explain: '家猫是宠物不属于野生动物走私目标。象牙、穿山甲、犀牛角是常见走私品。' },
        { text: '候鸟迁徙途中最大的威胁是？', options: ['栖息地丧失和非法捕猎','不会飞','天气','年龄'], correct: 0, explain: '湿地减少和非法捕鸟网是候鸟迁徙的主要威胁，中国是东亚-澳大利西亚迁徙路线的重要节点。' },
        { text: '购买和饲养野生保护动物？', options: ['违法','合法','看情况','无所谓'], correct: 0, explain: '私自购买和饲养国家重点保护野生动物是违法行为，可被追究刑事责任。' },
        { text: '中华白海豚主要分布在？', options: ['珠江口和厦门海域','长江上游','黄河','青海湖'], correct: 0, explain: '中华白海豚是国家一级保护动物，主要栖息在珠江口、厦门等近岸海域。' },
        { text: '看到售卖野生动物应该？', options: ['拨打12315或110举报','购买','不管','拍照发朋友圈'], correct: 0, explain: '发现非法出售野生动物请拨打12315(市监)或110(公安)举报。' },
        { text: '救助幼鸟的正确做法？', options: ['放回附近安全高处让亲鸟找回','带回家养','喂食','不管'], correct: 0, explain: '落地幼鸟通常亲鸟就在附近，将其放回附近安全树枝或高处即可。' },
        { text: '为什么不能随意放生动物？', options: ['可能造成生物入侵威胁本土物种','太贵了','影响美观','无所谓'], correct: 0, explain: '随意放生外来物种可能造成生态灾难，如巴西龟已严重威胁本土龟类生存。' },
        { text: '藏羚羊保护的转折点是？', options: ['青藏铁路修建动物通道和严厉打击盗猎','自然恢复','数量太多','没有转折'], correct: 0, explain: '通过青藏铁路动物通道建设和反盗猎行动，藏羚羊数量从2万恢复到20万+。' },
        { text: '昆虫多样性的重要性是？', options: ['传粉、分解、食物链基石','没用的虫子','只对科学家有意义','只有蜜蜂重要'], correct: 0, explain: '昆虫承担着传粉、分解有机物、维持食物链等关键生态功能，是生态系统的基石。' },

        { text: '安全知识测试题1：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题2：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题3：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题4：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题5：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题6：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题7：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题8：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题9：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题10：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题11：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题12：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题13：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题14：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题15：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题16：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题17：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题18：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题19：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题20：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题21：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题22：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题23：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题24：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题25：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题26：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题27：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题28：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题29：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题30：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题31：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题32：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题33：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题34：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题35：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题36：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题37：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题38：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题39：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题40：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题41：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题42：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题43：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题44：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题45：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题46：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题47：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题48：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题49：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题50：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题51：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题52：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
];
    if (window._qadventure) window._qadventure.destroy();
    window._qadventure = new QAdventureEngine({
        gameId: 'animal',
        themeId: 'animal',
        questions: questions,
        areaElId: 'animal-game-area',
        scoreElId: 'animal-score',
        resultDivId: 'animal-result',
        resultTextId: 'animal-score-text'
    });
    window._qadventure.init();
}
function initPhishGame() {
    var resultDiv = document.getElementById('phish-result');
    if (resultDiv) resultDiv.classList.add('hidden');
    var questions = [
        { text: "收到短信：\"您的快递已到达，点击链接领取\"，链接是短网址，应该？", options: ["不点击，去官方App查询", "立即点击", "转发给朋友", "回复短信确认"], correct: 0, explain: "短网址可能隐藏恶意链接，应通过官方渠道核实，绝不点击陌生链接。" },
        { text: "以下哪个网址可能是钓鱼网站？", options: ["ta0bao.com", "taobao.com", "alipay.com", "wechat.com"], correct: 0, explain: "ta0bao.com使用数字0代替字母o，是常见的域名仿冒钓鱼手段。" },
        { text: "收到\"银行\"邮件要求更新密码，邮件中有紧急字样，应该？", options: ["直接拨打银行官方客服核实", "点击邮件中的链接更新", "回复邮件询问", "转发给亲友判断"], correct: 0, explain: "紧急字样是施压手段，应通过官方客服电话核实，绝不点击邮件链接。" },
        { text: "钓鱼网站通常不会有以下哪个特征？", options: ["使用HTTPS安全证书", "拼写错误的域名", "要求立即行动", "索要敏感信息"], correct: 0, explain: "正规网站使用HTTPS，但钓鱼网站也可能使用，不能仅凭此判断安全性。" },
        { text: "在公共场所使用免费WiFi进行网银操作，风险是？", options: ["可能被中间人攻击窃取信息", "完全没有风险", "只会被广告骚扰", "只会网速变慢"], correct: 0, explain: "公共WiFi易被黑客设置中间人攻击，窃取账号密码等敏感信息。" },
        { text: "收到一封邮件，发件人显示为\"支付宝\"，但发件邮箱是alipay-notice@gmial.com，这是？", options: ["钓鱼邮件（域名拼写错误）", "官方邮件", "系统自动邮件", "广告邮件"], correct: 0, explain: "gmail拼写为gmial是典型钓鱼手法，官方邮件只会使用官方域名，务必仔细核对发件人地址。" },
        { text: "以下哪项是钓鱼网站最常使用的心理操纵手段？", options: ["制造紧迫感（限时/紧急）", "提供详细产品介绍", "使用正式公文格式", "附上公司营业执照"], correct: 0, explain: "钓鱼网站常用「24小时内冻结」「领取失效」等话语制造紧迫感，迫使受害者在恐慌中做出错误操作。" },
        { text: "手机收到「健康码异常」短信并附链接，正确做法是？", options: ["打开官方政务App核实", "点击链接查看详情", "转发给家人提醒", "回复短信查询"], correct: 0, explain: "疫情期间已出现大量假冒健康码的钓鱼短信，任何健康码相关问题应直接在官方App中查看，不点击任何短信链接。" },
        { text: "以下哪项是识别钓鱼邮件的最有效方法？", options: ["检查发件人邮箱是否为官方域名", "看邮件是否有图片", "看邮件是否使用彩色字体", "看邮件是否带附件"], correct: 0, explain: "发件人邮箱域名是最难伪造的要素（相比显示名），qq12345@qq.com不等于来自官方机构。" },
        { text: "假冒的「Apple安全中心」邮件要求你登录验证，URL显示apple-id-verify.com，应该？", options: ["不点击，Apple不会发此类邮件", "立即登录验证", "转发给朋友确认", "回复提供Apple ID"], correct: 0, explain: "Apple官方不会通过邮件要求用户登录验证账号，且官方域名是apple.com，任何变种域名均为假冒。" },
        { text: "你收到「微信团队」的好友辅助验证请求，但你不认识对方，应该？", options: ["忽略，可能是诈骗分子盗号后试探", "帮忙辅助验证", "转发给朋友圈", "拉黑对方"], correct: 0, explain: "诈骗分子盗取微信号后，会利用辅助验证功能解封账号，从而继续诈骗该账号好友中的其他人。" },
        { text: "以下哪个是识别HTTPS证书真伪的最有效方法？", options: ["点击浏览器地址栏的锁形图标查看证书详情", "看网址是否以https://开头", "看网页是否有绿色标记", "看网址中有无汉字"], correct: 0, explain: "仅凭https://无法判断安全性（钓鱼网站也有SSL证书），必须点击锁形图标查看证书颁发给的实体名称。" }
    ,
        { text: '钓鱼网站的典型特征是？', options: ['仿冒正规网站域名和界面','运行速度慢','有广告','需要注册'], correct: 0, explain: '钓鱼网站模仿正规网站的域名和界面，诱导用户输入账号密码等敏感信息。' },
        { text: '如何识别一封钓鱼邮件？', options: ['检查发件人地址和链接实际指向','看邮件内容','看对方称呼','看邮件签名'], correct: 0, explain: '最关键的是检查发件人地址是否来自官方域名，悬停查看链接的实际目标地址。' },
        { text: 'https一定代表网站安全可信吗？', options: ['不一定，钓鱼网站也可能用https','一定安全','一定不安全','只代表速度快'], correct: 0, explain: 'https只代表传输加密，不代表网站本身可信。钓鱼网站越来越多使用https伪装。' },

        { text: '钓鱼网站的典型特征是？', options: ['仿冒正规网站域名和界面','运行速度慢','有广告','需要注册'], correct: 0, explain: '钓鱼网站模仿正规网站的域名和界面，诱导用户输入账号密码等敏感信息。' },
        { text: '如何识别一封钓鱼邮件？', options: ['检查发件人地址和链接实际指向','看邮件内容','看对方称呼','看邮件签名'], correct: 0, explain: '最关键的是检查发件人地址是否来自官方域名，悬停查看链接的实际目标地址。' },
        { text: 'https一定代表网站安全可信吗？', options: ['不一定，钓鱼网站也可能用https','一定安全','一定不安全','只代表速度快'], correct: 0, explain: 'https只代表传输加密，不代表网站本身可信。钓鱼网站越来越多使用https伪装。' },

        { text: '安全知识测试题1：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题2：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题3：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题4：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题5：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题6：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题7：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题8：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题9：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题10：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题11：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题12：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题13：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题14：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题15：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题16：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题17：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题18：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题19：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题20：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题21：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题22：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题23：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题24：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题25：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题26：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题27：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题28：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题29：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题30：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题31：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题32：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题33：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题34：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题35：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题36：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题37：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题38：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题39：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题40：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题41：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题42：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题43：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题44：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题45：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题46：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题47：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题48：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题49：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题50：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题51：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题52：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题53：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题54：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题55：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题56：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题57：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题58：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题59：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题60：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题61：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题62：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题63：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题64：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题65：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题66：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题67：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题68：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题69：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题70：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题71：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题72：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题73：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题74：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题75：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题76：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题77：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题78：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题79：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题80：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题81：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题82：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
];
    if (window._qadventure) window._qadventure.destroy();
    window._qadventure = new QAdventureEngine({
        gameId: 'phish',
        themeId: 'phish',
        questions: questions,
        areaElId: 'phish-game-area',
        scoreElId: 'phish-score',
        resultDivId: 'phish-result',
        resultTextId: 'phish-score-text'
    });
    window._qadventure.init();
}
function initScriptGame() {
    var resultDiv = document.getElementById('script-result');
    if (resultDiv) resultDiv.classList.add('hidden');
    var questions = [
        { text: "\"您涉嫌洗钱，需要将资金转入安全账户配合调查\"——这是什么套路？", options: ["冒充公检法诈骗", "正常执法", "银行风控", "税务检查"], correct: 0, explain: "公检法机关绝不会电话要求转账到\"安全账户\"，这是典型的冒充公检法诈骗。" },
        { text: "\"恭喜您中奖！先交税费/保证金即可领奖\"——应该？", options: ["拒绝，中奖不应先交钱", "立即交钱领奖", "询问具体金额", "转发朋友圈"], correct: 0, explain: "正规中奖无需先交任何费用，要求先交钱的多为诈骗。" },
        { text: "\"我是您领导，不方便打电话，帮我转笔钱\"——这是？", options: ["冒充领导诈骗", "领导真的需要", "正常借款", "公司报销"], correct: 0, explain: "这是冒充领导诈骗，应通过原有联系方式核实，绝不仅凭短信/微信转账。" },
        { text: "\"您的账户异常，请点击链接验证\"——链接可能是？", options: ["钓鱼网站", "正规官网", "安全认证页", "银行主页"], correct: 0, explain: "此类链接多为钓鱼网站，目的是窃取账号密码，应通过官方App核实。" },
        { text: "\"投资导师带你赚钱，稳赚不赔\"——这属于？", options: ["投资理财诈骗", "正规理财", "善意帮助", "金融教育"], correct: 0, explain: "\"稳赚不赔\"是投资理财诈骗的典型话术，所有投资都有风险。" },
        { text: "\"您的医保卡已停用，请点击链接恢复使用\"——这是？", options: ["医保诈骗短信", "医保局正规通知", "系统自动提醒", "银行通知"], correct: 0, explain: "医保部门不会通过短信发送链接要求操作，此类短信均为诈骗，目的是窃取个人信息和银行卡信息。" },
        { text: "诈骗分子在电话中播放\"背景噪音（公安局背景音）\"的目的是？", options: ["增加可信度，制造场景真实感", "掩盖其真实位置", "录音质量差", "节省通话费用"], correct: 0, explain: "这是AI变声+场景伪造的高级诈骗手法，通过播放公安局背景音让受害者相信对方真的在公安局。" },
        { text: "\"您的包裹被海关扣留，需缴纳清关费\"——正确做法是？", options: ["联系官方快递公司核实", "立即转账缴费", "提供身份证照片", "点击链接填写信息"], correct: 0, explain: "海关不会通过快递公司个人联系收件人要求转账，正规清关有书面通知单，不会通过电话/短信要求缴费。" },
        { text: "以下哪种\"杀猪盘\"的信号出现最早？", options: ["对方拒绝视频/见面", "对方要求转账", "对方发送虚假盈利截图", "对方消失"], correct: 0, explain: "\"杀猪盘\"诈骗中，对方会以各种理由拒绝视频通话或见面，这是最早期的预警信号，一旦出现应立即警惕。" },
        { text: "\"您的手机已植入病毒，需下载安全助手清除\"——应该？", options: ["不下载，挂断后去官方应用商店检测", "立即下载对方提供的App", "支付\"清除费\"", "按照指示操作手机"], correct: 0, explain: "这是远程控制类诈骗，对方会诱导你下载带有远程控制功能的App（如假的\"安全助手\"），从而完全控制你的手机。" },
        { text: "诈骗电话中，对方准确报出你的姓名和身份证号，说明？", options: ["你的个人信息已被泄露", "对方真的是公检法", "是巧合", "你的电话被监听了"], correct: 0, explain: "个人信息泄露已成黑色产业链，诈骗分子花几元钱就能买到你的详细信息，准确报出信息不代表对方身份真实。" },
        { text: "\"双十一退款，请提供银行卡号和验证码\"——应该？", options: ["拒绝提供，通过官方平台核实", "立即提供", "先问清楚金额", "转发给朋友确认"], correct: 0, explain: "正规退款原路返回，不需要你提供银行卡号或验证码，所有要求提供验证码的\"退款\"都是诈骗。" }
    ,
        { text: '诈骗话术中制造紧迫感常用手法？', options: ['限时优惠/即将失效/涉嫌违法','详细解释原因','给充足时间考虑','让你去核实'], correct: 0, explain: '诈骗者常制造时间紧迫感让你来不及思考和核实就做出决定。' },
        { text: '冒充客服的典型话术是？', options: ['您购买的商品有质量问题我们给您退款','祝您购物愉快','包裹正在配送中','系统维护中'], correct: 0, explain: '冒充客服退款诈骗是最常见的话术，主动联系说退款的大多是诈骗。' },
        { text: '杀猪盘诈骗中骗子会？', options: ['先建立感情再诱导投资或借钱','直接要钱','只聊不骗','很快见面'], correct: 0, explain: '杀猪盘通过长期感情投入获取信任后，再以投资、急用等理由骗取钱财。' },

        { text: '诈骗话术中制造紧迫感常用手法？', options: ['限时优惠/即将失效/涉嫌违法','详细解释原因','给充足时间考虑','让你去核实'], correct: 0, explain: '诈骗者常制造时间紧迫感让你来不及思考和核实就做出决定。' },
        { text: '冒充客服的典型话术是？', options: ['您购买的商品有质量问题我们给您退款','祝您购物愉快','包裹正在配送中','系统维护中'], correct: 0, explain: '冒充客服退款诈骗是最常见的话术，主动联系说退款的大多是诈骗。' },
        { text: '杀猪盘诈骗中骗子会？', options: ['先建立感情再诱导投资或借钱','直接要钱','只聊不骗','很快见面'], correct: 0, explain: '杀猪盘通过长期感情投入获取信任后，再以投资、急用等理由骗取钱财。' },

        { text: '安全知识测试题1：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题2：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题3：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题4：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题5：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题6：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题7：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题8：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题9：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题10：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题11：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题12：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题13：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题14：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题15：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题16：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题17：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题18：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题19：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题20：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题21：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题22：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题23：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题24：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题25：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题26：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题27：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题28：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题29：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题30：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题31：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题32：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题33：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题34：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题35：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题36：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题37：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题38：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题39：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题40：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题41：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题42：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题43：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题44：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题45：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题46：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题47：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题48：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题49：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题50：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题51：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题52：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题53：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题54：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题55：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题56：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题57：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题58：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题59：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题60：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题61：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题62：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题63：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题64：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题65：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题66：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题67：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题68：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题69：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题70：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题71：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题72：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题73：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题74：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题75：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题76：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题77：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题78：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题79：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题80：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题81：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题82：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
];
    if (window._qadventure) window._qadventure.destroy();
    window._qadventure = new QAdventureEngine({
        gameId: 'script',
        themeId: 'script',
        questions: questions,
        areaElId: 'script-game-area',
        scoreElId: 'script-score',
        resultDivId: 'script-result',
        resultTextId: 'script-score-text'
    });
    window._qadventure.init();
}
function initIdentityGame() {
    var resultDiv = document.getElementById('identity-result');
    if (resultDiv) resultDiv.classList.add('hidden');
    var questions = [
        { text: "接到\"公安局\"电话说你涉嫌犯罪，要求视频通话做笔录，应该？", options: ["挂断并拨打110核实", "配合做视频笔录", "提供银行卡信息", "按指示操作手机"], correct: 0, explain: "公检法机关不会电话/video做笔录，更不会要求转账，应立即挂断并拨打110核实。" },
        { text: "\"客服\"来电说您开通了会员需取消，否则扣费，应该？", options: ["自己登录官方App核实", "按客服指示操作", "提供验证码", "下载对方提供的App"], correct: 0, explain: "正规客服不会要求下载App或提供验证码，应通过官方渠道自行核实。" },
        { text: "网友认识3天后向你借钱，理由是急用，应该？", options: ["拒绝，网络交友不借钱", "立即转账帮助", "询问具体金额", "要求见面再借"], correct: 0, explain: "网络交友诈骗常见套路，认识不久就借钱的多为诈骗，坚决不转账。" },
        { text: "收到\"学校老师\"短信要求交培训费到私人账户，应该？", options: ["联系班主任核实", "立即转账", "回复短信确认", "转发家长群"], correct: 0, explain: "学校收费有正规流程，不会要求转账到私人账户，务必先核实。" },
        { text: "\"医保局\"短信说您的医保卡被冻结，点击链接解冻，应该？", options: ["不点击，拨打社保局官方电话", "点击链接解冻", "回复短信询问", "转发给亲友"], correct: 0, explain: "医保局不会短信发送链接要求操作，应通过官方渠道核实账户状态。" },
        { text: "有人自称是你朋友，在微信上说手机丢了，要求扫码转账，应该？", options: ["打电话给朋友本人核实", "立即扫码帮助", "先问几个私密问题", "转发给共同好友"], correct: 0, explain: "这是账号被盗后的常见诈骗手法，微信好友关系链被盗用后，诈骗分子会向所有好友发送转账/借钱信息。" },
        { text: "\"快递客服\"主动加你微信说可以双倍理赔，应该？", options: ["拒绝，通过官方平台申请理赔", "加微信详谈", "提供银行卡号", "发送身份证照片"], correct: 0, explain: "正规快递理赔通过官方平台进行，主动加微信\"双倍理赔\"是诈骗，目的是诱导下载钓鱼App或窃取银行卡信息。" },
        { text: "收到一封来自\"法院\"的邮件，要求点击链接查看传票，你应该？", options: ["致电法院官方电话核实", "点击链接查看", "转发给律师朋友", "忽略删除"], correct: 0, explain: "法院不会通过邮件发送传票链接，正式法律文书通过邮寄或专人送达，任何形式的\"电子传票链接\"均为诈骗。" },
        { text: "\"您的护照有异常入境记录，需缴纳保证金\"——这是？", options: ["冒充出入境管理局诈骗", "正常出入境提醒", "旅行社通知", "航空公司通知"], correct: 0, explain: "出入境管理部门不会通过电话要求缴纳保证金，此类诈骗常瞄准有出国记录的人群，要求其转账到\"安全账户\"。" },
        { text: "识别AI换脸视频通话的最有效方法是？", options: ["让对方做随机动作（如摸鼻子）", "看视频是否卡顿", "看对方衣着是否整齐", "数对方有几颗牙齿"], correct: 0, explain: "AI换脸在实时互动中难以精确同步细微面部动作，要求对方做触摸面部等随机动作可有效识别伪造视频。" }
    ,
        { text: '以下哪种方式是验证对方身份最可靠的？', options: ['通过官方渠道回拨确认','看对方穿制服','看对方工作证','对方知道你的个人信息'], correct: 0, explain: '制服和工作证可伪造，个人信息可能泄露。通过官方公开号码回拨确认最可靠。' },
        { text: '收到自称银行客服电话索要验证码应？', options: ['挂断后拨打银行官方客服确认','直接告诉验证码','问对方是哪个银行','核对来电号码后告诉'], correct: 0, explain: '银行绝不会索要验证码！挂断后拨打银行卡背面或官网公布的客服电话。' },
        { text: '数字证书在身份验证中的作用？', options: ['证明通信方身份的真实性','加速网速','美化界面','存储密码'], correct: 0, explain: '数字证书由权威CA签发，用于证明网站或应用的身份，防止中间人攻击。' },
        { text: '人脸识别可以完全防伪吗？', options: ['不能，AI换脸和3D面具可攻破','完全可以','比指纹还可靠','不需要其他验证'], correct: 0, explain: 'AI换脸和3D打印面具已能攻破部分人脸识别，重要场合需多因素认证。' },
        { text: '收到领导的微信要求紧急转账应？', options: ['电话或当面与领导确认','立即转账','问清楚原因后转账','回复收到后转账'], correct: 0, explain: '骗子常冒充领导微信诈骗！涉及转账必须通过电话或当面二次确认。' },
        { text: '验证码的正确使用方式是？', options: ['仅在自己操作的页面输入不告诉任何人','告诉客服','分享给朋友','发朋友圈'], correct: 0, explain: '验证码是个人操作授权凭证，任何索要验证码的电话短信都是诈骗。' },
        { text: '双重认证(2FA)是什么？', options: ['密码+手机验证码或生物特征','两次输入密码','两个密码','密码+用户名'], correct: 0, explain: '双重认证要求同时提供密码和另一因素(如短信验证码)，大幅提高安全性。' },
        { text: '以下哪个是钓鱼网站的特征？', options: ['网址与正规网站仅一字之差','有https','有公司logo','有联系电话'], correct: 0, explain: '钓鱼网站常用与正规网站相似的域名(如taobao-vip.com)，仔细辨别网址。' },
        { text: '快递员上门要求查看身份证应？', options: ['只出示不交给他并核实其身份','直接把身份证给他','让他进屋','不用核实'], correct: 0, explain: '快递员一般不需要查看身份证。如确需验证，只出示不交付，并通过官方核实其身。' },
        { text: '接到自称公检法的电话应如何验证？', options: ['挂断后拨打110核实','按对方指示操作','报出自己的身份证号','问对方警号就够了'], correct: 0, explain: '公检法不会电话办案！挂断后直接拨打110核实是最稳妥的方式。' },

        { text: '以下哪种方式是验证对方身份最可靠的？', options: ['通过官方渠道回拨确认','看对方穿制服','看对方工作证','对方知道你的个人信息'], correct: 0, explain: '制服和工作证可伪造，个人信息可能泄露。通过官方公开号码回拨确认最可靠。' },
        { text: '收到自称银行客服电话索要验证码应？', options: ['挂断后拨打银行官方客服确认','直接告诉验证码','问对方是哪个银行','核对来电号码后告诉'], correct: 0, explain: '银行绝不会索要验证码！挂断后拨打银行卡背面或官网公布的客服电话。' },
        { text: '数字证书在身份验证中的作用？', options: ['证明通信方身份的真实性','加速网速','美化界面','存储密码'], correct: 0, explain: '数字证书由权威CA签发，用于证明网站或应用的身份，防止中间人攻击。' },
        { text: '人脸识别可以完全防伪吗？', options: ['不能，AI换脸和3D面具可攻破','完全可以','比指纹还可靠','不需要其他验证'], correct: 0, explain: 'AI换脸和3D打印面具已能攻破部分人脸识别，重要场合需多因素认证。' },
        { text: '收到领导的微信要求紧急转账应？', options: ['电话或当面与领导确认','立即转账','问清楚原因后转账','回复收到后转账'], correct: 0, explain: '骗子常冒充领导微信诈骗！涉及转账必须通过电话或当面二次确认。' },
        { text: '验证码的正确使用方式是？', options: ['仅在自己操作的页面输入不告诉任何人','告诉客服','分享给朋友','发朋友圈'], correct: 0, explain: '验证码是个人操作授权凭证，任何索要验证码的电话短信都是诈骗。' },
        { text: '双重认证(2FA)是什么？', options: ['密码+手机验证码或生物特征','两次输入密码','两个密码','密码+用户名'], correct: 0, explain: '双重认证要求同时提供密码和另一因素(如短信验证码)，大幅提高安全性。' },
        { text: '以下哪个是钓鱼网站的特征？', options: ['网址与正规网站仅一字之差','有https','有公司logo','有联系电话'], correct: 0, explain: '钓鱼网站常用与正规网站相似的域名(如taobao-vip.com)，仔细辨别网址。' },
        { text: '快递员上门要求查看身份证应？', options: ['只出示不交给他并核实其身份','直接把身份证给他','让他进屋','不用核实'], correct: 0, explain: '快递员一般不需要查看身份证。如确需验证，只出示不交付，并通过官方核实其身。' },
        { text: '接到自称公检法的电话应如何验证？', options: ['挂断后拨打110核实','按对方指示操作','报出自己的身份证号','问对方警号就够了'], correct: 0, explain: '公检法不会电话办案！挂断后直接拨打110核实是最稳妥的方式。' },

        { text: '安全知识测试题1：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题2：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题3：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题4：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题5：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题6：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题7：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题8：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题9：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题10：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题11：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题12：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题13：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题14：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题15：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题16：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题17：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题18：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题19：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题20：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题21：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题22：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题23：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题24：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题25：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题26：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题27：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题28：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题29：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题30：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题31：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题32：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题33：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题34：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题35：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题36：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题37：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题38：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题39：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题40：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题41：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题42：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题43：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题44：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题45：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题46：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题47：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题48：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题49：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题50：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题51：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题52：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题53：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题54：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题55：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题56：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题57：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题58：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题59：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题60：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题61：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题62：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题63：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题64：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题65：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题66：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题67：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题68：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题69：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题70：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
];
    if (window._qadventure) window._qadventure.destroy();
    window._qadventure = new QAdventureEngine({
        gameId: 'identity',
        themeId: 'identity',
        questions: questions,
        areaElId: 'identity-game-area',
        scoreElId: 'identity-score',
        resultDivId: 'identity-result',
        resultTextId: 'identity-score-text'
    });
    window._qadventure.init();
}
function initTransferGame() {
    var resultDiv = document.getElementById('transfer-result');
    if (resultDiv) resultDiv.classList.add('hidden');
    var questions = [
        { text: "网恋对象说想见面但路费不够，让你转账，应该？", options: ["拒绝，警惕杀猪盘", "立即转账", "先视频确认", "转一半试试"], correct: 0, explain: "这是典型的\"杀猪盘\"诈骗套路，网络恋情中涉及转账的99%是诈骗。" },
        { text: "\"刷单返利\"，先垫付小额再要求大额，这是？", options: ["刷单诈骗", "正常兼职", "商家促销", "平台活动"], correct: 0, explain: "刷单本身就是违法行为，所有要求先垫付的刷单都是诈骗。" },
        { text: "收到\"孩子\"QQ说学校要交培训费，应该？", options: ["打电话给孩子确认", "立即转账", "回复QQ询问", "转发班级群"], correct: 0, explain: "QQ被盗冒充子女诈骗很常见，务必电话或当面确认，不要QQ/微信确认。" },
        { text: "\"快递丢失理赔\"，要求下载App操作，这是？", options: ["诈骗，官方理赔不需要下载App", "正常流程", "快速理赔", "保险公司要求"], correct: 0, explain: "正规理赔通过官方平台完成，要求下载陌生App的多为诈骗。" },
        { text: "游戏账号交易，对方要求先交\"保证金\"，应该？", options: ["拒绝，账号交易不先交钱", "交保证金", "讨价还价", "要求平台担保"], correct: 0, explain: "游戏账号交易要求先交保证金/押金的多为诈骗，应在正规平台交易。" },
        { text: "\"你的征信有问题，需转账清除记录\"——这是？", options: ["征信诈骗（个人征信无法用钱清除）", "银行新规定", "正规征信修复", "法律要求"], correct: 0, explain: "个人征信记录由中国人民银行管理，任何第三方声称可以\"花钱消除征信污点\"都是诈骗。" },
        { text: "对方发来一个\"投资项目\"的二维码，要求扫码下载App，应该？", options: ["不扫，二维码可能指向恶意App", "立即扫码下载", "先问朋友再说", "转发给其他人"], correct: 0, explain: "诈骗分子常将恶意App托管在第三方平台，通过二维码分享，扫码即下载安装，随后窃取银行信息。" },
        { text: "以下哪种转账方式最安全可追溯？", options: ["银行柜台/官方App转账", "ATM无卡存款", "微信/支付宝扫码给陌生人", "购买点卡充值"], correct: 0, explain: "银行转账有完整记录且可追溯，而无卡存款和扫码支付给陌生人的钱几乎无法追回。" },
        { text: "\"您的银行卡涉嫌洗钱，需将资金转到安全账户接受检查\"——转账后钱会？", options: ["立即被转走且无法追回", "被冻结等待检查", "检查后自动返回", "产生利息收入"], correct: 0, explain: "\"安全账户\"就是诈骗分子的账户，钱一旦转入会立即被多级分流转走，几乎无法追回，这是此类诈骗最残忍的地方。" },
        { text: "遭遇电信诈骗后，黄金挽回期是多久？", options: ["30分钟内（立即报警可止付）", "24小时内", "3天内", "一周内"], correct: 0, explain: "被骗后应在30分钟内拨打110并申请紧急止付，超过此时限资金往往已被多级转移，追回难度大幅增加。" }
    ,
        { text: '最安全的转账方式是？', options: ['核实身份后通过银行官方App转账','ATM给陌生人转账','二维码直接扫','现金交易'], correct: 0, explain: '任何转账前必须通过独立渠道核实对方身份，使用银行官方渠道操作。' },
        { text: '对方要求你到ATM机进行英文界面操作意味着？', options: ['诈骗！立即停止','正常操作','国际汇款','高级服务'], correct: 0, explain: '骗子利用英文界面迷惑受害人进行转账操作，任何要你去ATM的人都值得警惕。' },
        { text: '屏幕共享时对方能看到什么？', options: ['手机上的所有信息包括密码验证码','什么都看不到','只能看App界面','只能听声音'], correct: 0, explain: '屏幕共享会让对方看到你的所有操作、验证码、密码，是极其危险的！' },
        { text: '安全账户真的存在吗？', options: ['不存在，任何要求转入安全账户的都是诈骗','存在但不常用','只有银行有','公安局有'], correct: 0, explain: '安全账户是诈骗分子的虚构概念！公安机关和银行都没有所谓的\'安全账户\'。' },
        { text: '转账时收款人姓名和账号不一致，钱能到账吗？', options: ['不能，银行会校验一致性','能到账','部分能到','看情况'], correct: 0, explain: '银行系统会校验收款人姓名与账号是否匹配，不一致时会拒绝交易。' },

        { text: '最安全的转账方式是？', options: ['核实身份后通过银行官方App转账','ATM给陌生人转账','二维码直接扫','现金交易'], correct: 0, explain: '任何转账前必须通过独立渠道核实对方身份，使用银行官方渠道操作。' },
        { text: '对方要求你到ATM机进行英文界面操作意味着？', options: ['诈骗！立即停止','正常操作','国际汇款','高级服务'], correct: 0, explain: '骗子利用英文界面迷惑受害人进行转账操作，任何要你去ATM的人都值得警惕。' },
        { text: '屏幕共享时对方能看到什么？', options: ['手机上的所有信息包括密码验证码','什么都看不到','只能看App界面','只能听声音'], correct: 0, explain: '屏幕共享会让对方看到你的所有操作、验证码、密码，是极其危险的！' },
        { text: '安全账户真的存在吗？', options: ['不存在，任何要求转入安全账户的都是诈骗','存在但不常用','只有银行有','公安局有'], correct: 0, explain: '安全账户是诈骗分子的虚构概念！公安机关和银行都没有所谓的\'安全账户\'。' },
        { text: '转账时收款人姓名和账号不一致，钱能到账吗？', options: ['不能，银行会校验一致性','能到账','部分能到','看情况'], correct: 0, explain: '银行系统会校验收款人姓名与账号是否匹配，不一致时会拒绝交易。' },

        { text: '安全知识测试题1：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题2：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题3：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题4：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题5：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题6：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题7：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题8：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题9：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题10：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题11：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题12：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题13：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题14：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题15：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题16：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题17：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题18：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题19：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题20：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题21：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题22：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题23：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题24：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题25：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题26：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题27：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题28：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题29：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题30：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题31：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题32：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题33：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题34：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题35：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题36：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题37：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题38：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题39：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题40：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题41：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题42：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题43：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题44：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题45：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题46：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题47：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题48：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题49：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题50：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题51：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题52：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题53：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题54：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题55：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题56：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题57：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题58：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题59：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题60：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题61：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题62：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题63：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题64：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题65：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题66：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题67：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题68：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题69：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题70：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题71：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题72：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题73：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题74：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题75：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题76：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题77：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题78：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题79：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题80：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
];
    if (window._qadventure) window._qadventure.destroy();
    window._qadventure = new QAdventureEngine({
        gameId: 'transfer',
        themeId: 'transfer',
        questions: questions,
        areaElId: 'transfer-game-area',
        scoreElId: 'transfer-score',
        resultDivId: 'transfer-result',
        resultTextId: 'transfer-score-text'
    });
    window._qadventure.init();
}
function initLeakGame() {
    var resultDiv = document.getElementById('leak-result');
    if (resultDiv) resultDiv.classList.add('hidden');
    var questions = [
        { text: "以下哪种行为最容易导致个人信息泄露？", options: ["在不明网站填写身份证号", "使用复杂密码", "开启双重验证", "定期修改密码"], correct: 0, explain: "不明网站可能专门收集个人信息用于诈骗或贩卖，切勿随意填写敏感信息。" },
        { text: "快递单上的个人信息最好的处理方式是？", options: ["涂抹/撕碎后丢弃", "直接丢弃", "留着备用", "卖给回收站"], correct: 0, explain: "快递单包含姓名电话地址，应涂抹或撕碎后再丢弃，防止被不法分子利用。" },
        { text: "手机App要求获取\"通讯录权限\"，应该？", options: ["谨慎授权，非必要不授予", "全部允许", "只允许一个", "无所谓"], correct: 0, explain: "通讯录权限可能被用于精准诈骗（冒充亲友），非必要不授予。" },
        { text: "以下哪种密码最安全？", options: ["3个不相关词+数字符号", "生日+姓名", "123456", "password"], correct: 0, explain: "使用3个不相关的词组合加数字符号，既好记又安全，避免使用个人信息。" },
        { text: "在社交媒体晒照片时，最应该注意隐藏？", options: ["定位信息和行程", "照片滤镜", "拍摄时间", "照片尺寸"], correct: 0, explain: "定位信息和行程暴露后，可能被用于精准诈骗或踩点盗窃。" },
        { text: "以下哪种是「撞库攻击」？", options: ["用泄露的账号密码尝试登录其他网站", "暴力破解密码", "发送钓鱼邮件", "冒充客服诈骗"], correct: 0, explain: "很多人习惯在多个网站使用相同密码，黑客拿到一组账号密码后会\"撞库\"尝试登录电商、银行等其他平台。" },
        { text: "公共场所的充电桩（USB充电）可能存在哪种风险？", options: ["被植入恶意软件/窃取数据", "充电速度慢", "电费过高", "损坏电池"], correct: 0, explain: "USB充电桩可通过\"果汁借用\"（Juice Jacking）攻击，在充电同时窃取手机数据或植入恶意软件，建议使用自己的充电头。" },
        { text: "收到\"人脸识别失败，需重新采集\"的短信并附链接，应该？", options: ["不点击，通过官方App核实", "点击链接重新采集", "发送身份证照片", "告诉给家人"], correct: 0, explain: "人脸识别数据属于高度敏感生物信息，任何机构不会通过短信链接要求\"重新采集\"，这是钓鱼诈骗。" },
        { text: "旧手机出售前，最安全的处理方式是？", options: ["恢复出厂设置+覆盖写入垃圾文件", "仅恢复出厂设置", "删除所有App", "格式化存储卡"], correct: 0, explain: "仅恢复出厂设置无法彻底清除数据，专业工具可恢复，应在重置后填充大文件（如电影）覆盖存储空间。" },
        { text: "以下哪项不是《个人信息保护法》规定的个人权利？", options: ["要求平台删除你的数据", "查阅平台收集的你的个人信息", "要求平台不向第三方分享你的信息", "要求平台赔偿精神损失费（无实际损失时）"], correct: 3, explain: "《个人信息保护法》赋予用户查阅、复制、更正、删除个人信息等权利，但精神损害赔偿需有实际损害后果。" }
    ,
        { text: '以下哪种行为最可能导致个人信息泄露？', options: ['随意连接公共WiFi','使用移动支付','手机设密码','不用社交媒体'], correct: 0, explain: '公共WiFi可能被黑客控制，连接后可窃取你传输的所有信息。' },
        { text: 'App索要通讯录权限时应该？', options: ['评估是否必要，不必要就拒绝','全部允许','不看直接同意','卸载App'], correct: 0, explain: '谨慎授予App权限，通讯录等敏感权限仅在确有必要时授权。' },
        { text: '旧手机处理前最安全的做法？', options: ['恢复出厂设置并清除所有数据','直接扔掉','送人','放抽屉里'], correct: 0, explain: '旧手机处理前应备份数据、退出所有账号、恢复出厂设置。' },
        { text: '快递单上的个人信息应该怎样处理？', options: ['撕毁或涂抹后再丢弃','直接扔掉','留着做纪念','给别人看'], correct: 0, explain: '快递单上有姓名地址电话，应用碎纸机销毁或用笔涂抹后丢弃。' },

        { text: '以下哪种行为最可能导致个人信息泄露？', options: ['随意连接公共WiFi','使用移动支付','手机设密码','不用社交媒体'], correct: 0, explain: '公共WiFi可能被黑客控制，连接后可窃取你传输的所有信息。' },
        { text: 'App索要通讯录权限时应该？', options: ['评估是否必要，不必要就拒绝','全部允许','不看直接同意','卸载App'], correct: 0, explain: '谨慎授予App权限，通讯录等敏感权限仅在确有必要时授权。' },
        { text: '旧手机处理前最安全的做法？', options: ['恢复出厂设置并清除所有数据','直接扔掉','送人','放抽屉里'], correct: 0, explain: '旧手机处理前应备份数据、退出所有账号、恢复出厂设置。' },
        { text: '快递单上的个人信息应该怎样处理？', options: ['撕毁或涂抹后再丢弃','直接扔掉','留着做纪念','给别人看'], correct: 0, explain: '快递单上有姓名地址电话，应用碎纸机销毁或用笔涂抹后丢弃。' },

        { text: '安全知识测试题1：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题2：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题3：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题4：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题5：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题6：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题7：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题8：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题9：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题10：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题11：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题12：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题13：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题14：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题15：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题16：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题17：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题18：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题19：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题20：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题21：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题22：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题23：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题24：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题25：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题26：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题27：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题28：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题29：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题30：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题31：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题32：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题33：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题34：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题35：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题36：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题37：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题38：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题39：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题40：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题41：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题42：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题43：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题44：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题45：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题46：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题47：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题48：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题49：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题50：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题51：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题52：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题53：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题54：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题55：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题56：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题57：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题58：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题59：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题60：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题61：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题62：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题63：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题64：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题65：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题66：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题67：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题68：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题69：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题70：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题71：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题72：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题73：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题74：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题75：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题76：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题77：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题78：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题79：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题80：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题81：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题82：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
];
    if (window._qadventure) window._qadventure.destroy();
    window._qadventure = new QAdventureEngine({
        gameId: 'leak',
        themeId: 'leak',
        questions: questions,
        areaElId: 'leak-game-area',
        scoreElId: 'leak-score',
        resultDivId: 'leak-result',
        resultTextId: 'leak-score-text'
    });
    window._qadventure.init();
}
function initEvidenceGame() {
    var resultDiv = document.getElementById('evidence-result');
    if (resultDiv) resultDiv.classList.add('hidden');
    var questions = [
        { text: "诈骗链条的第一步通常是？", options: ["获取受害者信任", "立即要求转账", "发送恐吓信息", "直接打电话"], correct: 0, explain: "诈骗的第一步通常是获取信任（如冒充熟人、伪造身份），然后才实施诈骗。" },
        { text: "以下哪项是识别诈骗App的关键？", options: ["应用商店搜不到，需扫码下载", "有官方认证", "评分很高", "下载量很大"], correct: 0, explain: "诈骗App通常无法在正规应用商店上架，只能通过扫码或链接下载。" },
        { text: "\"杀猪盘\"诈骗的典型流程是？", options: ["培养感情→诱导投资→卷款消失", "直接抢劫", "发送病毒链接", "冒充客服退款"], correct: 0, explain: "杀猪盘先通过网恋培养感情（养猪），再诱导投资（杀猪），最后卷款消失。" },
        { text: "接到\"涉嫌洗钱\"电话后，诈骗分子下一步通常？", options: ["要求转账到安全账户", "上门逮捕", "发送法院传票", "要求见面"], correct: 0, explain: "冒充公检法诈骗的核心是要求转账到所谓的\"安全账户\"配合调查。" },
        { text: "以下哪个不是典型的诈骗收款方式？", options: ["正规银行对公账户", "个人账户转账", "虚拟货币", "游戏点卡充值"], correct: 0, explain: "诈骗分子通常使用个人账户、虚拟货币、游戏点卡等难以追踪的方式收款，而非正规对公账户。" },
        { text: "诈骗短信中常用的心理操纵技术不包括？", options: ["给予充分时间考虑", "制造紧迫感", "权威暗示", "社会认同（其他人已操作）"], correct: 0, explain: "诈骗信息从不给受害者充分思考时间，这是识别诈骗的重要特征——真正的官方通知会给你合理的反应时间。" },
        { text: "保存诈骗证据时，最重要的是保存？", options: ["完整的通话录音/聊天记录", "对方承诺的收益截图", "自己的银行流水", "朋友的证词"], correct: 0, explain: "完整的通话录音和聊天记录是最重要的证据，报警时应一并提供，有助于警方快速立案侦查。" },
        { text: "诈骗电话的号码通常具有什么特征？", options: ["使用虚拟改号技术伪装成本地号码", "一定是境外号码", "一定是座机号码", "显示真实的呼叫方号码"], correct: 0, explain: "诈骗分子使用改号软件（Caller ID Spoofing）将显示号码伪装成银行、公安局等官方号码，因此来电显示不可信。" },
        { text: "以下哪种是最近新兴的AI诈骗手段？", options: ["AI拟声打电话冒充亲友借钱", "发送传统钓鱼邮件", "张贴小广告", "上门推销"], correct: 0, explain: "\"AI拟声诈骗\"通过几秒钟的公开语音样本训练模型，然后冒充亲友打电话借钱，声音相似度极高，需通过暗语或挂断回拨核实。" },
        { text: "国家反诈中心App的核心功能不包括？", options: ["自动冻结对方银行账户", "诈骗预警", "一键举报", "身份真实性验证"], correct: 0, explain: "国家反诈中心App可以预警、举报和验证，但无法主动冻结他人账户（需公安机关依法操作），声称可以\"一键冻结\"的App均为假冒。" }
    ,
        { text: '遭遇诈骗后最重要的证据是？', options: ['转账记录聊天记录和通话录音','回忆中的对话','对方的承诺','自己的感觉'], correct: 0, explain: '转账记录、聊天截图和通话录音是可取证的关键证据，遭遇诈骗后应立即保存。' },
        { text: '被骗后第一步应该做什么？', options: ['立即拨打110报警并联系银行止付','找对方理论','等待对方还款','删除一切证据'], correct: 0, explain: '被骗后第一时间报警和银行止付可能挽回损失，不要删除任何证据。' },
        { text: '反诈中心96110是什么电话？', options: ['全国统一反诈预警劝阻咨询专线','诈骗电话','推销电话','客服电话'], correct: 0, explain: '96110是公安部全国统一反诈预警劝阻专线，如接到此号码来电请务必接听。' },

        { text: '遭遇诈骗后最重要的证据是？', options: ['转账记录聊天记录和通话录音','回忆中的对话','对方的承诺','自己的感觉'], correct: 0, explain: '转账记录、聊天截图和通话录音是可取证的关键证据，遭遇诈骗后应立即保存。' },
        { text: '被骗后第一步应该做什么？', options: ['立即拨打110报警并联系银行止付','找对方理论','等待对方还款','删除一切证据'], correct: 0, explain: '被骗后第一时间报警和银行止付可能挽回损失，不要删除任何证据。' },
        { text: '反诈中心96110是什么电话？', options: ['全国统一反诈预警劝阻咨询专线','诈骗电话','推销电话','客服电话'], correct: 0, explain: '96110是公安部全国统一反诈预警劝阻专线，如接到此号码来电请务必接听。' },

        { text: '安全知识测试题1：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题2：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题3：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题4：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题5：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题6：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题7：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题8：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题9：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题10：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题11：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题12：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题13：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题14：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题15：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题16：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题17：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题18：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题19：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题20：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题21：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题22：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题23：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题24：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题25：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题26：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题27：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题28：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题29：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题30：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题31：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题32：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题33：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题34：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题35：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题36：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题37：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题38：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题39：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题40：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题41：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题42：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题43：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题44：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题45：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题46：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题47：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题48：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题49：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题50：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题51：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题52：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题53：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题54：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题55：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题56：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题57：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题58：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题59：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题60：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题61：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题62：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题63：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题64：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题65：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题66：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题67：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题68：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题69：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题70：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题71：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题72：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题73：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题74：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题75：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题76：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题77：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题78：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题79：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题80：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题81：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题82：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题83：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题84：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
];
    if (window._qadventure) window._qadventure.destroy();
    window._qadventure = new QAdventureEngine({
        gameId: 'evidence',
        themeId: 'evidence',
        questions: questions,
        areaElId: 'evidence-game-area',
        scoreElId: 'evidence-score',
        resultDivId: 'evidence-result',
        resultTextId: 'evidence-score-text'
    });
    window._qadventure.init();
}
function initAlertGame() {
    var resultDiv = document.getElementById('alert-result');
    if (resultDiv) resultDiv.classList.add('hidden');
    var questions = [
        { text: "国家反诈中心App的主要功能是？", options: ["预警诈骗电话/短信", "玩游戏", "购物优惠", "社交聊天"], correct: 0, explain: "国家反诈中心App可预警诈骗电话和短信，建议所有人安装。" },
        { text: "收到\"00\"或\"+\"开头的境外来电，应该？", options: ["提高警惕，大概率是诈骗", "立即接听", "回拨过去", "添加通讯录"], correct: 0, explain: "境外来电（00或+开头）极可能是诈骗电话，如无境外亲友建议直接挂断。" },
        { text: "以下哪个电话是真正的反诈预警电话？", options: ["96110", "110", "120", "119"], correct: 0, explain: "96110是全国反诈预警专线，接到此电话说明你可能正在遭遇诈骗。" },
        { text: "手机收到\"ETC失效\"短信带链接，应该？", options: ["删除短信，通过官方渠道核实", "点击链接处理", "转发给朋友", "回复短信"], correct: 0, explain: "ETC失效短信带链接是常见诈骗，应删除并通过官方App/客服核实。" },
        { text: "设置诈骗预警最有效的方式是？", options: ["安装国家反诈中心App+开启来电预警", "只靠自己判断", "不接电话", "更换手机号"], correct: 0, explain: "安装国家反诈中心App并开启来电预警，是最有效的技术防护手段。" }
    ,
        { text: '以下哪种情况应该提高警惕？', options: ['陌生人要求转账汇款','朋友约饭','收到快递','天气预报'], correct: 0, explain: '任何陌生人通过电话/短信/网络要求转账汇款都应高度警惕。' },
        { text: '老年人最应警惕哪类诈骗？', options: ['冒充公检法和保健品推销','网上购物','玩游戏','看视频'], correct: 0, explain: '冒充公检法和保健品推销是针对老年人最常见的诈骗类型。' },
        { text: '国家反诈中心App主要功能是？', options: ['诈骗预警识别和举报','天气预报','购物比价','看新闻'], correct: 0, explain: '国家反诈中心App可识别诈骗电话短信、预警诈骗风险、快速举报。' },

        { text: '以下哪种情况应该提高警惕？', options: ['陌生人要求转账汇款','朋友约饭','收到快递','天气预报'], correct: 0, explain: '任何陌生人通过电话/短信/网络要求转账汇款都应高度警惕。' },
        { text: '老年人最应警惕哪类诈骗？', options: ['冒充公检法和保健品推销','网上购物','玩游戏','看视频'], correct: 0, explain: '冒充公检法和保健品推销是针对老年人最常见的诈骗类型。' },
        { text: '国家反诈中心App主要功能是？', options: ['诈骗预警识别和举报','天气预报','购物比价','看新闻'], correct: 0, explain: '国家反诈中心App可识别诈骗电话短信、预警诈骗风险、快速举报。' },

        { text: '安全知识测试题1：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题2：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题3：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题4：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题5：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题6：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题7：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题8：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题9：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题10：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题11：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题12：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题13：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题14：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题15：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题16：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题17：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题18：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题19：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题20：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题21：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题22：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题23：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题24：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题25：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题26：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题27：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题28：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题29：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题30：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题31：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题32：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题33：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题34：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题35：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题36：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题37：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题38：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题39：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题40：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题41：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题42：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题43：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题44：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题45：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题46：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题47：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题48：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题49：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题50：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题51：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题52：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题53：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题54：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题55：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题56：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题57：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题58：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题59：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题60：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题61：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题62：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题63：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题64：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题65：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题66：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题67：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题68：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题69：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题70：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题71：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题72：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题73：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题74：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题75：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题76：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题77：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题78：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题79：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题80：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题81：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题82：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题83：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题84：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题85：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题86：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题87：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题88：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题89：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
];
    if (window._qadventure) window._qadventure.destroy();
    window._qadventure = new QAdventureEngine({
        gameId: 'alert',
        themeId: 'alert',
        questions: questions,
        areaElId: 'alert-game-area',
        scoreElId: 'alert-score',
        resultDivId: 'alert-result',
        resultTextId: 'alert-score-text'
    });
    window._qadventure.init();
}
function initForestGame() {
    var resultDiv = document.getElementById('forest-result');
    if (resultDiv) resultDiv.classList.add('hidden');
    var questions = [
        { text: "森林被称为\"地球之肺\"，主要是因为？", options: ["吸收二氧化碳释放氧气", "产生大量水蒸气", "阻挡风沙", "提供木材"], correct: 0, explain: "森林通过光合作用吸收二氧化碳释放氧气，维持大气碳氧平衡。" },
        { text: "以下哪种行为对森林破坏最大？", options: ["乱砍滥伐+毁林开荒", "适度采摘野果", "森林徒步", "科学植树"], correct: 0, explain: "乱砍滥伐和毁林开荒直接导致森林面积减少，是破坏森林的主要原因。" },
        { text: "森林防火最关键的措施是？", options: ["严控野外火源", "多建消防站", "砍伐防火带", "人工降雨"], correct: 0, explain: "绝大多数森林火灾由人为火源引起，严控野外用火是最关键的预防措施。" },
        { text: "一棵成年大树一天约能吸收多少二氧化碳？", options: ["约20-40kg", "约1kg", "约100kg", "不吸收"], correct: 0, explain: "一棵成年大树一天约吸收20-40kg二氧化碳，相当于一辆汽车行驶100公里的排放。" },
        { text: "以下哪种是保护生物多样性的有效方式？", options: ["建立自然保护区", "大量引进外来物种", "全面禁止人类进入", "砍伐老树种新树"], correct: 0, explain: "自然保护区是保护生物多样性的最有效方式，为野生动植物提供栖息地。" }
    ,
        { text: '森林的主要生态功能不包括？', options: ['生产氧气','涵养水源','保持水土','生产塑料'], correct: 0, explain: '森林被称为地球之肺，具有固碳释氧、涵养水源、保持水土等功能。' },
        { text: '我国森林覆盖率约为？', options: ['约25%','约5%','约50%','约90%'], correct: 0, explain: '我国森林覆盖率约25%，经过数十年努力近翻番增长但仍需继续加强保护。' },
        { text: '森林病虫害防治最佳策略是？', options: ['预防为主综合防治','大量使用农药','不防治','砍光重种'], correct: 0, explain: '预防为主综合防治是森林保护的基本原则，包括生物防治和科学用药。' },

        { text: '森林的主要生态功能不包括？', options: ['生产氧气','涵养水源','保持水土','生产塑料'], correct: 0, explain: '森林被称为地球之肺，具有固碳释氧、涵养水源、保持水土等功能。' },
        { text: '我国森林覆盖率约为？', options: ['约25%','约5%','约50%','约90%'], correct: 0, explain: '我国森林覆盖率约25%，经过数十年努力近翻番增长但仍需继续加强保护。' },
        { text: '森林病虫害防治最佳策略是？', options: ['预防为主综合防治','大量使用农药','不防治','砍光重种'], correct: 0, explain: '预防为主综合防治是森林保护的基本原则，包括生物防治和科学用药。' },

        { text: '安全知识测试题1：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题2：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题3：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题4：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题5：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题6：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题7：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题8：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题9：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题10：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题11：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题12：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题13：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题14：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题15：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题16：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题17：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题18：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题19：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题20：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题21：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题22：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题23：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题24：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题25：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题26：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题27：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题28：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题29：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题30：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题31：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题32：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题33：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题34：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题35：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题36：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题37：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题38：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题39：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题40：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题41：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题42：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题43：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题44：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题45：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题46：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题47：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题48：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题49：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题50：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题51：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题52：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题53：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题54：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题55：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题56：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题57：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题58：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题59：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题60：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题61：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题62：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题63：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题64：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题65：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题66：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题67：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题68：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题69：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题70：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题71：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题72：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题73：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题74：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题75：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题76：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题77：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题78：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题79：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题80：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题81：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题82：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题83：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题84：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题85：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题86：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题87：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题88：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题89：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
];
    if (window._qadventure) window._qadventure.destroy();
    window._qadventure = new QAdventureEngine({
        gameId: 'forest',
        themeId: 'forest',
        questions: questions,
        areaElId: 'forest-game-area',
        scoreElId: 'forest-score',
        resultDivId: 'forest-result',
        resultTextId: 'forest-score-text'
    });
    window._qadventure.init();
}
function initLightGame() {
    var resultDiv = document.getElementById('light-result');
    if (resultDiv) resultDiv.classList.add('hidden');
    var questions = [
        { text: "以下哪种能源属于可再生能源？", options: ["太阳能", "煤炭", "石油", "天然气"], correct: 0, explain: "太阳能是可再生能源，取之不尽用之不竭，且无污染。" },
        { text: "一盏LED灯比传统白炽灯节能约多少？", options: ["约80%", "约10%", "不节能", "约30%"], correct: 0, explain: "LED灯比白炽灯节能约80%，寿命也更长，是最佳的照明选择。" },
        { text: "偏远地区最适合的供电方案是？", options: ["分布式太阳能", "大型火电站", "核电站", "远距离输电"], correct: 0, explain: "分布式太阳能适合偏远地区，无需远距离输电，维护简单。" },
        { text: "以下哪种行为最节电？", options: ["人走灯灭+使用节能电器", "一直开灯方便", "空调开26度以下", "电器待机不关闭"], correct: 0, explain: "人走灯灭和使用节能电器是最基本的节电行为，待机也会耗电。" },
        { text: "我国\"西电东送\"工程主要输送的是？", options: ["水电和风电", "火电", "核电", "太阳能"], correct: 0, explain: "西电东送主要输送西南地区的水电和西北地区的风电，优化能源配置。" }
    ,
        { text: '太阳能发电的优势不包括？', options: ['24小时持续发电不受天气影响','清洁无污染','可再生','适合分布式'], correct: 0, explain: '太阳能发电受天气和昼夜影响大，夜间无法发电，需要储能配套。' },
        { text: '一度电可以让25W节能灯亮多久？', options: ['约40小时','约1小时','约10小时','约100小时'], correct: 0, explain: '1度电=1000瓦时，1000/25=40小时。节能灯效率远高于白炽灯。' },
        { text: '偏远地区供电最适合的能源是？', options: ['分布式光伏或风电','大型火电站','核电','地热'], correct: 0, explain: '偏远地区电网难以覆盖，分布式光伏和风电是最经济可行的供电方式。' },

        { text: '太阳能发电的优势不包括？', options: ['24小时持续发电不受天气影响','清洁无污染','可再生','适合分布式'], correct: 0, explain: '太阳能发电受天气和昼夜影响大，夜间无法发电，需要储能配套。' },
        { text: '一度电可以让25W节能灯亮多久？', options: ['约40小时','约1小时','约10小时','约100小时'], correct: 0, explain: '1度电=1000瓦时，1000/25=40小时。节能灯效率远高于白炽灯。' },
        { text: '偏远地区供电最适合的能源是？', options: ['分布式光伏或风电','大型火电站','核电','地热'], correct: 0, explain: '偏远地区电网难以覆盖，分布式光伏和风电是最经济可行的供电方式。' },

        { text: '安全知识测试题1：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题2：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题3：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题4：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题5：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题6：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题7：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题8：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题9：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题10：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题11：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题12：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题13：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题14：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题15：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题16：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题17：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题18：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题19：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题20：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题21：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题22：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题23：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题24：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题25：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题26：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题27：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题28：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题29：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题30：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题31：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题32：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题33：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题34：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题35：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题36：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题37：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题38：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题39：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题40：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题41：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题42：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题43：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题44：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题45：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题46：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题47：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题48：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题49：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题50：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题51：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题52：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题53：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题54：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题55：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题56：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题57：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题58：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题59：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题60：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题61：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题62：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题63：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题64：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题65：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题66：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题67：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题68：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题69：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题70：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题71：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题72：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题73：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题74：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题75：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题76：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题77：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题78：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题79：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题80：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题81：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题82：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题83：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题84：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题85：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题86：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题87：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题88：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题89：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
];
    if (window._qadventure) window._qadventure.destroy();
    window._qadventure = new QAdventureEngine({
        gameId: 'light',
        themeId: 'light',
        questions: questions,
        areaElId: 'light-game-area',
        scoreElId: 'light-score',
        resultDivId: 'light-result',
        resultTextId: 'light-score-text'
    });
    window._qadventure.init();
}
function initSeedGame() {
    var resultDiv = document.getElementById('seed-result');
    if (resultDiv) resultDiv.classList.add('hidden');
    var questions = [
        { text: "种子银行（种质库）的主要作用是？", options: ["保存植物遗传多样性", "贩卖种子", "展示植物", "研究农药"], correct: 0, explain: "种子银行保存濒危植物种子，保护遗传多样性，为未来恢复生态提供可能。" },
        { text: "以下哪种植物是我国特有的濒危物种？", options: ["水杉", "松树", "柳树", "杨树"], correct: 0, explain: "水杉是中国特有珍稀植物，被称为\"活化石\"，曾一度被认为已灭绝。" },
        { text: "种子长期保存的最佳条件是？", options: ["低温干燥", "常温湿润", "高温干燥", "低温湿润"], correct: 0, explain: "低温（-18°C左右）干燥环境可降低种子代谢，实现数十年甚至上百年的保存。" },
        { text: "以下哪种行为有助于保护植物多样性？", options: ["不购买野生保护植物", "大量采摘野花", "随意引入外来植物", "砍伐原生林种经济林"], correct: 0, explain: "不购买野生保护植物可减少盗采，保护植物多样性从拒绝消费做起。" },
        { text: "濒危植物保护的最高优先级措施是？", options: ["就地保护（建立保护区）", "移栽到城市", "制作标本", "拍照记录"], correct: 0, explain: "就地保护是保护濒危植物最有效的方式，维持其自然生态环境和种群。" }
    ,
        { text: '种子银行的主要目的是？', options: ['保存植物遗传多样性防止物种灭绝','赚钱','种地','研究'], correct: 0, explain: '种子银行保护濒危植物遗传资源，是应对气候变化和物种灭绝的重要防线。' },
        { text: '全球最大种子库位于？', options: ['挪威斯瓦尔巴全球种子库','中国北京','美国纽约','英国伦敦'], correct: 0, explain: '斯瓦尔巴种子库位于北极圈内，储存着来自全球的超过100万份种子样本。' },
        { text: '为什么需要保护地方传统品种种子？', options: ['保持农业生物多样性应对未来挑战','产量太高','太老了','没意义'], correct: 0, explain: '传统品种可能具有抗逆、耐旱等特性，是应对气候变化下粮食安全的宝贵资源。' },

        { text: '种子银行的主要目的是？', options: ['保存植物遗传多样性防止物种灭绝','赚钱','种地','研究'], correct: 0, explain: '种子银行保护濒危植物遗传资源，是应对气候变化和物种灭绝的重要防线。' },
        { text: '全球最大种子库位于？', options: ['挪威斯瓦尔巴全球种子库','中国北京','美国纽约','英国伦敦'], correct: 0, explain: '斯瓦尔巴种子库位于北极圈内，储存着来自全球的超过100万份种子样本。' },
        { text: '为什么需要保护地方传统品种种子？', options: ['保持农业生物多样性应对未来挑战','产量太高','太老了','没意义'], correct: 0, explain: '传统品种可能具有抗逆、耐旱等特性，是应对气候变化下粮食安全的宝贵资源。' },

        { text: '安全知识测试题1：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题2：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题3：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题4：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题5：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题6：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题7：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题8：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题9：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题10：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题11：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题12：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题13：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题14：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题15：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题16：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题17：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题18：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题19：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题20：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题21：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题22：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题23：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题24：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题25：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题26：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题27：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题28：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题29：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题30：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题31：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题32：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题33：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题34：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题35：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题36：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题37：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题38：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题39：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题40：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题41：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题42：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题43：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题44：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题45：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题46：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题47：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题48：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题49：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题50：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题51：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题52：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题53：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题54：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题55：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题56：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题57：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题58：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题59：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题60：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题61：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题62：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题63：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题64：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题65：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题66：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题67：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题68：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题69：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题70：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题71：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题72：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题73：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题74：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题75：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题76：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题77：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题78：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题79：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题80：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题81：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题82：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题83：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题84：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题85：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题86：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题87：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题88：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题89：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
];
    if (window._qadventure) window._qadventure.destroy();
    window._qadventure = new QAdventureEngine({
        gameId: 'seed',
        themeId: 'seed',
        questions: questions,
        areaElId: 'seed-game-area',
        scoreElId: 'seed-score',
        resultDivId: 'seed-result',
        resultTextId: 'seed-score-text'
    });
    window._qadventure.init();
}
function initCivilGame() {
    var resultDiv = document.getElementById('civil-result');
    if (resultDiv) resultDiv.classList.add('hidden');
    var questions = [
        { text: "以下哪项是中国非物质文化遗产？", options: ["京剧", "篮球", "电影", "油画"], correct: 0, explain: "京剧是中国国粹，2006年被列入国家级非物质文化遗产名录。" },
        { text: "保护非物质文化遗产最有效的方式是？", options: ["传承人培养+活态传承", "全部放入博物馆", "录制视频保存", "禁止商业化"], correct: 0, explain: "非遗保护的核心是活态传承，培养年轻传承人让技艺延续下去。" },
        { text: "以下哪种行为有助于保护古建筑？", options: ["不刻画涂鸦，文明参观", "刻字留念", "攀爬拍照", "带走古砖"], correct: 0, explain: "文明参观、不刻画涂鸦是保护古建筑的基本要求，刻画会造成不可逆损害。" },
        { text: "中国传统节日中，哪个与祭祖和缅怀先人有关？", options: ["清明节", "春节", "端午节", "中秋节"], correct: 0, explain: "清明节是传统的祭祖节日，体现了中华民族慎终追远的文化传统。" },
        { text: "以下哪种是保护濒危语言的有效措施？", options: ["建立语言档案+双语教育", "禁止使用", "只用普通话", "不采取任何措施"], correct: 0, explain: "建立语言档案和开展双语教育可有效保护濒危语言，让文化多样性延续。" }
    ,
        { text: '古籍修复中最重要的原则是？', options: ['修旧如旧保持原貌','修得比原来新','随意修改','用现代技术重做'], correct: 0, explain: '古籍修复遵循修旧如旧原则，最大限度保留原始信息和历史价值。' },
        { text: '敦煌文献主要价值在于？', options: ['记录丝绸之路历史文化宗教经济','只有文学价值','没什么用','是假文物'], correct: 0, explain: '敦煌文献涵盖宗教、历史、文学、经济等多领域，是研究中古中国的百科全书。' },
        { text: '甲骨文最早是被谁发现的？', options: ['王懿荣在药店龙骨上发现','偶然挖出来的','外国人发现的','现代考古发现的'], correct: 0, explain: '1899年王懿荣在中药龙骨上发现甲骨文，揭开了殷商历史研究的新篇章。' },

        { text: '古籍修复中最重要的原则是？', options: ['修旧如旧保持原貌','修得比原来新','随意修改','用现代技术重做'], correct: 0, explain: '古籍修复遵循修旧如旧原则，最大限度保留原始信息和历史价值。' },
        { text: '敦煌文献主要价值在于？', options: ['记录丝绸之路历史文化宗教经济','只有文学价值','没什么用','是假文物'], correct: 0, explain: '敦煌文献涵盖宗教、历史、文学、经济等多领域，是研究中古中国的百科全书。' },
        { text: '甲骨文最早是被谁发现的？', options: ['王懿荣在药店龙骨上发现','偶然挖出来的','外国人发现的','现代考古发现的'], correct: 0, explain: '1899年王懿荣在中药龙骨上发现甲骨文，揭开了殷商历史研究的新篇章。' },

        { text: '安全知识测试题1：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题2：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题3：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题4：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题5：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题6：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题7：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题8：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题9：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题10：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题11：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题12：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题13：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题14：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题15：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题16：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题17：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题18：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题19：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题20：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题21：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题22：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题23：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题24：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题25：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题26：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题27：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题28：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题29：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题30：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题31：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题32：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题33：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题34：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题35：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题36：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题37：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题38：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题39：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题40：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题41：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题42：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题43：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题44：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题45：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题46：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题47：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题48：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题49：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题50：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题51：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题52：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题53：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题54：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题55：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题56：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题57：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题58：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题59：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题60：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题61：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题62：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题63：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题64：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题65：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题66：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题67：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题68：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题69：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题70：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题71：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题72：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题73：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题74：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题75：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题76：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题77：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题78：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题79：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题80：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题81：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题82：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题83：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题84：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题85：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题86：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题87：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题88：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
        { text: '安全知识测试题89：遇到紧急情况首先应该保持冷静并及时求助专业人士', options: ['正确','错误','不确定','都不是'], correct: 0, explain: '在任何紧急情况下，保持冷静并及时向专业人士（如医生、警察、消防员）求助是最重要的第一步。' },
];
    if (window._qadventure) window._qadventure.destroy();
    window._qadventure = new QAdventureEngine({
        gameId: 'civil',
        themeId: 'civil',
        questions: questions,
        areaElId: 'civil-game-area',
        scoreElId: 'civil-score',
        resultDivId: 'civil-result',
        resultTextId: 'civil-score-text'
    });
    window._qadventure.init();
}

// ============================================================
// 🔗 全局按钮事件绑定 — 新增游戏入口（修复按钮无反应问题）
// ============================================================

function bindAllGameButtons() {
    function bindGuardedClick(id, handler) {
        var btn = document.getElementById(id);
        if (!btn || btn.dataset.skGuardedClick === 'true') return;
        btn.dataset.skGuardedClick = 'true';
        btn.addEventListener('click', function(e) {
            if (e) {
                e.preventDefault();
                e.stopImmediatePropagation();
            }
            handler(e);
        });
    }

    function openGame(screenId, initFn) {
        cleanupTransientGames(screenId);
        transitionToScreen(screenId);
        if (typeof initFn === 'function') initFn();
        updateGameplayCoach(screenId);
    }

    function initMemoryMatchOnce() {
        if (!window._memoryMatchGame) window._memoryMatchGame = new MemoryMatchGame();
        window._memoryMatchGame.init();
    }

    var openBindings = [
        ['btn-open-match', 'screen-match', initMemoryMatchOnce],
        ['btn-open-timeline', 'screen-timeline', initTimelineGame],
        ['btn-open-hidden', 'screen-hidden', initHiddenGame],
        ['btn-open-maze', 'screen-maze', initMazeGame],
        ['btn-open-color', 'screen-color', initColorGame],
        ['btn-open-face', 'screen-face', initFaceGame],
        ['btn-open-word', 'screen-word', initWordGame],
        ['btn-open-rhythm', 'screen-rhythm', initRhythmGame],
        ['btn-open-spatial', 'screen-spatial', initSpatialGame],
        ['btn-open-eco', 'screen-eco', function() { initEcoGame('easy'); }],
        ['btn-open-fraud', 'screen-fraud', function() { initFraudGame('easy'); }],
        ['btn-open-a11y', 'screen-a11y', initA11yGame],
        ['btn-open-water', 'screen-water', initWaterGame],
        ['btn-open-carbon', 'screen-carbon', initCarbonGame],
        ['btn-open-repair', 'screen-repair', initRepairGame],
        ['btn-open-aid', 'screen-aid', initAidGame],
        ['btn-open-food', 'screen-food', initFoodGame],
        ['btn-open-animal', 'screen-animal', initAnimalGame],
        ['btn-open-trace', 'screen-trace', initTraceGame],
        ['btn-open-decode', 'screen-decode', initDecodeGame],
        ['btn-open-phish', 'screen-phish', initPhishGame],
        ['btn-open-script', 'screen-script', initScriptGame],
        ['btn-open-identity', 'screen-identity', initIdentityGame],
        ['btn-open-transfer', 'screen-transfer', initTransferGame],
        ['btn-open-leak', 'screen-leak', initLeakGame],
        ['btn-open-evidence', 'screen-evidence', initEvidenceGame],
        ['btn-open-alert', 'screen-alert', initAlertGame],
        ['btn-open-ocean', 'screen-ocean', function() { if (_oceanGame) _oceanGame.destroy(); _oceanGame = new OceanRepairGame(); _oceanGame.init(); }],
        ['btn-open-oracle', 'screen-oracle', function() { if (_oracleGame) _oracleGame.destroy(); _oracleGame = new OracleRepairGame(); _oracleGame.init(); }],
        ['btn-open-truth', 'screen-truth', function() { if (_truthGame) _truthGame.destroy(); _truthGame = new TruthPuzzleGame(); _truthGame.init(); }],
        ['btn-open-heart', 'screen-heart', function() { if (_heartGame) _heartGame.destroy(); _heartGame = new HeartBridgeGame(); _heartGame.init(); }],
        ['btn-open-grain', 'screen-grain', function() { if (_grainGame) _grainGame.destroy(); _grainGame = new GrainJourneyGame(); _grainGame.init(); }],
        ['btn-open-forest', 'screen-forest', initForestGame],
        ['btn-open-light', 'screen-light', initLightGame],
        ['btn-open-seed', 'screen-seed', initSeedGame],
        ['btn-open-civil', 'screen-civil', initCivilGame]
    ];

    openBindings.forEach(function(binding) {
        bindGuardedClick(binding[0], function() {
            openGame(binding[1], binding[2]);
        });
    });

    var qaGames = ['water','carbon','repair','aid','food','animal','phish','script','identity','transfer','leak','evidence','alert','forest','light','seed','civil'];
    qaGames.forEach(function(gid) {
        bindGuardedClick('btn-' + gid + '-back', function() {
            destroyTransientGameRef('_qadventure');
            transitionToScreen('screen-hub');
        });
        bindGuardedClick('btn-' + gid + '-replay', function() {
            destroyTransientGameRef('_qadventure');
            var initFn = window['init' + gid.charAt(0).toUpperCase() + gid.slice(1) + 'Game'];
            if (typeof initFn === 'function') initFn();
            updateGameplayCoach('screen-' + gid);
        });
        bindGuardedClick('btn-' + gid + '-hub', function() {
            destroyTransientGameRef('_qadventure');
            transitionToScreen('screen-hub');
        });
    });
}

// 页面加载后执行绑定
bindAllGameButtons();

// ============================================================================
//
