(function(root) {
    'use strict';

    var STORAGE_KEY = 'shanxing-workshop:game-state:v1';
    var SAVE_VERSION = 1;
    var memoryStore = {};
    var saveTimer = null;
    var MAX_LIST_ITEMS = 160;
    var MAX_ALBUM_ENTRIES = 120;
    var MAX_ALBUM_TEXT = 6000;
    var MAX_ALBUM_FIELD = 160;
    var MAX_GAME_STATS = 96;

    var PERSIST_KEYS = [
        'unlockedItems',
        'completedItems',
        'fraudCompleted',
        'albumEntries',
        'fraudAlbumEntries',
        'progress',
        'memorySilver',
        'totalEmpathy',
        'lastMaxCombo',
        'totalGamesPlayed',
        'totalGamesCompleted',
        'upgrades',
        'achievements',
        'gameStats',
        'dailyChallenge'
    ];

    function getStorage() {
        try {
            var storage = root.localStorage;
            if (!storage) throw new Error('localStorage unavailable');
            var probe = STORAGE_KEY + ':probe';
            storage.setItem(probe, '1');
            storage.removeItem(probe);
            return storage;
        } catch (error) {
            return {
                getItem: function(key) {
                    return Object.prototype.hasOwnProperty.call(memoryStore, key) ? memoryStore[key] : null;
                },
                setItem: function(key, value) {
                    memoryStore[key] = String(value);
                },
                removeItem: function(key) {
                    delete memoryStore[key];
                }
            };
        }
    }

    function clone(value, fallback) {
        try {
            return JSON.parse(JSON.stringify(value));
        } catch (error) {
            return fallback;
        }
    }

    function number(value, fallback, min, max) {
        var n = Number(value);
        if (!Number.isFinite(n)) return fallback;
        if (typeof min === 'number') n = Math.max(min, n);
        if (typeof max === 'number') n = Math.min(max, n);
        return n;
    }

    function boundedString(value, max, fallback) {
        if (typeof value !== 'string') return fallback || '';
        return value.slice(0, max);
    }

    function uniqueStrings(value, fallback) {
        var base = Array.isArray(fallback) ? fallback.slice() : [];
        var list = Array.isArray(value) ? value : [];
        var result = [];
        var seen = {};
        base.concat(list).forEach(function(item) {
            if (typeof item !== 'string') return;
            var clean = boundedString(item, MAX_ALBUM_FIELD).trim();
            if (!clean || seen[clean]) return;
            seen[clean] = true;
            result.push(clean);
        });
        return result.slice(0, MAX_LIST_ITEMS);
    }

    function normalizeObject(value, fallback) {
        if (!value || typeof value !== 'object' || Array.isArray(value)) return clone(fallback || {}, {});
        return clone(value, {});
    }

    function normalizeUpgrades(value, fallback) {
        var source = value && typeof value === 'object' ? value : {};
        var base = fallback && typeof fallback === 'object' ? fallback : {};
        var result = {};
        Object.keys(base).forEach(function(key) {
            var baseItem = base[key] || {};
            var item = source[key] && typeof source[key] === 'object' ? source[key] : {};
            result[key] = {
                level: Math.max(1, Math.round(number(item.level, baseItem.level || 1, 1, 999))),
                baseCost: Math.max(1, Math.round(number(item.baseCost, baseItem.baseCost || 100, 1, 999999)))
            };
        });
        return result;
    }

    function normalizeAlbumEntry(entry) {
        return {
            id: boundedString(entry.id, MAX_ALBUM_FIELD),
            title: boundedString(entry.title, MAX_ALBUM_FIELD),
            choiceId: boundedString(entry.choiceId, MAX_ALBUM_FIELD),
            storyText: boundedString(entry.storyText, MAX_ALBUM_TEXT),
            date: boundedString(entry.date, MAX_ALBUM_FIELD)
        };
    }

    function normalizeAlbum(value) {
        if (!Array.isArray(value)) return [];
        return value
            .filter(function(entry) { return entry && typeof entry === 'object'; })
            .slice(-MAX_ALBUM_ENTRIES)
            .map(normalizeAlbumEntry)
            .filter(function(entry) { return entry.id || entry.title || entry.storyText; });
    }

    function normalizeBooleanMap(value, fallback) {
        var source = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
        var base = fallback && typeof fallback === 'object' && !Array.isArray(fallback) ? fallback : {};
        var result = {};
        Object.keys(base).forEach(function(key) {
            result[key] = Boolean(source[key]);
        });
        return result;
    }

    function normalizeGameStats(value, fallback) {
        var source = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
        var base = fallback && typeof fallback === 'object' && !Array.isArray(fallback) ? fallback : {};
        var result = {};
        var seen = {};
        Object.keys(base).concat(Object.keys(source)).forEach(function(key) {
            if (seen[key]) return;
            seen[key] = true;
            if (Object.keys(result).length >= MAX_GAME_STATS) return;
            if (typeof key !== 'string' || !/^[a-z0-9_-]{1,64}$/i.test(key)) return;
            var stat = source[key] && typeof source[key] === 'object' ? source[key] : (base[key] || {});
            result[key] = {
                played: Math.max(0, Math.round(number(stat.played, 0, 0, 999999))),
                completed: Math.max(0, Math.round(number(stat.completed, 0, 0, 999999))),
                bestScore: Math.max(0, Math.round(number(stat.bestScore, 0, 0, 99999999)))
            };
        });
        return result;
    }

    function normalizeDaily(value, fallback) {
        var base = fallback && typeof fallback === 'object' ? fallback : {};
        var source = value && typeof value === 'object' ? value : {};
        return {
            date: boundedString(typeof source.date === 'string' ? source.date : (base.date || ''), 40),
            target: Math.max(0, Math.round(number(source.target, base.target || 0, 0, 999))),
            reward: Math.max(0, Math.round(number(source.reward, base.reward || 0, 0, 999999))),
            progress: Math.max(0, Math.round(number(source.progress, base.progress || 0, 0, 999))),
            completed: Boolean(source.completed)
        };
    }

    function extract(gameState, defaults) {
        var base = defaults || gameState || {};
        var state = {};
        state.unlockedItems = uniqueStrings(gameState.unlockedItems, base.unlockedItems);
        state.completedItems = uniqueStrings(gameState.completedItems, base.completedItems);
        state.fraudCompleted = uniqueStrings(gameState.fraudCompleted, base.fraudCompleted);
        state.albumEntries = normalizeAlbum(gameState.albumEntries);
        state.fraudAlbumEntries = normalizeAlbum(gameState.fraudAlbumEntries);
        state.progress = Math.round(number(gameState.progress, base.progress || 0, 0, 100));
        state.memorySilver = Math.max(0, Math.round(number(gameState.memorySilver, base.memorySilver || 0, 0, 99999999)));
        state.totalEmpathy = Math.max(0, Math.round(number(gameState.totalEmpathy, base.totalEmpathy || 0, 0, 99999999)));
        state.lastMaxCombo = Math.max(0, Math.round(number(gameState.lastMaxCombo, base.lastMaxCombo || 0, 0, 9999)));
        state.totalGamesPlayed = Math.max(0, Math.round(number(gameState.totalGamesPlayed, base.totalGamesPlayed || 0, 0, 999999)));
        state.totalGamesCompleted = Math.max(0, Math.round(number(gameState.totalGamesCompleted, base.totalGamesCompleted || 0, 0, 999999)));
        state.upgrades = normalizeUpgrades(gameState.upgrades, base.upgrades);
        state.achievements = normalizeBooleanMap(gameState.achievements, base.achievements);
        state.gameStats = normalizeGameStats(gameState.gameStats, base.gameStats);
        state.dailyChallenge = normalizeDaily(gameState.dailyChallenge, base.dailyChallenge);
        return state;
    }

    function load() {
        try {
            var raw = getStorage().getItem(STORAGE_KEY);
            if (!raw) return null;
            var parsed = JSON.parse(raw);
            return parsed && parsed.data ? parsed.data : parsed;
        } catch (error) {
            console.warn('Saved game state could not be read.', error);
            return null;
        }
    }

    function mergeSavedState(target, saved) {
        var merged = clone(target, {});
        if (!saved || typeof saved !== 'object' || Array.isArray(saved)) return merged;
        PERSIST_KEYS.forEach(function(key) {
            if (Object.prototype.hasOwnProperty.call(saved, key)) {
                merged[key] = saved[key];
            }
        });
        return merged;
    }

    function hydrate(target) {
        var saved = load();
        if (!saved || !target) return false;
        var normalized = extract(mergeSavedState(target, saved), target);
        PERSIST_KEYS.forEach(function(key) {
            target[key] = normalized[key];
        });
        return true;
    }

    function save(gameState) {
        if (!gameState) return null;
        var data = extract(gameState, gameState);
        try {
            getStorage().setItem(STORAGE_KEY, JSON.stringify({
                version: SAVE_VERSION,
                savedAt: new Date().toISOString(),
                data: data
            }));
        } catch (error) {
            console.warn('Game state could not be saved.', error);
        }
        return data;
    }

    function saveDebounced(gameState, delay) {
        clearTimeout(saveTimer);
        saveTimer = setTimeout(function() {
            save(gameState);
        }, typeof delay === 'number' ? delay : 250);
    }

    root.SKStatePersistence = {
        key: STORAGE_KEY,
        version: SAVE_VERSION,
        hydrate: hydrate,
        load: load,
        save: save,
        saveDebounced: saveDebounced,
        clear: function() {
            try {
                getStorage().removeItem(STORAGE_KEY);
            } catch (error) {
                console.warn('Saved game state could not be cleared.', error);
            }
        },
        test: {
            extract: extract,
            mergeSavedState: mergeSavedState,
            uniqueStrings: uniqueStrings,
            normalizeAlbum: normalizeAlbum,
            normalizeGameStats: normalizeGameStats,
            normalizeDaily: normalizeDaily
        }
    };
})(typeof window !== 'undefined' ? window : globalThis);
