/**
 * Time's Echo: Memory Weaver - Web Audio API Synthesizer & Audio Engine
 * This script dynamically synthesizes ambient music, vinyl crackle, and retro UI sound effects.
 * Created for the Tencent Cloud Hackathon public welfare game track.
 */

// Strict Chromium Environment: Establish pass-through Trusted Types Policy
// 注意：sound.js 无 innerHTML 注入操作，此策略仅用于阻止 Chromium 报错
// 真正的 HTML 消毒器在 game.js 中 —— safeHTML() 会经过完整 DOMParser 过滤
if (window.trustedTypes && window.trustedTypes.createPolicy) {
    if (!window.trustedTypes.defaultPolicy) {
        try {
            // 最小安全策略：剥离 on* 事件处理器，放行其余
            window.trustedTypes.createPolicy('default', {
                createHTML: (string) => {
                    return string.replace(/\s+on\w+\s*=\s*['"][^'"]*['"]/gi, '');
                },
                createScript: (string) => string.replace(/javascript:/gi, ''),
                createScriptURL: (string) => string
            });
        } catch (e) {
            console.warn("Trusted Types default policy creation failed inside sound.js:", e);
        }
    }
}

class AudioEngine {
    constructor() {
        this.ctx = null;
        this.masterVolume = null;
        this.bgmVolume = null;
        this.sfxVolume = null;
        
        this.isPlayingBGM = false;
        this.bgmInterval = null;
        this.noiseNode = null;
        
        // Lo-Fi Chord progressions (Rhodes Piano synthesis)
        // Mellow 9th jazz chord extensions for vintage high-end public welfare feel
        this.chords = [
            [174.61, 220.00, 261.63, 329.63, 392.00], // Fmaj9 (F3, A3, C4, E4, G4)
            [130.81, 164.81, 196.00, 246.94, 293.66], // Cmaj9 (C3, E3, G3, B3, D4)
            [146.83, 174.61, 220.00, 261.63, 329.63], // Dm9   (D3, F3, A3, C4, E4)
            [110.00, 164.81, 196.00, 261.63, 493.88]  // Am9   (A2, E3, G3, C4, B4)
        ];
        this.currentChordIndex = 0;
    }

    init() {
        if (this.ctx) return;
        
        try {
            // Initialize Audio Context (Standardized across browsers)
            const AudioContextClass = window.AudioContext || window.webkitAudioContext;
            if (!AudioContextClass) {
                console.warn("Web Audio API is not supported in this browser.");
                return;
            }
            this.ctx = new AudioContextClass();
            
            // Master Gain Node
            this.masterVolume = this.ctx.createGain();
            this.masterVolume.gain.value = 0.8;
            this.masterVolume.connect(this.ctx.destination);
            
            // BGM Gain Node
            this.bgmVolume = this.ctx.createGain();
            this.bgmVolume.gain.value = 0.25;
            this.bgmVolume.connect(this.masterVolume);
            
            // SFX Gain Node
            this.sfxVolume = this.ctx.createGain();
            this.sfxVolume.gain.value = 0.55;
            this.sfxVolume.connect(this.masterVolume);
            
            // Self-healing: Unlock AudioContext if suspended by browser Autoplay restriction policies
            if (this.ctx.state === 'suspended') {
                const resumeAudio = () => {
                    if (this.ctx && this.ctx.state === 'suspended') {
                        this.ctx.resume().then(() => {
                            console.log("AudioContext successfully resumed via user gesture self-healing.");
                            if (this.isPlayingBGM) {
                                this.isPlayingBGM = false;
                                this.startBGM();
                            }
                        }).catch(err => {
                            console.warn("AudioContext resume failed:", err);
                        });
                    }
                    // Clean up event listeners once successfully running
                    document.removeEventListener('click', resumeAudio);
                    document.removeEventListener('pointerdown', resumeAudio);
                    document.removeEventListener('keydown', resumeAudio);
                };
                document.addEventListener('click', resumeAudio, { passive: true });
                document.addEventListener('pointerdown', resumeAudio, { passive: true });
                document.addEventListener('keydown', resumeAudio, { passive: true });
            }

            // Start Vinyl Tape Crackle Noise
            this.startVinylNoise();
        } catch (e) {
            console.error("AudioEngine failed to initialize or has no output device:", e);
            this.ctx = null;
        }
    }

    /**
     * Synthesize realistic Vinyl Record Scratch and Crackle
     */
    startVinylNoise() {
        if (!this.ctx) return;

        const bufferSize = 2 * this.ctx.sampleRate;
        const noiseBuffer = this.ctx.createBuffer(1, bufferSize, this.ctx.sampleRate);
        const output = noiseBuffer.getChannelData(0);
        
        // Generate Pink-ish Noise with random crackle impulses
        let lastOut = 0.0;
        for (let i = 0; i < bufferSize; i++) {
            const white = Math.random() * 2 - 1;
            // Filter white noise to pink
            output[i] = (lastOut + (0.02 * white)) / 1.02;
            lastOut = output[i];
            output[i] *= 0.15; // Soften volume
            
            // Add scratch pops (impulses) randomly
            if (Math.random() < 0.00015) {
                // Impulses
                output[i] += (Math.random() * 2 - 1) * 0.7;
            }
        }
        
        const noise = this.ctx.createBufferSource();
        noise.buffer = noiseBuffer;
        noise.loop = true;
        
        const noiseFilter = this.ctx.createBiquadFilter();
        noiseFilter.type = 'bandpass';
        noiseFilter.frequency.value = 1000;
        noiseFilter.Q.value = 0.5;
        
        const noiseGain = this.ctx.createGain();
        noiseGain.gain.value = 0.08; // Very subtle vintage tape hum
        
        noise.connect(noiseFilter);
        noiseFilter.connect(noiseGain);
        noiseGain.connect(this.bgmVolume);
        
        noise.start(0);
        this.noiseNode = noise;
    }

    /**
     * Start the nostalgic generative Lo-Fi ambient background music
     */
    startBGM() {
        this.init();
        if (!this.ctx || this.isPlayingBGM) return;
        
        this.isPlayingBGM = true;
        this.ctx.resume();
        
        // Schedule warm synth chords in sequence
        const playNextChord = () => {
            if (!this.isPlayingBGM || !this.ctx) return;
            
            const chord = this.chords[this.currentChordIndex];
            const duration = 6.0; // Play chord for 6 seconds
            
            chord.forEach(freq => {
                this.synthesizePianoNote(freq, duration);
            });
            
            // Advance to next chord
            this.currentChordIndex = (this.currentChordIndex + 1) % this.chords.length;
            
            // Schedule next play
            this.bgmInterval = setTimeout(playNextChord, (duration - 0.5) * 1000);
        };
        
        playNextChord();
    }

    stopBGM() {
        this.isPlayingBGM = false;
        if (this.bgmInterval) {
            clearTimeout(this.bgmInterval);
            this.bgmInterval = null;
        }
    }

    toggleBGM() {
        this.init();
        if (!this.ctx) return false;
        if (this.isPlayingBGM) {
            this.stopBGM();
            return false;
        } else {
            this.startBGM();
            return true;
        }
    }

    /**
     * Synthesize a Rhodes vintage electric piano note
     * Uses filter sweep and low pass to sound mellow
     */
    synthesizePianoNote(frequency, duration) {
        if (!this.ctx) return;
        
        const now = this.ctx.currentTime;
        
        // Main Oscillator: Triangle wave for sweet mellow tone
        const osc = this.ctx.createOscillator();
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(frequency, now);
        
        // Sub Oscillator: Sine wave for rich fundamental bass
        const subOsc = this.ctx.createOscillator();
        subOsc.type = 'sine';
        subOsc.frequency.setValueAtTime(frequency / 2, now);
        
        // Subtly modulate frequency with LFO to simulate analog tape flutter (Wow & Flutter)
        const lfo = this.ctx.createOscillator();
        lfo.frequency.setValueAtTime(3.5, now); // 3.5 Hz speed
        
        const lfoGain = this.ctx.createGain();
        lfoGain.gain.setValueAtTime(frequency * 0.002, now); // Subtle pitch vibrato
        
        lfo.connect(lfoGain);
        lfoGain.connect(osc.frequency);
        lfoGain.connect(subOsc.frequency);
        
        // Low-pass Filter for retro warmth
        const filter = this.ctx.createBiquadFilter();
        filter.type = 'lowpass';
        filter.frequency.setValueAtTime(800, now);
        filter.frequency.exponentialRampToValueAtTime(350, now + duration * 0.7);
        
        // Envelope Gain
        const gainNode = this.ctx.createGain();
        gainNode.gain.setValueAtTime(0, now);
        gainNode.gain.linearRampToValueAtTime(0.3, now + 0.5); // Warm slow attack
        gainNode.gain.exponentialRampToValueAtTime(0.001, now + duration); // Long fade
        
        // Hook up main
        osc.connect(filter);
        subOsc.connect(filter);
        filter.connect(gainNode);
        gainNode.connect(this.bgmVolume);
        
        // Start and stop
        lfo.start(now);
        osc.start(now);
        subOsc.start(now);
        
        lfo.stop(now + duration);
        osc.stop(now + duration);
        subOsc.stop(now + duration);
    }

    /**
     * SFX: Soft Click when item hovered
     */
    playHover() {
        this.init();
        if (!this.ctx) return;
        
        const now = this.ctx.currentTime;
        const osc = this.ctx.createOscillator();
        const gainNode = this.ctx.createGain();
        
        osc.type = 'sine';
        osc.frequency.setValueAtTime(1000, now);
        osc.frequency.exponentialRampToValueAtTime(600, now + 0.05);
        
        gainNode.gain.setValueAtTime(0.04, now);
        gainNode.gain.exponentialRampToValueAtTime(0.0001, now + 0.05);
        
        osc.connect(gainNode);
        gainNode.connect(this.sfxVolume);
        
        osc.start(now);
        osc.stop(now + 0.06);
    }

    /**
     * SFX: Click when dragging starts
     */
    playGrab() {
        this.init();
        if (!this.ctx) return;
        
        const now = this.ctx.currentTime;
        const osc = this.ctx.createOscillator();
        const gainNode = this.ctx.createGain();
        
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(300, now);
        osc.frequency.setValueAtTime(600, now + 0.02);
        
        gainNode.gain.setValueAtTime(0.12, now);
        gainNode.gain.exponentialRampToValueAtTime(0.001, now + 0.06);
        
        osc.connect(gainNode);
        gainNode.connect(this.sfxVolume);
        
        osc.start(now);
        osc.stop(now + 0.07);
    }

    /**
     * SFX: Success snap chime (crystal bell harmonics)
     */
    playSnap() {
        this.init();
        if (!this.ctx) return;
        
        const now = this.ctx.currentTime;
        
        // Synthesize 2 bell notes forming a major third (peaceful and satisfying)
        const playBell = (freq, delay) => {
            const osc = this.ctx.createOscillator();
            const oscHarmonic = this.ctx.createOscillator();
            const gain = this.ctx.createGain();
            
            osc.type = 'sine';
            osc.frequency.setValueAtTime(freq, now + delay);
            
            oscHarmonic.type = 'sine';
            oscHarmonic.frequency.setValueAtTime(freq * 2, now + delay); // Ringing octave harmonic
            
            gain.gain.setValueAtTime(0, now + delay);
            gain.gain.linearRampToValueAtTime(0.15, now + delay + 0.01);
            gain.gain.exponentialRampToValueAtTime(0.001, now + delay + 0.8);
            
            // Subtle vintage delay/reverb emulation
            const delayNode = this.ctx.createDelay();
            delayNode.delayTime.value = 0.15;
            
            const delayGain = this.ctx.createGain();
            delayGain.gain.value = 0.4;
            
            osc.connect(gain);
            oscHarmonic.connect(gain);
            
            // Reverb feedback path
            gain.connect(this.sfxVolume);
            gain.connect(delayNode);
            delayNode.connect(delayGain);
            delayGain.connect(this.sfxVolume);
            
            osc.start(now + delay);
            oscHarmonic.start(now + delay);
            
            osc.stop(now + delay + 1.0);
            oscHarmonic.stop(now + delay + 1.0);
        };
        
        playBell(523.25, 0);     // C5 (pure healing frequency)
        playBell(659.25, 0.08);  // E5
    }

    /**
     * SFX: Sweeping awakening arpeggio
     */
    playAwake() {
        this.init();
        if (!this.ctx) return;
        
        const now = this.ctx.currentTime;
        // Pentatonic sweep: C4 -> D4 -> E4 -> G4 -> A4 -> C5
        const freqs = [261.63, 293.66, 329.63, 392.00, 440.00, 523.25];
        
        freqs.forEach((freq, idx) => {
            const osc = this.ctx.createOscillator();
            const gain = this.ctx.createGain();
            const time = now + (idx * 0.08);
            
            osc.type = 'triangle';
            osc.frequency.setValueAtTime(freq, time);
            
            gain.gain.setValueAtTime(0, time);
            gain.gain.linearRampToValueAtTime(0.15, time + 0.02);
            gain.gain.exponentialRampToValueAtTime(0.001, time + 1.2);
            
            osc.connect(gain);
            gain.connect(this.sfxVolume);
            
            osc.start(time);
            osc.stop(time + 1.3);
        });
    }

    /**
     * SFX: Soft keyboard tap clicks for the typewriter story effect
     */
    playTypewriterClick() {
        this.init();
        if (!this.ctx) return;
        
        const now = this.ctx.currentTime;
        const osc = this.ctx.createOscillator();
        const gainNode = this.ctx.createGain();
        
        // Random pitch to simulate realistic mechanical keypresses
        const pitch = 300 + Math.random() * 200;
        
        osc.type = 'sine';
        osc.frequency.setValueAtTime(pitch, now);
        osc.frequency.exponentialRampToValueAtTime(80, now + 0.03);
        
        gainNode.gain.setValueAtTime(0.06, now);
        gainNode.gain.exponentialRampToValueAtTime(0.0001, now + 0.03);
        
        osc.connect(gainNode);
        gainNode.connect(this.sfxVolume);
        
        osc.start(now);
        osc.stop(now + 0.04);
    }

    /**
     * SFX: Error / wrong answer buzzer — short dissonant beep
     */
    playError() {
        this.init();
        if (!this.ctx) return;
        const now = this.ctx.currentTime;
        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();
        osc.type = 'square';
        osc.frequency.setValueAtTime(200, now);
        osc.frequency.linearRampToValueAtTime(120, now + 0.25);
        gain.gain.setValueAtTime(0.12, now);
        gain.gain.linearRampToValueAtTime(0, now + 0.35);
        osc.connect(gain);
        gain.connect(this.ctx.destination);
        osc.start(now);
        osc.stop(now + 0.35);
    }

    /**
     * SFX: Start continuous white noise representing radio static tuning
     */
    startRadioStatic() {
        this.init();
        if (!this.ctx || this.staticSource) return;

        const bufferSize = this.ctx.sampleRate * 2;
        const buffer = this.ctx.createBuffer(1, bufferSize, this.ctx.sampleRate);
        const data = buffer.getChannelData(0);
        
        for (let i = 0; i < bufferSize; i++) {
            data[i] = Math.random() * 2 - 1; // Pure White Noise
        }

        const source = this.ctx.createBufferSource();
        source.buffer = buffer;
        source.loop = true;

        const filter = this.ctx.createBiquadFilter();
        filter.type = 'bandpass';
        filter.frequency.value = 1400; // Bandpass for metallic retro speaker filter
        filter.Q.value = 2.0;

        this.staticGain = this.ctx.createGain();
        this.staticGain.gain.value = 0.0; // Silenced at first, adjusted dynamically

        source.connect(filter);
        filter.connect(this.staticGain);
        this.staticGain.connect(this.sfxVolume);

        source.start(0);
        this.staticSource = source;
    }

    setRadioStaticVolume(volume) {
        if (this.staticGain) {
            this.staticGain.gain.setValueAtTime(volume * 0.35, this.ctx.currentTime); // cap at comfortable volume
        }
    }

    stopRadioStatic() {
        if (this.staticSource) {
            try {
                this.staticSource.stop();
            } catch (e) {}
            this.staticSource.disconnect();
            this.staticSource = null;
            this.staticGain = null;
        }
    }

    /**
     * SFX: Generative Sequencer playing C-major / Pentatonic version of classic "Farewell" (送别)
     */
    playRadioMelody() {
        this.init();
        if (!this.ctx || this.isMelodyPlaying) return;
        this.isMelodyPlaying = true;
        
        // Notes for "送别"
        // MIDI notes: 67 (G4), 64 (E4), 67 (G4), 72 (C5), 69 (A4), 72 (C5), 67 (G4)...
        const melody = [
            { note: 67, dur: 0.5 }, { note: 64, dur: 0.5 }, { note: 67, dur: 0.5 }, { note: 72, dur: 1.0 },
            { note: 69, dur: 0.5 }, { note: 72, dur: 0.5 }, { note: 67, dur: 1.5 },
            { note: 67, dur: 0.5 }, { note: 60, dur: 0.5 }, { note: 62, dur: 0.5 }, { note: 64, dur: 1.0 },
            { note: 62, dur: 0.5 }, { note: 60, dur: 0.5 }, { note: 62, dur: 1.5 },
            { note: 67, dur: 0.5 }, { note: 64, dur: 0.5 }, { note: 67, dur: 0.5 }, { note: 72, dur: 1.0 },
            { note: 69, dur: 0.5 }, { note: 72, dur: 0.5 }, { note: 67, dur: 1.5 },
            { note: 67, dur: 0.5 }, { note: 62, dur: 0.5 }, { note: 64, dur: 0.5 }, { note: 60, dur: 2.0 }
        ];

        let accumTime = 0;
        this.melodyTimeouts = [];

        const playNote = (midiNote, startTime, duration) => {
            if (!this.isMelodyPlaying || !this.ctx) return;
            const freq = 440 * Math.pow(2, (midiNote - 69) / 12);
            
            const osc = this.ctx.createOscillator();
            const harmonic = this.ctx.createOscillator();
            const noteGain = this.ctx.createGain();
            const bandpass = this.ctx.createBiquadFilter();

            osc.type = 'triangle';
            osc.frequency.setValueAtTime(freq, startTime);
            
            // Add warmth vibrato
            const vibrato = this.ctx.createOscillator();
            const vibGain = this.ctx.createGain();
            vibrato.frequency.value = 4.5; // 4.5Hz warm sweep
            vibGain.gain.value = freq * 0.005;
            vibrato.connect(vibGain);
            vibGain.connect(osc.frequency);
            vibrato.start(startTime);

            harmonic.type = 'sine';
            harmonic.frequency.setValueAtTime(freq * 2, startTime);
            
            bandpass.type = 'bandpass';
            bandpass.frequency.setValueAtTime(1200, startTime); // radio speaker tinny filter
            bandpass.Q.setValueAtTime(1.5, startTime);

            noteGain.gain.setValueAtTime(0, startTime);
            noteGain.gain.linearRampToValueAtTime(0.18, startTime + 0.05);
            noteGain.gain.exponentialRampToValueAtTime(0.001, startTime + duration);

            osc.connect(bandpass);
            harmonic.connect(bandpass);
            bandpass.connect(noteGain);
            noteGain.connect(this.sfxVolume);

            osc.start(startTime);
            harmonic.start(startTime);
            osc.stop(startTime + duration + 0.1);
            harmonic.stop(startTime + duration + 0.1);
            vibrato.stop(startTime + duration + 0.1);
        };

        const runMelody = () => {
            if (!this.isMelodyPlaying) return;
            accumTime = 0;

            melody.forEach(item => {
                const triggerTime = accumTime;
                const timeout = setTimeout(() => {
                    if (!this.isMelodyPlaying) return;
                    playNote(item.note, this.ctx.currentTime, item.dur * 1.2);
                }, triggerTime * 1000);
                
                this.melodyTimeouts.push(timeout);
                accumTime += item.dur * 1.3; // add slight pause between notes
            });

            // Loop
            const loopTimeout = setTimeout(() => {
                if (this.isMelodyPlaying) {
                    this.clearMelodyTimeouts();
                    runMelody();
                }
            }, accumTime * 1000 + 500);
            this.melodyTimeouts.push(loopTimeout);
        };

        runMelody();
    }

    clearMelodyTimeouts() {
        if (this.melodyTimeouts) {
            this.melodyTimeouts.forEach(t => clearTimeout(t));
            this.melodyTimeouts = [];
        }
    }

    stopRadioMelody() {
        this.isMelodyPlaying = false;
        this.clearMelodyTimeouts();
        this.stopOperaMelody();
        this.stopNewsBroadcast();
    }

    /**
     * SFX: Mechanical camera shutter click-clack (2 stages: click-down and rebound)
     */
    playCameraShutter() {
        this.init();
        if (!this.ctx) return;

        const now = this.ctx.currentTime;
        
        // Stage 1: Shutter Click Down (high freq metallic snap)
        const clickDown = () => {
            const osc = this.ctx.createOscillator();
            const gain = this.ctx.createGain();
            osc.type = 'triangle';
            osc.frequency.setValueAtTime(3200, now);
            osc.frequency.exponentialRampToValueAtTime(100, now + 0.015);
            
            gain.gain.setValueAtTime(0.3, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.015);
            
            osc.connect(gain);
            gain.connect(this.sfxVolume);
            osc.start(now);
            osc.stop(now + 0.02);
        };

        // Stage 2: Mirror Rebound (lower springy clack 0.06 seconds later)
        const clickUp = () => {
            const osc = this.ctx.createOscillator();
            const gain = this.ctx.createGain();
            osc.type = 'sawtooth';
            osc.frequency.setValueAtTime(180, now + 0.06);
            osc.frequency.linearRampToValueAtTime(40, now + 0.12);
            
            gain.gain.setValueAtTime(0, now + 0.06);
            gain.gain.linearRampToValueAtTime(0.15, now + 0.07);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.12);
            
            osc.connect(gain);
            gain.connect(this.sfxVolume);
            osc.start(now + 0.06);
            osc.stop(now + 0.13);
        };

        clickDown();
        clickUp();
    }

    /**
     * SFX: Sewing machine continuous "哒哒哒哒" rhythmic clicking engine
     */
    startSewingLoop() {
        this.init();
        if (!this.ctx || this.sewingInterval) return;

        let isDownBeat = true;
        const tick = () => {
            const now = this.ctx.currentTime;
            
            // Primary needle plunge (louder click)
            const osc = this.ctx.createOscillator();
            const gain = this.ctx.createGain();
            
            osc.type = 'triangle';
            // Alternating pitch for realistic wooden/mechanical gear rocking
            osc.frequency.setValueAtTime(isDownBeat ? 260 : 210, now);
            osc.frequency.exponentialRampToValueAtTime(30, now + 0.035);
            
            gain.gain.setValueAtTime(isDownBeat ? 0.28 : 0.16, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.035);
            
            osc.connect(gain);
            gain.connect(this.sfxVolume);
            
            osc.start(now);
            osc.stop(now + 0.04);
            
            isDownBeat = !isDownBeat;
        };

        // Fire continuous clicks representing needle runs at 145 BPM (approx 410ms intervals)
        this.sewingInterval = setInterval(tick, 135);
    }

    stopSewingLoop() {
        if (this.sewingInterval) {
            clearInterval(this.sewingInterval);
            this.sewingInterval = null;
        }
    }

    /**
     * Web Speech API Synthesis & High-Quality Cloud Fallback for Grandma's voiceovers (智能混血TTS配音引擎)
     */
    speak(text) {
        // Cancel any currently playing Cloud TTS stream
        if (this.currentTtsAudio) {
            try {
                this.currentTtsAudio.pause();
                this.currentTtsAudio = null;
            } catch (e) {}
        }
        
        // Cancel any running local SpeechSynthesis
        if (window.speechSynthesis) {
            window.speechSynthesis.cancel();
        }
        
        // Clean up layout emojis for natural reading flow
        const cleanText = text.replace(/📻|📢|📸|👣|✨|🏬|🕯|🧥/g, '').trim();
        
        // Delay extraction to let the browser cache load voice models
        const voices = window.speechSynthesis ? window.speechSynthesis.getVoices() : [];
        
        let selectedVoice = null;
        let isOnlyRoboticVoice = true; // Flag to identify if we only have Huihui or default robotic system voices
        
        if (voices.length > 0) {
            const premiumMatches = [
                v => v.lang.includes('zh') && v.name.includes('Xiaoxiao'), // Premium emotional female
                v => v.lang.includes('zh') && v.name.includes('Natural'),  // Modern Natural Online voice
                v => v.lang.includes('zh') && v.name.includes('Xiaoyi'),   // Friendly child/female voice
                v => v.lang.includes('zh') && v.name.includes('Google'),   // Google Mandarin
                v => v.lang.includes('zh') && v.name.includes('Tingting'), // Apple High-Quality
                v => v.lang.includes('zh') && v.name.includes('Yaoyao')    // Windows 10/11 natural female offline
            ];
            
            for (const matchFn of premiumMatches) {
                const found = voices.find(matchFn);
                if (found) {
                    selectedVoice = found;
                    isOnlyRoboticVoice = false;
                    break;
                }
            }
            
            // If no premium voice was found, fall back to standard Chinese voices
            if (!selectedVoice) {
                const fallbackZh = voices.find(v => v.lang.includes('zh'));
                if (fallbackZh) {
                    selectedVoice = fallbackZh;
                    // If the voice doesn't have 'Huihui' or 'Desktop' (the ultra-robotic legacy ones), it might be decent
                    if (!fallbackZh.name.includes('Huihui') && !fallbackZh.name.includes('Desktop')) {
                        isOnlyRoboticVoice = false;
                    }
                }
            }
        }
        
        // Dynamic Hybrid Switch:
        // If we are online, and the browser ONLY has the robotic Huihui/legacy voice,
        // we stream Google Translate's highly polished, extremely natural Mandarin female announcer stream!
        if (navigator.onLine && (isOnlyRoboticVoice || !window.speechSynthesis || voices.length === 0)) {
            console.log("Local voice engine is highly robotic (Huihui or empty). Streaming premium online Google Translate narrator...");
            
            const ttsUrl = `https://translate.google.com/translate_tts?ie=UTF-8&tl=zh-CN&client=tw-ob&q=${encodeURIComponent(cleanText)}`;
            
            const audioEl = new Audio(ttsUrl);
            audioEl.volume = 1.0;
            this.currentTtsAudio = audioEl;
            
            audioEl.play().catch(err => {
                console.warn("Google Cloud TTS stream failed to play. Forcing local synthesis fallback:", err);
                this.speakLocally(cleanText, selectedVoice);
            });
        } else {
            console.log("Local voice engine supports high-quality voices. Running local speech synthesis.");
            this.speakLocally(cleanText, selectedVoice);
        }
    }

    speakLocally(cleanText, selectedVoice) {
        if (!window.speechSynthesis) return;
        
        const utterance = new SpeechSynthesisUtterance(cleanText);
        utterance.lang = 'zh-CN';
        
        if (selectedVoice) {
            utterance.voice = selectedVoice;
            
            // If the selected voice is the robotic "Huihui" or generic Windows Offline Desktop,
            // we lower the pitch and rate. This shifts the resonant frequency down,
            // transforming the squeaky metallic robot into a warm, mature, soothing elderly grandma voice!
            if (selectedVoice.name.includes('Huihui') || selectedVoice.name.includes('Desktop') || selectedVoice.name.includes('local') || selectedVoice.name.includes('offline')) {
                utterance.rate = 0.76;  // Slow, comforting maternal pace
                utterance.pitch = 0.78; // Deep, rich, mature grandma tone
            } else {
                utterance.rate = 0.88; 
                utterance.pitch = 1.02; 
            }
        } else {
            // No voice selected (default fallback) - apply grandma filters
            utterance.rate = 0.76; 
            utterance.pitch = 0.78;
        }
        
        utterance.volume = 1.0;
        window.speechSynthesis.speak(utterance);
    }

    stopSpeak() {
        if (this.currentTtsAudio) {
            try {
                this.currentTtsAudio.pause();
                this.currentTtsAudio = null;
            } catch (e) {}
        }
        if (window.speechSynthesis) {
            window.speechSynthesis.cancel();
        }
    }

    /**
     * SFX: Generative Sequencer playing 93.5MHz Traditional Opera / Jasmine Flower melody (昆曲)
     */
    playOperaMelody() {
        this.init();
        if (!this.ctx || this.isOperaPlaying) return;
        this.isOperaPlaying = true;
        
        // Jasmine Flower (茉莉花) notes representing local traditional opera feel
        const melody = [
            { note: 64, dur: 0.5 }, { note: 64, dur: 0.5 }, { note: 67, dur: 0.5 }, { note: 69, dur: 0.5 },
            { note: 72, dur: 0.7 }, { note: 72, dur: 0.3 }, { note: 69, dur: 0.5 }, { note: 67, dur: 1.0 },
            { note: 64, dur: 0.5 }, { note: 67, dur: 0.5 }, { note: 69, dur: 0.5 }, { note: 67, dur: 1.0 },
            { note: 64, dur: 0.5 }, { note: 62, dur: 0.5 }, { note: 60, dur: 1.5 }
        ];

        let accumTime = 0;
        this.operaTimeouts = [];

        const playNote = (midiNote, startTime, duration) => {
            if (!this.isOperaPlaying || !this.ctx) return;
            const freq = 440 * Math.pow(2, (midiNote - 69) / 12);
            
            const osc = this.ctx.createOscillator();
            const gain = this.ctx.createGain();
            const bandpass = this.ctx.createBiquadFilter();

            osc.type = 'sine'; // Pure flutelike traditional tone
            osc.frequency.setValueAtTime(freq, startTime);
            
            bandpass.type = 'bandpass';
            bandpass.frequency.setValueAtTime(1500, startTime);
            bandpass.Q.setValueAtTime(2.5, startTime);

            gain.gain.setValueAtTime(0, startTime);
            gain.gain.linearRampToValueAtTime(0.14, startTime + 0.1);
            gain.gain.exponentialRampToValueAtTime(0.001, startTime + duration);

            osc.connect(bandpass);
            bandpass.connect(gain);
            gain.connect(this.sfxVolume);

            osc.start(startTime);
            osc.stop(startTime + duration + 0.1);
        };

        const runMelody = () => {
            if (!this.isOperaPlaying) return;
            accumTime = 0;

            melody.forEach(item => {
                const triggerTime = accumTime;
                const timeout = setTimeout(() => {
                    if (!this.isOperaPlaying) return;
                    playNote(item.note, this.ctx.currentTime, item.dur * 1.5);
                }, triggerTime * 1000);
                
                this.operaTimeouts.push(timeout);
                accumTime += item.dur * 1.6;
            });

            const loopTimeout = setTimeout(() => {
                if (this.isOperaPlaying) {
                    this.clearOperaTimeouts();
                    runMelody();
                }
            }, accumTime * 1000 + 1000);
            this.operaTimeouts.push(loopTimeout);
        };

        runMelody();
    }

    clearOperaTimeouts() {
        if (this.operaTimeouts) {
            this.operaTimeouts.forEach(t => clearTimeout(t));
            this.operaTimeouts = [];
        }
    }

    stopOperaMelody() {
        this.isOperaPlaying = false;
        this.clearOperaTimeouts();
    }

    /**
     * SFX: Generative Sequencer playing 102.4MHz retro News broadcast time signal (新闻嘀嘀声)
     */
    playNewsBroadcast() {
        this.init();
        if (!this.ctx || this.isNewsPlaying) return;
        this.isNewsPlaying = true;
        
        const runBroadcast = () => {
            if (!this.isNewsPlaying || !this.ctx) return;
            
            const now = this.ctx.currentTime;
            const playBeep = (time, duration, freq = 800) => {
                const osc = this.ctx.createOscillator();
                const gain = this.ctx.createGain();
                const filter = this.ctx.createBiquadFilter();
                
                osc.type = 'sine';
                osc.frequency.setValueAtTime(freq, time);
                
                filter.type = 'bandpass';
                filter.frequency.setValueAtTime(1000, time);
                
                gain.gain.setValueAtTime(0, time);
                gain.gain.linearRampToValueAtTime(0.12, time + 0.01);
                gain.gain.exponentialRampToValueAtTime(0.001, time + duration);
                
                osc.connect(filter);
                filter.connect(gain);
                gain.connect(this.sfxVolume);
                
                osc.start(time);
                osc.stop(time + duration + 0.1);
            };
            
            // Di-di-di-dah! (Time signal beep)
            playBeep(now, 0.08);
            playBeep(now + 0.15, 0.08);
            playBeep(now + 0.3, 0.08);
            playBeep(now + 0.45, 0.35, 1000); // Higher long beep
            
            this.newsTimeout = setTimeout(runBroadcast, 2500);
        };
        
        runBroadcast();
    }

    stopNewsBroadcast() {
        this.isNewsPlaying = false;
        if (this.newsTimeout) {
            clearTimeout(this.newsTimeout);
            this.newsTimeout = null;
        }
    }
}

// Global Audio Instance
const audio = new AudioEngine();

// Pre-load speech synthesis voices for instant, non-robotic emotional voiceovers
if (typeof window !== 'undefined' && window.speechSynthesis) {
    window.speechSynthesis.getVoices();
    if (window.speechSynthesis.onvoiceschanged !== undefined) {
        window.speechSynthesis.onvoiceschanged = () => {
            window.speechSynthesis.getVoices();
        };
    }
}
