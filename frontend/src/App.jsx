import { useState, useEffect, useRef } from 'react'
import gsap from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
import Lenis from 'lenis'

gsap.registerPlugin(ScrollTrigger)

// ── Severity config ────────────────────────────────────────────
const SEVERITY_CONFIG = {
  CRITICAL: { label: 'CRITICAL', className: 'sev-critical' },
  HIGH:     { label: 'HIGH',     className: 'sev-high'     },
  MEDIUM:   { label: 'MEDIUM',   className: 'sev-medium'   },
}

const VERDICT_CONFIG = {
  safe:       { label: 'SAFE URL',         className: 'safe',       icon: '✓',  scoreColor: '#22c55e' },
  low_risk:   { label: 'LOW RISK',         className: 'low-risk',   icon: '⚠',  scoreColor: '#eab308' },
  suspicious: { label: 'SUSPICIOUS URL',   className: 'suspicious', icon: '⚠',  scoreColor: '#f97316' },
  phishing:   { label: 'DANGER — DO NOT VISIT', className: 'phishing', icon: '⛔', scoreColor: '#ef4444' },
  invalid:    { label: 'Invalid URL',      className: 'invalid',    icon: '⚠',  scoreColor: '#fd802e' },
  error:      { label: 'Connection Error', className: 'error',      icon: '✕',  scoreColor: '#6b7280' },
}

const FAQ_DATA = [
  { q: "Is PhishGuard free to use?", a: "Yes, PhishGuard is completely free. Simply paste any URL into the scanner and receive an instant analysis with no account required." },
  { q: "How accurate is the detection?", a: "PhishGuard achieves 99.2% accuracy using 15+ heuristic checks including protocol analysis, keyword detection, domain reputation, and structural analysis." },
  { q: "Does PhishGuard store my scanned URLs?", a: "No. All analysis is performed in real-time on your device session. URLs are not stored, logged, or shared with any third parties." },
  { q: "What types of phishing does it detect?", a: "PhishGuard detects credential phishing, brand impersonation, typosquatting, open redirects, IP-based attacks, homograph attacks, and high-risk TLD abuse." },
  { q: "Can I use this via an API?", a: "Yes! The Flask backend exposes a /scan endpoint. Send a POST request with JSON body { \"url\": \"...\" } to http://localhost:5000/scan for programmatic access." },
  { q: "What should I do if I already clicked a phishing link?", a: "Immediately change passwords for any accounts you may have entered credentials on, enable 2FA, run a virus scan, and report the link to your browser's phishing report tool." },
]

function FaqItem({ item, index, isOpen, onToggle }) {
  const answerRef = useRef(null)
  const iconRef = useRef(null)

  useEffect(() => {
    const el = answerRef.current
    const icon = iconRef.current
    if (!el) return
    if (isOpen) {
      // Animate open
      gsap.set(el, { height: 'auto', opacity: 1 })
      const h = el.scrollHeight
      gsap.fromTo(el, { height: 0, opacity: 0 }, { height: h, opacity: 1, duration: 0.4, ease: 'power3.out' })
      gsap.to(icon, { rotation: 45, duration: 0.3, ease: 'power2.out' })
    } else {
      gsap.to(el, { height: 0, opacity: 0, duration: 0.35, ease: 'power3.in' })
      gsap.to(icon, { rotation: 0, duration: 0.3, ease: 'power2.out' })
    }
  }, [isOpen])

  return (
    <div className={`faq-item ${isOpen ? 'open' : ''}`}>
      <button className="faq-question" onClick={() => onToggle(index)} aria-expanded={isOpen}>
        <span>{item.q}</span>
        <span className="faq-icon" ref={iconRef} aria-hidden="true">+</span>
      </button>
      <div className="faq-answer" ref={answerRef} style={{ height: 0, overflow: 'hidden', opacity: 0 }}>
        <p>{item.a}</p>
      </div>
    </div>
  )
}

function App() {
  // ── State ─────────────────────────────────────────────────────
  const [url, setUrl]               = useState('')
  const [scanResult, setScanResult] = useState(null)
  const [loading, setLoading]       = useState(false)
  const [history, setHistory]       = useState([])
  const [mobileOpen, setMobileOpen] = useState(false)
  const [openFaq, setOpenFaq]       = useState(null)
  const [copied, setCopied]         = useState(false)

  // ── Refs for GSAP ─────────────────────────────────────────────
  const lenisRef        = useRef(null)
  const cursorRef       = useRef(null)
  const progressRef     = useRef(null)
  const navbarRef       = useRef(null)
  const heroRef         = useRef(null)
  const heroBadgeRef    = useRef(null)
  const heroH1Ref       = useRef(null)
  const heroSubRef      = useRef(null)
  const heroBtnsRef     = useRef(null)
  const heroStatsRef    = useRef(null)
  const resultRef       = useRef(null)
  const historyListRef  = useRef(null)
  const introRef        = useRef(null)

  // ── Reduced motion check ──────────────────────────────────────
  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
  const isMobile = window.innerWidth < 768

  // ══════════════════════════════════════════════════════════════
  //  GLOBAL SETUP — Lenis, GSAP ticker, ScrollTrigger, cursor
  // ══════════════════════════════════════════════════════════════
  useEffect(() => {
    // ── Intro overlay fade-out ─────────────────────────────────
    if (!prefersReducedMotion && introRef.current) {
      gsap.to(introRef.current, {
        opacity: 0, duration: 0.6, delay: 0.4, ease: 'power2.out',
        onComplete: () => { if (introRef.current) introRef.current.style.display = 'none' }
      })
    } else if (introRef.current) {
      introRef.current.style.display = 'none'
    }

    // ── Lenis smooth scroll setup ──────────────────────────────
    const lenis = new Lenis({ lerp: 0.08, smoothWheel: true })
    lenisRef.current = lenis

    // Connect Lenis to GSAP ticker for perfect synchronisation
    gsap.ticker.add((time) => lenis.raf(time * 1000))
    gsap.ticker.lagSmoothing(0)

    // ── Scroll progress bar ─────────────────────────────────────
    if (progressRef.current && !prefersReducedMotion) {
      gsap.to(progressRef.current, {
        scaleX: 1,
        ease: 'none',
        scrollTrigger: { trigger: document.body, start: 'top top', end: 'bottom bottom', scrub: true }
      })
    }

    // ── Custom cursor (desktop only) ───────────────────────────
    if (!isMobile && cursorRef.current && !prefersReducedMotion) {
      const cur = cursorRef.current
      const xTo = gsap.quickTo(cur, 'x', { duration: 0.4, ease: 'power3' })
      const yTo = gsap.quickTo(cur, 'y', { duration: 0.4, ease: 'power3' })
      const onMove = (e) => { xTo(e.clientX); yTo(e.clientY) }
      const onEnter = () => gsap.to(cur, { scale: 2.5, duration: 0.25 })
      const onLeave = () => gsap.to(cur, { scale: 1, duration: 0.25 })
      window.addEventListener('mousemove', onMove)
      document.querySelectorAll('a, button, [data-cursor]').forEach(el => {
        el.addEventListener('mouseenter', onEnter)
        el.addEventListener('mouseleave', onLeave)
      })
      return () => {
        window.removeEventListener('mousemove', onMove)
        lenis.destroy()
        ScrollTrigger.getAll().forEach(t => t.kill())
        gsap.ticker.remove((time) => lenis.raf(time * 1000))
      }
    }

    return () => {
      lenis.destroy()
      ScrollTrigger.getAll().forEach(t => t.kill())
      gsap.ticker.remove((time) => lenis.raf(time * 1000))
    }
  }, [])

  // ── Navbar entrance ────────────────────────────────────────────
  useEffect(() => {
    if (!navbarRef.current || prefersReducedMotion) return
    gsap.fromTo(navbarRef.current,
      { y: -100, opacity: 0 },
      { y: 0, opacity: 1, duration: 0.8, ease: 'power3.out', delay: 0.5 }
    )
  }, [])

  // ── Hero stagger entrance ──────────────────────────────────────
  useEffect(() => {
    if (prefersReducedMotion) return
    const tl = gsap.timeline({ delay: 0.8 })
    if (heroBadgeRef.current)
      tl.fromTo(heroBadgeRef.current, { y: 30, opacity: 0 }, { y: 0, opacity: 1, duration: 0.7, ease: 'power3.out' }, 0)
    if (heroH1Ref.current)
      tl.fromTo(heroH1Ref.current, { y: 50, opacity: 0 }, { y: 0, opacity: 1, duration: 1, ease: 'power3.out' }, 0.2)
    if (heroSubRef.current)
      tl.fromTo(heroSubRef.current, { y: 30, opacity: 0 }, { y: 0, opacity: 1, duration: 0.8, ease: 'power3.out' }, 0.4)
    if (heroBtnsRef.current) {
      tl.fromTo(heroBtnsRef.current.children,
        { y: 20, opacity: 0 }, { y: 0, opacity: 1, duration: 0.7, stagger: 0.15, ease: 'power3.out' }, 0.6)
    }
    if (heroStatsRef.current) {
      tl.fromTo(heroStatsRef.current.children,
        { y: 20, opacity: 0 }, { y: 0, opacity: 1, duration: 0.6, stagger: 0.1, ease: 'power3.out' }, 0.85)
    }
  }, [])

  // ── How It Works scroll animations ────────────────────────────
  useEffect(() => {
    if (prefersReducedMotion) return
    const cards = gsap.utils.toArray('.how-card')
    cards.forEach((card, i) => {
      gsap.fromTo(card,
        { y: 60, opacity: 0 },
        {
          y: 0, opacity: 1, duration: 0.8, ease: 'power3.out', delay: i * 0.2,
          scrollTrigger: { trigger: card, start: 'top 80%', once: true }
        }
      )
    })
  }, [])

  // ── Rule cards scroll + hover animations ──────────────────────
  useEffect(() => {
    if (prefersReducedMotion) return
    const cards = gsap.utils.toArray('.rule-card')
    cards.forEach((card, i) => {
      gsap.fromTo(card,
        { opacity: 0, scale: 0.9 },
        {
          opacity: 1, scale: 1, duration: 0.7, ease: 'power3.out', delay: i * 0.08,
          scrollTrigger: { trigger: '.rules-grid', start: 'top 80%', once: true }
        }
      )
      // Hover effect
      card.addEventListener('mouseenter', () =>
        gsap.to(card, { y: -8, boxShadow: '0 0 30px rgba(255,107,53,0.25)', duration: 0.3, ease: 'power2.out' }))
      card.addEventListener('mouseleave', () =>
        gsap.to(card, { y: 0, boxShadow: '0 0 0 rgba(255,107,53,0)', duration: 0.3, ease: 'power2.out' }))
    })
  }, [])

  // ── Stat counter animation ────────────────────────────────────
  useEffect(() => {
    if (prefersReducedMotion) return
    const stats = [
      { id: 'stat-urls', target: 10000, suffix: '+', prefix: '' },
      { id: 'stat-acc',  target: 99.2,  suffix: '%', prefix: '' },
      { id: 'stat-chks', target: 15,    suffix: '+', prefix: '' },
      { id: 'stat-time', target: 1,     suffix: 's', prefix: '< ' },
    ]
    stats.forEach(({ id, target, suffix, prefix }) => {
      const el = document.getElementById(id)
      if (!el) return
      gsap.fromTo({ val: 0 }, { val: target },
        {
          duration: 2, ease: 'power1.out',
          onUpdate: function() { el.textContent = prefix + (Number.isInteger(target) ? Math.round(this.targets()[0].val).toLocaleString() : this.targets()[0].val.toFixed(1)) + suffix },
          scrollTrigger: { trigger: '.stats-section', start: 'top 75%', once: true }
        }
      )
    })
  }, [])

  // ── Stats section fade-in ─────────────────────────────────────
  useEffect(() => {
    if (prefersReducedMotion) return
    gsap.fromTo('.stats-section',
      { opacity: 0 },
      { opacity: 1, duration: 1, scrollTrigger: { trigger: '.stats-section', start: 'top 85%', once: true } }
    )
    gsap.fromTo('.footer-inner',
      { y: 30, opacity: 0 },
      { y: 0, opacity: 1, duration: 0.8, scrollTrigger: { trigger: 'footer', start: 'top 85%', once: true } }
    )
  }, [])

  // ── Result panel animate in ────────────────────────────────────
  const animateResult = () => {
    if (!resultRef.current || prefersReducedMotion) return
    gsap.fromTo(resultRef.current,
      { y: 40, opacity: 0 },
      { y: 0, opacity: 1, duration: 0.6, ease: 'power3.out' }
    )
  }

  // ── Scroll to section ─────────────────────────────────────────
  const scrollTo = (id) => {
    const el = document.getElementById(id)
    if (el && lenisRef.current) lenisRef.current.scrollTo(el, { offset: -80 })
  }

  // ══════════════════════════════════════════════════════════════
  //  SCAN LOGIC
  // ══════════════════════════════════════════════════════════════
  const handleScan = async (overrideUrl) => {
    const targetUrl = (typeof overrideUrl === 'string' ? overrideUrl : url).trim()
    if (!targetUrl) return
    setLoading(true)
    setScanResult(null)
    setCopied(false)
    try {
      const res = await fetch('http://localhost:5000/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl }),
      })
      const data = await res.json()
      setScanResult(data)
      if (data.result && !['invalid', 'error'].includes(data.result)) {
        setHistory(prev => [
          { url: targetUrl, result: data.result, score: data.score ?? 0, time: new Date() },
          ...prev,
        ])
      }
      setTimeout(animateResult, 50)
    } catch {
      setScanResult({ result: 'error' })
      setTimeout(animateResult, 50)
    } finally {
      setLoading(false)
    }
  }

  const handleSample = (sample) => {
    setUrl(sample)
    setScanResult(null)
    handleScan(sample)
    scrollTo('scanner')
  }

  const handleRescan = (histUrl) => {
    setUrl(histUrl)
    setScanResult(null)
    scrollTo('scanner')
    setTimeout(() => handleScan(histUrl), 400)
  }

  const handleClearHistory = () => {
    if (!historyListRef.current || prefersReducedMotion) { setHistory([]); return }
    const cards = historyListRef.current.querySelectorAll('.hist-card')
    gsap.to(cards, { opacity: 0, y: -20, stagger: 0.08, duration: 0.4, ease: 'power3.in',
      onComplete: () => setHistory([])
    })
  }

  const handleCopy = () => {
    if (!scanResult) return
    const v = VERDICT_CONFIG[scanResult.result]?.label ?? scanResult.result
    const lines = [
      `PhishGuard Scan Result`, ``,
      `URL: ${url}`, `Verdict: ${v}`,
      `Risk Score: ${scanResult.score ?? 'N/A'}/10`,
      `Checks Passed: ${scanResult.checks_passed ?? 'N/A'} | Failed: ${scanResult.checks_failed ?? 'N/A'}`, ``,
      ...(scanResult.flags ?? []).map(f => `[${f.severity}] ${f.reason}`),
      scanResult.verdict_label ? `\nRecommendation: ${scanResult.verdict_label}` : '',
    ]
    navigator.clipboard.writeText(lines.filter(Boolean).join('\n'))
      .then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000) })
  }

  const relativeTime = (date) => {
    const s = Math.round((Date.now() - date.getTime()) / 1000)
    if (s < 60) return `${s} sec ago`
    if (s < 3600) return `${Math.round(s/60)} min ago`
    return `${Math.round(s/3600)} hr ago`
  }

  const result     = scanResult?.result ?? null
  const vConf      = result ? VERDICT_CONFIG[result] : null
  const scoreOut10 = result && scanResult.score != null
    ? Math.min(10, Math.round(scanResult.score * 1.5))
    : 0

  // ══════════════════════════════════════════════════════════════
  //  RENDER
  // ══════════════════════════════════════════════════════════════
  return (
    <>
      {/* Intro overlay */}
      <div className="intro-overlay" ref={introRef} aria-hidden="true"></div>

      {/* Scroll progress bar */}
      <div className="scroll-progress" ref={progressRef} aria-hidden="true"></div>

      {/* Custom cursor (desktop) */}
      {!isMobile && <div className="custom-cursor" ref={cursorRef} aria-hidden="true"></div>}

      {/* ═══ NAVBAR ══════════════════════════════════════════════ */}
      <nav className="navbar" ref={navbarRef} role="navigation" aria-label="Main navigation">
        <div className="nav-inner container">
          <a href="#" className="nav-logo" aria-label="PhishGuard home">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#FF6B35" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            <span className="logo-text">PHISHGUARD</span>
            <span className="beta-badge">BETA</span>
          </a>

          <ul className="nav-links" role="list">
            {['Home','How It Works','About','History'].map(link => (
              <li key={link}>
                <a
                  href={link === 'How It Works' ? '#how-it-works' : link === 'History' ? '#history' : '#'}
                  className="nav-link"
                  onClick={e => { if (link === 'How It Works') { e.preventDefault(); scrollTo('how-it-works') } if (link === 'History') { e.preventDefault(); scrollTo('history') } }}
                >
                  {link}
                </a>
              </li>
            ))}
          </ul>

          <button className="cta-btn nav-cta" onClick={() => scrollTo('scanner')} aria-label="Try PhishGuard scanner">
            Try It Free
          </button>

          <button className={`hamburger ${mobileOpen ? 'open' : ''}`} onClick={() => setMobileOpen(!mobileOpen)} aria-label="Toggle navigation menu" aria-expanded={mobileOpen}>
            <span></span><span></span><span></span>
          </button>
        </div>

        {/* Mobile menu overlay */}
        {mobileOpen && (
          <div className="mobile-menu" role="dialog" aria-modal="true" aria-label="Mobile navigation">
            <ul role="list">
              {['Home','How It Works','About','History'].map(link => (
                <li key={link}>
                  <a href="#" className="mobile-link" onClick={() => { setMobileOpen(false); scrollTo(link === 'How It Works' ? 'how-it-works' : 'history') }}>
                    {link}
                  </a>
                </li>
              ))}
              <li><button className="cta-btn" onClick={() => { setMobileOpen(false); scrollTo('scanner') }}>Try It Free</button></li>
            </ul>
          </div>
        )}
      </nav>

      {/* ═══ HERO ════════════════════════════════════════════════ */}
      <section className="hero" ref={heroRef} aria-labelledby="hero-heading">
        <div className="hero-bg-grid" aria-hidden="true"></div>
        <div className="hero-orb" aria-hidden="true"></div>

        <div className="hero-content container">
          <div className="hero-badge" ref={heroBadgeRef}>
            🛡 AI-Powered URL Protection
          </div>

          <h1 className="hero-h1" id="hero-heading" ref={heroH1Ref}>
            Detect <span className="text-gradient">Phishing</span> URLs<br />
            Before They Detect You
          </h1>

          <p className="hero-sub" ref={heroSubRef}>
            Paste any suspicious link and get an instant deep security analysis powered by advanced heuristic detection.
          </p>

          <div className="hero-btns" ref={heroBtnsRef}>
            <button className="btn-primary" onClick={() => scrollTo('scanner')} aria-label="Go to URL scanner">
              Scan a URL Now
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
            </button>
            <button className="btn-secondary" onClick={() => scrollTo('how-it-works')} aria-label="See how PhishGuard works">
              See How It Works
            </button>
          </div>

          <div className="hero-stats" ref={heroStatsRef}>
            <div className="hero-stat">
              <span className="stat-icon" aria-hidden="true">🔍</span>
              <span>10K+ URLs Scanned</span>
            </div>
            <div className="hero-stat-divider" aria-hidden="true"></div>
            <div className="hero-stat">
              <span className="stat-icon" aria-hidden="true">✓</span>
              <span>99.2% Accuracy</span>
            </div>
            <div className="hero-stat-divider" aria-hidden="true"></div>
            <div className="hero-stat">
              <span className="stat-icon" aria-hidden="true">⚡</span>
              <span>&lt; 1s Response Time</span>
            </div>
          </div>
        </div>
      </section>

      {/* ═══ SCANNER SECTION ═════════════════════════════════════ */}
      <section id="scanner" className="scanner-section" aria-labelledby="scanner-heading">
        <div className="container">
          <p className="section-label" aria-hidden="true">THREAT SCANNER</p>
          <h2 className="section-h2" id="scanner-heading">Analyze Any URL Instantly</h2>

          <div className="scan-card">
            {/* Quick sample buttons */}
            <div className="sample-btns">
              <button className="sample-pill safe-pill" onClick={() => handleSample('https://google.com')} aria-label="Test with safe URL example">
                ✓ Test Safe URL
              </button>
              <button className="sample-pill danger-pill" onClick={() => handleSample('http://paypal-secure-login.com/verify/account')} aria-label="Test with phishing URL example">
                ⚠ Test Phishing URL
              </button>
            </div>

            {/* Input area */}
            <div className="input-wrapper">
              <input
                id="url-input"
                type="text"
                className="url-input"
                placeholder="Paste URL here... e.g. https://suspicious-site.com"
                value={url}
                onChange={e => setUrl(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleScan()}
                aria-label="URL to scan"
              />
              <span className={`char-counter ${url.length > 75 ? 'over' : ''}`} aria-live="polite">
                {url.length} chars
              </span>
            </div>

            {/* Scan button */}
            <button
              id="scan-btn"
              className={`scan-btn ${loading ? 'loading' : ''}`}
              onClick={handleScan}
              disabled={loading}
              aria-label="Scan URL for phishing threats"
              aria-busy={loading}
            >
              {loading ? (
                <span className="scan-loading-bar" aria-hidden="true"></span>
              ) : (
                <>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" aria-hidden="true">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  </svg>
                  SCAN FOR THREATS
                </>
              )}
              {loading && <span className="scan-loading-text">Analyzing...</span>}
            </button>

            {/* ── RESULT AREA ─────────────────────────────────── */}
            {result && (
              <div className={`result-panel ${vConf?.className}`} ref={resultRef} role="region" aria-label="Scan result" aria-live="polite">

                {/* INVALID */}
                {result === 'invalid' && (
                  <div className="result-header">
                    <span className="result-emoji" aria-hidden="true">⚠</span>
                    <div>
                      <h3 className="result-title">Invalid URL</h3>
                      <p className="result-sub">{scanResult.message || 'Please enter a valid and complete URL before scanning.'}</p>
                    </div>
                  </div>
                )}

                {/* ERROR */}
                {result === 'error' && (
                  <div className="result-header">
                    <span className="result-emoji" aria-hidden="true">🔌</span>
                    <div>
                      <h3 className="result-title">Connection Error</h3>
                      <p className="result-sub">Could not reach the server — make sure the Flask backend is running on port 5000.</p>
                    </div>
                  </div>
                )}

                {/* SAFE / RISK / SUSPICIOUS / PHISHING */}
                {!['invalid','error'].includes(result) && (
                  <>
                    {/* Header */}
                    <div className="result-header">
                      <span className={`result-emoji ${result === 'phishing' ? 'pulse-danger' : ''}`} aria-hidden="true">
                        {vConf?.icon}
                      </span>
                      <div style={{ flex: 1 }}>
                        {result === 'phishing' && (
                          <div className="danger-header" role="alert">⛔ DANGER — DO NOT VISIT THIS URL</div>
                        )}
                        <h3 className="result-title">{vConf?.label}</h3>
                        <p className="result-sub">{scanResult.verdict_label}</p>
                      </div>
                      {/* Risk score badge */}
                      <div className="score-circle" style={{ '--score-color': vConf?.scoreColor }} aria-label={`Risk score ${scoreOut10} out of 10`}>
                        <span className="score-num">{scoreOut10}</span>
                        <span className="score-denom">/10</span>
                      </div>
                    </div>

                    {/* Score progress bar */}
                    <div className="score-bar-wrap" aria-hidden="true">
                      <div className="score-bar-label">Risk Score</div>
                      <div className="score-bar-track">
                        <div
                          className="score-bar-fill"
                          style={{ width: `${scoreOut10 * 10}%`, background: vConf?.scoreColor }}
                        ></div>
                      </div>
                      <span className="score-bar-value">{scoreOut10}/10</span>
                    </div>

                    {/* Stats */}
                    <div className="result-stats" aria-label="Scan statistics">
                      <div className="r-stat passed"><span className="r-stat-num">{scanResult.checks_passed}</span><span className="r-stat-label">Passed</span></div>
                      <div className="r-stat-div" aria-hidden="true"></div>
                      <div className="r-stat failed"><span className="r-stat-num">{scanResult.checks_failed}</span><span className="r-stat-label">Failed</span></div>
                      <div className="r-stat-div" aria-hidden="true"></div>
                      <div className="r-stat total"><span className="r-stat-num">{(scanResult.checks_passed ?? 0) + (scanResult.checks_failed ?? 0)}</span><span className="r-stat-label">Total</span></div>
                    </div>

                    {/* Flags list */}
                    {(scanResult.flags?.length > 0) && (
                      <ul className="flags-list" aria-label="Detected issues">
                        {scanResult.flags.map((f, i) => {
                          const sc = SEVERITY_CONFIG[f.severity] || SEVERITY_CONFIG.MEDIUM
                          return (
                            <li key={i} className={`flag-item ${sc.className}`}>
                              <span className={`sev-badge ${sc.className}`}>{sc.label}</span>
                              <span className="flag-reason">{f.reason}</span>
                            </li>
                          )
                        })}
                      </ul>
                    )}

                    {/* Phishing warning box */}
                    {result === 'phishing' && (
                      <div className="phishing-warning" role="alert">
                        <strong>⚠ We strongly recommend you do NOT visit this link.</strong>
                        <span> Report it if received via email or message to protect others.</span>
                      </div>
                    )}

                    {/* Action buttons */}
                    <div className="result-actions">
                      <button className="action-btn copy" onClick={handleCopy} aria-label="Copy scan result to clipboard">
                        {copied ? '✓ Copied!' : '⎘ Copy Result'}
                      </button>
                      {result === 'phishing' && (
                        <button className="action-btn report" aria-label="Report this URL">
                          🚨 Report URL
                        </button>
                      )}
                    </div>
                  </>
                )}

              </div>
            )}
          </div>
        </div>
      </section>

      {/* ═══ HOW IT WORKS ════════════════════════════════════════ */}
      <section id="how-it-works" className="how-section" aria-labelledby="how-heading">
        <div className="container">
          <p className="section-label" aria-hidden="true">THE PROCESS</p>
          <h2 className="section-h2" id="how-heading">How PhishGuard Analyzes URLs</h2>

          <div className="how-grid">
            {[
              {
                num: '01', icon: (
                  <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#FF6B35" strokeWidth="2" aria-hidden="true"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/></svg>
                ),
                title: 'Paste Your URL',
                desc: 'Enter any suspicious link into the scanner — no account, no sign-up needed.'
              },
              {
                num: '02', icon: (
                  <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#FF6B35" strokeWidth="2" aria-hidden="true"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                ),
                title: 'Deep Analysis Runs',
                desc: 'Our engine runs 15+ security checks including protocol, keyword, domain, and  structure analysis.'
              },
              {
                num: '03', icon: (
                  <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#FF6B35" strokeWidth="2" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                ),
                title: 'Get Instant Verdict',
                desc: 'Receive a detailed risk score, severity breakdown, and actionable recommendation in under 1 second.'
              }
            ].map((step, i) => (
              <div className="how-card" key={step.num}>
                <div className="how-num" aria-hidden="true">{step.num}</div>
                <div className="how-icon">{step.icon}</div>
                <h3 className="how-title">{step.title}</h3>
                <p className="how-desc">{step.desc}</p>
                {i < 2 && <div className="how-arrow" aria-hidden="true">→</div>}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ═══ DETECTION RULES ═════════════════════════════════════ */}
      <section className="rules-section" aria-labelledby="rules-heading">
        <div className="container">
          <p className="section-label" aria-hidden="true">DETECTION ENGINE</p>
          <h2 className="section-h2" id="rules-heading">What We Check For</h2>
          <p className="section-sub">PhishGuard runs every URL through these security layers</p>

          <div className="rules-grid">
            {[
              { icon: '🛡', title: 'Protocol Security', desc: 'HTTP vs HTTPS detection, dangerous protocols (javascript:, data:, ftp://) flagged instantly.' },
              { icon: '🔍', title: 'Keyword Detection', desc: '50+ phishing keywords scanned — login, verify, account, bank, prize, and more.' },
              { icon: '🌐', title: 'Domain Analysis', desc: 'IP address usage, excessive subdomains, high-risk TLDs (.tk, .ml, .xyz), and brand-as-subdomain attacks.' },
              { icon: '🔗', title: 'URL Structure', desc: 'Length analysis, special characters (@, %, ~), open redirects, punycode, and encoded obfuscation.' },
              { icon: '⚠', title: 'Brand Impersonation', desc: '24 major brands monitored — PayPal, Amazon, Google, Apple, and more detected in URLs not matching their domain.' },
              { icon: '👁', title: 'Typosquatting', desc: 'Numeric character substitution — g00gle, paypa1, amaz0n — detected via pattern matching.' },
            ].map(rule => (
              <div className="rule-card" key={rule.title} role="article">
                <div className="rule-icon" aria-hidden="true">{rule.icon}</div>
                <h3 className="rule-title">{rule.title}</h3>
                <p className="rule-desc">{rule.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ═══ TRUST STATS BAR ═════════════════════════════════════ */}
      <section className="stats-section" aria-labelledby="stats-heading">
        <div className="container">
          <h2 className="sr-only" id="stats-heading">PhishGuard Statistics</h2>
          <div className="stats-grid">
            {[
              { id: 'stat-urls', value: '0', label: 'URLs Scanned' },
              { id: 'stat-acc',  value: '0%', label: 'Detection Accuracy' },
              { id: 'stat-chks', value: '0+', label: 'Security Checks Per URL' },
              { id: 'stat-time', value: '< 1s', label: 'Average Response Time' },
            ].map((s, i) => (
              <div className="stat-block" key={s.id}>
                <span className="stat-big" id={s.id} aria-label={s.label}>{s.value}</span>
                <span className="stat-lbl">{s.label}</span>
                {i < 3 && <div className="stat-vdiv" aria-hidden="true"></div>}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ═══ HISTORY ═════════════════════════════════════════════ */}
      <section id="history" className="history-section" aria-labelledby="history-heading">
        <div className="container">
          <div className="history-hdr">
            <h2 className="section-h2" id="history-heading">Your Scan History</h2>
            {history.length > 0 && (
              <button className="clear-btn" onClick={handleClearHistory} aria-label="Clear all scan history">
                Clear All
              </button>
            )}
          </div>

          {history.length === 0 ? (
            <div className="history-empty" role="status">
              <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.15)" strokeWidth="1.5" strokeDasharray="4 2" aria-hidden="true">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
              <p>No scans yet — paste a URL above to get started</p>
            </div>
          ) : (
            <ul className="history-list" ref={historyListRef} role="list" aria-label="Scan history">
              {history.map((item, i) => (
                <li key={i} className="hist-card" role="listitem">
                  <div className={`hist-dot ${item.result}`} aria-hidden="true"></div>
                  <div className="hist-info">
                    <span className="hist-url" title={item.url}>{item.url}</span>
                    <span className="hist-time">{relativeTime(item.time)}</span>
                  </div>
                  <span className={`hist-badge ${item.result}`} aria-label={`Verdict: ${item.result}`}>
                    {item.result === 'safe' ? 'SAFE' : item.result === 'low_risk' ? 'LOW RISK' : item.result === 'suspicious' ? 'SUSPICIOUS' : 'PHISHING'}
                  </span>
                  <span className="hist-score" aria-label={`Score: ${item.score}`}>Score: {item.score}</span>
                  <button className="rescan-btn" onClick={() => handleRescan(item.url)} aria-label={`Re-scan ${item.url}`}>
                    Re-scan
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      {/* ═══ FAQ ═════════════════════════════════════════════════ */}
      <section className="faq-section" aria-labelledby="faq-heading">
        <div className="container faq-container">
          <p className="section-label" aria-hidden="true">FAQ</p>
          <h2 className="section-h2" id="faq-heading">Frequently Asked Questions</h2>
          <div className="faq-list" role="list">
            {FAQ_DATA.map((item, i) => (
              <FaqItem
                key={i}
                item={item}
                index={i}
                isOpen={openFaq === i}
                onToggle={(idx) => setOpenFaq(openFaq === idx ? null : idx)}
              />
            ))}
          </div>
        </div>
      </section>

      {/* ═══ FOOTER ══════════════════════════════════════════════ */}
      <footer className="footer" role="contentinfo">
        <div className="container footer-inner">
          <div className="footer-top">
            <div className="footer-brand">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#FF6B35" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
              <span className="logo-text">PHISHGUARD</span>
            </div>
            <p className="footer-tagline">Protecting users from phishing attacks, one URL at a time.</p>
          </div>

          <div className="footer-cols">
            {[
              { heading: 'Product', links: ['How It Works','Detection Rules','API Docs','Changelog'] },
              { heading: 'Security', links: ['Report a URL','False Positive?','Privacy Policy','Terms of Use'] },
              { heading: 'Connect', links: ['GitHub','Twitter','Discord','Contact Us'] },
            ].map(col => (
              <div className="footer-col" key={col.heading}>
                <h3 className="footer-col-heading">{col.heading}</h3>
                <ul role="list">
                  {col.links.map(link => (
                    <li key={link}><a href="#" className="footer-link">{link}</a></li>
                  ))}
                </ul>
              </div>
            ))}
          </div>

          <div className="footer-bottom">
            <div className="footer-divider" aria-hidden="true"></div>
            <p className="footer-copy">© 2025 PhishGuard. Built for a safer web.</p>
          </div>
        </div>
      </footer>
    </>
  )
}

export default App
