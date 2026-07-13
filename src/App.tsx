import { useState } from 'react'
import './App.css'
import scanner from './utils/promptScanner'
import type { ScanResult as LocalScanResult } from './types/risk'
import logo from './assets/promptshield-logo.svg'

function App() {
  const [prompt, setPrompt] = useState('')
  const [result, setResult] = useState<LocalScanResult | null>(null)

  const getRiskClass = (level: string | null | undefined) => {
    if (!level) return 'risk-none'
    if (level.toLowerCase() === 'critical' || level.toLowerCase() === 'high') return 'risk-high'
    if (level.toLowerCase() === 'elevated' || level.toLowerCase() === 'moderate') return 'risk-medium'
    if (level.toLowerCase() === 'low') return 'risk-low'
    return 'risk-none'
  }

  const handleScan = () => {
    const trimmed = prompt.trim()
    if (!trimmed) {
      setResult(null)
      return
    }
    const r = scanner.scanPrompt(trimmed)
    setResult(r)
  }

  const suggestedPrompt = result
    ? `Please assist with the following prompt (sensitive details removed):\n\n${result.redactedText}`
    : ''

  return (
    <div className="app-shell">
      <header className="topbar">
        <img src={logo} alt="PromptShield logo" className="brand-logo" />
      </header>

      <main className="scanner-card">
        <h1>Scan your prompt before submitting it.</h1>
        <p className="subtitle">Review prompt content locally before sharing it with an AI tool.</p>

        <label className="prompt-label" htmlFor="prompt-input">
          Enter prompt
        </label>
        <textarea
          id="prompt-input"
          className="prompt-input"
          placeholder="Paste the prompt you plan to submit…"
          value={prompt}
          onChange={(event) => setPrompt(event.target.value)}
        />

        <div style={{ display: 'flex', gap: 8 }}>
          <button type="button" className="scan-button" onClick={handleScan}>
            Scan Prompt
          </button>
          <button
            type="button"
            className="scan-button secondary"
            onClick={() => {
              setPrompt('')
              setResult(null)
            }}
          >
            Clear
          </button>
        </div>

        <section className="results" aria-live="polite">
          <h2>Scan results</h2>
          {result ? (
            <div className="results-grid">
              <div className="result-item">
                <span className="result-label">Risk score</span>
                <span className="result-value">{result.overallScore}/100</span>
              </div>
              <div className="result-item">
                <span className="result-label">Risk level</span>
                <span className={`result-value ${getRiskClass(result.riskLevel)}`}>{result.riskLevel}</span>
              </div>
              <div className="result-item">
                <span className="result-label">Recommended action</span>
                <span className="result-value">{result.recommendedAction}</span>
              </div>
              <div className="result-item" style={{ gridColumn: '1 / -1' }}>
                <span className="result-label">Redacted prompt</span>
                <div className="result-value" style={{ whiteSpace: 'pre-wrap' }}>{result.redactedText}</div>
              </div>
              <div className="result-item" style={{ gridColumn: '1 / -1' }}>
                <span className="result-label">Findings</span>
                <div className="result-value">
                  {result.findings.length === 0 ? (
                    'None'
                  ) : (
                    <ul>
                      {result.findings.map((f) => (
                        <li key={f.id}>
                          <strong>{f.categoryName}</strong>: {f.findingType} — {f.explanation} — {f.redactedValue}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>

              <div className="result-item" style={{ gridColumn: '1 / -1' }}>
                <span className="result-label">Suggested safe prompt</span>
                <div className="result-value">
                  {suggestedPrompt ? (
                    <>
                      <div style={{ whiteSpace: 'pre-wrap' }}>{suggestedPrompt}</div>
                      <div style={{ marginTop: 8 }}>
                        <button
                          type="button"
                          className="scan-button"
                          onClick={() => setPrompt(suggestedPrompt)}
                        >
                          Use suggested prompt
                        </button>
                      </div>
                    </>
                  ) : (
                    'No suggestion available'
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="results-grid">
              <div className="result-item">
                <span className="result-label">Status</span>
                <span className="result-value">Not scanned yet</span>
              </div>
            </div>
          )}
        </section>

        <p className="privacy-notice">Submitted text is not stored. This preview runs locally in your browser.</p>
      </main>
    </div>
  )
}

export default App
