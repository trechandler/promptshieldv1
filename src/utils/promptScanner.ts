import riskCategories from '../data/riskCategories'
import type { Finding, ScanResult } from '../types/risk'

type Detector = (text: string) => Finding[]

function makeFinding(
  categoryId: string,
  findingType: string,
  matchedText: string,
  startIndex: number,
  endIndex: number,
  baseScoreOverride?: number,
  explanation?: string,
): Finding {
  const category = riskCategories.find((c) => c.id === categoryId)!
  const base = baseScoreOverride ?? category.baseScore
  return {
    id: `${categoryId}:${startIndex}-${endIndex}`,
    categoryId,
    categoryName: category.name,
    findingType,
    matchedText,
    redactedValue: '[REDACTED]',
    startIndex,
    endIndex,
    baseScore: base,
    finalScore: base,
    explanation,
  }
}

// Simple detectors
const detectors: Detector[] = [
  // Email addresses
  (text) => {
    const re = /\b([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})\b/gi
    const out: Finding[] = []
    let m
    // Distinguish work vs personal by domain hint (heuristic)
    while ((m = re.exec(text))) {
      const start = m.index
      const end = re.lastIndex
      const domain = (m[1].split('@')[1] || '').toLowerCase()
      const isWork = /company|corp|inc|llc|org|edu|gov|co\.|aws|google|microsoft|amazon/.test(domain)
      out.push(
        makeFinding(
          'CONTACT',
          isWork ? 'work_email' : 'personal_email',
          m[1],
          start,
          end,
          isWork ? 60 : 45,
          isWork ? 'Detected likely work email' : 'Detected personal email',
        ),
      )
    }
    return out
  },

  // Credit card numbers (Luhn check)
  (text) => {
    const re = /\b(\d[ \-]?){13,19}\b/g
    const out: Finding[] = []
    let m
    while ((m = re.exec(text))) {
      const raw = m[0].replace(/[^0-9]/g, '')
      const valid = luhnCheck(raw) && raw.length >= 13 && raw.length <= 19
      if (valid) {
        out.push(makeFinding('FINANCIAL_INFORMATION', 'credit_card', m[0], m.index, re.lastIndex, 95, 'Likely credit card number'))
      }
    }
    return out
  },

  // SSN (US) patterns
  (text) => {
    const re = /\b\d{3}-\d{2}-\d{4}\b/g
    const out: Finding[] = []
    let m
    while ((m = re.exec(text))) {
      out.push(makeFinding('PERSONALLY_IDENTIFIABLE_INFORMATION', 'ssn', m[0], m.index, re.lastIndex, 90, 'US Social Security Number format'))
    }
    return out
  },

  // API keys / sk- style
  (text) => {
    const re = /\b(sk-[A-Za-z0-9]{16,})\b/g
    const out: Finding[] = []
    let m
    while ((m = re.exec(text))) {
      out.push(makeFinding('AUTH_CREDENTIAL', 'api_key', m[1], m.index, re.lastIndex, 100, 'API key pattern (sk-...)'))
    }
    return out
  },

  // Bearer tokens or JWT-looking strings
  (text) => {
    const re = /\b([A-Za-z0-9-_]+=*\.[A-Za-z0-9-_]+=*\.[A-Za-z0-9-_]+=*)\b/g
    const out: Finding[] = []
    let m
    while ((m = re.exec(text))) {
      out.push(makeFinding('AUTH_CREDENTIAL', 'jwt', m[1], m.index, re.lastIndex, 100, 'Probable JWT / bearer token'))
    }
    return out
  },

  // IPv4 private ranges
  (text) => {
    const re = /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g
    const out: Finding[] = []
    let m
    while ((m = re.exec(text))) {
      out.push(makeFinding('INTERNAL_HOST', 'private_ip', m[1], m.index, re.lastIndex, 60, 'Private IPv4 address'))
    }
    return out
  },

  // Simple password label detection ("password: 12345")
  (text) => {
    const re = /\b(password|passwd|pwd|secret|passphrase)\s*[:=]\s*([^\s,;]+)/gi
    const out: Finding[] = []
    let m
    while ((m = re.exec(text))) {
      out.push(makeFinding('AUTH_CREDENTIAL', 'labeled_password', m[2], m.index + m[0].indexOf(m[2]), m.index + m[0].length, 95, 'Labeled password or secret'))
    }
    return out
  },

  // Basic phone number detection
  (text) => {
    const re = /\b\+?\d{1,3}?[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b/g
    const out: Finding[] = []
    let m
    while ((m = re.exec(text))) {
      const raw = m[0]
      // skip when short
      if (raw.replace(/\D/g, '').length < 7) continue
      out.push(makeFinding('CONTACT', 'phone', raw, m.index, re.lastIndex, 50, 'Phone number-like pattern'))
    }
    return out
  },
]

function luhnCheck(numStr: string) {
  let sum = 0
  let shouldDouble = false
  for (let i = numStr.length - 1; i >= 0; i--) {
    let d = parseInt(numStr.charAt(i), 10)
    if (shouldDouble) {
      d = d * 2
      if (d > 9) d -= 9
    }
    sum += d
    shouldDouble = !shouldDouble
  }
  return sum % 10 === 0
}

export function scanPrompt(text: string): ScanResult {
  const findings: Finding[] = []
  detectors.forEach((det) => {
    try {
      findings.push(...det(text))
    } catch (e) {
      // detector should not throw; ignore
    }
  })

  // Deduplicate overlapping findings: keep highest finalScore per span
  findings.sort((a, b) => a.startIndex - b.startIndex || b.finalScore - a.finalScore)
  const filtered: Finding[] = []
  for (const f of findings) {
    const overlap = filtered.find((g) => !(f.endIndex <= g.startIndex || f.startIndex >= g.endIndex))
    if (!overlap) filtered.push(f)
    else if (f.finalScore > overlap.finalScore) {
      // replace
      const idx = filtered.indexOf(overlap)
      filtered[idx] = f
    }
  }

  // Compute overall score: start with max finding finalScore, then add small modifiers
  let overall = 0
  if (filtered.length > 0) {
    overall = Math.max(...filtered.map((f) => f.finalScore))
    // simple modifier: +10 if multiple categories
    const uniqueCats = new Set(filtered.map((f) => f.categoryId)).size
    if (uniqueCats >= 2) overall = Math.min(100, overall + 10)
  }

  // Determine risk level
  let riskLevel: any = 'Low'
  if (overall >= 90) riskLevel = 'Critical'
  else if (overall >= 75) riskLevel = 'High'
  else if (overall >= 50) riskLevel = 'Elevated'
  else if (overall >= 30) riskLevel = 'Moderate'

  // Redact by replacing spans from end to start
  let redacted = text
  const byStartDesc = filtered.slice().sort((a, b) => b.startIndex - a.startIndex)
  for (const f of byStartDesc) {
    const before = redacted.slice(0, f.startIndex)
    const after = redacted.slice(f.endIndex)
    redacted = before + f.redactedValue + after
  }

  // Recommended action: choose the strictest defaultAction among findings
  const defaultActions = filtered.map((f) => {
    const cat = riskCategories.find((c) => c.id === f.categoryId)
    return cat?.defaultAction || 'Warn'
  })
  let recommended: any = 'Allow'
  if (defaultActions.includes('Hard block')) recommended = 'Hard block'
  else if (defaultActions.includes('Block and redact') || defaultActions.includes('Block or require approval')) recommended = 'Block or require approval'
  else if (defaultActions.includes('Warn and redact')) recommended = 'Warn and redact'

  return {
    overallScore: overall,
    riskLevel,
    recommendedAction: recommended,
    findings: filtered,
    redactedText: redacted,
    scannedAt: new Date().toISOString(),
  }
}

export default { scanPrompt }
