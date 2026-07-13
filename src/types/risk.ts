export type RiskLevel = 'Low' | 'Moderate' | 'Elevated' | 'High' | 'Critical'

export type DefaultAction =
  | 'Allow'
  | 'Warn'
  | 'Warn and redact'
  | 'Block or require approval'
  | 'Block and redact'
  | 'Hard block'

export interface SensitiveDataCategory {
  id: string
  name: string
  description: string
  baseScore: number
  defaultAction: DefaultAction
}

export interface Finding {
  id: string
  categoryId: string
  categoryName: string
  findingType: string
  matchedText: string
  redactedValue: string
  startIndex: number
  endIndex: number
  baseScore: number
  finalScore: number
  explanation?: string
}

export interface ScanResult {
  overallScore: number
  riskLevel: RiskLevel
  recommendedAction: DefaultAction
  findings: Finding[]
  redactedText: string
  scannedAt: string
}
