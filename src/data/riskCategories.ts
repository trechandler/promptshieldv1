import type { SensitiveDataCategory } from '../types/risk'

// Core categories with base severity scores and default actions
const riskCategories: SensitiveDataCategory[] = [
  {
    id: 'AUTH_CREDENTIAL',
    name: 'Authentication Credential',
    description: 'Username/password, API keys, tokens, and other authentication secrets.',
    baseScore: 90,
    defaultAction: 'Hard block',
  },
  {
    id: 'PERSONALLY_IDENTIFIABLE_INFORMATION',
    name: 'Personally Identifiable Information (PII)',
    description:
      'Names, email addresses, phone numbers, government IDs, and other personal identifiers.',
    baseScore: 70,
    defaultAction: 'Warn and redact',
  },
  {
    id: 'FINANCIAL_INFORMATION',
    name: 'Financial Information',
    description: 'Credit card numbers, bank account numbers, routing numbers, and CVV codes.',
    baseScore: 90,
    defaultAction: 'Hard block',
  },
  {
    id: 'HEALTH_MEDICAL',
    name: 'Medical / PHI',
    description: 'Health data or protected health information.',
    baseScore: 80,
    defaultAction: 'Block or require approval',
  },
  {
    id: 'CONFIDENTIAL_BUSINESS',
    name: 'Confidential Business Information',
    description: 'Proprietary code, internal-only secrets, NDAs, and confidential product details.',
    baseScore: 75,
    defaultAction: 'Block or require approval',
  },
  {
    id: 'CONTACT',
    name: 'Contact Information',
    description: 'Email addresses (work vs personal), phone numbers, and postal addresses.',
    baseScore: 50,
    defaultAction: 'Warn and redact',
  },
  {
    id: 'IDENTIFIERS',
    name: 'Identifiers and IDs',
    description: 'Driver license, passport, internal IDs, and similar identifiers.',
    baseScore: 70,
    defaultAction: 'Warn and redact',
  },
  {
    id: 'CODE_SNIPPET',
    name: 'Source Code / Credentials in Code',
    description: 'Proprietary source code, hard-coded secrets, or configuration with credentials.',
    baseScore: 85,
    defaultAction: 'Block and redact',
  },
  {
    id: 'INTERNAL_HOST',
    name: 'Internal Host or IP',
    description: 'Private IP addresses, internal hostnames, and production hostnames.',
    baseScore: 60,
    defaultAction: 'Warn and redact',
  },
]

export default riskCategories
