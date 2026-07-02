/**
 * Shared internal utilities — not exported from package public API.
 */
import { base64urlDecodeString } from '@baseworks/core'

export function parseJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const part = token.split('.')[1]
    if (!part) return null
    return JSON.parse(base64urlDecodeString(part)) as Record<string, unknown>
  } catch {
    return null
  }
}
