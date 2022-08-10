import type { Capability } from './types'

/**
 * @template S
 *
 */
export class CapabilityEscalationError<S> extends Error {
  parent: S
  child: S
  /**
   * @param {string} msg
   * @param {S} parent
   * @param {S} child
   */

  constructor(msg: string, parent: S, child: S) {
    super(msg)
    this.parent = parent
    this.child = child
  }

  static CODE = 'ERROR_CAPABILITY_ESCALATION'
}

/**
 * @template S
 *
 */
export class CapabilityUnrelatedError<S> extends Error {
  parent: S
  child: S
  /**
   * @param {S} parent
   * @param {S} child
   */
  constructor(parent: S, child: S) {
    super('Capabilities are unrelated.')
    this.parent = parent
    this.child = child
  }
  static CODE = 'ERROR_CAPABILITY_UNRELEATED'
}

export class CapabilityParseError extends Error {
  cap: Capability
  /**
   * @param {string} msg
   * @param {import('./types.js').Capability} cap
   */
  constructor(msg: string, cap: Capability) {
    super(msg)
    this.cap = cap
  }
  static CODE = 'ERROR_CAPABILITY_PARSE'
}
