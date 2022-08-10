import type {
  Capability,
  CapabilitySemantics,
  Ucan,
  ValidateOptions,
} from './types'
import { validate } from './ucan'

/**
 * @template A
 * @param {import('./types').CapabilitySemantics<A>} semantics
 * @param {UcanChain} ucan
 */
export function* findValidCaps<A>(
  semantics: CapabilitySemantics<A>,
  ucan: UcanChain
) {
  const caps = ucan.capabilities()
  const parentCaps = []

  for (const cap of caps) {
    if (cap.with.startsWith('prf:')) {
      const proofs = ucan.proofs()
      const [, index] = cap.with.split(':')
      const parsedIndex = Number.parseInt(index)
      if (index === '*') {
        for (const proof of proofs) {
          parentCaps.push(...proof.capabilities())
        }
      }

      if (Number.isInteger(parsedIndex)) {
        parentCaps.push(...proofs[parsedIndex].capabilities())
      }
    }

    const parsed = semantics.tryParsing(cap)
    if (!(parsed instanceof Error)) {
      yield parsed
    }
  }

  for (const parentCap of parentCaps) {
    const parsed = semantics.tryParsing(parentCap)
    if (!(parsed instanceof Error)) {
      yield parsed
    }
  }
}

/**
 * Can ucan delegate capability with semantics
 *
 * @template A
 * @param {UcanChain} ucan
 * @param {A} capParsed
 * @param {import('./types').CapabilitySemantics<A>} semantics
 */
function canDelegate<A>(
  ucan: UcanChain,
  capParsed: A,
  semantics: CapabilitySemantics<A>
) {
  const ucanCapsParsed = findValidCaps(semantics, ucan)
  let escalation

  for (const ucanCapParsed of ucanCapsParsed) {
    const result = semantics.tryDelegating(ucanCapParsed, capParsed)

    if (result instanceof Error) {
      escalation = result
    } else if (result !== null) {
      return { value: ucanCapParsed }
    }
  }

  return {
    error: escalation || new Error('Not found.'),
  }
}

/**
 * Find root ucan for capability with semantics
 *
 * @template A
 * @param {UcanChain} ucan
 * @param {A} capParsed
 * @param {import('./types').CapabilitySemantics<A>} semantics
 * @returns {UcanChain}
 */
function findRoot<A>(
  ucan: UcanChain,
  capParsed: A,
  semantics: CapabilitySemantics<A>
): UcanChain {
  const proofs = ucan.proofs()
  if (proofs.length === 0) {
    return ucan
  } else {
    let lastError
    for (const parent of proofs) {
      const { value, error } = canDelegate(parent, capParsed, semantics)
      if (value) {
        return findRoot(parent, value, semantics)
      } else {
        lastError = error
      }
    }
    throw lastError
  }
}

/**
 * Represents a UCAN chain with all the proofs parsed into UCAN chains too.
 * - Validates each ucan
 * - Parses all the proofs in a UCAN chain
 * - Validate parent audience matches child issuer
 */
export class UcanChain {
  /**
   * @param {string} encoded
   * @param {import('./types').Ucan<UcanChain>} decoded
   */
  _encoded: string
  _decoded: Ucan<UcanChain>
  constructor(encoded: string, decoded: Ucan<UcanChain>) {
    this._encoded = encoded
    this._decoded = decoded
  }

  /**
   * Create an instance of UcanChain from a ucan jwt token
   *
   * @param {string} encodedUcan
   * @param {import('./types').ValidateOptions} [options]
   * @returns {Promise<UcanChain>}
   */
  static async fromToken(
    encodedUcan: string,
    options: ValidateOptions
  ): Promise<UcanChain> {
    const token = await validate(encodedUcan, options)

    // parse proofs recursively
    const proofs: UcanChain[] = await Promise.all(
      token.payload.prf.map(async (encodedPrf) => {
        return await UcanChain.fromToken(encodedPrf, options)
      })
    )

    // check sender/receiver matchups. A parent ucan's audience must match the child ucan's issuer
    const incorrectProof = proofs.find(
      (proof) => proof.audience() !== token.payload.iss
    )

    if (incorrectProof !== undefined) {
      throw new Error(
        `Invalid UCAN: Audience ${incorrectProof.audience()} doesn't match issuer ${
          token.payload.iss
        }`
      )
    }

    const ucanTransformed = {
      ...token,
      payload: {
        ...token.payload,
        prf: proofs,
      },
    }

    return new UcanChain(encodedUcan, ucanTransformed)
  }

  /**
   * Get valid capabilities for the semantics
   *
   * @template A
   * @param {import('./types').CapabilitySemantics<A>} semantics
   */
  caps<A>(semantics: CapabilitySemantics<A>) {
    const validCaps: Array<{ root: UcanChain; cap: A }> = []
    for (const cap of findValidCaps(semantics, this)) {
      try {
        const root = findRoot(this, cap, semantics)
        validCaps.push({ root, cap })
      } catch {}
    }

    return validCaps
  }

  /**
   * @template A
   * @param {import('./types').Capability} cap
   * @param {import('./types').CapabilitySemantics<A>} semantics
   */
  claim(cap: Capability, semantics: CapabilitySemantics<any>) {
    const capParsed = semantics.tryParsing(cap)
    if (capParsed instanceof Error) {
      throw capParsed
    }

    const { value, error } = canDelegate(this, capParsed, semantics)
    if (value) {
      return findRoot(this, value, semantics)
    } else {
      throw error
    }
  }

  proofs(): UcanChain[] {
    return this._decoded.payload.prf
  }

  audience(): string {
    return this._decoded.payload.aud
  }

  issuer(): string {
    return this._decoded.payload.iss
  }

  /**
   * The payload the top level represented by this Chain element.
   * Its proofs are omitted. To access proofs, use `.proofs()`
   *
   * @returns {import('./types').Ucan<never>}
   */
  payload(): Ucan<never> {
    return {
      ...this._decoded,
      payload: {
        ...this._decoded.payload,
        prf: [],
      },
    }
  }

  capabilities(): Capability[] {
    return this._decoded.payload.att
  }
}
