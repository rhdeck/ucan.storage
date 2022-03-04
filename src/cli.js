#!/usr/bin/env node
/* eslint-disable no-console */
import sade from 'sade'
import { KeyPair } from './keypair.js'
import * as Ucan from './ucan-storage.js'

const prog = sade('ucan-storage')
prog
  .command('keypair')
  .describe('Create a keypair.')
  .option('--from', 'Output keypair from exported private key.')
  .action(async (opts) => {
    try {
      const kp = await (opts.from
        ? KeyPair.fromExportedKey(opts.from)
        : KeyPair.create())

      console.log(`DID:           ${kp.did()}`)
      console.log(`Public Key:    ${kp.publicKeyStr()}`)
      console.log(`Private Key:   ${kp.export()}`)
    } catch (error) {
      console.error(error)
      process.exit(1)
    }
  })

prog
  .command('ucan', 'Create a ucan.')
  .option('--issuer')
  .option('--audience', 'Audience DID')
  .option('--expiration', 'Expiration date in ISO 8601 format.')
  .option('--with', 'Resource pointer.')
  .option('--can', 'Allowed action on the resource.')
  .action(async (opts) => {
    try {
      const kp = await (opts.issuer
        ? KeyPair.fromExportedKey(opts.from)
        : KeyPair.create())

      const milliseconds = Date.parse(opts.expiration)
      const cap = { with: `storage://${opts.audience}`, can: 'upload/*' }

      const ucan = await Ucan.build({
        issuer: kp,
        audience: opts.audience,
        expiration: Math.floor(milliseconds / 1000),
        capabilities: [
          {
            with: opts.with || cap.with,
            can: opts.can || cap.can,
          },
        ],
      })

      const validated = await Ucan.validate(ucan)

      console.log(JSON.stringify(validated.payload, undefined, 2))
      console.log(`UCAN:\n${ucan}`)
    } catch (error) {
      console.error(error)
      process.exit(1)
    }
  })

prog.parse(process.argv)
